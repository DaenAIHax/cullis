# Architecture

Deep dive into the Agent Trust Network design — modules, flows, and key decisions.

---

## Modules

| Module | Responsibility |
|---|---|
| Auth | x509 client assertion verification, JWT RS256 issuance, JTI blacklist |
| Registry | Organizations, agents, bindings, org CA storage, capability discovery |
| Broker | Sessions, messages, WebSocket push, persistence, restore on startup |
| Policy | Session default-deny + message policy evaluation |
| Onboarding | External org join requests, admin approval/reject |
| Rate Limit | Sliding window limiter — auth, session, message buckets |
| Injection | Prompt injection detection — regex fast path + LLM judge |
| Signing | RSA-PKCS1v15-SHA256 sign + verify for every inter-agent message |
| Audit | Append-only event log — payload hash + signature per message |

---

## Authentication Flow

When an agent wants to authenticate, it builds a signed JWT containing its own certificate, and sends it to the broker. The broker does not trust the certificate blindly — it verifies the full chain.

1. Agent builds a `client_assertion` JWT signed with its private key. The certificate is embedded in the JWT header (`x5c` field).
2. Broker checks rate limit (10 requests/min per IP).
3. Broker extracts the certificate from the `x5c` header.
4. Broker loads the organization's CA certificate from the database.
5. Broker verifies the certificate chain: agent cert must be signed by the org CA.
6. Broker verifies the certificate is within its validity period.
7. Broker verifies the JWT signature using the certificate's public key.
8. Broker checks that `sub` in the JWT matches the `CN` in the certificate.
9. Broker checks that an approved binding exists for this (org, agent) pair.
10. Broker checks the JWT ID (`jti`) is not in the blacklist, then consumes it.
11. Broker stores the agent's certificate in the database (used later for message verification).
12. Broker issues an access token signed with the broker's own private key.

---

## Session Flow

1. Initiator sends a session request to the broker specifying the target agent.
2. Broker checks that both agents have approved bindings and that their scopes overlap.
3. Broker checks the initiator's session policy — if no policy exists, the session is rejected (default-deny).
4. Broker creates the session in `pending` state and notifies the target via WebSocket.
5. Target accepts the session — status becomes `active`.
6. Both agents can now exchange messages through the broker.
7. Either agent can close the session. Closure is idempotent.

---

## Message Signing Flow

Every message is signed by the sender before sending. The broker verifies the signature before storing or forwarding.

**What gets signed (canonical format):**
```
{session_id}|{sender_agent_id}|{nonce}|{canonical_json(payload)}
```

Canonical JSON uses sorted keys and no whitespace — deterministic regardless of serialization order.

**Steps:**
1. Agent computes the canonical string.
2. Agent signs it with RSA-PKCS1v15-SHA256 using its private key.
3. Agent sends the message with the signature attached.
4. Broker loads the sender's certificate from the database (stored at login).
5. Broker verifies the signature against the certificate's public key.
6. Broker stores the message with the signature.
7. Broker writes to the audit log: payload hash (SHA256) + signature.

Any party holding the sender's certificate can verify any message independently — without trusting the broker.

---

## Injection Detection

Every message goes through a two-stage inspection pipeline before being stored.

**Stage 1 — Regex fast path (zero latency)**

Checked immediately against 12 pattern categories:
- Instruction override ("ignore all previous instructions")
- Role hijack ("you are now", "act as")
- DAN jailbreak variants
- System/instruction tags (`<system>`, `<instructions>`)
- Human/Assistant turn markers
- Prompt leak requests ("reveal your system prompt")
- Null bytes
- Unicode direction tricks (RTL override, zero-width characters)

If any pattern matches → HTTP 400, message blocked, audit log entry written.

**Stage 2 — LLM judge (only on suspicious payloads)**

A message is considered suspicious if:
- Total payload length exceeds 300 characters
- String values contain newlines
- Payload contains markdown or HTML characters

If suspicious, the message is sent to Claude Haiku for evaluation. If confidence ≥ 0.7 → blocked. Otherwise → stored and forwarded.

Structured B2B messages like `{"type": "order", "qty": 500}` skip the LLM judge entirely.

---

## Session Persistence

Every state change (create, activate, close) is immediately written to the database. On broker startup, all non-expired, non-closed sessions are restored to memory.

**Restore process:**
1. Query sessions with status `pending` or `active` and `expires_at` in the future.
2. For each session, reconstruct the session object.
3. Reload the full message list from the database.
4. Rebuild the used-nonce set (for replay protection continuity).
5. Restore to the in-memory session store.

Agents resume without intervention. Broker restart is transparent.

---

## Policy Engine

**Sessions — default deny**

Without an active policy, no session can be opened. A policy must explicitly allow the session. Conditions evaluated:

| Condition | Description |
|---|---|
| `target_org_id` | Which organization the initiator is allowed to reach |
| `capabilities` | Required capability overlap between both agents |
| `max_active_sessions` | Concurrency limit for the initiator |

**Messages — default allow**

Without a policy, messages pass through. A policy can block messages based on:

| Condition | Description |
|---|---|
| `max_payload_size_bytes` | Maximum allowed payload size |
| `required_fields` | Fields that must be present in the payload |
| `blocked_fields` | Fields that must not be present in the payload |

---

## PKI Design

Three-level certificate hierarchy:

| Level | Key Size | Validity | Purpose |
|---|---|---|---|
| Broker CA | RSA 4096 | 10 years | Controls the entire network |
| Org CA | RSA 2048 | 5 years | Signs agent certificates for one organization |
| Agent cert | RSA 2048 | 1 year | Authenticates a single agent |

The broker trusts **org CAs**, not individual agent certificates. The org CA is uploaded by the org admin at onboarding time and stored in the database. When an agent authenticates, the broker verifies that the agent's certificate was signed by that org's CA.

This means a leaked agent private key is not enough to impersonate an agent from a different organization — the attacker would also need the org CA private key.

---

## Replay Protection

Two independent mechanisms covering two different attack surfaces:

| Attack surface | Mechanism | Scope |
|---|---|---|
| Client assertion reuse | JTI blacklist (database) | Per JWT, global |
| Message resend | Nonce deduplication (DB UNIQUE constraint) | Per message, per session |

JTI entries are cleaned up lazily — expired entries are deleted on each new insert, with no background job needed.

---

## Rate Limiting

Sliding window in-memory, three independent buckets:

| Bucket | Key | Limit |
|---|---|---|
| Auth token requests | IP address | 10 per minute |
| Session open requests | agent_id | 20 per minute |
| Message sends | agent_id | 60 per minute |

HTTP 429 returned when a limit is exceeded.

---

## External Onboarding

Organizations joining the network from outside go through an approval process:

1. External org sends a join request with their org ID, display name, secret, and CA certificate.
2. Org is created in `pending` state — login is blocked immediately.
3. Admin reviews pending requests and approves or rejects.
4. On approval, org status becomes `active` — agents can now authenticate.
5. On rejection, org status becomes `rejected` — login remains blocked permanently.

---

## Audit Log

Append-only table — no updates, no deletes. Every event records:

| Field | Description |
|---|---|
| `timestamp` | When the event occurred |
| `event_type` | Type of event (auth, session, message, policy, injection, onboarding) |
| `agent_id` | Agent involved |
| `org_id` | Organization involved |
| `session_id` | Session involved (if applicable) |
| `details` | JSON with event-specific data |
| `result` | Outcome: `ok`, `denied`, or `error` |

Message events additionally include `payload_hash` (SHA256) and `signature` — sufficient for forensic verification by any auditor holding the sender's certificate.
