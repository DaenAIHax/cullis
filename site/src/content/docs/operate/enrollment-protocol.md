---
title: "Enrollment protocol (dashboard approval)"
description: "Bootstrap an agent identity through the Mastio dashboard approval flow: start → admin approves → poll-with-proof. Includes the Python SDK factory, curl + openssl recipe, and the M-onb-1 proof-of-possession rationale."
category: "Operate"
order: 5
updated: "2026-05-25"
---

# Enrollment protocol (dashboard approval)

**Who this is for**: a developer (or operator) bootstrapping a fresh agent identity into a community Mastio bundle without enterprise Connector tooling. The result is a local identity directory (`agent.key`, `agent.crt`, `dpop.key`, `meta.json`) that the SDK reads on every subsequent run. `agent.crt` carries the full ADR-034 chain (leaf + Mastio Intermediate) inline, so no separate chain file is needed.

## 30-second TL;DR

1. Agent dev calls `POST /v1/enrollment/start` with a freshly-generated public key, a proof of possession over that key, and a public DPoP JWK. The server returns a `session_id`.
2. Admin opens `https://<mastio>/proxy/enrollments` and clicks **Approve**. The server signs a leaf cert against the Mastio Intermediate CA and pins the DPoP JKT to the row.
3. Agent dev polls `GET /v1/enrollment/{session_id}/status` with an `X-Enrollment-Proof` header (signed over `enrollment-status:v1|<session_id>` using the original enrollment private key). The server releases `cert_pem` (already concatenated as leaf + Mastio Intermediate), `agent_id`, and `capabilities`.
4. Agent dev writes the identity directory and starts calling `chat_completion`, `list_mcp_tools`, etc.

The **proof header** is the M-onb-1 audit gate: without it, an attacker who guesses or steals a `session_id` cannot exfiltrate the issued cert. The gate is non-negotiable, but as of v0.5.4 the server returns a `detail` hint in the status response when the proof header is missing, so the path is discoverable from the wire.

## Python (SDK factory)

The `cullis-sdk` Python package ships a single-call factory that handles all five steps: keypair generation, fingerprint computation (SHA-256 of DER `SubjectPublicKeyInfo`, the trap that costs cold-readers half a day), pop signature, polling with the proof header, and atomic 0600 writes.

```python
from cullis_sdk import CullisClient

client = CullisClient.enroll_via_dashboard_approval(
    "https://mastio.example.com:9443",
    requester_name="Alice Developer",
    requester_email="alice@example.com",
    reason="building an MCP agent for daily trading",
    device_info="macOS 15.4 / cullis-sdk 0.5.4",
    save_to="~/.cullis/agent-alice",
    poll_interval_s=5.0,
    timeout_s=600.0,
    verify_tls=True,
    ca_chain_path=None,  # or path to a pinned org-ca.pem
    on_pending=lambda sid, url: print(
        f"Pending session {sid}. Ask the admin to approve at {url}"
    ),
)

# The returned client is fully wired: TLS client cert (the credential
# under ADR-014), persistent DPoP key, auto-login on first authed call.
print(client.chat_completion(model="gpt-4o-mini", messages=[{
    "role": "user", "content": "hello",
}]))
```

The factory raises:

- `ConnectionError` — Mastio unreachable (TLS / DNS / refused).
- `PermissionError` — start rejected (bad pop signature, rate limited) OR admin clicked **Reject** (the `rejection_reason` is in the message).
- `TimeoutError` — admin did not act before `timeout_s` (the server-side TTL is 30 minutes; pick something similar or shorter).
- `ValueError` — cryptographic failure (should not happen in normal use).

After enrollment completes the identity directory looks like:

```
~/.cullis/agent-alice/
├── agent.key       # PKCS8 PEM, 0600 — enrollment private key + signing key
├── agent.crt       # PEM — leaf + Mastio Intermediate, ADR-034 chain inline
├── dpop.key        # PKCS8 PEM, 0600 — runtime DPoP egress key
└── meta.json       # {agent_id, capabilities, enrolled_at, mastio_url}
```

The server-side `cert_pem` already concatenates `leaf || Mastio Intermediate` (see `sign_external_pubkey` in `mcp_proxy/egress/agent_manager.py`), so the factory writes that single blob to `agent.crt` and the local-key login path walks the chain back to the Org Root without a sibling file.

Subsequent runs skip the dashboard dance entirely:

```python
client = CullisClient.from_identity_dir(
    "https://mastio.example.com:9443",
    cert_path="~/.cullis/agent-alice/agent.crt",
    key_path="~/.cullis/agent-alice/agent.key",
)
```

`from_identity_dir` reads the chained `agent.crt`, signs JWT assertions whose `x5c` header carries both certs, and the broker validates the path to the Org Root.

## Curl + openssl (non-Python clients)

The same flow without the SDK, suitable for Go / Rust / shell agents.

### Step 1: generate the enrollment keypair (EC P-256)

```bash
openssl ecparam -name prime256v1 -genkey -noout -out agent.key
openssl ec -in agent.key -pubout -out agent.pub
```

### Step 2: compute the server-shape fingerprint

The Mastio computes SHA-256 over the **DER** `SubjectPublicKeyInfo`. PEM text does not work.

```bash
openssl pkey -in agent.pub -pubin -outform DER -out agent.pub.der
FP=$(openssl dgst -sha256 -binary agent.pub.der | xxd -p -c 64)
echo "fingerprint: $FP"
```

### Step 3: sign the pop_signature

Domain-separated message `enrollment-pop:v1|<fingerprint>`:

```bash
printf 'enrollment-pop:v1|%s' "$FP" > pop.msg
openssl dgst -sha256 -sign agent.key -out pop.sig pop.msg
POP_B64URL=$(base64 -w0 pop.sig \
  | tr '+/' '-_' \
  | tr -d '=')
```

### Step 4: POST start

```bash
PUBKEY_PEM=$(awk '{printf "%s\\n",$0}' agent.pub)
RESPONSE=$(curl -sS -X POST \
  "https://mastio.example.com:9443/v1/enrollment/start" \
  -H 'Content-Type: application/json' \
  -d "{
    \"pubkey_pem\": \"$PUBKEY_PEM\",
    \"requester_name\": \"Alice\",
    \"requester_email\": \"alice@example.com\",
    \"reason\": \"shell-bootstrapped agent\",
    \"device_info\": \"curl/openssl recipe\",
    \"pop_signature\": \"$POP_B64URL\",
    \"principal_type\": \"agent\"
  }")
SESSION_ID=$(echo "$RESPONSE" | jq -r .session_id)
echo "session_id: $SESSION_ID"
echo "Ask the admin to approve at https://mastio.example.com:9443/proxy/enrollments"
```

(In production agents you would also generate a DPoP JWK and include it under `dpop_jwk`. Omitting it leaves the agent on the `egress_dpop_mode=optional` grace path; the admin endpoint can populate it post-hoc.)

### Step 5: sign the proof header ONCE

Bind it to the session_id — non-replayable across sessions.

```bash
printf 'enrollment-status:v1|%s' "$SESSION_ID" > proof.msg
openssl dgst -sha256 -sign agent.key -out proof.sig proof.msg
PROOF=$(base64 -w0 proof.sig \
  | tr '+/' '-_' \
  | tr -d '=')
```

### Step 6: poll for the admin decision

```bash
while true; do
  BODY=$(curl -sS -H "X-Enrollment-Proof: $PROOF" \
    "https://mastio.example.com:9443/v1/enrollment/$SESSION_ID/status")
  STATUS=$(echo "$BODY" | jq -r .status)
  case "$STATUS" in
    approved) # cert_pem already carries leaf || Mastio Intermediate
              echo "$BODY" | jq -r .cert_pem > agent.crt
              break ;;
    rejected) echo "rejected: $(echo "$BODY" | jq -r .rejection_reason)"
              exit 1 ;;
    expired)  echo "expired"; exit 1 ;;
    *)        sleep 5 ;;
  esac
done
```

If you **forget** the `X-Enrollment-Proof` header on the poll, the server returns `status: "approved"` with `cert_pem: null` AND a `detail` field describing the missing header. This is the v0.5.4 cold-reader fix: the wire now hints at the proof-of-possession gate instead of silently nulling everything out.

## Why the proof header exists (M-onb-1 audit)

The `session_id` is a 128-bit URL-safe random token, but it travels through logs, CI pipelines, browser histories, and admin dashboards. Without an additional gate, anyone who shoulder-surfed or grepped a log could pull a freshly-approved cert just by knowing the `session_id`.

The proof header binds the `/status` poll to the original enrollment keypair: the server holds the public key on the pending row, the caller signs a domain-separated message (`enrollment-status:v1|<session_id>`) with the private half, and the server verifies before releasing `cert_pem`. The signature is non-replayable across sessions (binds to `session_id`) and across keys (binds via verification against the row's `pubkey_pem`).

The gate is **not optional** and never will be. The v0.5.4 fix only adds discoverability: the `detail` field tells a caller who forgot the header what to send next, and links here.

## See also

- [Rotate keys](rotate-keys) — once enrolled, the cert is rotated via `POST /v1/registry/agents/{id}/rotate-cert`.
- [Vault as Org CA private key store](vault-org-ca) — how the Mastio loads the CA that signs the leaf during approve.
- [Rego policies](rego-policies) — the `capabilities` granted at approval drive policy evaluation on every call.
