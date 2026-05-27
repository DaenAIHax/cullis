# Cullis Mastio threat model (public)

**Audience:** CISOs, security architects, and customer security teams
evaluating Cullis Mastio for regulated deployments.

**Status:** Version 1.0, 2026-05-27. Updated as architectural
decisions land.

**Contact:** security@cullis.io for technical clarifications;
hello@cullis.io for pilot timing alignment.

**Scope:** The public Cullis repo ships **Cullis Mastio** (the
self-hosted org gateway in `mcp_proxy/`) and **Cullis SDK** (the
Python client in `cullis_sdk/`). Components living in the private
`cullis-enterprise` repo (Connector desktop, Frontdesk shared-mode
SPA, Court federation, sandbox/agents-demo) have their own threat
model tracked separately and shared with prospects under NDA.

---

## 1. Trust boundary

Mastio is the **policy decision and audit anchoring point** for one
organisation. Inside the boundary:

- The Org CA (3-tier PKI: Root → Intermediate → Agent leaf).
- The audit chain (append-only hash chain + optional Merkle batch
  + RFC 3161 TSA external anchor).
- The PDP webhook hook (operator-supplied policy engine).
- The AI gateway (embedded LiteLLM) and the MCP reverse-proxy.

Outside the boundary:

- The agents themselves (the SDK runs in the agent's process; Mastio
  treats every inbound call as untrusted until DPoP+mTLS prove
  identity).
- Upstream AI providers (Anthropic, OpenAI, Bedrock, Vertex, Ollama).
- Upstream MCP backends registered via `/proxy/backends/create`.
- The TSA used for audit anchoring (see §3).

Mastio is **not** a credential store. Authentication credentials live
at the sign-in channel (Frontdesk users.db, Connector laptop keystore,
external IdP via OIDC/SAML). Mastio mints short-lived agent certs and
records the principal chain.

---

## 2. Audit chain integrity

Cullis's central forensic claim is that **a logged action cannot be
silently removed or rewritten by anyone with operational access to
the Mastio database**, including the operator. Three defenses stack:

### 2.1 Hash chain (append-only)

Every audit row carries `row_hash = SHA-256(canonical(row) ||
previous_row_hash)`. A `BEFORE UPDATE / BEFORE DELETE` trigger refuses
any modification at the SQLite/Postgres layer (`alembic/versions/
0031_audit_append_only_v2.py`). An operator who manages to bypass the
trigger (drop trigger + manual edit) breaks the chain at the edit
point, which the offline verifier (`scripts/cullis-audit-verify.py`)
detects.

### 2.2 Merkle batch + STH (ADR-037)

Per-epoch batches of leaves are hashed into a Merkle tree; the
**Signed Tree Head (STH)** is what the TSA timestamps, not each
individual row. An auditor with a bundle export + an inclusion proof
file can replay verification offline and assert that a specific row
at a specific `chain_seq` was included in the anchored root.
`mcp_proxy/audit/merkle.py` + the inlined math in the verifier ship
the same algorithm — a third party with the verifier and the bundle
does not need Mastio access to confirm inclusion.

### 2.3 RFC 3161 TSA external anchor

The STH is sent to an RFC 3161 TSA (default: DigiCert public TSA at
`http://timestamp.digicert.com`) which returns a CMS-signed
TimeStampToken. The TST is persisted alongside the chain. An operator
who tries to backdate or fabricate STHs cannot also fabricate a
TimeStampToken with a credible `genTime` from a TSA they do not
control, because the TSA signature is verifiable offline against the
TSA's public certificate chain.

---

## 3. TSA anchoring: transport decisions

Two operator-visible decisions about how Mastio talks to the TSA
attract recurring CISO questions. Both are intentional, both reduce
the surface that ops needs to harden.

### 3.1 TSA URL must not point at a private network in production

`MCP_PROXY_AUDIT_ANCHOR_TSA_URL` is refused at startup
(`SystemExit(1)`, audit finding F-A-406) when it resolves to a
loopback address (`127.0.0.0/8`, `::1`), an RFC 1918 / RFC 4193
private range, or a link-local block (`169.254.0.0/16`, `fe80::/10`).
A privately-reachable TSA is operationally **mock-equivalent**: the
operator (or any attacker on the same LAN segment) can spin up a fake
TSA on that address and fabricate signed-looking tokens for arbitrary
digests, collapsing the dispute-grade claim. Production deploys must
point at a public TSA (DigiCert, GlobalSign, Sectigo, Apple) or
disable anchoring outright with `MCP_PROXY_AUDIT_ANCHOR_ENABLED=false`
(air-gapped customers).

### 3.2 TSA transport may be plain HTTP

The gate accepts `http://timestamp.digicert.com` and does **not**
require `https://`. This is deliberate:

- The dispute-grade guarantee comes from the **CMS signature** on the
  returned TimeStampToken, not from the transport. The TST embeds the
  TSA's signer certificate, the operator's trust store pins the TSA
  root, and the offline verifier
  (`scripts/cullis-audit-verify.py`) walks the chain from leaf to
  pinned root with full signature verification — none of which uses
  TLS as evidence.
- The request body contains **only the SHA-256 hash of the row_hash**.
  Nothing about the audit row contents leaks on the wire. TLS on
  transport adds privacy of "this IP is asking for timestamps at
  this rate", not privacy of the audited material.
- Public TSAs (DigiCert / GlobalSign / Sectigo / Apple) publish their
  RFC 3161 endpoints on plain HTTP for the same reason: TLS on
  transport is non-load-bearing for provenance, and requiring it
  would block air-gapped or mTLS-constrained deploys that can route
  HTTP egress but not HTTPS through their own intermediate proxies.

An attacker who MITMs the plain-HTTP request would have to forge a
TimeStampToken whose CMS signature validates against the operator's
pinned TSA roots — a property no MITM gains from being on the wire.

---

## 4. PKI lifecycle

- **Root CA** (Org Root): RSA-4096, never on disk in plaintext after
  ADR-031 (KMS-backed via Vault in production; filesystem in dev).
  Rotation is a planned event (multi-year cadence).
- **Intermediate CA**: RSA-4096, signs short-lived agent leaves.
  Rotation cadence is operator-driven; ADR-030 defines the
  pre-promote → atomic-swap flow.
- **Agent leaf**: RSA-2048 or ECDSA P-256, TTL configurable
  (default 90d). Cert-thumbprint pinning enforces that a re-enrolled
  agent cannot impersonate a prior agent with the same name unless
  the operator explicitly rotates the binding via
  `/registry/agents/{id}/rotate-cert`.

---

## 5. DPoP + mTLS binding

Every authenticated request to Mastio carries **both**:

- An x509 client cert presented over mTLS (RFC 8705 §3).
- A DPoP proof JWT (RFC 9449) bound to the agent's signing key.

The `cnf.jkt` thumbprint in the issued access token MUST equal the
SHA-256 of the JWK presenting the DPoP proof. Replay protection is
provided by the JTI store (Redis in production, in-memory in dev for
single-worker stacks). DPoP `htu` is checked against the operator's
configured `MCP_PROXY_PROXY_PUBLIC_URL`.

Mastio refuses plain Bearer authentication on every endpoint that
matters. The dashboard cookie-auth path is bound by httponly + secure
+ samesite + CSRF token.

---

## 6. Out of scope (today)

- **MCP backend egress hardening.** Mastio acts as a reverse-proxy
  to operator-registered MCP backends; mTLS to those backends is
  optional today (bearer / API key supported). Hardening to
  Mastio-issued mTLS certs for intra-org MCP server auth is tracked
  as ADR-007 Phase 2+.
- **Cross-org federation** is in `cullis-enterprise`, not in this
  threat model.
- **Post-quantum migration** has its own document at
  [`post-quantum-roadmap.md`](./post-quantum-roadmap.md).

---

## 7. Reporting a vulnerability

See [`SECURITY.md`](../.well-known/security.txt) and `SECURITY.md` at
the repo root for the coordinated disclosure process. Encrypted
reports to security@cullis.io.
