# ADR-014 — nginx mTLS for Connector ↔ Mastio (intra-org)

- **Status:** Proposed
- **Date:** 2026-04-27
- **Supersedes:** parts of the implicit "X-API-Key over HTTP plain" intra-org auth model (no ADR ever wrote this down — it was inherited from when the Mastio was a thin reverse-proxy, before ADR-006 turned it into a mini-broker)
- **Related:** ADR-006 (Trojan Horse standalone Mastio), ADR-009 (Mastio identity / countersign), ADR-011 (unified enrollment), ADR-013 (layered defence)

## Context

The Mastio started life as a thin reverse-proxy in front of the Court. Internal agents authenticated to it with `X-API-Key` over HTTP plain on port 9100, and the Mastio forwarded the real auth (mTLS + DPoP + RFC 8705 cert-binding) outward to the Court. The trust boundary was the Court; the Mastio was an in-process gateway.

ADR-006 inverted this. The Mastio is now a self-contained mini-broker: it issues its own Org CA, signs its agents' certificates, terminates intra-org sessions end-to-end, persists agent identity, and (in standalone mode, ADR-006 §2.2) doesn't talk to the Court at all. The trust boundary moved into the Mastio.

The intra-org auth path did not move with it. Today:

- Connector → Mastio: `X-API-Key` header over HTTP plain on port 9100. Anyone on-path sees the credential. The cert that the Mastio just issued the Connector during enrollment is held but never presented at the transport layer — it's used only later, for outbound traffic to the Court via the Mastio's reverse-proxy.
- Mastio → Court (cross-org): full OAuth 2.0 client_credentials with `private_key_jwt` client authentication, DPoP proof-of-possession, and RFC 8705 mTLS-bound tokens. Clean.

This asymmetry produced two visible failures by the time of writing:

1. Issue **#325** — the api_key the Connector generates locally embeds `$HOSTNAME` (or `"connector"` under pipx) as the label. The Mastio's O(1) lookup path (post enterprise-#6) parses the agent_name out of the key prefix and queries `WHERE agent_id = '{org_id}::{label}'`. Under pipx the label is always `"connector"`, never the assigned `agent_id`, so every device-code-enrolled agent gets a 401 on the first authenticated egress call.

2. The threat-model intuition that "intra-org doesn't need to be E2E, but it can't pass in chiaro." Today it does pass in chiaro. nginx in front of the Mastio is documented in `deploy_proxy.sh` as a *production* recommendation — meaning by default, even for the demo, the credential travels in plain text over the loopback or LAN.

The threat model the Mastio inherited is no longer the threat model it inhabits. This ADR fixes the gap by binding the transport to the trust.

## Decision

A short list, then justification.

1. **All Connector → Mastio traffic terminates TLS at an nginx sidecar bundled with the Mastio.** No more port 9100 HTTP. The Mastio container exposes only port 9443 to the world, served by `mastio-nginx` (a sidecar in the same compose project). Internally `mcp-proxy` keeps listening on 9100 but only on the internal docker network — never published.

2. **Routes that carry agent identity require client certificates** (mTLS in the strict sense). The Org CA the Mastio already issues at first-boot is the trust bundle for client cert verification — same CA, same chain, the cert is the one the Connector received during enrollment. nginx forwards the verified cert to FastAPI in `X-SSL-Client-Cert: $ssl_client_escaped_cert`. A new dependency `get_agent_from_client_cert` parses the header, pins the leaf against `internal_agents.cert_pem`, and returns the `InternalAgent` row. This dependency replaces `get_agent_from_dpop_api_key` on `/v1/egress/*` and authenticates `/v1/agents/me/*`.

3. **Routes that carry no caller identity stay anonymous over server-only TLS.** `/v1/enrollment/start` (anonymous by design — the caller has no cert yet) and `/v1/enrollment/{session_id}/status` (poll endpoint, ditto) are reachable over TLS without `ssl_verify_client`. The wire is encrypted; there's just nothing to authenticate at the transport layer until enrollment completes.

4. **Dashboard admin routes (`/proxy/*`) use server-only TLS plus the existing session/OIDC login.** Browsers don't carry agent client certs. The browser admin authenticates at the application layer (password, OIDC) — same as today, just over TLS now.

5. **The api_key auth path is removed.** Once mTLS lands and the routes above migrate, `get_agent_from_api_key`, `get_agent_from_dpop_api_key`, `internal_agents.api_key_hash`, the api_key-rotate endpoints, the Connector's `_generate_api_key` / `_bcrypt_hash` helpers, the api_key file in the identity bundle, and the `api_key_hash` enrollment payload all go away. The cert is the credential. Issue #325 closes by dissolution: the path that carried the bug stops existing.

6. **DPoP stays.** It's not redundant with mTLS — DPoP is proof-of-possession on a per-request basis. The combination "cert authenticates identity at TLS handshake + DPoP signs each request payload" maintains replay protection at request granularity, which mTLS alone doesn't give. The DPoP keypair persists where it already lives in the identity bundle.

7. **No backward compatibility for HTTP plain.** The current install base is "the maintainer + the demo VM." Burning a deprecation window costs us more than burning the install base. The 9100 HTTP listener disappears when PR-A merges; deployments updating past that release point at 9443.

### Routing table

| Path prefix | TLS | Client cert | Auth dependency |
|---|---|---|---|
| `/v1/egress/*` | required | required | `get_agent_from_client_cert` + DPoP |
| `/v1/agents/me/*` | required | required | `get_agent_from_client_cert` |
| `/v1/agents/search` | required | required | `get_agent_from_client_cert` |
| `/v1/enrollment/start` | required | none | anonymous |
| `/v1/enrollment/{session_id}/status` | required | none | anonymous (session_id is the capability) |
| `/v1/auth/*` (login-challenge, etc.) | required | none | application-layer (existing) |
| `/proxy/*` (dashboard) | required | none | session cookie or OIDC |
| `/health`, `/readyz` | required | none | anonymous |
| `/pdp/policy` | required | required (broker cert) | broker mTLS (existing semantics) |

### Architecture (compose project layout)

```
                                    ┌───────────────────────┐
                                    │  mastio-nginx (9443)  │
                                    │  TLS termination      │
                                    │  ssl_verify_client on │
                                    │  for /v1/egress/*     │
                                    │  /v1/agents/*         │
                                    └──────────┬────────────┘
                                               │ X-SSL-Client-Cert
                                               │ (URL-encoded PEM)
                                               ▼
                                    ┌───────────────────────┐
                                    │  mcp-proxy (9100)     │
                                    │  internal docker net  │
                                    │  no host binding      │
                                    └───────────────────────┘
```

### Server cert for nginx

Mastio's first-boot already generates the Org CA. PR-A extends `agent_manager.py` first-boot to also emit a server certificate for nginx, signed by the Org CA, with `subjectAltName = DNS:mastio.local` (default — overridable via `MCP_PROXY_NGINX_SAN`), and writes it to a shared docker volume `mastio-nginx-certs`. nginx mounts the volume read-only; rotation is the same path as Org CA rotation (Phase 2 closed, see `project_pki_rotation_plan.md`).

The Org CA certificate (public part) gets the same treatment — copied to the same volume as `org-ca.pem` for nginx's `ssl_client_certificate` directive. Org CA private key never leaves the Mastio.

### Anti-spoofing on `X-SSL-Client-Cert`

The header is a textbook header-injection target. nginx must always overwrite it with `$ssl_client_escaped_cert` regardless of what the client sent (`proxy_set_header` does this), and `mcp-proxy` must refuse the header when it arrives without nginx's signature pattern (we'll add an internal shared secret header `X-Mastio-Edge: <token>` set by nginx and verified by FastAPI middleware — the bound on the threat is "anyone who reaches mcp-proxy directly bypasses nginx," which is exactly what binding mcp-proxy to the internal docker net prevents).

## Migration plan

Three sequential PRs, each shippable on its own. Stacked-PR base=fix/* problem (`feedback_stacked_pr_ci_trigger`) avoided by keeping each PR rebased on `main` before opening.

**PR-A — nginx sidecar.** New `mastio-nginx` service in `docker-compose.proxy.yml`. nginx config with the routing table above. Mastio first-boot extension to emit server cert + Org CA into the shared volume. `deploy_proxy.sh` updated: `--standalone` and default mode both bind 9443, drop 9100 host publish. Smoke test exercises curl with valid client cert (200), without (401), with cert from a different CA (401).

**PR-B — `get_agent_from_client_cert` + apply.** New FastAPI dependency reads `X-SSL-Client-Cert`, URL-decodes, parses PEM, extracts SAN URI (preferred — SPIFFE format `spiffe://<org_id>/<agent_name>`) or falls back to CN, builds canonical `agent_id = {org_id}::{agent_name}`, looks up `internal_agents`, pins the leaf DER against `cert_pem`, applies rate limiting, records audit. Apply to `/v1/egress/*`, `/v1/agents/me/*`, `/v1/agents/search`. Connector grows an `httpx.Client` factory that loads `cert_pem + private_key_pem` from the identity bundle and reuses it across requests.

**PR-C — drop api_key auth.** Remove `get_agent_from_api_key`, `get_agent_from_dpop_api_key`, the `internal_agents.api_key_hash` column (alembic migration `0022_drop_api_key_hash`), `auth/api_key.py::generate_api_key/hash_api_key/verify_api_key` (only the helpers — the dependency comes out separately), Connector `_generate_api_key/_bcrypt_hash`, the `api_key` file in the identity bundle, `start_enrollment.api_key_hash` payload field, dashboard admin rotate-key endpoint + UI, related tests, related docs. Closes #325 by dissolution.

After PR-C, **issue #327** (smoke E2E gate) lands as the persistent regression net. The gate's sole job is asserting the post-PR-C wire path works end-to-end: `deploy --standalone → enroll ×2 → send_oneshot → receive_oneshot`, all over mTLS.

Issue **#326** (wizard breaks `--standalone`) is independent of this ADR and ships in parallel as a separate PR. The wizard fix doesn't touch auth.

## Consequences

### Positive

- Intra-org wire matches intra-org trust. The transport binding catches up with what ADR-006 made the Mastio.
- The Connector's auth credential is the cert+private key, which it already has and which never crosses the wire (only the public cert does, during the TLS handshake).
- The api_key surface area — generation, hashing, lookup, rotation, label-vs-agent-id invariant, the smoke pipeline that didn't catch #325 — disappears.
- Cross-org and intra-org now use the same auth model conceptually (cert chain + pin), differing only in *which* CA roots the chain. Easier mental model.
- One layer of "you can run on HTTP if you want" is removed. The default is the safe path.

### Negative

- Adding a sidecar to the compose project. Operationally it's one more container to monitor, healthcheck, restart-policy, and version-pin.
- Cert rotation operationally couples the nginx server cert to the Org CA rotation cadence. Pre-existing playbook (`project_pki_rotation_plan.md`) covers it but adds a step.
- First-boot becomes more involved: the Mastio now emits *two* certs at boot (Org CA + nginx server). Extra failure mode if cert generation fails after volume mount.
- Test surface grows: every test that hit `http://localhost:9100` now hits `https://mastio.local:9443` with a client cert. Existing test fixtures need a one-time update to load the test identity bundle.
- Dashboard admin path stays "TLS + cookie" — different model from the agent path. Documenting this clearly is on us.

### Risks

- **Header spoofing** if `mcp-proxy` ever gets exposed directly. Mitigation: bind to internal docker net only, internal shared-secret header `X-Mastio-Edge` verified by middleware, fail-closed. Acceptance test: curl `mcp-proxy:9100` directly inside the network without the edge header → 401.
- **First-boot deadlock** if nginx starts before the Mastio has emitted the cert. Mitigation: nginx healthcheck waits on cert file presence; Mastio writes the cert before serving.
- **Org CA leak via volume** is the same risk as today (the CA private key is in Mastio state) — except that the volume is now shared with nginx. nginx mounts read-only and only reads the *public* CA cert, not the private key. This must be enforced at compose-volume level.
- **Browser admin who tries the agent paths**. Today an admin can curl `/v1/egress/peers` from their browser console with a copied api_key. Post-PR-C, that's impossible without the cert. We document this and make sure the dashboard's "test agent" tooling submits via the agent's identity bundle, not the admin's session.

## Alternatives considered

**(a) uvicorn directly with `ssl_cert_reqs=REQUIRED`** — single-process, no sidecar. Rejected: doesn't scale beyond a single uvicorn worker, restart = downtime, doesn't match production guidance that already mentions a reverse proxy. Bonus: today's `deploy_proxy.sh` already has nginx-equivalent guidance commented in for the broker path; the sidecar is the path of least surprise.

**(b) Application-layer signed JWT with x5c chain (the existing pattern in `auth/sign_assertion.py`)** — no deployment change, ~150 LOC, ships today. Rejected: doesn't move the wire to TLS. Solves #325 chirurgically but leaves "intra-org passes in chiaro" untouched. Half-fix.

**(c) OAuth client_credentials intra-org** — symmetric to the cross-org pattern. Rejected: adds a `/token` round-trip every N minutes, triples the auth surface, and gains nothing over "mTLS + cert as identity" because the trust scope is a single Mastio (which is the authorization server in this analogy anyway). OAuth shines when there are multiple resource servers per token; here there's one.

**(d) Status quo + better api_key hygiene (e.g., schema column for label, see issue #325 Option C)** — fixes #325 without a transport change. Rejected: leaves the credential on the wire, leaves the tech debt, doesn't move the trust model. Same issues will resurface in different shape.

## Open questions

1. **Default SAN for the nginx server cert.** Hardcoded `mastio.local` is fine for dev; production needs the operator's actual hostname. We'll plumb `MCP_PROXY_NGINX_SAN` env into first-boot. Open: do we accept comma-separated lists in v1, or single SAN with multi-SAN deferred?

2. **Connector → Mastio over the public internet** (when an org runs the Mastio behind their corporate gateway and the Connector is on a remote employee laptop). The Connector's cert chains to the Org CA, which only the Mastio knows. nginx config is the same. Open question: should the nginx config support TLS SNI-based dispatch for orgs that put multiple Mastios behind one host? Defer to v2.

3. **Health-check endpoints.** `/health` and `/readyz` are anonymous over TLS. Operational tools (Prometheus, k8s probe, gh actions smoke) need to reach them. The smoke gate (#327) hits them without a client cert. This works because `ssl_verify_client` is set per-location, not globally. Confirm: documenting that operators who lock down their network must allow the probes through TLS-only.

4. **Does `/v1/agents/search` need its own auth?** Today it auths the *caller* and lists agents the caller can see. With mTLS the caller is identified by cert. Same semantics, different dependency. No open question here, just flagging that PR-B's apply-list includes search.

5. **Helm chart** has the same wiring; PR-A covers compose, a follow-up handles the chart. Not a blocker.

## Acceptance

- All existing intra-org tests pass after switching their HTTP fixture to the mTLS fixture (one-time update, ~30 test files estimated).
- Smoke #327 `deploy --standalone → enroll ×2 → send_oneshot` passes 50 consecutive runs against `main` after PR-C.
- A request with `X-SSL-Client-Cert` set by the caller (without going through nginx) returns 401, even if the cert in the header is otherwise valid.
- `/v1/egress/peers?limit=1` over `https://mastio.local:9443` with the issued client cert returns 200.
- The Mastio container exposes no listener on host port 9100 after PR-A.
