# Cullis MCP Proxy — operator guide

The MCP proxy is a standalone org-level gateway for AI agents: it terminates agent authentication, routes intra-org agent-to-agent traffic, enforces policy, records audit, and hosts an OIDC-protected dashboard for operators. You deploy it as a single container — no Cullis broker required.

Cross-org federation (agent-to-agent between different organizations) requires a Cullis broker in front of multiple proxies. That piece is optional and can be added later. This guide treats standalone as the primary mode.

---

## 1. What the proxy does

Standalone, the proxy gives your org:

- **Agent enrollment and identity** — issues x509 certs signed by an Org CA the proxy generates on first boot. Agents authenticate with their cert + DPoP; the proxy validates both locally.
- **Intra-org message bus** — session open/accept/close, E2E-encrypted send, polling and WebSocket receive. A local mini-broker in the proxy DB. Agents inside the same org never leave your network.
- **MCP tool proxying** — `/v1/ingress/*` fronts the MCP servers your agents need to call. One place to wire auth, rate limit, and policy.
- **Policy enforcement** — YAML rules (blocked agents, allowed orgs for future federation, capability whitelists) evaluated on every session open.
- **Audit log** — append-only, per-org hash chain, exportable from the dashboard.
- **OIDC dashboard** — org admins sign in with their existing IdP (Keycloak / Okta / Entra) to manage agents, policies, audit.

When (and if) you want **cross-org** messaging, you attach a Cullis broker. Same binary, same config, one env flag. See §11.

**Footprint:** one proxy per org, per environment. Usually 2-3 replicas behind a network LB, sharing a Postgres (or SQLite for dev) and optionally Vault for secrets.

**Security boundary:** the proxy is your org trust boundary. Anyone who can reach the dashboard is an org admin. Run it on an internal network, put OIDC in front, use mTLS if your agents can terminate it.

---

## 2. Install

### 2.1 Docker (single host)

```bash
docker run -d --name cullis-proxy \
  -p 9100:9100 \
  -e MCP_PROXY_STANDALONE=true \
  -e MCP_PROXY_ENVIRONMENT=production \
  -e MCP_PROXY_ORG_ID=acme \
  -e MCP_PROXY_PROXY_PUBLIC_URL=https://cullis.acme.internal \
  -e MCP_PROXY_ADMIN_SECRET="$(openssl rand -hex 32)" \
  -v cullis-proxy-data:/data \
  ghcr.io/cullis-security/mcp-proxy:0.1.0-rc1
```

Verify:

```bash
curl http://localhost:9100/health        # {"status":"ok"}
curl -I http://localhost:9100/health     # x-cullis-mode: standalone
```

Open the dashboard at `http://localhost:9100/proxy`. On first boot it asks you to set the admin password, then lands you on the overview page. The proxy has already generated its Org CA by that point — see **Organization** in the sidebar to download the CA cert.

### 2.2 Kubernetes (Helm)

```bash
helm install cullis-proxy \
  oci://ghcr.io/cullis-security/charts/cullis-proxy \
  --version 0.1.0-rc1 \
  --namespace cullis --create-namespace \
  --set proxy.orgId=acme \
  --set proxy.proxyPublicUrl=https://cullis.acme.internal \
  --set postgresql.enabled=true \
  --set vault.enabled=true
```

Standalone mode is the chart default. Minimum values to review:

| Key | Meaning | Default |
|---|---|---|
| `proxy.standalone` | Skip broker uplink. | `true` |
| `proxy.orgId` | Your org identifier. Used in every internal agent ID as `${orgId}::${agent}`. | `""` |
| `proxy.proxyPublicUrl` | The URL your internal agents + browsers use. DPoP htu + OIDC redirect. | `""` |
| `proxy.adminSecret` | Dashboard break-glass secret. | random |
| `postgresql.enabled` | Inline Postgres for dev. Set `false` and point at managed instance for prod. | `true` |
| `vault.enabled` | Store agent private keys in Vault KV v2 instead of DB. Required for prod. | `false` |
| `oidc.issuerUrl` | Your IdP issuer. Leave empty to fall back to the admin secret. | `""` |

Full surface: `helm show values oci://ghcr.io/cullis-security/charts/cullis-proxy --version 0.1.0-rc1`.

### 2.3 What the first boot does

With no broker configured:

1. Runs Alembic migrations on the DB.
2. Generates a fresh self-signed Org CA (RSA-2048, 10 years, `BasicConstraints: CA=true, path_length=1`). Persists it to Vault if enabled, to `proxy_config` otherwise.
3. Waits for you to log into the dashboard and enroll your first agent.

If you want to bring your own Org CA (existing internal PKI), set `MCP_PROXY_ORG_CA_KEY_PATH` + `MCP_PROXY_ORG_CA_CERT_PATH` before the first boot — the proxy loads them instead of generating new ones.

---

## 3. Configure

Environment variables (prefix `MCP_PROXY_`) plus a `proxy_config` table in the DB. The list below is what you actually touch; full reference in `mcp_proxy/config.py`.

| Var | Purpose |
|---|---|
| `MCP_PROXY_STANDALONE` | `true` for no-broker mode. Chart default is `true`. |
| `MCP_PROXY_PROXY_PUBLIC_URL` | What agents and browsers see in the URL bar. DPoP htu + OIDC redirect. |
| `MCP_PROXY_DATABASE_URL` | SQLAlchemy URL. `postgresql+asyncpg://...` in prod, `sqlite+aiosqlite:////data/mcp_proxy.db` by default. |
| `MCP_PROXY_ADMIN_SECRET` | Dashboard break-glass secret. Required even with OIDC. |
| `MCP_PROXY_ORG_ID` | Your org identifier. Used as the prefix in every local agent ID. |
| `MCP_PROXY_ALLOWED_ORIGINS` | CORS origins for the dashboard. Comma-separated. |
| `MCP_PROXY_SECRET_BACKEND` | `env` (dev) or `vault` (prod). |
| `MCP_PROXY_VAULT_ADDR` | Vault address when backend is `vault`. |
| `MCP_PROXY_VAULT_TOKEN` | Token with write access to `${VAULT_SECRET_PREFIX}/agents/*`. Prefer AppRole in prod. |
| `MCP_PROXY_ENVIRONMENT` | `development` / `production`. Flips production-safety checks. |

Federation-only (unset in standalone mode):

| Var | Purpose |
|---|---|
| `MCP_PROXY_BROKER_URL` | Broker base URL. |
| `MCP_PROXY_BROKER_JWKS_URL` | Broker JWKS endpoint. Usually `${BROKER_URL}/.well-known/jwks.json`. |

Production validators **fail startup** when `MCP_PROXY_ENVIRONMENT=production` and:
- `MCP_PROXY_ADMIN_SECRET` is still the insecure default.
- You are in federation mode (not standalone) and `BROKER_JWKS_URL` is empty or uses `http://`.

Don't work around these. Set the values.

---

## 4. Enroll internal agents

Internal agents are the workloads inside your org that use the Cullis SDK. Enrollment creates the cert (signed by your Org CA) and an API key the agent uses against the proxy.

### 4.1 From the dashboard (interactive)

1. Sign in at `${MCP_PROXY_PROXY_PUBLIC_URL}/proxy` with your IdP.
2. **Agents** → **Invite new agent** → name + capabilities → submit.
3. Copy the one-shot enrollment URL. Give it to the owner of the workload.
4. On the workload:

   ```python
   from cullis_sdk import CullisClient

   client = CullisClient.from_enrollment(
       "https://proxy.example.com/v1/enroll/enroll_xxx",
       save_config="/etc/cullis/agent.env",
   )
   # Key stays on the proxy; SDK gets an API key + authenticates via sign-assertion.
   client.login_via_proxy()
   ```

5. The dashboard shows the agent as **Active** as soon as it hits the enrollment URL.

### 4.2 Non-interactive (CI / automation)

```bash
# Admin issues the invite via API.
curl -X POST https://proxy.example.com/v1/admin/enrollments \
  -H "X-Admin-Secret: ${ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"ci-runner","capabilities":["build.read","artifact.push"]}'
# → { "session_id": "enroll_xxx", "enrollment_url": "..." }
```

Store the returned URL as a CI secret. The CI job bootstraps itself via `from_enrollment(..., save_config=...)`, writes the API key to `/etc/cullis/agent.env`, and reuses it from then on.

### 4.3 Classic BYOCA (own cert, no enrollment)

If your agent has its own cert signed by the Org CA (e.g. your existing internal PKI), skip enrollment. Use `client.login(agent_id, org_id, cert_path, key_path)` instead. The proxy never sees the private key; auth uses the certificate chain directly.

---

## 5. Intra-org messaging

Once two agents are enrolled in the same proxy, they open sessions and exchange E2E-encrypted messages without any external service.

```python
# agent-a (initiator)
agents = client.discover(capabilities=["order.write"])
session = client.open_session(agents[0].agent_id, agents[0].org_id, ["order.write"])
client.send(session, sender_agent_id=my_id, payload={"text":"Hello"},
            recipient_agent_id=agents[0].agent_id)

# agent-b (responder)
for msg in client.poll(session_id=...):
    handle(msg.payload)
```

Path: agent-a → proxy `/v1/egress/send` → local queue → proxy delivers to agent-b on poll/subscribe. Zero broker involvement, single proxy round-trip.

Session policy is evaluated on open (dashboard → **Policies**). Default-deny for cross-org sessions (only relevant once you federate), default-allow for intra-org.

---

## 6. SDK usage

The SDK always talks to the proxy — never direct to a broker, even when one exists later (ADR-004).

```python
from cullis_sdk import CullisClient

client = CullisClient("https://cullis-proxy.internal.acme.com")

# (a) enrolled: proxy holds the cert, SDK only needs the API key
client.login_via_proxy()

# (b) BYOCA: SDK holds the cert+key, signs client_assertion locally
client.login("acme::agent-a", "acme", "cert.pem", "key.pem")

# (c) SPIFFE: SVID fetched from the local Workload API socket
CullisClient.from_spiffe_workload_api("https://cullis-proxy...", org_id="acme")
```

Every response carries `x-cullis-role: proxy`. If the SDK ever sees `x-cullis-role: broker`, it raises a `DeprecationWarning` — the agent is bypassing its proxy, fix the config.

---

## 7. Expose the dashboard

Two auth modes side by side:

- **OIDC** — production. Per-org realm on your IdP. Users sign in with their org email; the proxy maps IdP claims to a Cullis session.
- **Admin secret** — break-glass. Single password, bcrypt-hashed, stored in the KMS backend (filesystem default, Vault if configured). Use for first boot and incident response.

### 7.1 OIDC setup (Keycloak example)

1. In Keycloak, create a realm `acme-cullis`.
2. Add client `cullis-proxy-dashboard` → `client_authentication=ON`, `valid_redirect_uris=https://proxy.example.com/proxy/oidc/callback`.
3. Set:
   ```
   OIDC_ISSUER_URL=https://keycloak.example.com/realms/acme-cullis
   OIDC_CLIENT_ID=cullis-proxy-dashboard
   OIDC_CLIENT_SECRET=<from Keycloak>
   ```
4. Restart the proxy. `/proxy` now redirects to Keycloak on unauthenticated access.

First user to log in via OIDC becomes org admin. Subsequent users need an admin to grant them a role — **Agents → Team → Invite**.

### 7.2 Admin secret fallback

First boot without OIDC, `/proxy` shows a one-time setup form. The bcrypt hash is written via the KMS backend:
- `MCP_PROXY_SECRET_BACKEND=env` → local file (`certs/.admin_secret_hash`, relative to CWD).
- `MCP_PROXY_SECRET_BACKEND=vault` → Vault at `${VAULT_SECRET_PREFIX}/dashboard`.

> **Containerized deploy gotcha.** The default local KMS backend writes to `certs/` relative to the container's working directory (`/app`). That path is owned by `root` but the proxy runs as non-root. The Helm chart handles this; if you run the container with a custom setup, mount a writable volume at `/app/certs` or set `MCP_PROXY_SECRET_BACKEND=vault`. If the setup form returns *"Failed to save the new password (KMS backend may be unreachable)"* → this is why.

---

## 8. Observability

### 8.1 Health

| Endpoint | Purpose | Healthy response |
|---|---|---|
| `/health` | Liveness — process alive. | `200 {"status":"ok"}` |
| `/healthz` | Liveness alias for K8s. | `200 {"status":"ok"}` |
| `/readyz` | Readiness — DB writable (+ JWKS in federation mode). | `200 {"status":"ready", ...}` |

Standalone mode: `/readyz` reports `jwks_cache: "standalone"`. Federation mode: fails readiness if JWKS is stale past `MCP_PROXY_JWKS_REFRESH_INTERVAL_SECONDS * 2` — LB should drain.

### 8.2 Logs

JSON structured logging. Every request line carries `request_id`, `agent_id`, `path`, `status`, `ms`. Pipe to any log backend.

Useful greps:

```
level=ERROR
logger=mcp_proxy.egress                         # intra-org egress
logger=mcp_proxy.enrollment                     # agent enrollment
logger=mcp_proxy.auth.sign_assertion            # enrolled-agent DPoP flow
logger=mcp_proxy.reverse_proxy                  # federation mode only
"htu mismatch"                                  # DPoP validation gone wrong
"use_dpop_nonce"                                # expected on first token req
```

### 8.3 Metrics

Prometheus scrape target: `GET /metrics`. Key series:

- `cullis_proxy_egress_send_total{path,status}` — intra-org send counter.
- `cullis_proxy_enrollment_pending_total` — pending one-shot invites.
- `cullis_proxy_reverse_forward_total{status}` — federation mode, broker response codes.
- `cullis_proxy_jwks_fetch_errors_total` — federation mode, broker unreachable.

Sample Grafana dashboard JSON in the chart under `dashboards/`.

### 8.4 Audit log

Dashboard → **Audit** — filter, export CSV. The chain is append-only and cryptographically linked (per-org hash chain + TSA anchors).

---

## 9. Backup and restore

Two pieces of state:

1. **DB**: `proxy_config`, `local_*`, enrollment invites, sessions, policy, audit.
2. **Agent private keys**: in Vault (if `SECRET_BACKEND=vault`) or in `proxy_config` otherwise.

### 9.1 Docker

```bash
# Nightly cron — dumps SQLite and Vault paths.
docker exec cullis-proxy python -m mcp_proxy.cli.backup --out /data/backup-$(date -u +%Y%m%dT%H%M%S).tar.gz
docker cp cullis-proxy:/data/backup-*.tar.gz /backups/
```

### 9.2 Kubernetes

Use your cluster's backup story (Velero, native volume snapshots). The chart sets `persistence.enabled: true` by default with a PVC at `/data`.

### 9.3 Org CA rotation

Rare and manual. Generate a new CA, re-issue every agent cert under it, update `proxy_config.org_ca_*`, restart. Agents with certs under the previous CA get 401 until re-enrolled. No graceful overlap window yet.

---

## 10. Upgrade and rollback

The proxy is stateless at the HTTP layer and durable in the DB.

```bash
docker pull ghcr.io/cullis-security/mcp-proxy:<new-tag>
docker stop cullis-proxy && docker rm cullis-proxy
docker run -d --name cullis-proxy ... ghcr.io/cullis-security/mcp-proxy:<new-tag>

# or:
helm upgrade cullis-proxy oci://ghcr.io/cullis-security/charts/cullis-proxy --version <new-version> --reuse-values
```

Alembic migrations run on startup. Migrations are forward-compatible inside a minor release line (0.1.x). Crossing a minor boundary may need a backup first — the release notes will say so.

Rollback is symmetric. If a migration was applied and you roll back the image, the DB is ahead of the code: the old image refuses to start. Either roll forward-fix or restore from backup.

---

## 11. Adding federation later

When your org wants to talk to agents in a partner org, you bring a Cullis broker online (run it yourself or use a hosted one):

1. Obtain an `attach-ca` invite from the broker admin.
2. Attach: `docker exec cullis-proxy python -m mcp_proxy.cli.attach_ca --broker https://broker.example.com --invite-token "<…>" --org-id acme`.
3. Set `MCP_PROXY_BROKER_URL` + `MCP_PROXY_BROKER_JWKS_URL`, flip `MCP_PROXY_STANDALONE=false`, restart.

Existing intra-org flows are unaffected. Cross-org sessions now route through the broker (reverse-proxy). No agent code change: the SDK already talks to the proxy and detects the federation capability from the proxy's health response.

Going the other direction — unset the broker vars, flip standalone back to `true`, restart. Cross-org stops, intra-org unchanged.

---

## 12. Troubleshooting

### "htu mismatch" 401 during login

DPoP validator rebuilt a different URL than the SDK signed. Causes:
- `MCP_PROXY_PROXY_PUBLIC_URL` mismatches what the agent used. Fix the env var.
- Proxy behind an ingress (Traefik, nginx) that rewrites `X-Forwarded-Host`. The server logs the expected vs proof htu — compare both.
- Agent used a stale cached URL after you changed the public URL. Restart the agent.

### Dashboard shows zero agents after a fresh deploy

First-boot CA generation might have failed (permission denied on the cert path). Check `docker logs cullis-proxy` for `"Failed to persist Org CA"` or similar. Usually a volume mount issue.

### Enrollment URL returns 404

One-shot URLs live in `pending_enrollments` with a 24 h TTL. Past the window, re-issue from the dashboard.

### `readyz` reports `jwks_cache: stale` (federation mode)

Broker JWKS refresh is failing. Check the broker's `/health` from inside the proxy container; fix the network path; the proxy recovers without a restart once JWKS fetch succeeds.

### SDK prints `DeprecationWarning: connected directly to the broker`

The agent's client URL points at a Cullis broker instead of your proxy. Fix the agent config — it should always be the proxy.

### Image pulls fail with 401/403

Anonymous pulls require the `ghcr.io/cullis-security/mcp-proxy` package to be marked public. On the org's **Packages** settings: Package settings → Change visibility → Public. Same for `ghcr.io/cullis-security/charts/cullis-proxy`. One-time operation.

---

## 13. When to open an issue

File at `github.com/cullis-security/cullis/issues` if:
- `/readyz` flaps without an external cause.
- Stack trace in proxy logs that doesn't cite user input.
- A documented env var produces a different behaviour than described here.

Include: image tag (`docker inspect ... | jq '.[0].Config.Labels["org.opencontainers.image.version"]'`), chart version, relevant log lines, and what you were doing when it broke. Redact any secret, cert, or agent ID you don't want public.
