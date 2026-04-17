# Cullis demo network — smoke test

One-command end-to-end smoke for the broker protocol. If `smoke.sh full`
exits 0, the core flow is not broken: TLS, DNS, onboarding (both
`/join` and `/attach-ca`), agent x509 auth, session open/accept, E2E
encryption, cross-org message routing.

```
./smoke.sh full          # down -v + up + check + down -v  (CI style)
./smoke.sh up            # bring the network up with a fresh nonce
./smoke.sh check         # assert checker received sender's nonce
./smoke.sh down          # tear down + wipe volumes
./smoke.sh logs [svc]    # tail compose logs
./smoke.sh dashboard     # print URLs for manual inspection
```

Full cycle takes ~50s on a warm cache, ~3min cold (image builds).

## Topology

```
              Traefik :8443  (test CA on *.cullis.test)
              │
   ┌──────────┼────────────────┬──────────┬──────────┐
   ▼          ▼                ▼          ▼          ▼
 broker   proxy-a.cullis.test  proxy-b   checker   (all HTTPS)
   │          │                │
   └──── broker (FastAPI, SQLite tmpfs) ───┘
              │
   bootstrap ─┤  registers demo-org-a via /onboarding/join
              │  registers demo-org-b via /onboarding/attach
              │  mints sender/checker x509 certs into /state
              │
 bootstrap-  ─┤  pins each Mastio pubkey on the Court
    mastio    │  seeds /v1/admin/agents on each Mastio (federated=true)
              │  publisher pushes agents to Court, then bindings approved
              │
   sender ────►  demo-org-a::sender — opens session, sends {nonce}
   checker ◄───  demo-org-b::checker — accepts, stores last payload
```

The two MCP proxies boot with pre-seeded config (no wizard) to validate
their startup path (JWKS fetch, Org CA load, BrokerBridge init). Sender
and checker talk directly to the broker via the SDK — the proxies are
not on the critical path for message flow in this smoke.

## What passing this smoke tells you

Production-like stack — Postgres + Redis + Vault + policy enforcement ON:

- Alembic migrations apply cleanly on a fresh **Postgres** DB (including attach-ca)
- `POST /v1/onboarding/join` works (generic invite)
- `POST /v1/onboarding/attach` works (org-bound invite + secret rotation + webhook URL)
- ADR-010 Mastio-sovereign registry: `POST /v1/admin/agents` on each Mastio + federation publisher push to the Court + `POST /v1/registry/bindings/{id}/approve` work
- x509 agent login via `/v1/auth/token` (DPoP) works — broker JWT signed with a key stored in **Vault**
- Session open/accept state machine works
- **Policy enforcement is ON**: broker calls proxy `/pdp/policy` webhook on every session — smoke exercises the full SSRF-protected webhook client path
- Proxy-side PDP default-allow decision returned via HTTPS, TLS verified through the test CA
- E2E encrypted send + decrypt works cross-org
- **Redis** backs DPoP JTI blacklist and WS pub/sub — no in-memory fallback

## What this smoke does NOT tell you

- Real PKI (real Let's Encrypt / corporate CA), real DNS, real multi-host network
- Enterprise plugins (license check, observability exporters) — community only
- MCP proxy ingress path (internal agents → proxy → broker) — sender/checker use SDK direct
- LLM-driven negotiation flows — the smoke sends a single static payload
- Load / concurrency / fault injection

## Dashboards for manual inspection

```sh
# one-time /etc/hosts edit
echo "127.0.0.1 broker.cullis.test proxy-a.cullis.test proxy-b.cullis.test checker.cullis.test" | sudo tee -a /etc/hosts

./smoke.sh up
./smoke.sh dashboard    # prints URLs + admin secrets

# browser: trust the test CA (or use `--cacert` with curl)
docker cp demo_network-traefik-1:/certs/ca.crt /tmp/cullis-demo-ca.crt
```

The broker dashboard lets you exercise the **attach-ca** flow manually:
create an org without CA, click "Attach-CA invite", paste the token into
a proxy wizard.
