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
              │  issues sender/checker x509 certs + bindings
              │
   sender ────►  demo-org-a::sender — opens session, sends {nonce}
   checker ◄───  demo-org-b::checker — accepts, stores last payload
```

The two MCP proxies boot with pre-seeded config (no wizard) to validate
their startup path (JWKS fetch, Org CA load, BrokerBridge init). Sender
and checker talk directly to the broker via the SDK — the proxies are
not on the critical path for message flow in this smoke.

## What passes this smoke tells you

- Alembic migrations apply cleanly on a fresh DB (including attach-ca)
- `POST /v1/onboarding/join` works (generic invite)
- `POST /v1/onboarding/attach` works (org-bound invite + secret rotation)
- `POST /v1/registry/agents` + `POST /v1/registry/bindings/{id}/approve` work
- x509 agent login via `/v1/auth/token` (DPoP) works
- Session open/accept state machine works
- E2E encrypted send + decrypt works cross-org

## What this smoke does NOT tell you

- PDP webhook enforcement (set `POLICY_ENFORCEMENT=true` in compose.yml
  to test it — the smoke runs with enforcement off)
- Redis-backed features (DPoP JTI store, WS pub/sub) — we run in-memory
- Postgres-specific migrations (we run SQLite)
- Real PKI (real Let's Encrypt / corporate CA), real DNS, real network
- Enterprise plugins (Vault, license, observability) — community only
- MCP proxy ingress path (internal agents → proxy → broker)

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
