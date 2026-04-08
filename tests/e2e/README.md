# Cullis E2E Test — full-stack integration

Automates the end-to-end flow that used to be a manual click-through:
deploy the broker, two MCP proxies, register two organizations, create
one agent in each, exchange one E2E-encrypted message between them, and
verify the recipient can decrypt it.

In one sentence: **if this test passes, the cross-org demo flow still
works end to end.**

---

## When to run it

- **Before opening a PR against `main`** that touches the broker, the
  MCP proxy, auth, the broker bridge, the AgentManager, anything in
  graceful-shutdown / persistence, or any of the egress endpoints.
- **After bumping a dependency** (cryptography, fastapi, sqlalchemy,
  httpx).
- **Before a production release** if the changeset includes a protocol
  change (DPoP, AAD layout, message signing).
- **Whenever you remember it exists and feel guilty for not having run it.**

It is not part of CI by default — a full run takes ~40 seconds and we
do not want to gate every push on it. Run it explicitly, or wire it
into a nightly cron.

---

## How to run it

### The fast way — wrapper

```bash
tests/e2e/run.sh
```

The wrapper:
1. Verifies that `docker` and `pytest` are available
2. Tears down any leftover `cullis-e2e` stack from a previous run
3. Builds the broker + 2 proxy images
4. Brings the stack up and waits for `/healthz` and `/readyz` on every service
5. Runs the e2e suite with `pytest -m e2e -s -v`
6. Tears the stack down (even on failure — no zombie containers)

### Expected timings

| Phase                                              | Cold start          | Warm run        |
|----------------------------------------------------|---------------------|-----------------|
| 1. Cleanup of any previous stack                   | ~5 s                | ~5 s            |
| 2. **Docker image build** (broker + 2 proxies)     | **60–180 s** (pip)  | ~5 s (cached)   |
| 3. Container boot (postgres → redis → broker → 2 proxies) | ~15–30 s     | ~15–30 s        |
| 4. Health polling                                  | ~5–15 s             | ~5–15 s         |
| 5. Run the 3 e2e tests                             | ~25–35 s            | ~25–35 s        |
| 6. Teardown                                        | ~5–10 s             | ~5–10 s         |
| **Total**                                          | **~3–5 min**        | **~40 s**       |

### "It looks stuck — is that normal?"

`run.sh` passes `-s -v` to pytest, so the conftest's progress messages
are visible live (`[e2e] Booting stack...`, `[e2e] Stack is healthy.
Yielding to tests.`).

If you see no output for more than 30 s, open a second terminal and
inspect the stack directly:

```bash
# Container state (healthy / starting / unhealthy)
docker compose --project-name cullis-e2e \
  -f tests/e2e/docker-compose.e2e.yml ps

# Broker logs — if /healthz is not responding, the reason shows up here
docker compose --project-name cullis-e2e \
  -f tests/e2e/docker-compose.e2e.yml logs -f broker

# Proxy logs
docker compose --project-name cullis-e2e \
  -f tests/e2e/docker-compose.e2e.yml logs -f proxy-alpha
```

Common causes of "looks stuck":
- **Slow first-time pip build**: the broker requirements pull ~200 MB
  of wheels on the first build. Be patient.
- **Postgres health timeout**: the broker waits for postgres to be
  `healthy` before starting; if postgres misbehaves the broker stays
  in `starting`.
- **Stale `cullis_e2e_net` network**: rare, but `docker network ls |
  grep cullis_e2e` then `docker network rm` if leftover.

The fixture has a **180-second timeout** per health check. If the
broker still does not respond after 3 minutes, the test fails with
`TimeoutError: broker did not become healthy within 180s` and the
stack is torn down. No zombies.

### The manual way — pytest directly

```bash
# Run the whole e2e suite
pytest -m e2e -o addopts="" tests/e2e/

# Filter by test name
pytest -m e2e -o addopts="" tests/e2e/ -k full_two_org
```

The `-o addopts=""` overrides the default `-m "not e2e"` filter set in
`pytest.ini`. Without it, pytest skips every test marked `@pytest.mark.e2e`.

### Keeping the stack up for inspection

```bash
KEEP_E2E_STACK=1 tests/e2e/run.sh
```

After the run the stack is left running. You can poke at it:

```bash
docker compose --project-name cullis-e2e \
               -f tests/e2e/docker-compose.e2e.yml ps

# Hit the broker directly:
curl http://localhost:18000/healthz
curl http://localhost:18000/readyz

# Hit the proxies:
curl http://localhost:19100/health   # alpha
curl http://localhost:19101/health   # beta
```

When you are done:

```bash
docker compose --project-name cullis-e2e \
               -f tests/e2e/docker-compose.e2e.yml down -v
```

---

## What it tests, exactly

`tests/e2e/test_full_flow.py::test_full_two_org_message_exchange`:

| Step | Operation                                                      | Real endpoint                                                           |
|------|----------------------------------------------------------------|-------------------------------------------------------------------------|
| 1    | Generate invite token for alpha                                | `POST /v1/admin/invites` (X-Admin-Secret)                               |
| 2    | Generate invite token for beta                                 | same                                                                    |
| 3    | proxy-alpha registers org `alpha` (status=pending)             | `setup_proxy_org.py --phase=org` in container → `POST /v1/onboarding/join` |
| 4    | proxy-beta registers org `beta` (status=pending)               | same                                                                    |
| 5    | Network admin approves both orgs                               | `POST /v1/admin/orgs/{id}/approve` for alpha and beta                   |
| 6    | proxy-alpha creates agent `alpha::buyer` (cert + API key + binding) | `setup_proxy_org.py --phase=agent` in container → `AgentManager.create_agent` + binding auto-approve |
| 7    | proxy-beta creates agent `beta::seller`                        | same                                                                    |
| 8    | alpha::buyer discovers beta::seller cross-org                  | `POST /v1/egress/discover` on proxy-alpha                               |
| 9    | Assert beta::seller is visible from alpha                      | `assert beta.agent_id in discovered_ids`                                |
| 10   | alpha::buyer opens a session to beta::seller                   | `POST /v1/egress/sessions` on proxy-alpha                               |
| 11   | beta::seller accepts the pending session                       | `POST /v1/egress/sessions/{id}/accept` on proxy-beta                    |
| 12   | alpha::buyer sends an E2E message with a known marker          | `POST /v1/egress/send` on proxy-alpha                                   |
| 13   | beta::seller polls for the message                             | `GET /v1/egress/messages/{id}` on proxy-beta                            |
| 14   | Assert the decrypted payload matches the marker exactly        | `assert payload["marker"] == ... and payload["items"] == ...`           |

The split between phase=org (steps 3–4), admin approval (step 5) and
phase=agent (steps 6–7) is **intentional**: the broker rejects any
agent registration call while the org is still `pending`, so the
admin approval has to land between the two phases.

Other tests in the suite:

- `test_invite_token_invalid_is_rejected` — a garbage invite token
  must be rejected by `/v1/onboarding/join`.
- `test_admin_invite_requires_admin_secret` — the admin endpoint must
  reject calls without a valid `X-Admin-Secret` header.

---

## What it does NOT test (yet)

Things deliberately left out of the MVP. Add them if you need
coverage for a specific regression class:

- **Reply path**: today the test is one-way (alpha → beta). If you
  break the beta → alpha path you will not notice here.
- **Audit log hash chain verification**: the test does not call
  `verify_chain()` at the end.
- **RFQ broadcast** (`POST /v1/broker/rfq`).
- **Transaction tokens** (`POST /v1/auth/token/transaction`).
- **Graceful shutdown / drain watcher**: the fixture does a hard
  `down -v`, it does not exercise the SIGTERM drain path.
- **Cert rotation**.
- **OIDC role mapping**: covered by mock-based unit tests instead.

---

## Why it is wired the way it is

### Decision 1 — `setup_proxy_org.py` runs *inside* the proxy container

The intuitive way to register an org through the proxy would be to
drive its HTML dashboard. That means scraping the CSRF token,
form-encoded POSTs with session cookies, and parsing HTML to extract
the issued API key. All fragile.

The actual setup: a Python script (`tests/e2e/scripts/setup_proxy_org.py`)
is bind-mounted into the proxy containers and invoked via
`docker compose exec`. It calls the real proxy modules directly
(`set_config`, `generate_org_ca`, `AgentManager.create_agent`) — the
same ones the dashboard calls. The test runner reads the JSON the
script prints on stdout.

Pros:
- No HTML scraping.
- Exercises the **real** production code path (same modules, same DB,
  same CA logic).
- The dashboard HTML can change without breaking the test.

Cons:
- The script lives in `tests/e2e/scripts/` and has to stay aligned
  with the signatures of `mcp_proxy.dashboard.router.generate_org_ca`
  and `mcp_proxy.egress.agent_manager.AgentManager.create_agent`.
  Rename either function and the script needs an update.

### Decision 2 — high port range (18xxx / 19xxx) and a dedicated project name

The e2e stack uses port mappings completely separate from the dev
compose file so it never collides with a developer's running stack:

| Service     | Dev compose port | E2E port      |
|-------------|------------------|---------------|
| broker      | 8000             | 18000         |
| proxy alpha | 9100             | 19100         |
| proxy beta  | n/a              | 19101         |
| nginx HTTPS | 8443             | (not exposed) |

Plus `--project-name cullis-e2e`: every container, volume and network
is prefixed `cullis-e2e_*` and removed by `down -v`. No collision with
a dev stack already running, no collision with another e2e run.

### Decision 3 — no nginx in front of the broker

The e2e stack talks to the broker on `http://localhost:18000` directly.
No nginx, no self-signed cert, no `verify=False` workarounds. The test
verifies the application flow (auth, session, E2E message), not TLS
termination. As a side effect, `BROKER_PUBLIC_URL` is empty so
`build_htu()` derives the URL from the request itself — zero risk of
the htu-mismatch foot-gun documented in `docs/ops-runbook.md`.

### Decision 4 — `KMS_BACKEND=local` instead of Vault

`deploy_broker.sh` runs the broker against an in-stack Vault and has
an explicit "load broker key into Vault" bootstrap step. Reproducing
that bootstrap inside an ephemeral compose was fragile: the broker
would come up before the key was loaded and `/readyz` would fail
forever on the KMS check.

The e2e stack uses `KMS_BACKEND=local` instead. The conftest fixture
generates a broker CA (via `generate_certs.py` if needed), copies it
into `tests/e2e/.fixtures/broker_certs/` with permissions the
container's `appuser` can read AND write (the lifespan persists
`.admin_secret_hash` there on first boot), and bind-mounts that
directory into the broker as `/app/certs`. Same code path the unit
tests already exercise.

### Decision 5 — `POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=true`

The broker has an SSRF guard that rejects any PDP webhook URL
resolving to a private/loopback/link-local/reserved IP. In the e2e
stack the PDP webhooks live at `http://proxy-alpha:9100/pdp/policy`
and `http://proxy-beta:9100/pdp/policy` — both private docker IPs.
Production behaviour is unchanged: the flag defaults to `False`,
the e2e compose sets it to `True` explicitly.

---

## Troubleshooting

**`pytest` skips every e2e test.**
You forgot the marker override. Use `tests/e2e/run.sh` or
`pytest -m e2e -o addopts="" tests/e2e/`.

**`docker compose up` fails with "port already allocated".**
A leftover `cullis-e2e` stack (likely from a `KEEP_E2E_STACK` run) is
still bound, or something else on your host is using 18000 / 19100 /
19101. Diagnose:

```bash
docker compose --project-name cullis-e2e -f tests/e2e/docker-compose.e2e.yml ps
docker compose --project-name cullis-e2e -f tests/e2e/docker-compose.e2e.yml down -v
```

**`broker did not become healthy within 180s`.**
The broker is failing its own `/readyz`. Check the logs:

```bash
docker compose --project-name cullis-e2e -f tests/e2e/docker-compose.e2e.yml logs broker
```

Common causes: postgres health timeout, KMS broker CA fixture not
readable by `appuser`, alembic migration failure.

**`setup_proxy_org.py failed in proxy-alpha`.**
The provisioning helper failed inside the container. The Python
exception, including stdout and stderr, is included in the test
output. Common causes:

- The broker is unreachable via internal DNS (`http://broker:8000`)
  → check that `proxy-alpha` is on the `cullis_e2e_net` network.
- An invite token is already used (persistent DB from a previous run)
  → make sure to `down -v` before re-running.
- `mcp_proxy.dashboard.router.generate_org_ca` or
  `mcp_proxy.egress.agent_manager.AgentManager.create_agent` changed
  signature — update the script.

**`htu mismatch`.**
Should not happen any more because `BROKER_PUBLIC_URL=""` is set
explicitly in the e2e compose. If it does, see the "Common pitfalls"
section in `docs/ops-runbook.md`.

---

## Extending the test

To cover the reply path beta → alpha, append these steps to
`test_full_two_org_message_exchange` after step 14:

```python
reply_payload = {"kind": "purchase_order_ack", "marker": "e2e-mvp-002", "ok": True}
await send_message(
    proxy_beta_url, beta.api_key,
    session_id=session_id,
    payload=reply_payload,
    recipient_agent_id=alpha.agent_id,
)
ack = await wait_for_message_with_payload(
    proxy_alpha_url, alpha.api_key,
    session_id=session_id,
    expected_marker_key="marker",
    expected_marker_value="e2e-mvp-002",
)
assert ack["payload"]["ok"] is True
```

For RFQ broadcast and transaction tokens you need to add helper
endpoints similar to the ones in `tests/e2e/helpers/e2e_messaging.py`
— the proxy egress API does not yet expose those as "internal" calls,
so you either hit the broker endpoints directly or add wrapper
endpoints in the proxy.
