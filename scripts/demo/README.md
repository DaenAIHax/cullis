# Cullis demo

A single-host, scripted, "click and explore" demo of the Cullis trust
network. Brings up the full architecture (broker + two MCP proxies +
postgres + redis), provisions two organizations, creates one agent in
each, and lets you watch one agent route an end-to-end encrypted
message to the other through the broker.

Two ~70-line standalone Python scripts (`sender.py` and `checker.py`)
play the role of the agents. They are dumb HTTP loops — **no LLM, no
Anthropic API key, no SDK magic** — so the only thing the demo proves
is that the broker actually routes messages between two organizations.

Designed for live demos and self-guided exploration. Not production.

## What you get

| Component         | URL                                   | Purpose                                                    |
| ----------------- | ------------------------------------- | ---------------------------------------------------------- |
| **Broker**        | http://localhost:8800                 | Trust broker — registry, sessions, audit, policies         |
| **Proxy alpha**   | http://localhost:9800                 | Org alpha's MCP gateway (`alpha::sender` lives here)       |
| **Proxy beta**    | http://localhost:9801                 | Org beta's MCP gateway (`beta::checker` lives here)        |
| Postgres + Redis  | (internal)                            | Broker store + DPoP/JTI cache                              |

Demo agents (created automatically by `up`):

| Org    | Agent             | Role                                              | Capability     |
| ------ | ----------------- | ------------------------------------------------- | -------------- |
| alpha  | `alpha::sender`   | one-shot script that fires `{"check": "ok"}`      | `order.check`  |
| beta   | `beta::checker`   | background daemon that auto-accepts and prints    | `order.check`  |

## Prerequisites

The demo deliberately keeps the host-side dependencies minimal. Everything
heavy (FastAPI, SQLAlchemy, cryptography, the broker itself) runs inside
the Docker containers, not on your machine.

- **Docker Engine + Compose v2 plugin** — `docker compose version` must work.
  The demo starts 5 containers: broker, two MCP proxies, postgres, redis.
- **Python 3.10+** on the host — only because the orchestrator
  (`orchestrate.py`), the `sender.py` agent, and the `checker.py` daemon
  run on your laptop, not in containers.
- **`httpx`** — the **only** host-side Python dependency the demo touches.
  All four scripts (`orchestrate`, `sender`, `checker`, plus the wrapper's
  `import httpx` check) need it. Nothing else from `requirements.txt`.
- **Free TCP ports**: `8800`, `9800`, `9801`. The wrapper fails fast with
  a clear message and the name of the conflicting container if any of them
  is taken. The 88xx/98xx range is intentional so the demo never collides
  with a developer's `docker compose up` (8000/9100) or with the e2e test
  stack (18000/19100).
- **~2 GB free disk + outbound network** for the first-time image build.

### Installing `httpx`

The wrapper auto-detects a `.venv/bin/python` in the repo root, so a
project venv is the easiest path:

```bash
python3 -m venv .venv && .venv/bin/pip install httpx
```

If you would rather not create a venv:

```bash
# user-wide
python3 -m pip install --user httpx

# Debian/Ubuntu/macOS Homebrew with PEP 668:
python3 -m pip install --user --break-system-packages httpx
```

### Supported operating systems

- **Linux** — works natively, this is the primary target.
- **macOS** — works with Docker Desktop, OrbStack, or Colima. Python 3 is
  already installed on recent macOS versions; just install `httpx`.
- **Windows** — use WSL2 + Docker Desktop with the WSL integration enabled.
  The bash wrapper does not run from native PowerShell.

The first `up` builds three Docker images (~1 min on a clean host);
subsequent runs reuse the layer cache and warm starts complete in ~15 s.

## Quick start

From the repo root:

```bash
./deploy_demo.sh up               # build, bootstrap, start checker daemon  (~1 min cold)
python scripts/demo/sender.py     # one-shot: sender → checker, ~1 s round-trip
./deploy_demo.sh checker-log      # tail the checker daemon log to watch routes arrive
./deploy_demo.sh info             # reprint dashboard URLs + credentials
./deploy_demo.sh down             # stop containers + checker daemon, keep volumes
./deploy_demo.sh nuke             # stop + wipe volumes + clear demo state
```

`up` is idempotent — re-running it after `down` resumes the existing state.
`nuke` is the only command that destroys data.

For convenience `./deploy_demo.sh send` is a shortcut for
`python scripts/demo/sender.py` (same behavior, shorter to type during
a live demo).

## What `up` actually does

1. Generates a broker CA into `scripts/demo/.fixtures/broker_certs/`
   (the bind mount the broker container uses for `KMS_BACKEND=local`).
2. `docker compose up -d --build` for postgres, redis, broker,
   proxy-alpha, proxy-beta.
3. Waits for `/readyz` on the broker and `/health` on both proxies.
4. **As network admin**, generates two single-use invite tokens via
   `POST /v1/admin/invites`.
5. **Inside each proxy container**, runs `setup_proxy_org.py --phase=org`:
   - generates an Org CA (RSA-4096),
   - persists `broker_url` + `org_secret` + Org CA into proxy_config,
   - calls `POST /v1/onboarding/join` on the broker (org status =
     `pending`),
   - restarts the proxy container so its lifespan picks up the new
     `broker_url` and instantiates the `BrokerBridge`.
6. **As network admin**, approves both orgs via
   `POST /v1/admin/orgs/{id}/approve` (status flips to `active`).
7. **Inside each proxy container**, runs `setup_proxy_org.py --phase=agent`:
   - issues an x509 cert signed by the Org CA with SPIFFE SAN
     `spiffe://atn.local/<org>/<agent>`,
   - mints an internal API key (`sk_local_*`),
   - registers the agent + binding in the broker registry,
   - the binding is auto-approved by the org.
8. Persists everything the agents need (their agent ids, their
   `sk_local_*` API keys, the org secrets) to `scripts/demo/.state.json`.
9. **Starts `checker.py` in the background** (PID file in
   `.checker.pid`, stdout in `.checker.log`). The daemon polls
   proxy-beta forever for incoming sessions.
10. Prints the **Architecture tour** — every URL and credential needed
    to log into the three dashboards.

## How `sender.py` and `checker.py` work

Both scripts authenticate to their own MCP proxy with the
`X-API-Key: sk_local_*` header that `init` minted for them. **There is
no Anthropic API key, no LLM call, no SDK** — just `httpx` against the
proxy's egress endpoints (`/v1/egress/sessions`, `/v1/egress/send`,
`/v1/egress/messages`).

`sender.py` (one-shot, ~70 lines):
1. POST `/v1/egress/sessions` on proxy-alpha with target = `beta::checker`
2. Polls until the session flips to `active` (the checker daemon
   accepts it within ~1 s)
3. POST `/v1/egress/send` with payload `{"check": "ok"}`
4. Exits — total round-trip ~1 s

`checker.py` (daemon, ~70 lines):
1. Every 1 s, GET `/v1/egress/sessions` on proxy-beta
2. For every `pending` session where it is the target, POST
   `/v1/egress/sessions/{id}/accept` (the broker flips it to `active`)
3. For every accepted session, GET `/v1/egress/messages/{id}?after=<seq>`
4. Prints one line per received message: agent_id, seq, payload
5. Loops until SIGTERM (sent by `./deploy_demo.sh down`)

The full conversation looks like this in two terminals:

```
$ python scripts/demo/sender.py
[alpha::sender] opening session to beta::checker (capability 'order.check')
[alpha::sender] session_id = 291e6993-d132-46a5-9ff3-b9ebbfef988e
[alpha::sender] waiting for checker to accept...
[alpha::sender] session is active
[alpha::sender] sending {"check": "ok"}
[alpha::sender] message routed through the broker — done

$ ./deploy_demo.sh checker-log
[beta::checker] checker daemon started, polling http://localhost:9801 every 1.0s
[beta::checker] accepted pending session 291e6993-d132-46a5-9ff3-b9ebbfef988e
[beta::checker] received from alpha::sender (seq 0): {"check": "ok"}
```

Run `sender.py` again — it opens a fresh session each time, so the
checker auto-accepts and prints a new line. Repeat live for the
audience as many times as you want.

## Tour the architecture

After `up`, open three browser tabs and explore:

### Broker dashboard — http://localhost:8800/dashboard/login

Three different views, depending on who you log in as:

| Login as     | Username | Password (from `info`)            | What you see                                                          |
| ------------ | -------- | --------------------------------- | --------------------------------------------------------------------- |
| Network admin| `admin`  | `cullis-demo-admin-secret`        | Everything: orgs, all agents, all sessions, audit log, invite tokens  |
| Org alpha    | `alpha`  | `<alpha_org_secret>`              | Only alpha's agents, alpha's bindings, alpha's audit slice            |
| Org beta     | `beta`   | `<beta_org_secret>`               | Only beta's agents, beta's bindings, beta's audit slice               |

Pages worth visiting (as `admin`):

- **Overview** (`/dashboard`) — counters and recent activity
- **Orgs** (`/dashboard/orgs`) — `alpha` and `beta` should be `active`
- **Agents** (`/dashboard/agents`) — `alpha::sender` and `beta::checker`
  with their SPIFFE IDs and certificates
- **Sessions** (`/dashboard/sessions`) — every `python sender.py` adds
  one row here. Refresh after each run.
- **Audit** (`/dashboard/audit`) — every action with hash chain
  (`onboarding.join_ok`, `onboarding.approved`, `registry.agent_registered`,
  `binding.approved`, `broker.session_created`, `policy.session_allowed`, …)

### Proxy alpha dashboard — http://localhost:9800/proxy/login

- **broker URL**: `http://localhost:8800`
- **invite token**: any string (the form does not validate it on login)

Then click around:

- **Agents** (`/proxy/agents`) — `alpha::sender`, click to see the cert,
  the API key hash, and the local audit
- **Audit** (`/proxy/audit`) — egress events: session_open, send
- **Policies** (`/proxy/policies`) — local PDP rules (empty by default
  → allow all). Add a rule (e.g. block `beta::checker`) and re-run
  `python scripts/demo/sender.py` to see the broker reject the session
- **PKI** (`/proxy/pki`) — Org CA cert and the agent cert chain
- **Tools** (`/proxy/tools`) — MCP tool registry (empty in the demo)

### Proxy beta dashboard — http://localhost:9801/proxy/login

Same UI, scoped to `beta::checker`. Useful for demonstrating that the
two orgs are completely isolated — neither dashboard ever sees the
other org's agents, only the broker has the federated view. Check
`/proxy/audit` here to see the inbound `accept_session` and the
inbox polls performed by the daemon.

## Customize

The demo is intentionally minimal but easy to bend.

### Change the message payload

Edit the `payload = {"check": "ok"}` line in `scripts/demo/sender.py`.
Re-run `python scripts/demo/sender.py` — no need to restart anything.
The checker daemon prints whatever JSON arrives.

### Change the capability

Replace `DEMO_CAPABILITY = "order.check"` in `orchestrate.py` (and the
matching `["order.check"]` literal in `sender.py`) with whatever string
you want. Run `./deploy_demo.sh nuke && ./deploy_demo.sh up` because
both agents need to be re-issued with the new capability in their
bindings.

### Add a deny rule and watch the broker reject the session

1. Open http://localhost:9800/proxy/policies (proxy-alpha dashboard)
2. Add a policy that blocks `beta::checker`
3. Run `python scripts/demo/sender.py`
4. The broker's PDP webhook call to alpha returns `deny` → 403 →
   sender exits with the policy reason
5. Check `/dashboard/audit` on the broker — the denial is in the
   hash-chained audit log

### Make the checker reply

Right now the checker only reads. To make it echo back, add this after
the `_log(... received from ...)` line in `checker.py`:

```python
client.post(
    f"{_PROXY_BETA_URL}/v1/egress/send",
    json={
        "session_id":         sid,
        "recipient_agent_id": sender,
        "payload":            {"check": "ok", "echo": payload},
    },
)
```

Then add a poll loop in `sender.py` to wait for the echo. Two-way
conversation in ~10 lines.

### Add a third org

Add a third proxy service to `scripts/demo/docker-compose.demo.yml`
(copy `proxy-beta`, change the port to e.g. `9802:9100` and the
`MCP_PROXY_PDP_URL`). Then add a `register_org` + `create_agent` step
to `cmd_init` in `orchestrate.py`. Don't forget to add the new port
to `require_demo_ports_free` in `deploy_demo.sh`.

## Reset / cleanup

| Command                    | Effect                                                          |
| -------------------------- | --------------------------------------------------------------- |
| `./deploy_demo.sh down`    | Stop containers. Postgres and proxy SQLite volumes survive.     |
| `./deploy_demo.sh nuke`    | Stop + remove volumes + delete `.state.json` + delete fixtures. |
| `docker compose ... down`  | Don't. Use the wrapper — it knows the project name and paths.   |

Re-running `up` after `down` reuses the existing state (orgs, agents,
API keys). After `nuke` it bootstraps from scratch.

## Troubleshooting

### "the following demo ports are already in use: 8800 → ..."

Something else is bound to one of `8800`, `9800`, `9801`. The pre-flight
check tells you which container holds it. Stop it (`docker stop <name>`
or `docker compose down` from the offending project) and re-run `up`.

### "broker did not become healthy within 180s"

Almost always means the bind mount of the broker CA fixture is wrong
or the file isn't readable by the container's `appuser`. Check
`scripts/demo/.fixtures/broker_certs/`:

```bash
ls -la scripts/demo/.fixtures/broker_certs/
# expected: broker-ca.pem (0644) + broker-ca-key.pem (0644)
# directory must be 0777 so the broker can write .admin_secret_hash
```

If the dir is wrong, `./deploy_demo.sh nuke && ./deploy_demo.sh up`
regenerates it from scratch.

### "ImportError: httpx" or similar from `orchestrate.py`

The wrapper expects the repo `.venv` (created by the project setup),
or a system Python with `httpx` installed:

```bash
.venv/bin/pip install httpx     # if you have the venv
# or
pip install --user httpx        # otherwise
```

### Containers up but `sender.py` returns 502 from `/v1/broker/sessions`

The PDP webhook on the proxy is returning `deny`. Check the broker's
audit log:

```bash
docker exec cullis-demo-postgres-1 \
  psql -U cullis -d cullis_demo \
  -c "SELECT event_type, result, details FROM audit_log
      WHERE result = 'denied' ORDER BY id DESC LIMIT 5;"
```

The `details` column will tell you which org denied and why.

### `sender.py` exits with "checker did not accept within 5s"

The background checker daemon is not running. Check it:

```bash
./deploy_demo.sh status         # docker containers
ls scripts/demo/.checker.pid    # exists if the daemon is alive
./deploy_demo.sh checker-log    # tail the daemon log
```

If the daemon died, the log will say why. Re-run `./deploy_demo.sh up`
(idempotent) to restart it.

### I want to inspect the broker DB by hand

```bash
docker exec -it cullis-demo-postgres-1 psql -U cullis -d cullis_demo
```

Useful tables: `organizations`, `agents`, `bindings`, `sessions`,
`session_messages`, `audit_log`, `invite_tokens`.

### I want to follow the logs

```bash
./deploy_demo.sh logs                                       # all three
docker compose --project-name cullis-demo \
  -f scripts/demo/docker-compose.demo.yml logs -f broker    # broker only
```

## Files

| Path                                     | Purpose                                                        |
| ---------------------------------------- | -------------------------------------------------------------- |
| `deploy_demo.sh`                         | Bash wrapper — single entry point                              |
| `scripts/demo/docker-compose.demo.yml`   | Stack definition (broker + 2 proxies + postgres + redis)       |
| `scripts/demo/orchestrate.py`            | Bootstrap + info commands (run from `deploy_demo.sh`)          |
| `scripts/demo/sender.py`                 | Standalone agent: opens session, sends one check, exits        |
| `scripts/demo/checker.py`                | Standalone agent (daemon): polls + auto-accepts + prints       |
| `scripts/demo/.state.json`               | Agent ids + API keys + org secrets (generated by `up`)         |
| `scripts/demo/.checker.pid`              | PID of the checker daemon (managed by `up` / `down`)           |
| `scripts/demo/.checker.log`              | stdout of the checker daemon                                   |
| `scripts/demo/.fixtures/broker_certs/`   | Broker CA bind-mounted into the broker container               |
| `tests/e2e/scripts/setup_proxy_org.py`   | In-container provisioning helper, shared with e2e tests        |

## What this is NOT

> **⚠️ The demo deliberately disables production security features so you can explore the routing with two simple scripts on a laptop.**

### Security features OFF in demo mode

| Security layer | Demo | Production |
|---|---|---|
| **TLS / HTTPS** | Plain HTTP (`:8800`) | nginx + TLS (self-signed, ACME, or BYOCA) |
| **KMS** | Filesystem — keys on disk | HashiCorp Vault KV v2 |
| **Admin secrets** | Hardcoded (`cullis-demo-admin-secret`) | Strong random, from secrets manager |
| **SSRF protection** | Bypassed (private IPs allowed) | Enforced — webhooks cannot hit RFC 1918 |
| **OIDC admin login** | Disabled | Okta / Azure AD / Google federation |
| **LLM injection detection** | Regex only | + LLM judge (Claude Haiku) |
| **Observability** | Off | OpenTelemetry + Jaeger + Prometheus |
| **CORS** | `*` (all origins) | Specific allowed origins |
| **Cookie secure flag** | `False` (HTTP) | `True` (HTTPS only) |
| **SPIFFE SAN validation** | Not enforced | Enforced |
| **Certificate chain validation** | Not enforced | Enforced |
| **Workers** | 1 process | Multiple + Redis distributed state |
| **Agent keys** | Plain files on disk | Vault-stored, never exported |

### What the demo DOES show

The full routing flow (agent → proxy → broker → proxy → agent), E2E encryption, DPoP token binding, dual-org policy, the dashboard. **The architecture is real — the hardening is off.**

**Do not expose demo ports outside localhost. Do not reuse demo credentials anywhere.**

For production deployment, see the Helm chart in `deploy/helm/cullis/` and the BYOCA guide in `enterprise-kit/`.
