# Nightly stress test

Lean multi-org setup for long-running load / soak / chaos runs. Surfaces the
criticalities that the ~50s `sandbox/smoke.sh` can't hit: queue depth under
sustained load, WS reconnect spikes, message expiry, cert rotation in-flight,
memory growth, etc.

**Scope**: Court + 2 Mastio (`orga`, `orgb`) + N agents/org enrolled via BYOCA.
No SPIRE, no Keycloak, no MCP servers — pure agent-to-agent traffic.

## Quick start

```bash
cd test/nightly
./nightly.sh full        # bring up stack + enroll 10 agents/org (default)
./nightly.sh smoke       # verify 20/20 agents can authenticate
./nightly.sh logs        # tail docker compose logs
./nightly.sh down        # tear down + wipe state/
```

Customise via `config.env` or env vars:

```bash
AGENTS_PER_ORG=20 ./nightly.sh full
```

## Commands (roadmap)

| Command  | Status    | Description                                     |
|----------|-----------|-------------------------------------------------|
| `full`   | PR 1      | Bring up the lean stack + BYOCA enroll agents.  |
| `down`   | PR 1      | Tear down containers, volumes, and state.       |
| `smoke`  | PR 1      | Probe N/N agents via `/v1/egress/peers`.        |
| `logs`   | PR 1      | Tail compose logs (optionally for one service). |
| `go`     | PR 2 (TBD) | Start workload drivers (spammer/sessionator/chatter). |
| `chaos`  | PR 3 (TBD) | Fault injection (kill, restart, clock skew).    |
| `report` | PR 3 (TBD) | Render markdown report from collected metrics.  |

## Layout

```
test/nightly/
├── nightly.sh              # entry point
├── config.env              # defaults
├── docker-compose.yml      # lean topology
├── bootstrap/              # bootstrap + bootstrap_mastio docker build
├── smoke.py                # host-side auth probe
└── state/                  # bind-mounted, gitignored
    ├── orga/, orgb/        # CA + org_secret + agents/*/identity
    └── agents.json         # manifest written by bootstrap
```

## Ports

| Host port | Service     |
|-----------|-------------|
| 8000      | Court       |
| 9100      | Mastio A    |
| 9200      | Mastio B    |

Conflicts with `sandbox/` — only one stack at a time.
