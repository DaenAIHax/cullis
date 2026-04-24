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
./nightly.sh full              # bring up stack + enroll 10 agents/org
./nightly.sh smoke             # verify N/N agents can authenticate
./nightly.sh go                # start workload drivers (foreground)
./nightly.sh chaos light       # inject faults (in a second terminal)
./nightly.sh report            # render markdown report from logs
./nightly.sh down              # tear down + wipe state/
```

Customise via `config.env` or env vars:

```bash
AGENTS_PER_ORG=20 ./nightly.sh full
```

## Commands

| Command  | Description                                                 |
|----------|-------------------------------------------------------------|
| `full`   | Bring up the lean stack + BYOCA enroll agents.              |
| `down`   | Tear down containers, volumes, and state.                   |
| `smoke`  | Probe N/N agents via `/v1/egress/peers`.                    |
| `go`     | Start workload drivers (spammer/chatter/sessionator).       |
| `chaos`  | Fault injection — `light`, `heavy`, `kill <svc>`, `partition <svc>`. |
| `report` | Render markdown report from JSONL logs in `logs/<run-ts>/`. |
| `logs`   | Tail compose logs (optionally for one service).             |

## Workload drivers (`go`)

Each driver is a host-side Python script that loads an enrolled agent via
`cullis_sdk.CullisClient.from_api_key_file` and runs a traffic pattern
until SIGINT/SIGTERM. Every event is appended to
`logs/<run-ts>/<driver>-<agent>.jsonl` one JSON record per line, flushed
immediately so `tail -f` works.

- `spammer.py <agent>` — periodic burst of one-shots to every peer in
  parallel. Exercises the Mastio concurrency path.
- `chatter.py <agent>` — low-rate random one-shots, baseline noise.
- `sessionator.py initiator|responder <self> …` — one long-lived
  intra-org session, ping-pong loop. Cross-org sessions via the proxy
  aren't wired yet (`send_via_proxy` envelope transport is
  NotImplementedError — tracked as follow-up).

`nightly.sh go` starts a default mix: 1 spammer + 4 chatter + 1
sessionator pair (7 processes). Stop with Ctrl-C — the trap signals
every child, JSONL logs flush, then the shell exits.

## Chaos (`chaos`)

Runs against the currently active workload run (reads `NIGHTLY_RUN_TS`
env or falls back to the newest `logs/*` subdir), tagging every fault
in `logs/<run-ts>/chaos.jsonl` so `report` can correlate them with
workload latency/failures.

- `chaos light` — warm-up, 1 Mastio kill, 1 Court partition (~2 min).
- `chaos heavy` — both Mastio killed, Court partition + kill (~5 min).
- `chaos kill <service> [--down-seconds N]` — one-off.
- `chaos partition <service> [--duration N]` — one-off.

## Report (`report`)

Aggregates all `*.jsonl` under `logs/<run-ts>/`, computes per-driver
stats (count, fail rate, p50/p99/max latency), auto-detects
criticalities (latency > threshold, fail rate > 5 %, echo timeouts,
chaos healthy-timeouts), writes `reports/<run-ts>.md`.

Thresholds in `report/collect.py` are intentionally lenient — they're
"show-me anything suspicious", not production SLOs.

## Layout

```
test/nightly/
├── nightly.sh              # entry point
├── config.env              # defaults
├── docker-compose.yml      # lean topology
├── bootstrap/              # bootstrap + bootstrap_mastio docker build
├── smoke.py                # host-side auth probe
├── workload/               # host-side traffic drivers
│   ├── _common.py          # identity loader, JSONL logger, shutdown helper
│   ├── chatter.py
│   ├── spammer.py
│   └── sessionator.py
├── chaos/                  # fault injection scripts
│   ├── _common.sh          # chaos_log JSONL writer, compose shortcut
│   ├── kill.sh
│   ├── partition.sh
│   └── sequence.sh         # light/heavy timeline
├── report/                 # log aggregator + markdown renderer
│   ├── collect.py
│   └── render.py
├── logs/                   # bind-mounted, gitignored, one subdir per go run
├── reports/                # gitignored, one markdown per run
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
