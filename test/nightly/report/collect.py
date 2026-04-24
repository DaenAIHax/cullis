"""Aggregate JSONL logs from one nightly run into a structured dict.

Output shape (JSON-serializable):

    {
      "run_ts": "20260424-083254",
      "started": 1777019594.3,
      "ended":   1777019661.9,
      "duration_s": 67.6,
      "drivers": [
        {"kind": "chatter", "agent": "orga::nightly-a-05",
         "sent": 4, "ok": 4, "fail": 0,
         "latency_ms": {"p50": 5991, "p99": 9577, "max": 9577, "n": 4}},
        ...
      ],
      "chaos": [
        {"ts": ..., "event": "kill_start", "service": "proxy-a", ...},
        ...
      ],
      "criticalities": [
        {"id": "chatter_p99_high", "severity": "high",
         "message": "chatter p99 latency 9577ms > 1000ms threshold",
         "evidence": {...}},
        ...
      ],
    }

Run via ``nightly.sh report`` or ``python report/collect.py [<run-ts>]``.
"""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

LOGS_ROOT = pathlib.Path(__file__).resolve().parent.parent / "logs"

# Criticality thresholds. These are not production SLOs, just the line
# above which the report flags a latency/failure pattern worth showing.
CHATTER_P99_THRESHOLD_MS = 1000
SPAMMER_P99_THRESHOLD_MS = 1000
SESSION_RTT_P99_THRESHOLD_MS = 500
FAIL_RATIO_THRESHOLD = 0.05  # 5%


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    vs = sorted(values)
    idx = min(len(vs) - 1, max(0, int(len(vs) * pct) - 1))
    return vs[idx]


def _latency_stats(values: list[int]) -> dict[str, int]:
    if not values:
        return {"p50": 0, "p99": 0, "max": 0, "n": 0}
    return {
        "p50": _percentile(values, 0.50),
        "p99": _percentile(values, 0.99),
        "max": max(values),
        "n": len(values),
    }


def _load_jsonl(path: pathlib.Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # best-effort; a truncated tail shouldn't kill the report
    return rows


def _aggregate_chatter(rows: list[dict], agent: str) -> dict[str, Any]:
    sent = [r for r in rows if r.get("event") == "send_ok"]
    fail = [r for r in rows if r.get("event") == "send_fail"]
    latencies = [r["latency_ms"] for r in sent if "latency_ms" in r]
    return {
        "kind": "chatter", "agent": agent,
        "sent": len(sent), "ok": len(sent), "fail": len(fail),
        "latency_ms": _latency_stats(latencies),
    }


def _aggregate_spammer(rows: list[dict], agent: str) -> dict[str, Any]:
    sends = [r for r in rows if r.get("event") in ("send_ok", "send_fail")]
    ok = sum(1 for r in sends if r["event"] == "send_ok")
    fail = sum(1 for r in sends if r["event"] == "send_fail")
    latencies = [r["latency_ms"] for r in sends if "latency_ms" in r]
    bursts = [r for r in rows if r.get("event") == "burst_end"]
    return {
        "kind": "spammer", "agent": agent,
        "sent": len(sends), "ok": ok, "fail": fail,
        "bursts": len(bursts),
        "latency_ms": _latency_stats(latencies),
    }


def _aggregate_sessionator(rows: list[dict], agent: str, role: str) -> dict[str, Any]:
    rtts = [r["rtt_ms"] for r in rows if r.get("event") == "rtt" and "rtt_ms" in r]
    timeouts = sum(1 for r in rows if r.get("event") == "echo_timeout")
    opens = sum(1 for r in rows if r.get("event") == "session_opened")
    accepts = sum(1 for r in rows if r.get("event") == "session_accepted")
    echoes = sum(1 for r in rows if r.get("event") == "echo")
    fails = sum(1 for r in rows if r.get("event") in ("open_fail", "send_fail", "recv_fail",
                                                       "accept_fail", "echo_fail", "list_fail"))
    return {
        "kind": f"sessionator-{role}", "agent": agent,
        "sessions_opened": opens, "sessions_accepted": accepts,
        "rtts": len(rtts), "echoes": echoes,
        "timeouts": timeouts, "errors": fails,
        "latency_ms": _latency_stats(rtts) if role == "initiator" else _latency_stats([]),
    }


def _detect_criticalities(drivers: list[dict], chaos: list[dict]) -> list[dict]:
    out: list[dict] = []
    for d in drivers:
        kind = d["kind"]
        lat = d.get("latency_ms", {})
        p99 = lat.get("p99", 0)

        if kind == "chatter" and p99 > CHATTER_P99_THRESHOLD_MS and lat["n"] > 0:
            out.append({
                "id": "chatter_p99_high", "severity": "high",
                "driver": d["agent"],
                "message": f"chatter p99={p99}ms > {CHATTER_P99_THRESHOLD_MS}ms "
                           f"(n={lat['n']}, max={lat['max']}ms)",
            })
        if kind == "spammer" and p99 > SPAMMER_P99_THRESHOLD_MS and lat["n"] > 0:
            out.append({
                "id": "spammer_p99_high", "severity": "high",
                "driver": d["agent"],
                "message": f"spammer p99={p99}ms > {SPAMMER_P99_THRESHOLD_MS}ms "
                           f"(n={lat['n']}, max={lat['max']}ms)",
            })
        if kind == "sessionator-initiator":
            if p99 > SESSION_RTT_P99_THRESHOLD_MS and lat["n"] > 0:
                out.append({
                    "id": "session_rtt_p99_high", "severity": "high",
                    "driver": d["agent"],
                    "message": f"session RTT p99={p99}ms > {SESSION_RTT_P99_THRESHOLD_MS}ms "
                               f"(n={lat['n']}, max={lat['max']}ms)",
                })
            if d.get("timeouts", 0) > 0:
                out.append({
                    "id": "session_echo_timeout", "severity": "medium",
                    "driver": d["agent"],
                    "message": f"{d['timeouts']} echo_timeout(s) — messages enqueued "
                               f"but no reply within 10s window",
                })

        ok = d.get("sent", 0) or d.get("rtts", 0)
        fail = d.get("fail", 0) or d.get("errors", 0)
        attempts = ok + fail
        if attempts > 0 and fail / attempts > FAIL_RATIO_THRESHOLD:
            pct = int(100 * fail / attempts)
            out.append({
                "id": "fail_rate_high", "severity": "high",
                "driver": d["agent"],
                "message": f"{d['kind']} {fail}/{attempts} attempts failed "
                           f"({pct}% > {int(FAIL_RATIO_THRESHOLD*100)}% threshold)",
            })

    if any(e["event"] == "healthy_timeout" for e in chaos):
        out.append({
            "id": "chaos_healthy_timeout", "severity": "high",
            "driver": "chaos",
            "message": "a chaos'd service never went back to healthy within 60s",
        })
    return out


def collect(run_ts: str | None = None) -> dict[str, Any]:
    if run_ts:
        run_dir = LOGS_ROOT / run_ts
    else:
        candidates = sorted(p for p in LOGS_ROOT.iterdir() if p.is_dir()) if LOGS_ROOT.exists() else []
        if not candidates:
            raise SystemExit(f"no runs under {LOGS_ROOT}")
        run_dir = candidates[-1]

    if not run_dir.exists():
        raise SystemExit(f"{run_dir} does not exist")

    drivers: list[dict[str, Any]] = []
    all_start: list[float] = []
    all_end: list[float] = []

    for jsonl in sorted(run_dir.glob("*.jsonl")):
        if jsonl.name == "chaos.jsonl":
            continue
        rows = _load_jsonl(jsonl)
        if not rows:
            continue
        all_start.extend(r["ts"] for r in rows if r.get("event") == "start" and "ts" in r)
        all_end.extend(r["ts"] for r in rows if r.get("event") == "stop" and "ts" in r)

        # Infer driver kind from filename: <kind>-<agent>.jsonl
        name = jsonl.stem
        kind, _, agent_safe = name.partition("-")
        agent = agent_safe.replace("_", "::", 1)

        if kind == "chatter":
            drivers.append(_aggregate_chatter(rows, agent))
        elif kind == "spammer":
            drivers.append(_aggregate_spammer(rows, agent))
        elif kind == "sessionator":
            # filename: sessionator-<role>-<agent>.jsonl
            role, _, rest = agent_safe.partition("-")
            agent = rest.replace("_", "::", 1)
            drivers.append(_aggregate_sessionator(rows, agent, role))
        # Unknown kinds are silently skipped — new drivers should add
        # their aggregator here explicitly.

    chaos_path = run_dir / "chaos.jsonl"
    chaos = _load_jsonl(chaos_path) if chaos_path.exists() else []

    started = min(all_start) if all_start else 0.0
    ended = max(all_end) if all_end else 0.0
    result = {
        "run_ts": run_dir.name,
        "run_dir": str(run_dir),
        "started": started,
        "ended": ended,
        "duration_s": round(ended - started, 2) if (started and ended) else 0.0,
        "drivers": drivers,
        "chaos": chaos,
        "criticalities": _detect_criticalities(drivers, chaos),
    }
    return result


def main() -> int:
    run_ts = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(collect(run_ts), indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
