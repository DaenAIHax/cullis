"""Render the collect.py aggregate into a Markdown report.

Usage:
    python report/render.py [<run-ts>]

Writes to ``test/nightly/reports/<run-ts>.md`` and prints the path.
"""
from __future__ import annotations

import datetime
import pathlib
import sys

from collect import collect

REPORTS_ROOT = pathlib.Path(__file__).resolve().parent.parent / "reports"

SEVERITY_GLYPH = {"high": "🔴", "medium": "🟡", "low": "🟢"}


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "—"
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")


def _driver_table(drivers: list[dict]) -> list[str]:
    lines = ["| Driver | Agent | Sent/RTTs | OK | Fail | p50 ms | p99 ms | max ms |",
             "|---|---|---|---|---|---|---|---|"]
    for d in drivers:
        lat = d.get("latency_ms", {})
        total = d.get("sent") or d.get("rtts") or 0
        ok = d.get("ok", d.get("echoes", 0))
        fail = d.get("fail") or d.get("errors") or 0
        lines.append(
            f"| {d['kind']} | `{d['agent']}` | {total} | {ok} | {fail} | "
            f"{lat.get('p50', '—')} | {lat.get('p99', '—')} | {lat.get('max', '—')} |"
        )
    return lines


def _chaos_timeline(chaos: list[dict], started: float) -> list[str]:
    if not chaos:
        return ["_No chaos events recorded._"]
    lines = ["| t (s) | Event | Detail |", "|---|---|---|"]
    for e in chaos:
        ts = e.get("ts", 0)
        offset = round(ts - started, 1) if started else "?"
        detail = ", ".join(
            f"{k}={v}" for k, v in e.items() if k not in ("ts", "event")
        )
        lines.append(f"| {offset} | {e.get('event', '?')} | {detail} |")
    return lines


def _criticalities(crits: list[dict]) -> list[str]:
    if not crits:
        return ["_No criticalities detected._"]
    lines = []
    for c in crits:
        glyph = SEVERITY_GLYPH.get(c["severity"], "•")
        lines.append(f"- {glyph} **{c['id']}** ({c['severity']}) — `{c.get('driver','')}` — {c['message']}")
    return lines


def render(run_ts: str | None = None) -> pathlib.Path:
    data = collect(run_ts)
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_ROOT / f"{data['run_ts']}.md"

    md: list[str] = []
    md.append(f"# Nightly run {data['run_ts']}")
    md.append("")
    md.append(f"- Started: {_fmt_ts(data['started'])}")
    md.append(f"- Ended:   {_fmt_ts(data['ended'])}")
    md.append(f"- Duration: {data['duration_s']} s")
    md.append(f"- Drivers: {len(data['drivers'])}")
    md.append(f"- Chaos events: {len(data['chaos'])}")
    md.append("")

    md.append("## Criticalities detected")
    md.append("")
    md.extend(_criticalities(data["criticalities"]))
    md.append("")

    md.append("## Workload summary")
    md.append("")
    md.extend(_driver_table(data["drivers"]))
    md.append("")

    md.append("## Chaos timeline")
    md.append("")
    md.extend(_chaos_timeline(data["chaos"], data["started"]))
    md.append("")

    md.append("## Raw logs")
    md.append("")
    md.append(f"`{data['run_dir']}/`")
    md.append("")

    out_path.write_text("\n".join(md))
    return out_path


def main() -> int:
    run_ts = sys.argv[1] if len(sys.argv) > 1 else None
    path = render(run_ts)
    print(f"[report] wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
