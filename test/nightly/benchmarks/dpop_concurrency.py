"""Concurrency benchmark for the Mastio egress DPoP path.

Sweeps the number of parallel agents hitting /v1/egress/peers while
measuring per-request latency + overall error rate. Written for
cullis-enterprise issue #2 ("Mastio egress DPoP validation stalls under
concurrency") — it's the gauge we use to decide whether a fix to the
auth path actually moves the needle.

Pre-req: `./nightly.sh full` has enrolled ≥N agents on the target org.

Usage:
    python benchmarks/dpop_concurrency.py \\
        --ns 1,5,10,20 --requests 10 --org orga

For each N in --ns: spin N threads, each thread owns one enrolled agent
client and fires --requests GET /v1/egress/peers back-to-back. Report:

    N   n_req  p50_ms  p99_ms  max_ms  err  rps
    1      10     370     480     510    0  2.6
    5      50    1800    2700    2900    0  2.1
    10    100    6500    9800   10000   12  1.1

Written so the same file can re-run before/after the fix and land the
numbers in the PR body.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "workload"))
from _common import load_client, load_manifest  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent.parent


def _probe_loop(agent_id: str, requests: int) -> list[tuple[int, bool]]:
    """Open one client, fire N requests, collect (latency_ms, ok)."""
    try:
        client = load_client(agent_id)
    except Exception as exc:
        return [(0, False) for _ in range(requests)] + [(-1, False)]

    out: list[tuple[int, bool]] = []
    for _ in range(requests):
        t0 = time.monotonic()
        try:
            client.list_peers(limit=1)
            out.append((int((time.monotonic() - t0) * 1000), True))
        except Exception:
            out.append((int((time.monotonic() - t0) * 1000), False))
    return out


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    vs = sorted(values)
    idx = min(len(vs) - 1, max(0, int(len(vs) * pct) - 1))
    return vs[idx]


def run_one(n: int, requests: int, agents: list[str]) -> dict:
    """Run one N-level sweep. Returns stats dict."""
    pool_agents = agents[:n]
    if len(pool_agents) < n:
        raise SystemExit(
            f"need {n} enrolled agents on target org but found only "
            f"{len(pool_agents)} — rerun ./nightly.sh full AGENTS_PER_ORG={n}"
        )

    wall_start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_probe_loop, a, requests) for a in pool_agents]
        results_nested = [f.result() for f in futures]
    wall_s = time.monotonic() - wall_start

    latencies_ok: list[int] = []
    errors = 0
    for per_agent in results_nested:
        for lat_ms, ok in per_agent:
            if ok:
                latencies_ok.append(lat_ms)
            else:
                errors += 1

    total = n * requests
    rps = total / wall_s if wall_s > 0 else 0.0

    return {
        "n": n,
        "n_req": total,
        "p50_ms": _percentile(latencies_ok, 0.50),
        "p99_ms": _percentile(latencies_ok, 0.99),
        "max_ms": max(latencies_ok) if latencies_ok else 0,
        "err": errors,
        "rps": round(rps, 2),
        "wall_s": round(wall_s, 2),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", default="1,5,10,20",
                    help="comma-separated concurrency levels (default 1,5,10,20)")
    ap.add_argument("--requests", type=int, default=10,
                    help="requests per agent at each level (default 10)")
    ap.add_argument("--org", default="orga", choices=["orga", "orgb"],
                    help="which org's agents to recruit (default orga)")
    ap.add_argument("--csv", type=pathlib.Path, default=None,
                    help="append each row as CSV to this path")
    ap.add_argument("--label", default="",
                    help="free-form label written to CSV (e.g. 'pre-fix', 'post-fix')")
    args = ap.parse_args()

    manifest = load_manifest()
    org_agents = sorted(
        e["agent_id"] for e in manifest if e["org_id"] == args.org
    )
    if not org_agents:
        print(f"no agents enrolled for org={args.org} — run ./nightly.sh full", file=sys.stderr)
        return 1

    ns = [int(x) for x in args.ns.split(",")]
    max_n = max(ns)
    if len(org_agents) < max_n:
        print(f"need {max_n} agents on {args.org}; have {len(org_agents)}. "
              f"Rerun AGENTS_PER_ORG={max_n} ./nightly.sh full", file=sys.stderr)
        return 1

    header = ("N", "n_req", "p50_ms", "p99_ms", "max_ms", "err", "rps", "wall_s")
    print(f"{'N':>4} {'n_req':>7} {'p50_ms':>8} {'p99_ms':>8} {'max_ms':>8} "
          f"{'err':>4} {'rps':>6} {'wall_s':>7}")
    print("-" * 58)

    rows: list[dict] = []
    for n in ns:
        row = run_one(n, args.requests, org_agents)
        rows.append(row)
        print(f"{row['n']:>4} {row['n_req']:>7} {row['p50_ms']:>8} "
              f"{row['p99_ms']:>8} {row['max_ms']:>8} {row['err']:>4} "
              f"{row['rps']:>6} {row['wall_s']:>7}")

    if args.csv:
        exists = args.csv.exists()
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("a", newline="") as fh:
            w = csv.writer(fh)
            if not exists:
                w.writerow(("ts", "label", *header))
            for r in rows:
                w.writerow((time.time(), args.label, *[r[k.lower()] for k in header]))
        print(f"\n[bench] appended {len(rows)} rows → {args.csv}")

    # Also print a JSON trailer so a caller can `| jq`.
    print("\n" + json.dumps({"label": args.label, "rows": rows}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
