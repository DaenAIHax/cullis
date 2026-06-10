#!/usr/bin/env python3
"""Bench the embedded Rego policy engine — compile + per-decision eval.

Produces three honest numbers that operators (and CISOs comparing
Cullis to other agent-policy products) can quote:

  * **Compile time** — one-shot ``opa build -t wasm`` invocation for
    a representative Rego policy. Operator-visible at Save time on
    the dashboard Policies page.

  * **Per-eval latency** — p50 / p95 / p99 / max wall-clock for one
    ``evaluate_decision`` call against the compiled WASM bundle.
    Each iteration instantiates a fresh ``OPAPolicy`` so the number
    reflects the hot-path the runtime actually walks (today there
    is no shared instance cache; future work to add one is tracked
    separately).

  * **Throughput** — total iterations / total wall-clock seconds.

Run::

    python scripts/bench-rego-eval.py
    python scripts/bench-rego-eval.py --iterations 5000 --warmup 100
    MCP_PROXY_OPA_BINARY=/opt/opa python scripts/bench-rego-eval.py

The script does NOT touch any DB, network, or Mastio process. Pure
in-Python orchestration of ``mcp_proxy.policy.rego_engine`` against a
fixed in-source Rego policy. Reproducible from a clean checkout.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

# The bench needs the in-tree engine. When the script is invoked from
# the repo root (``python scripts/bench-rego-eval.py``) the import
# resolves naturally; from an installed wheel the package is on
# PYTHONPATH already.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mcp_proxy.policy.rego_engine import (  # noqa: E402
    RegoEngine,
    compile_rego,
    evaluate_decision,
)


# Representative policy — same shape the operator docs example uses,
# enough rules that the WASM bundle is non-trivial (the trivial
# ``always-allow`` policy compiles to a tiny module that doesn't
# reflect realistic workloads).
_REGO_SOURCE = """package cullis.policy

# Default-deny tool_call surface — explicit allowlist below.
tool_call := {"decision": "deny", "reason": "no rule matched"} if {
    not allow_tool_call
}

tool_call := {"decision": "allow"} if {
    allow_tool_call
}

# KYC screener: read-only KYC tools.
allow_tool_call if {
    input.agent_id == "orga::kyc-screener"
    input.tool_name == "sanctions_lookup"
}

allow_tool_call if {
    input.agent_id == "orga::kyc-screener"
    input.tool_name == "kyc_status_check"
}

# Treasury bot: explicit money-moving tools.
allow_tool_call if {
    input.agent_id == "orga::treasury"
    input.tool_name == "treasury_wire"
}

allow_tool_call if {
    input.agent_id == "orga::treasury"
    input.tool_name == "sepa_credit_transfer"
}

# Open knowledge-base lookups for any in-org agent.
allow_tool_call if {
    startswith(input.agent_id, "orga::")
    input.tool_name == "knowledge_base_query"
}

# Session surface — cross-org gated, same-org always allowed.
session := {"decision": "allow"} if {
    input.initiator_org_id == input.target_org_id
}

session := {"decision": "allow"} if {
    input.target_org_id == "approved-partner"
    "kyc.partner-disclose" == input.capabilities[_]
}

session := {"decision": "deny", "reason": "cross-org session not permitted"} if {
    input.initiator_org_id != input.target_org_id
    not partner_allowed
}

partner_allowed if {
    input.target_org_id == "approved-partner"
    "kyc.partner-disclose" == input.capabilities[_]
}
"""


# Inputs cycled across iterations so the bench doesn't fall into
# trivial cache hits in any layer (CPU branch predictor, OPA
# WASM cache, allocator hot-paths). Two represent the allow case
# (KYC screener + sanctions_lookup, same-org session), one the deny
# case (Treasury asking for forbidden KB tool — no allowed_tool rule
# matches), and one the partner-allow case.
_INPUTS = [
    {"agent_id": "orga::kyc-screener", "tool_name": "sanctions_lookup"},
    {"agent_id": "orga::treasury", "tool_name": "knowledge_base_query"},
    {
        "initiator_agent_id": "orga::scout",
        "target_agent_id": "approved-partner::vendor",
        "initiator_org_id": "orga",
        "target_org_id": "approved-partner",
        "session_context": "initiator",
        "capabilities": ["kyc.partner-disclose"],
    },
    {"agent_id": "orga::kyc-screener", "tool_name": "kyc_status_check"},
]

_ENTRYPOINTS = [
    "cullis/policy/tool_call",
    "cullis/policy/tool_call",
    "cullis/policy/session",
    "cullis/policy/tool_call",
]


def _percentile(samples: list[float], pct: float) -> float:
    """p50/p95/p99 over the sample list (ms)."""
    if not samples:
        return float("nan")
    sorted_samples = sorted(samples)
    k = (len(sorted_samples) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_samples) - 1)
    if f == c:
        return sorted_samples[f]
    d = k - f
    return sorted_samples[f] + (sorted_samples[c] - sorted_samples[f]) * d


def _fmt_ms(value: float) -> str:
    """Format a millisecond figure: ``0.12ms`` vs ``42.3ms``."""
    if value < 1.0:
        return f"{value:.3f}ms"
    return f"{value:.2f}ms"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000,
                        help="number of eval calls to time (default: 2000)")
    parser.add_argument("--warmup", type=int, default=50,
                        help="warmup eval calls to discard before timing "
                        "(default: 50)")
    parser.add_argument("--report-md", type=Path,
                        help="optional path to write a Markdown report")
    args = parser.parse_args()

    print("=== Cullis Rego eval bench ===")
    print(f"Source: in-script representative policy "
          f"({len(_REGO_SOURCE.splitlines())} lines)")
    print(f"Iterations: {args.iterations} (+ {args.warmup} warmup, discarded)")
    print()

    # Phase 1 — compile.
    t0 = time.perf_counter()
    compiled = compile_rego(_REGO_SOURCE)
    compile_ms = (time.perf_counter() - t0) * 1000
    print(f"Compile:    {_fmt_ms(compile_ms)} (wasm {len(compiled.wasm):,} bytes, "
          f"sha256={compiled.sha256[:12]})")

    # Phase 2 — warmup.
    engine = RegoEngine(compiled)
    for i in range(args.warmup):
        inp = _INPUTS[i % len(_INPUTS)]
        ep = _ENTRYPOINTS[i % len(_INPUTS)]
        engine.evaluate(inp, entrypoint=ep)

    # Phase 3 — timed.
    samples_ms: list[float] = []
    start_wall = time.perf_counter()
    for i in range(args.iterations):
        inp = _INPUTS[i % len(_INPUTS)]
        ep = _ENTRYPOINTS[i % len(_INPUTS)]
        t = time.perf_counter()
        engine.evaluate(inp, entrypoint=ep)
        samples_ms.append((time.perf_counter() - t) * 1000)
    total_wall = time.perf_counter() - start_wall

    # Phase 4 — also time the higher-level ``evaluate_decision`` (which
    # adds the result-normalisation layer on top of ``engine.evaluate``)
    # so the operator-visible API has its own number, separate from
    # the raw wasmtime call.
    norm_samples: list[float] = []
    for i in range(min(args.iterations, 500)):  # bounded — same shape
        inp = _INPUTS[i % len(_INPUTS)]
        ep = _ENTRYPOINTS[i % len(_INPUTS)]
        t = time.perf_counter()
        evaluate_decision(compiled, inp, entrypoint=ep)
        norm_samples.append((time.perf_counter() - t) * 1000)

    # Report.
    p50 = _percentile(samples_ms, 50)
    p95 = _percentile(samples_ms, 95)
    p99 = _percentile(samples_ms, 99)
    max_ms = max(samples_ms)
    mean_ms = statistics.fmean(samples_ms)
    throughput = args.iterations / total_wall

    n50 = _percentile(norm_samples, 50)
    n95 = _percentile(norm_samples, 95)
    n99 = _percentile(norm_samples, 99)

    print()
    print("RegoEngine.evaluate (raw wasmtime call):")
    print(f"  p50      {_fmt_ms(p50)}")
    print(f"  p95      {_fmt_ms(p95)}")
    print(f"  p99      {_fmt_ms(p99)}")
    print(f"  max      {_fmt_ms(max_ms)}")
    print(f"  mean     {_fmt_ms(mean_ms)}")
    print(f"  ops/sec  {throughput:,.0f}")
    print()
    print("evaluate_decision (raw + result normalisation):")
    print(f"  p50      {_fmt_ms(n50)}")
    print(f"  p95      {_fmt_ms(n95)}")
    print(f"  p99      {_fmt_ms(n99)}")

    if args.report_md:
        args.report_md.parent.mkdir(parents=True, exist_ok=True)
        with args.report_md.open("w") as f:
            f.write("# Rego eval bench\n\n")
            f.write(f"- Iterations: **{args.iterations}** "
                    f"(+ {args.warmup} warmup discarded)\n")
            f.write(f"- Compile: **{_fmt_ms(compile_ms)}** "
                    f"(wasm {len(compiled.wasm):,} bytes, "
                    f"sha256 `{compiled.sha256[:12]}`)\n\n")
            f.write("## RegoEngine.evaluate\n\n")
            f.write("| metric  | value |\n|---|---|\n")
            f.write(f"| p50     | {_fmt_ms(p50)} |\n")
            f.write(f"| p95     | {_fmt_ms(p95)} |\n")
            f.write(f"| p99     | {_fmt_ms(p99)} |\n")
            f.write(f"| max     | {_fmt_ms(max_ms)} |\n")
            f.write(f"| mean    | {_fmt_ms(mean_ms)} |\n")
            f.write(f"| ops/sec | {throughput:,.0f} |\n\n")
            f.write("## evaluate_decision (raw + normalisation)\n\n")
            f.write("| metric | value |\n|---|---|\n")
            f.write(f"| p50    | {_fmt_ms(n50)} |\n")
            f.write(f"| p95    | {_fmt_ms(n95)} |\n")
            f.write(f"| p99    | {_fmt_ms(n99)} |\n")
        print(f"\nReport: {args.report_md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
