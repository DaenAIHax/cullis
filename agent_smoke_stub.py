"""Deterministic MCP tool-call stub for dogfood smoke scenarios B8-B11.

Replaces an LLM-driven agent (kyc-screener, dora-reporter, pitchbook-builder)
with a fixed sequence of `client.call_mcp_tool()` calls. No LLM, no real
payload — only the same identity / capability / audit chain exercised that a
real agent would trigger.

Designed to run inside an existing stack container (agent-a) that mounts the
bootstrap-state volume at /state/, so any agent's identity material is
reachable without extracting certs to the host.

Exit codes:
    0  expected outcome reached (all tools called OK, or denial observed
       when --expect-denied)
    1  scenario failure (tool calls did not match expected outcome)
    2  setup error (identity not found, SDK import broken, etc.)

Usage:
    docker exec agent-a python3 /tmp/agent_smoke_stub.py \\
        --agent-id orga::kyc-screener \\
        --tools verify_identity,screen_sanctions,query_beneficial_owners,escalate_to_compliance \\
        --mastio https://mastio-a-nginx:9443

Capability-denied probe (B11):
    docker exec agent-a python3 /tmp/agent_smoke_stub.py \\
        --agent-id orga::kyc-screener \\
        --tools get_market_data \\
        --mastio https://mastio-a-nginx:9443 \\
        --expect-denied
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _agent_short_name(agent_id: str) -> str:
    return agent_id.split("::", 1)[1] if "::" in agent_id else agent_id


def _org_id(agent_id: str) -> str:
    return agent_id.split("::", 1)[0] if "::" in agent_id else "orga"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", required=True, help="e.g. orga::kyc-screener")
    parser.add_argument("--tools", required=True, help="comma-separated tool names")
    parser.add_argument("--mastio", required=True, help="Mastio TLS URL")
    parser.add_argument(
        "--state-root",
        default="/state",
        help="Bootstrap-state volume mount root (default /state)",
    )
    parser.add_argument(
        "--expect-denied",
        action="store_true",
        help="Scenario B11: tool call SHOULD return capability_denied",
    )
    parser.add_argument(
        "--scenario",
        default="smoke",
        help="Tag passed in tool args (audit chain visibility)",
    )
    args = parser.parse_args()

    sys.path.insert(0, "/app")
    try:
        from cullis_sdk.client import CullisClient
    except ImportError as exc:
        print(f"SETUP_FAIL: cullis_sdk not importable: {exc}", file=sys.stderr)
        return 2

    short = _agent_short_name(args.agent_id)
    org = _org_id(args.agent_id)
    id_dir = Path(args.state_root) / org / "agents" / short
    cert = id_dir / "agent.pem"
    key = id_dir / "agent-key.pem"
    ca = Path(args.state_root) / org / "ca.pem"

    for f in (cert, key, ca):
        if not f.exists():
            print(f"SETUP_FAIL: missing {f}", file=sys.stderr)
            return 2

    try:
        client = CullisClient.from_identity_dir(
            args.mastio,
            cert_path=str(cert),
            key_path=str(key),
            ca_chain_path=str(ca),
            verify_tls=True,
            agent_id=args.agent_id,
            org_id=org,
        )
        client.login(
            agent_id=args.agent_id,
            org_id=org,
            cert_path=str(cert),
            key_path=str(key),
        )
    except Exception as exc:
        print(f"SETUP_FAIL: client build/login: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    results = []
    for tool in tools:
        try:
            resp = client.call_mcp_tool(
                tool,
                {"flag": "smoke", "scenario": args.scenario, "agent": args.agent_id},
            )
            results.append((tool, "ok", json.dumps(resp)[:120]))
        except Exception as exc:
            cls = type(exc).__name__
            msg = str(exc)[:160]
            low = msg.lower()
            denied = (
                "capability" in low
                or "403" in msg
                or "denied" in low
                or "no active binding" in low
                or "binding" in low and "resource" in low
            )
            results.append((tool, "denied" if denied else "fail", f"{cls}: {msg}"))

    print(f"=== {args.agent_id} ===")
    for tool, status, detail in results:
        marker = {"ok": "OK", "denied": "DENIED", "fail": "FAIL"}[status]
        print(f"  [{marker}] {tool}  {detail}")

    if args.expect_denied:
        every_denied = all(s == "denied" for _, s, _ in results)
        if every_denied:
            print(f"RESULT: B11 OK ({len(results)} tool(s) correctly denied)")
            return 0
        print(f"RESULT: B11 FAIL (expected denied, got {[s for _,s,_ in results]})", file=sys.stderr)
        return 1
    else:
        all_ok = all(s == "ok" for _, s, _ in results)
        if all_ok:
            print(f"RESULT: OK {len(results)}/{len(results)} tools succeeded")
            return 0
        print(f"RESULT: FAIL (mixed outcomes: {[s for _,s,_ in results]})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
