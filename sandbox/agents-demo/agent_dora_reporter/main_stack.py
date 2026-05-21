"""DORA Vendor/TPA Compliance Reporter -- stack runtime entry.

Stack:
- LLM call goes to Mastio via CullisClient.chat_completion(). Default
  model `ollama/mistral-small` reaches the host Ollama daemon through
  the Mastio `host.docker.internal:11434` extra_hosts mapping. Override
  via ``--model`` or ``CULLIS_DORA_REPORTER_MODEL``.
- Tools dispatched through Mastio MCP aggregator (`local_mcp_resources`
  + `local_agent_resource_bindings` gate).
- Cross-org A2A submission to the auditor org: the `mcp-dora` MCP server
  joins both `orga-internal` and `orgb-internal` docker networks, so the
  submission semantically reaches "the auditor side" -- but the dual-write
  is still in-process (single mcp-dora server). Real cross-org with two
  Mastios + sealed A2A envelope is the follow-up; document the gap.

The `--role compliance_officer` flag tells the agent it is allowed to
attempt submission; without it the agent only drafts (skipped:not_authorized).
The Mastio binding gate enforces `dora.cross_org_submit` capability on the
principal; the role check itself is application-level here because the
production Mastio reads the role from a session claim that we do not
emulate end-to-end in the stack demo.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

DEFAULT_MODEL = os.environ.get("CULLIS_DORA_REPORTER_MODEL", "ollama/mistral-small")
DEFAULT_MASTIO_URL = "https://mastio-a-nginx:9443"
MAX_LOOP_ITERATIONS = 16

_THIS_DIR = Path(__file__).resolve().parent
SYSTEM_PROMPT_PATH = _THIS_DIR / "system_prompt.md"


@dataclass(frozen=True)
class DORAStackReport:
    report_id: str
    vendors_drafted: list[dict[str, Any]]
    summary: str
    submissions_attempted: int
    submissions_succeeded: int
    cullis_trace_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "vendors_drafted": self.vendors_drafted,
            "summary": self.summary,
            "submissions_attempted": self.submissions_attempted,
            "submissions_succeeded": self.submissions_succeeded,
            "cullis_trace_ids": self.cullis_trace_ids,
        }


_WANTED_TOOLS = {
    "list_third_party_vendors",
    "query_vendor_assessment",
    "draft_dora_register_entry",
    "submit_to_auditor_org",
}


def _resolve_tools(client: Any) -> list[dict[str, Any]]:
    raw = client.list_mcp_tools()
    tools = []
    for t in raw:
        if t.get("name") not in _WANTED_TOOLS:
            continue
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("inputSchema", {"type": "object"}),
                },
            }
        )
    if not tools:
        raise RuntimeError(
            "Mastio MCP aggregator returned no DORA tools for this principal. "
            "Verify binding + SEED_MCP_11..14 entries on mastio-a-init."
        )
    return tools


def _invoke_tool(client: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = client.call_mcp_tool(name, args)
    content = result.get("content") or []
    if content and isinstance(content[0], dict) and "text" in content[0]:
        try:
            return json.loads(content[0]["text"])
        except json.JSONDecodeError:
            return {"_raw": content[0]["text"]}
    return result


def run(
    *,
    report_id: str,
    target_auditor_org_id: str | None,
    is_compliance_officer: bool,
    mastio_url: str,
    identity_dir: Path,
    model: str = DEFAULT_MODEL,
    ca_chain_path: Path | None = None,
    verify_tls: bool = True,
) -> DORAStackReport:
    try:
        from cullis_sdk.client import CullisClient
    except ImportError as exc:
        raise RuntimeError("cullis_sdk not importable") from exc

    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=identity_dir / "agent.pem",
        key_path=identity_dir / "agent-key.pem",
        dpop_key_path=identity_dir / "dpop.jwk",
        agent_id="orga::dora-reporter",
        org_id="orga",
        verify_tls=verify_tls,
        ca_chain_path=ca_chain_path,
    )
    client._cert_pem = (identity_dir / "agent.pem").read_text()
    client._signing_key_pem = (identity_dir / "agent-key.pem").read_text()
    client.login_via_proxy_with_local_key()

    # Workaround for chat_completion DPoP pinning bug (see CullisClient memo
    # feedback_chat_completion_dpop_pinning_bug). The SDK egress path signs
    # with the persistent egress DPoP key, but the proof rejection chain
    # currently returns 401 with no auto-retry on cold nonce in some setups.
    # Mastio's /v1/llm/chat accepts mTLS cert-only auth as a fallback, so
    # we route the chat completion through a raw httpx client with the same
    # client cert. The MCP aggregator (list_mcp_tools / call_mcp_tool) keeps
    # using the SDK because that path works.
    import httpx as _httpx
    _direct = _httpx.Client(
        cert=(str(identity_dir / "agent.pem"), str(identity_dir / "agent-key.pem")),
        verify=False,  # demo: Mastio server CA different from Org A CA; for prod use Mastio public CA
        timeout=60.0,
    )

    def _direct_chat(request: dict[str, Any]) -> dict[str, Any]:
        r = _direct.post(f"{mastio_url.rstrip('/')}/v1/llm/chat", json=request)
        r.raise_for_status()
        return r.json()

    tools = _resolve_tools(client)
    system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    user_instruction = (
        f"Run DORA Art. 28 reporting cycle {report_id} for org orga. "
    )
    if target_auditor_org_id and is_compliance_officer:
        user_instruction += (
            f"After drafting, submit each CRITICAL entry to auditor org "
            f"'{target_auditor_org_id}'. "
        )
    elif target_auditor_org_id:
        user_instruction += (
            f"You DO NOT have the compliance_officer role. Mark each CRITICAL "
            f"vendor with submission_status 'skipped:not_authorized' and do NOT "
            f"attempt to call submit_to_auditor_org. "
        )
    else:
        user_instruction += "Draft only; do not cross-submit. "
    user_instruction += "Return the final JSON when ready."

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_instruction},
    ]
    trace_ids: list[str] = []

    for iteration in range(MAX_LOOP_ITERATIONS):
        response = _direct_chat(
            {"model": model, "messages": messages, "tools": tools}
        )
        if (tid := response.get("cullis_trace_id")):
            trace_ids.append(tid)

        choice = (response.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            parsed = _parse_output(msg.get("content", ""), report_id=report_id)
            attempted = sum(
                1 for v in parsed["vendors_drafted"]
                if v.get("submission_status") not in (None, "not_attempted")
            )
            succeeded = sum(
                1 for v in parsed["vendors_drafted"]
                if v.get("submission_status") == "submitted"
            )
            return DORAStackReport(
                report_id=parsed["report_id"],
                vendors_drafted=parsed["vendors_drafted"],
                summary=parsed["summary"],
                submissions_attempted=attempted,
                submissions_succeeded=succeeded,
                cullis_trace_ids=trace_ids,
            )

        messages.append(
            {
                "role": "assistant",
                "content": msg.get("content"),
                "tool_calls": tool_calls,
            }
        )
        for tc in tool_calls:
            name = tc["function"]["name"]
            args_raw = tc["function"]["arguments"]
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
            except json.JSONDecodeError:
                args = {}
            result = _invoke_tool(client, name, args)
            messages.append(
                {"role": "tool", "tool_call_id": tc["id"], "content": json.dumps(result)}
            )

    raise RuntimeError(
        f"DORA agent exceeded {MAX_LOOP_ITERATIONS} iterations without finalizing"
    )


def _parse_output(content: str, *, report_id: str) -> dict[str, Any]:
    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", content, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise ValueError(f"DORA final content did not contain JSON: {content!r}")
    data = json.loads(match.group(0))
    required = {"report_id", "vendors_drafted", "summary"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"DORA final JSON missing fields: {sorted(missing)}")
    if data["report_id"] != report_id:
        raise ValueError(f"report_id mismatch: expected {report_id!r}")
    return data


def main() -> int:  # pragma: no cover - CLI entrypoint
    parser = argparse.ArgumentParser(description="DORA Reporter stack runtime")
    parser.add_argument("--report-id", required=True)
    parser.add_argument("--target-auditor-org", default=None)
    parser.add_argument(
        "--role",
        choices=["compliance_officer", "analyst"],
        default="analyst",
        help="Application-level role; production Mastio reads this from a session claim.",
    )
    parser.add_argument(
        "--mastio-url",
        default=os.environ.get("CULLIS_MASTIO_URL", DEFAULT_MASTIO_URL),
    )
    parser.add_argument(
        "--identity-dir",
        type=Path,
        default=Path(
            os.environ.get("CULLIS_IDENTITY_DIR", "./.data/agents-demo/dora-reporter")
        ),
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ca-chain", type=Path, default=None)
    parser.add_argument("--no-verify-tls", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    report = run(
        report_id=args.report_id,
        target_auditor_org_id=args.target_auditor_org,
        is_compliance_officer=(args.role == "compliance_officer"),
        mastio_url=args.mastio_url,
        identity_dir=args.identity_dir,
        model=args.model,
        ca_chain_path=args.ca_chain,
        verify_tls=not args.no_verify_tls,
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
