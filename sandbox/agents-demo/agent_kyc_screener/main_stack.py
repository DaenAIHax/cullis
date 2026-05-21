"""KYC Screener -- stack runtime entry (Mastio-integrated).

Differs from `main.py` (standalone scaffold) in three ways:

1. The LLM call goes through `CullisClient.chat_completion()` -> Mastio's
   embedded LiteLLM gateway (ADR-017). Tool calls come back in OpenAI
   shape; we dispatch them through `client.call_mcp_tool()` which the
   Mastio MCP aggregator gates against `local_agent_resource_bindings`.
2. The audit chain is the production Mastio one: every tool call + every
   chat completion is appended to the Mastio audit log automatically.
   No local AuditChain.
3. The capability gate is the production Mastio PDP + binding row. No
   local CapabilityGate. The system_prompt's hard rules + outcome-level
   checks here are the LLM-side discipline layer; the binding gate is
   the OS-level discipline layer.

Required env / runtime arguments:
- ``CULLIS_MASTIO_URL`` (default ``https://mastio-a-nginx:9443`` for the
  stack; ``https://localhost:9443`` from the host).
- ``--identity-dir``: directory containing ``agent.pem``, ``agent-key.pem``,
  ``dpop.jwk``. The stack bootstrap parks these under
  ``/state/orga/agents/kyc-screener/``; for host use, run the
  ``stack/extract-agent-certs.sh`` helper.

Live LLM call requires the Mastio container to have
``MCP_PROXY_ANTHROPIC_API_KEY`` set in ``stack/docker-compose.yml`` (it is
empty by default; set via the operator's ``.env`` overlay).
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

DEFAULT_MODEL = "anthropic/claude-haiku-4-5-20251001"
DEFAULT_MASTIO_URL = "https://mastio-a-nginx:9443"
MAX_LOOP_ITERATIONS = 8

_THIS_DIR = Path(__file__).resolve().parent
SYSTEM_PROMPT_PATH = _THIS_DIR / "system_prompt.md"


@dataclass(frozen=True)
class KYCStackDecision:
    case_id: str
    document_hash: str
    score: int
    outcome: str
    reasoning_summary: str
    cullis_trace_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "document_hash": self.document_hash,
            "score": self.score,
            "outcome": self.outcome,
            "reasoning_summary": self.reasoning_summary,
            "cullis_trace_ids": self.cullis_trace_ids,
        }


def _resolve_tools(client: Any) -> list[dict[str, Any]]:
    """Pull the OpenAI-style tool definitions from the Mastio MCP
    aggregator, filtered to the 4 tools this agent is bound to."""

    raw = client.list_mcp_tools()
    wanted = {
        "verify_identity",
        "screen_sanctions",
        "query_beneficial_owners",
        "escalate_to_compliance",
    }
    tools = []
    for t in raw:
        if t.get("name") not in wanted:
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
            "Mastio MCP aggregator returned no KYC tools for this principal. "
            "Verify the binding via /v1/admin/agents/<agent_id> and the SEED_MCP "
            "entries in stack/docker-compose.yml on mastio-a-init."
        )
    return tools


def _invoke_tool(client: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Call the tool through the Mastio aggregator. Returns the unwrapped
    JSON payload that the MCP server emitted in its ``content[0].text``
    field. Raises on JSON-RPC errors."""

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
    case_id: str,
    document_id: str,
    mastio_url: str,
    identity_dir: Path,
    model: str = DEFAULT_MODEL,
    ca_chain_path: Path | None = None,
    verify_tls: bool = True,
) -> KYCStackDecision:
    """Drive one KYC case through the full Mastio stack.

    The Mastio gates + audits every tool call; the agent loop only
    holds the conversation state and parses the final decision JSON.
    """

    try:
        from cullis_sdk.client import CullisClient
    except ImportError as exc:
        raise RuntimeError(
            "cullis_sdk not importable. Run from the repo root with the venv "
            "activated, or pip install -e ./cullis_sdk."
        ) from exc

    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=identity_dir / "agent.pem",
        key_path=identity_dir / "agent-key.pem",
        dpop_key_path=identity_dir / "dpop.jwk",
        agent_id="orga::kyc-screener",
        org_id="orga",
        verify_tls=verify_tls,
        ca_chain_path=ca_chain_path,
    )

    tools = _resolve_tools(client)
    system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Process KYC case {case_id} for document {document_id}. "
                "Return the final JSON decision when ready."
            ),
        },
    ]
    trace_ids: list[str] = []

    for iteration in range(MAX_LOOP_ITERATIONS):
        response = client.chat_completion(
            {"model": model, "messages": messages, "tools": tools}
        )
        trace_id = response.get("cullis_trace_id")
        if trace_id:
            trace_ids.append(trace_id)

        choice = (response.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            # Final answer.
            return _parse_decision(msg.get("content", ""), case_id=case_id, trace_ids=trace_ids)

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
        f"KYC agent exceeded {MAX_LOOP_ITERATIONS} iterations without finalizing"
    )


def _parse_decision(content: str, *, case_id: str, trace_ids: list[str]) -> KYCStackDecision:
    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", content, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise ValueError(f"KYC stack agent did not produce JSON: {content!r}")
    data = json.loads(match.group(0))
    required = {"case_id", "document_hash", "score", "outcome", "reasoning_summary"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"KYC stack agent JSON missing fields: {sorted(missing)}")
    if data["case_id"] != case_id:
        raise ValueError(f"case_id mismatch: expected {case_id!r}, got {data['case_id']!r}")
    if data["outcome"] not in {"auto_approve", "escalate"}:
        raise ValueError(f"invalid outcome: {data['outcome']!r}")
    return KYCStackDecision(
        case_id=data["case_id"],
        document_hash=data["document_hash"],
        score=int(data["score"]),
        outcome=data["outcome"],
        reasoning_summary=str(data["reasoning_summary"]),
        cullis_trace_ids=trace_ids,
    )


def main() -> int:  # pragma: no cover - CLI entrypoint
    parser = argparse.ArgumentParser(description="KYC Screener stack runtime")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--document-id", required=True)
    parser.add_argument(
        "--mastio-url",
        default=os.environ.get("CULLIS_MASTIO_URL", DEFAULT_MASTIO_URL),
    )
    parser.add_argument(
        "--identity-dir",
        type=Path,
        default=Path(
            os.environ.get("CULLIS_IDENTITY_DIR", "./.data/agents-demo/kyc-screener")
        ),
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ca-chain", type=Path, default=None)
    parser.add_argument("--no-verify-tls", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    decision = run(
        case_id=args.case_id,
        document_id=args.document_id,
        mastio_url=args.mastio_url,
        identity_dir=args.identity_dir,
        model=args.model,
        ca_chain_path=args.ca_chain,
        verify_tls=not args.no_verify_tls,
    )
    print(json.dumps(decision.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
