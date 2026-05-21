"""Pitchbook Builder -- stack runtime entry (Mastio-integrated).

Chinese Wall enforcement: the desk scope is passed on the command line.
The agent passes it in the system prompt; the LLM is responsible for
NOT citing memos tagged with a different desk. The MCP server returns
memo.desk verbatim, so the Information Barrier is auditable post-hoc
via the Mastio audit chain (every read_internal_research tool call is
recorded with its arguments + result).

Required env / runtime arguments same as main_stack.py for KYC. The
principal's desk scope is supplied via ``--desk`` (the production
Mastio reads it from the user's session claim).
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
MAX_LOOP_ITERATIONS = 12

_THIS_DIR = Path(__file__).resolve().parent
SYSTEM_PROMPT_PATH = _THIS_DIR / "system_prompt.md"


@dataclass(frozen=True)
class PitchbookStackOutput:
    target: str
    desk: str
    comps_artifact_id: str
    deck_artifact_id: str
    sources_cited: list[dict[str, Any]]
    brief_summary: str
    mnpi_cited: bool
    cullis_trace_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "desk": self.desk,
            "comps_artifact_id": self.comps_artifact_id,
            "deck_artifact_id": self.deck_artifact_id,
            "sources_cited": self.sources_cited,
            "brief_summary": self.brief_summary,
            "mnpi_cited": self.mnpi_cited,
            "cullis_trace_ids": self.cullis_trace_ids,
        }


_WANTED_TOOLS = {
    "query_comps_db",
    "read_internal_research",
    "news_feed_query",
    "generate_excel",
    "generate_pptx",
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
            "Mastio MCP aggregator returned no Pitchbook tools for this principal. "
            "Verify the binding + SEED_MCP_6..10 entries in stack/docker-compose.yml."
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
    target: str,
    desk: str,
    mastio_url: str,
    identity_dir: Path,
    model: str = DEFAULT_MODEL,
    ca_chain_path: Path | None = None,
    verify_tls: bool = True,
) -> PitchbookStackOutput:
    try:
        from cullis_sdk.client import CullisClient
    except ImportError as exc:
        raise RuntimeError("cullis_sdk not importable") from exc

    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=identity_dir / "agent.pem",
        key_path=identity_dir / "agent-key.pem",
        dpop_key_path=identity_dir / "dpop.jwk",
        agent_id="orga::pitchbook-builder",
        org_id="orga",
        verify_tls=verify_tls,
        ca_chain_path=ca_chain_path,
    )
    client._cert_pem = (identity_dir / "agent.pem").read_text()
    client._signing_key_pem = (identity_dir / "agent-key.pem").read_text()
    client.login_via_proxy_with_local_key()

    # Workaround for chat_completion DPoP pinning bug (see memo
    # feedback_chat_completion_dpop_pinning_bug).
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
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Draft a pitchbook for target '{target}'. Your desk scope is "
                f"'{desk}'. You MUST refuse to cite any memo whose desk field "
                "does not match your desk scope. Return the final JSON when ready."
            ),
        },
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
            parsed = _parse_output(
                msg.get("content", ""), target=target, desk=desk
            )
            return PitchbookStackOutput(
                target=parsed["target"],
                desk=parsed["desk"],
                comps_artifact_id=parsed["comps_artifact_id"],
                deck_artifact_id=parsed["deck_artifact_id"],
                sources_cited=parsed["sources_cited"],
                brief_summary=parsed["brief_summary"],
                mnpi_cited=any(
                    s.get("type") == "internal_memo" and s.get("mnpi")
                    for s in parsed["sources_cited"]
                ),
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
        f"Pitchbook agent exceeded {MAX_LOOP_ITERATIONS} iterations without finalizing"
    )


def _parse_output(content: str, *, target: str, desk: str) -> dict[str, Any]:
    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", content, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise ValueError(f"Pitchbook final content did not contain JSON: {content!r}")
    data = json.loads(match.group(0))
    required = {"target", "desk", "comps_artifact_id", "deck_artifact_id", "sources_cited", "brief_summary"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"Pitchbook final JSON missing fields: {sorted(missing)}")
    if data["target"] != target:
        raise ValueError(f"target mismatch: expected {target!r}, got {data['target']!r}")
    if data["desk"] != desk:
        raise ValueError(f"desk mismatch: expected {desk!r}, got {data['desk']!r}")
    return data


def main() -> int:  # pragma: no cover - CLI entrypoint
    parser = argparse.ArgumentParser(description="Pitchbook Builder stack runtime")
    parser.add_argument("--target", required=True)
    parser.add_argument("--desk", required=True, choices=["tech", "industrials"])
    parser.add_argument(
        "--mastio-url",
        default=os.environ.get("CULLIS_MASTIO_URL", DEFAULT_MASTIO_URL),
    )
    parser.add_argument(
        "--identity-dir",
        type=Path,
        default=Path(
            os.environ.get("CULLIS_IDENTITY_DIR", "./.data/agents-demo/pitchbook-builder")
        ),
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ca-chain", type=Path, default=None)
    parser.add_argument("--no-verify-tls", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    out = run(
        target=args.target,
        desk=args.desk,
        mastio_url=args.mastio_url,
        identity_dir=args.identity_dir,
        model=args.model,
        ca_chain_path=args.ca_chain,
        verify_tls=not args.no_verify_tls,
    )
    print(json.dumps(out.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
