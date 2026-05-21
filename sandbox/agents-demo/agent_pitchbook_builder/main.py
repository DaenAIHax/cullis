"""Pitchbook Builder -- agent entry point.

Stack:
    Claude Opus 4.7 (live) or deterministic mock LLM (CI/offline).
    Routed through the Mastio embedded LiteLLM gateway (ADR-017).

Cullis primitives demonstrated:
    - per-agent + per-user identity -> the `Principal` carries a `desk`
                                          scope that the agent inherits.
    - capability gate (fine-grained) -> `pitchbook.read_research` requires
                                          `desk` to match the memo's `desk`.
    - hash-chained audit log         -> every read, every Chinese Wall
                                          denial, every artefact emission,
                                          every MNPI citation are recorded.

Quadrant: U2A + A2A intra-org (ADR-020). The "A2A" arises implicitly --
two Pitchbook Builder agents invoked by users on different desks share
the same agent definition but get distinct desk scopes, and they cannot
read each other's research even though they share the same `agent_id`
class. This is the cross-desk segregation pattern.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
_SANDBOX_DIR = _THIS_DIR.parent
if str(_SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(_SANDBOX_DIR))

from shared.audit_hooks import AuditChain  # noqa: E402
from shared.capability_gate import (  # noqa: E402
    CapabilityDenied,
    CapabilityGate,
    Principal,
)
from shared.llm_client import LLMClient, default_client  # noqa: E402

from .tools import HANDLERS, TOOL_SCHEMAS, dispatch  # noqa: E402

_log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-4-7"
CAPABILITIES_PATH = _THIS_DIR / "capabilities.yaml"
SYSTEM_PROMPT_PATH = _THIS_DIR / "system_prompt.md"
MAX_LOOP_ITERATIONS = 12


@dataclass(frozen=True)
class PitchbookOutput:
    target: str
    desk: str
    comps_artifact_id: str
    deck_artifact_id: str
    sources_cited: list[dict[str, Any]]
    brief_summary: str
    mnpi_cited: bool
    audit_entries: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "desk": self.desk,
            "comps_artifact_id": self.comps_artifact_id,
            "deck_artifact_id": self.deck_artifact_id,
            "sources_cited": self.sources_cited,
            "brief_summary": self.brief_summary,
            "mnpi_cited": self.mnpi_cited,
            "audit_entries": self.audit_entries,
        }


def run(
    *,
    target: str,
    principal: Principal,
    llm: LLMClient | None = None,
    audit: AuditChain | None = None,
) -> tuple[PitchbookOutput, AuditChain]:
    """Run one pitchbook draft. Returns the structured output + audit chain.

    Raises `CapabilityDenied` if the invoking `principal` lacks
    `pitchbook.draft` (floor) or if the agent's final brief claims to
    cite a memo the principal could not have read. Lower-level Chinese
    Wall denials inside the loop are surfaced as structured tool results,
    audited, and the LLM should respond by NOT citing the blocked memo.
    """

    if "desk" not in principal.scopes:
        raise ValueError(
            "Pitchbook Builder requires the principal to carry a `desk` scope. "
            "Got scopes=" + repr(principal.scopes)
        )

    audit = audit or AuditChain(
        agent_id="pitchbook_builder", org_id=principal.org_id
    )
    gate = CapabilityGate.from_yaml(CAPABILITIES_PATH, audit=audit)
    llm = llm or default_client(default_model=DEFAULT_MODEL)

    audit.append(
        "agent_invoked",
        {
            "agent": "pitchbook_builder",
            "target": target,
            "principal_id": principal.principal_id,
            "principal_type": principal.principal_type,
            "desk": principal.scopes.get("desk"),
            "model": DEFAULT_MODEL,
        },
    )
    gate.require(principal, capability="pitchbook.draft", context={"target": target})

    system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Draft a pitchbook for target '{target}'. Your desk scope is "
                f"'{principal.scopes['desk']}'. Return final JSON when ready."
            ),
        },
    ]

    final_content: str | None = None
    for iteration in range(MAX_LOOP_ITERATIONS):
        response = llm.complete(
            messages=messages,
            tools=TOOL_SCHEMAS,
            model=DEFAULT_MODEL,
        )
        audit.append(
            "llm_response",
            {
                "iteration": iteration,
                "model": response.model or DEFAULT_MODEL,
                "stop_reason": response.stop_reason,
                "wants_tool_call": response.wants_tool_call,
                "tool_calls": [
                    {"tool": tc.tool_name, "arguments": tc.arguments}
                    for tc in response.tool_calls
                ],
            },
        )

        if not response.wants_tool_call:
            final_content = response.content
            break

        messages.append(
            {
                "role": "assistant",
                "content": response.content or None,
                "tool_calls": [
                    {
                        "id": tc.call_id,
                        "type": "function",
                        "function": {
                            "name": tc.tool_name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in response.tool_calls
                ],
            }
        )
        for tc in response.tool_calls:
            result = dispatch(
                tc.tool_name,
                tc.arguments,
                principal=principal,
                gate=gate,
                audit=audit,
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.call_id,
                    "content": json.dumps(result),
                }
            )
    else:
        raise RuntimeError(
            f"Pitchbook agent exceeded {MAX_LOOP_ITERATIONS} iterations without finalizing"
        )

    if final_content is None:
        raise RuntimeError("Pitchbook agent produced no final content")

    parsed = _parse_output(final_content, target=target, desk=principal.scopes["desk"])
    _verify_sources_against_audit(parsed, audit=audit)
    audit.append("decision", parsed | {"audit_entries": "n/a"})

    mnpi_cited = any(
        src.get("type") == "internal_memo" and src.get("mnpi") for src in parsed["sources_cited"]
    )
    final = PitchbookOutput(
        target=parsed["target"],
        desk=parsed["desk"],
        comps_artifact_id=parsed["comps_artifact_id"],
        deck_artifact_id=parsed["deck_artifact_id"],
        sources_cited=parsed["sources_cited"],
        brief_summary=parsed["brief_summary"],
        mnpi_cited=mnpi_cited,
        audit_entries=len(audit.entries),
    )
    return final, audit


def _parse_output(content: str, *, target: str, desk: str) -> dict[str, Any]:
    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", content, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise ValueError(f"Pitchbook final content did not contain JSON: {content!r}")
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Pitchbook final JSON could not be parsed: {exc}") from exc

    required = {
        "target",
        "desk",
        "comps_artifact_id",
        "deck_artifact_id",
        "sources_cited",
        "brief_summary",
    }
    missing = required - data.keys()
    if missing:
        raise ValueError(f"Pitchbook final JSON missing fields: {sorted(missing)}")
    if data["target"] != target:
        raise ValueError(f"Pitchbook target mismatch: expected {target!r}, got {data['target']!r}")
    if data["desk"] != desk:
        raise ValueError(f"Pitchbook desk mismatch: expected {desk!r}, got {data['desk']!r}")
    if not isinstance(data["sources_cited"], list):
        raise ValueError("Pitchbook sources_cited must be a list")
    return data


def _verify_sources_against_audit(parsed: dict[str, Any], *, audit: AuditChain) -> None:
    """Cross-check: every `internal_memo` source cited in the final output
    must have a matching successful `read_internal_research` tool_result in
    the audit chain. This catches an LLM that hallucinates a memo cite,
    AND it catches an LLM that ignored a Chinese Wall denial and cited
    blocked content anyway."""

    successful_reads: set[str] = set()
    for entry in audit.entries:
        if entry.event_type != "tool_result":
            continue
        if entry.payload.get("tool") != "read_internal_research":
            continue
        result = entry.payload.get("result") or {}
        if result.get("ok") and "memo_id" in result:
            successful_reads.add(result["memo_id"])
    for src in parsed["sources_cited"]:
        if src.get("type") != "internal_memo":
            continue
        memo_id = src.get("memo_id")
        if memo_id and memo_id not in successful_reads:
            raise ValueError(
                f"Pitchbook cited memo {memo_id!r} but the audit chain has no "
                "successful read for it (hallucination or Chinese Wall violation)"
            )


def _demo() -> None:  # pragma: no cover - manual CLI usage
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    principal = Principal(
        principal_id="carol_industrials@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset(
            {
                "pitchbook.draft",
                "pitchbook.read_comps",
                "pitchbook.read_research",
                "pitchbook.read_news",
                "pitchbook.generate_artifact",
            }
        ),
        scopes={"desk": "industrials"},
    )
    out, audit = run(target="IndustrialDemoA", principal=principal)
    print(json.dumps(out.to_dict(), indent=2))
    print(f"audit chain: {len(audit.entries)} entries, verified={audit.verify()}")


if __name__ == "__main__":  # pragma: no cover
    _demo()
