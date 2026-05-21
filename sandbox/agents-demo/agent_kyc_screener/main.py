"""KYC Screener -- agent entry point.

Stack:
    Claude Sonnet 4.6 (live) or deterministic mock LLM (CI/offline).
    Routed through the Mastio embedded LiteLLM gateway (ADR-017) in live mode.

Cullis primitives demonstrated:
    - per-agent identity     -> the `Principal` invoking the agent must
                                  hold `kyc.read` to start, `kyc.submit` to
                                  finalize, `kyc.escalate` to escalate, and
                                  `kyc.auto_approve` for the no-human path.
    - capability gate        -> fail-closed YAML-driven evaluator runs *before*
                                  every tool dispatch; denials are audited.
    - hash-chained audit log -> every LLM turn, every tool call, every
                                  capability check and the final decision are
                                  appended to an append-only signed chain
                                  (Art. 12 EU AI Act).
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

DEFAULT_MODEL = "claude-sonnet-4-6"
CAPABILITIES_PATH = _THIS_DIR / "capabilities.yaml"
SYSTEM_PROMPT_PATH = _THIS_DIR / "system_prompt.md"
MAX_LOOP_ITERATIONS = 8

# Decision JSON shape -----------------------------------------------------------


@dataclass(frozen=True)
class KYCDecision:
    case_id: str
    document_hash: str
    score: int
    outcome: str  # "auto_approve" | "escalate"
    reasoning_summary: str
    audit_entries: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "document_hash": self.document_hash,
            "score": self.score,
            "outcome": self.outcome,
            "reasoning_summary": self.reasoning_summary,
            "audit_entries": self.audit_entries,
        }


# Public agent entry point ------------------------------------------------------


def run(
    *,
    case_id: str,
    document_id: str,
    principal: Principal,
    llm: LLMClient | None = None,
    audit: AuditChain | None = None,
) -> tuple[KYCDecision, AuditChain]:
    """Run one KYC case through the agent. Returns the decision + audit chain.

    Raises `CapabilityDenied` if the invoking `principal` lacks `kyc.read`
    (the floor capability required even to start). Lower-level denials
    inside the loop are surfaced as structured tool results so the LLM can
    self-correct and escalate.
    """

    audit = audit or AuditChain(
        agent_id="kyc_screener", org_id=principal.org_id
    )
    gate = CapabilityGate.from_yaml(CAPABILITIES_PATH, audit=audit)
    llm = llm or default_client(default_model=DEFAULT_MODEL)

    audit.append(
        "agent_invoked",
        {
            "agent": "kyc_screener",
            "case_id": case_id,
            "document_id": document_id,
            "principal_id": principal.principal_id,
            "principal_type": principal.principal_type,
            "model": DEFAULT_MODEL,
        },
    )
    gate.require(principal, capability="kyc.read", context={"case_id": case_id})

    system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Process KYC case {case_id} for document {document_id}. "
                f"Return the final JSON decision when ready."
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

        # OpenAI-style assistant message embedding the tool calls.
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
            f"KYC agent exceeded {MAX_LOOP_ITERATIONS} iterations without finalizing"
        )

    if final_content is None:
        raise RuntimeError("KYC agent produced no final content")

    decision = _parse_decision(final_content, case_id=case_id)
    _enforce_outcome_capabilities(decision, principal=principal, gate=gate)
    audit.append("decision", decision.to_dict() | {"audit_entries": "n/a"})

    final = KYCDecision(
        case_id=decision.case_id,
        document_hash=decision.document_hash,
        score=decision.score,
        outcome=decision.outcome,
        reasoning_summary=decision.reasoning_summary,
        audit_entries=len(audit.entries),
    )
    return final, audit


# Decision parsing + outcome-level capability enforcement -----------------------


def _parse_decision(content: str, *, case_id: str) -> KYCDecision:
    """Parse the final assistant message as KYC decision JSON.

    Tolerant to common LLM cosmetics (leading/trailing fences, prose around
    the JSON object). Fails closed if the JSON is missing required fields.
    """

    # Strip ``` fences if present.
    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", content, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    # Find the first {...} balanced block.
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise ValueError(f"KYC agent final content did not contain JSON: {content!r}")
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError(f"KYC agent final JSON could not be parsed: {exc}") from exc

    required = {"case_id", "document_hash", "score", "outcome", "reasoning_summary"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"KYC agent final JSON missing fields: {sorted(missing)}")
    outcome = data["outcome"]
    if outcome not in {"auto_approve", "escalate"}:
        raise ValueError(f"KYC agent returned invalid outcome: {outcome!r}")
    if data["case_id"] != case_id:
        raise ValueError(
            f"KYC agent decision case_id mismatch: expected {case_id!r}, got {data['case_id']!r}"
        )
    return KYCDecision(
        case_id=data["case_id"],
        document_hash=data["document_hash"],
        score=int(data["score"]),
        outcome=outcome,
        reasoning_summary=str(data["reasoning_summary"]),
        audit_entries=0,
    )


def _enforce_outcome_capabilities(
    decision: KYCDecision,
    *,
    principal: Principal,
    gate: CapabilityGate,
) -> None:
    """Re-check the capability gate at decision time.

    `kyc.submit` is required to finalize any decision. `kyc.auto_approve`
    is required only when the agent wants to auto-approve, and additionally
    the gate refuses to honor `auto_approve` when `score >= threshold`.
    """

    gate.require(
        principal,
        capability="kyc.submit",
        context={"case_id": decision.case_id, "outcome": decision.outcome},
    )
    if decision.outcome == "auto_approve":
        gate.require(
            principal,
            capability="kyc.auto_approve",
            context={"score": decision.score},
        )
        # Fine-grained threshold enforced here (the YAML declares it but the
        # generic gate does not know "score < N" semantics).
        threshold = (
            gate._definitions.get("capabilities", {})  # noqa: SLF001 -- demo
            .get("kyc.auto_approve", {})
            .get("fine_grained", {})
            .get("score_threshold", 30)
        )
        if decision.score >= threshold:
            raise CapabilityDenied(
                "kyc.auto_approve",
                principal.principal_id,
                f"score_above_threshold:{decision.score}>={threshold}",
            )
    else:
        # escalate -- needs kyc.escalate too (the tool itself enforces this,
        # but the agent might have skipped calling escalate_to_compliance and
        # gone straight to a final JSON. Re-check here.)
        gate.require(
            principal,
            capability="kyc.escalate",
            context={"case_id": decision.case_id},
        )


# CLI demo entry point ---------------------------------------------------------


def _demo() -> None:  # pragma: no cover - manual CLI usage
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    principal = Principal(
        principal_id="alice@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset(
            {"kyc.read", "kyc.submit", "kyc.auto_approve", "kyc.escalate"}
        ),
    )
    decision, audit = run(
        case_id="case_demo_001",
        document_id="doc_low_risk_retail",
        principal=principal,
    )
    print(json.dumps(decision.to_dict(), indent=2))
    print(f"audit chain: {len(audit.entries)} entries, verified={audit.verify()}")


if __name__ == "__main__":  # pragma: no cover
    _demo()
