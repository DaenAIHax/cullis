"""End-to-end tests for the KYC Screener reference demo agent.

These tests drive the agent loop with a deterministic `MockLLMClient` so the
test suite passes without an Anthropic API key or network access. The four
scenarios cover, in this order:

1. Low-risk retail customer -- auto-approved with score < threshold.
2. Sanctions hit -- escalated regardless of score.
3. High-risk PEP -- score above threshold forces escalation.
4. Capability gate bypass attempt -- principal missing `kyc.auto_approve`
   tries to auto-approve a low-score case, gate raises `CapabilityDenied`.

Production note: the same agent code runs in `live` mode with no test
changes by exporting `CULLIS_AGENT_DEMO_MODE=live` and providing
`ANTHROPIC_API_KEY`. The mock here only substitutes the LLM round-trip;
the audit chain, capability gate and tool dispatch are unchanged.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_THIS_DIR = Path(__file__).resolve().parent
_SANDBOX_DIR = _THIS_DIR.parent
if str(_SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(_SANDBOX_DIR))

from agent_kyc_screener.main import run  # noqa: E402
from agent_kyc_screener.tools import _document_hash  # noqa: E402
from shared.capability_gate import CapabilityDenied, Principal  # noqa: E402
from shared.llm_client import LLMResponse, MockLLMClient, make_tool_call  # noqa: E402


# Fixtures ---------------------------------------------------------------------


@pytest.fixture
def full_capabilities_principal() -> Principal:
    return Principal(
        principal_id="alice@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset(
            {"kyc.read", "kyc.submit", "kyc.auto_approve", "kyc.escalate"}
        ),
    )


@pytest.fixture
def no_auto_approve_principal() -> Principal:
    """Principal that can read and submit + escalate but NOT auto-approve.

    Mirrors the production binding for a junior compliance analyst whose
    role only allows review-and-escalate; the gate must block the
    auto-approve path even if the agent's reasoning says the score is low.
    """

    return Principal(
        principal_id="bob_junior@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset({"kyc.read", "kyc.submit", "kyc.escalate"}),
    )


# Helpers ----------------------------------------------------------------------


def _final_json(*, case_id: str, document_id: str, score: int, outcome: str, summary: str) -> str:
    return json.dumps(
        {
            "case_id": case_id,
            "document_hash": _document_hash(document_id),
            "score": score,
            "outcome": outcome,
            "reasoning_summary": summary,
        }
    )


# Scenarios --------------------------------------------------------------------


def test_low_risk_retail_auto_approved(full_capabilities_principal: Principal) -> None:
    """Mario Rossi, IT passport, image_quality 0.94, no sanctions, no PEP.
    Score 0. Auto-approved end-to-end without human in the loop."""

    case_id = "case_low_001"
    doc_id = "doc_low_risk_retail"
    script = [
        LLMResponse(
            content="",
            tool_calls=(make_tool_call("verify_identity", {"document_id": doc_id}),),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "screen_sanctions",
                    {"family_name": "Rossi", "given_name": "Mario", "dob": "1985-04-12"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                case_id=case_id,
                document_id=doc_id,
                score=0,
                outcome="auto_approve",
                summary=(
                    "Identity verified (image_quality 0.94 > 0.85), no sanctions hit, "
                    "no PEP hit, retail document. Score 0 < 30 threshold."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    decision, audit = run(
        case_id=case_id,
        document_id=doc_id,
        principal=full_capabilities_principal,
        llm=MockLLMClient(script=script),
    )

    assert decision.outcome == "auto_approve"
    assert decision.score == 0
    assert decision.document_hash == _document_hash(doc_id)
    assert audit.verify()
    # Audit chain contains: agent_invoked + capability_granted(kyc.read) + 3 llm_responses
    # + 2 tool_call + 2 tool_result + 4 capability_granted (1x kyc.read floor,
    # 1x kyc.read tool, 1x kyc.read tool, 1x kyc.submit, 1x kyc.auto_approve)
    # + decision. We assert at least the high-level shape rather than the
    # exact count so future audit refinements do not brittle-break the test.
    events = [e.event_type for e in audit.entries]
    assert events.count("tool_call") == 2
    assert events.count("tool_result") == 2
    assert "decision" in events
    assert "agent_invoked" in events
    # kyc.submit + kyc.auto_approve were both granted at decision time.
    granted_caps = {
        e.payload["capability"]
        for e in audit.entries
        if e.event_type == "capability_granted"
    }
    assert "kyc.submit" in granted_caps
    assert "kyc.auto_approve" in granted_caps


def test_sanctions_hit_forces_escalation(full_capabilities_principal: Principal) -> None:
    """Synthetic-Sanctions-Test Petrov, RU passport, exact match on the
    mock OFAC-SDN-DEMO list. Agent must escalate regardless of score."""

    case_id = "case_sanctions_001"
    doc_id = "doc_sanctions_hit"
    script = [
        LLMResponse(
            content="",
            tool_calls=(make_tool_call("verify_identity", {"document_id": doc_id}),),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "screen_sanctions",
                    {
                        "family_name": "Petrov",
                        "given_name": "Synthetic-Sanctions-Test",
                        "dob": "1970-01-01",
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "escalate_to_compliance",
                    {
                        "case_id": case_id,
                        "reason": "sanctions_hit:OFAC-SDN-DEMO",
                        "score": 100,
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                case_id=case_id,
                document_id=doc_id,
                score=100,
                outcome="escalate",
                summary=(
                    "Identity verified but OFAC-SDN-DEMO list hit on (Petrov, "
                    "1970-01-01). Sanctions hit forces escalation per rule 5; "
                    "score capped at 100."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    decision, audit = run(
        case_id=case_id,
        document_id=doc_id,
        principal=full_capabilities_principal,
        llm=MockLLMClient(script=script),
    )

    assert decision.outcome == "escalate"
    assert decision.score == 100
    assert audit.verify()
    events = [e.event_type for e in audit.entries]
    # Escalation tool was invoked, AND the gate granted kyc.escalate at
    # both the tool layer and the outcome-finalization layer.
    tool_calls = [
        e.payload["tool"] for e in audit.entries if e.event_type == "tool_call"
    ]
    assert "escalate_to_compliance" in tool_calls
    # The PR will see this as the auditable evidence chain Art. 12 requires.
    granted_escalate = sum(
        1
        for e in audit.entries
        if e.event_type == "capability_granted"
        and e.payload.get("capability") == "kyc.escalate"
    )
    assert granted_escalate >= 2  # 1x at tool dispatch, 1x at finalize


def test_high_risk_pep_forces_escalation(full_capabilities_principal: Principal) -> None:
    """Synthetic-PEP-Test Bianchi, matches mock PEP list. Sanctions clean.
    Score above threshold forces escalation; agent must NOT auto-approve."""

    case_id = "case_pep_001"
    doc_id = "doc_high_risk_pep"
    script = [
        LLMResponse(
            content="",
            tool_calls=(make_tool_call("verify_identity", {"document_id": doc_id}),),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "screen_sanctions",
                    {
                        "family_name": "Bianchi",
                        "given_name": "Synthetic-PEP-Test",
                        "dob": "1962-07-21",
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "escalate_to_compliance",
                    {"case_id": case_id, "reason": "pep_hit", "score": 50},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                case_id=case_id,
                document_id=doc_id,
                score=50,
                outcome="escalate",
                summary=(
                    "Identity verified, sanctions clean, but PEP list hit on "
                    "(Bianchi, 1962-07-21). Score 50 >= 30 threshold; escalation "
                    "mandatory."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    decision, audit = run(
        case_id=case_id,
        document_id=doc_id,
        principal=full_capabilities_principal,
        llm=MockLLMClient(script=script),
    )

    assert decision.outcome == "escalate"
    assert decision.score >= 30
    assert audit.verify()


def test_capability_gate_bypass_blocks_auto_approve(
    no_auto_approve_principal: Principal,
) -> None:
    """A principal without `kyc.auto_approve` tries to auto-approve a clean
    low-risk case. The agent loop completes (the LLM doesn't know the
    principal's binding), but the outcome-finalization gate denies the
    auto-approve and raises `CapabilityDenied`. The audit chain records
    the denial."""

    case_id = "case_bypass_001"
    doc_id = "doc_low_risk_retail"
    script = [
        LLMResponse(
            content="",
            tool_calls=(make_tool_call("verify_identity", {"document_id": doc_id}),),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "screen_sanctions",
                    {"family_name": "Rossi", "given_name": "Mario", "dob": "1985-04-12"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                case_id=case_id,
                document_id=doc_id,
                score=0,
                outcome="auto_approve",
                summary="Clean -- attempt to auto-approve",
            ),
            stop_reason="stop",
        ),
    ]
    with pytest.raises(CapabilityDenied) as exc_info:
        run(
            case_id=case_id,
            document_id=doc_id,
            principal=no_auto_approve_principal,
            llm=MockLLMClient(script=script),
        )
    assert exc_info.value.capability == "kyc.auto_approve"
    assert exc_info.value.principal_id == "bob_junior@bank-it-01"
