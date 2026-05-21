"""End-to-end tests for the DORA Vendor/TPA Compliance Reporter.

Three scenarios cover the cross-org A2A pattern:

1. **Single-org draft only**: a compliance analyst with `dora.read` +
   `dora.draft_report` but no `cross_org_submit` capability runs the
   reporting cycle without naming a target auditor. The agent lists
   vendors, queries assessments, drafts entries. No `submit_to_auditor_org`
   tool call is made. Audit chain has no `cross_org_evidence` entries.

2. **Cross-org submission happy path**: a compliance officer with the
   `compliance_officer` role + auditor org enrolled in the Cullis Court
   federation runs the full cycle. Each CRITICAL entry is submitted to
   the auditor; the dual-write (outbound + inbound_ack) appears in the
   audit chain.

3. **Capability gate denial (missing role)**: a principal holds the
   `dora.cross_org_submit` capability but NOT the `compliance_officer`
   role. The gate denies inline; the LLM observes the structured denial
   and emits `submission_status: skipped:not_authorized` in the final
   report. The audit chain records the `capability_denied` event with
   `reason: missing_role:compliance_officer`.
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

from agent_dora_reporter.main import run  # noqa: E402
from agent_dora_reporter.tools import _entry_hash  # noqa: E402
from shared.capability_gate import Principal  # noqa: E402
from shared.llm_client import LLMResponse, MockLLMClient, make_tool_call  # noqa: E402
from shared.test_fixtures import (  # noqa: E402
    VENDOR_ASSESSMENTS,
    VENDOR_REGISTRY,
)


# Fixtures ---------------------------------------------------------------------


@pytest.fixture
def analyst_principal() -> Principal:
    """Compliance analyst -- read + draft, NO cross-org submit, NO role."""

    return Principal(
        principal_id="frank_analyst@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset({"dora.read", "dora.draft_report"}),
    )


@pytest.fixture
def officer_principal() -> Principal:
    """Compliance officer -- full capabilities + role."""

    return Principal(
        principal_id="elena_compliance@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset(
            {"dora.read", "dora.draft_report", "dora.cross_org_submit"}
        ),
        roles=frozenset({"compliance_officer"}),
    )


@pytest.fixture
def no_role_principal() -> Principal:
    """Holds the cross_org_submit capability but is NOT a compliance officer.
    Gate must deny on role check; capability alone is insufficient."""

    return Principal(
        principal_id="gina_seconded@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset(
            {"dora.read", "dora.draft_report", "dora.cross_org_submit"}
        ),
        roles=frozenset(),  # no compliance_officer
    )


# Helpers ----------------------------------------------------------------------


def _entry_hash_for_vendor(vendor_id: str, principal: Principal) -> str:
    """Reconstruct the canonical entry_hash the draft tool would produce
    so we can assert against it from the test fixtures."""

    assessment = VENDOR_ASSESSMENTS[vendor_id]
    criticality = next(v["criticality"] for v in VENDOR_REGISTRY if v["vendor_id"] == vendor_id)
    entry = {
        "schema": "DORA_Art28_Register_v1",
        "vendor_id": vendor_id,
        "criticality": criticality,
        "rto_minutes": assessment["rto_minutes"],
        "exit_strategy_documented": assessment["exit_strategy_documented"],
        "drafted_by_principal": principal.principal_id,
        "drafted_by_org": principal.org_id,
    }
    return _entry_hash(entry)


def _final_json(*, report_id: str, vendors_drafted: list[dict], summary: str) -> str:
    return json.dumps(
        {"report_id": report_id, "vendors_drafted": vendors_drafted, "summary": summary}
    )


# Scenarios --------------------------------------------------------------------


def test_single_org_draft_only(analyst_principal: Principal) -> None:
    """Analyst drafts CRITICAL + IMPORTANT entries; no auditor target;
    no cross-org submission attempted."""

    report_id = "dora_test_001"
    vendor_id = "vendor_cloud_demo"
    expected_hash = _entry_hash_for_vendor(vendor_id, analyst_principal)
    script = [
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call("list_third_party_vendors", {"criticality_filter": "CRITICAL"}),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call("query_vendor_assessment", {"vendor_id": vendor_id}),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "draft_dora_register_entry",
                    {
                        "vendor_id": vendor_id,
                        "criticality": "CRITICAL",
                        "rto_minutes": 60,
                        "exit_strategy_documented": True,
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                report_id=report_id,
                vendors_drafted=[
                    {
                        "vendor_id": vendor_id,
                        "entry_hash": expected_hash,
                        "criticality": "CRITICAL",
                        "submitted_to": None,
                        "submission_status": "not_attempted",
                    }
                ],
                summary=(
                    "Drafted 1 CRITICAL vendor entry. No cross-org submission "
                    "requested by caller; report archived locally."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    report, audit = run(
        report_id=report_id,
        target_auditor_org_id=None,
        principal=analyst_principal,
        llm=MockLLMClient(script=script),
    )
    assert report.submissions_attempted == 0
    assert report.submissions_succeeded == 0
    # No cross_org_evidence entries in the chain.
    cross_org_events = [e for e in audit.entries if e.event_type == "cross_org_evidence"]
    assert cross_org_events == []
    # And no submit_to_auditor_org tool calls.
    tool_calls = [
        e.payload["tool"] for e in audit.entries if e.event_type == "tool_call"
    ]
    assert "submit_to_auditor_org" not in tool_calls
    assert audit.verify()


def test_cross_org_submission_happy_path(officer_principal: Principal) -> None:
    """Compliance officer + enrolled auditor -> full draft + submit cycle.
    Dual-write (outbound + inbound_ack) recorded in the audit chain."""

    report_id = "dora_test_002"
    vendor_id = "vendor_cloud_demo"
    auditor = "auditor_org_demo"
    expected_hash = _entry_hash_for_vendor(vendor_id, officer_principal)
    script = [
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call("list_third_party_vendors", {"criticality_filter": "CRITICAL"}),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call("query_vendor_assessment", {"vendor_id": vendor_id}),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "draft_dora_register_entry",
                    {
                        "vendor_id": vendor_id,
                        "criticality": "CRITICAL",
                        "rto_minutes": 60,
                        "exit_strategy_documented": True,
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "submit_to_auditor_org",
                    {
                        "entry_hash": expected_hash,
                        "vendor_id": vendor_id,
                        "auditor_org_id": auditor,
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                report_id=report_id,
                vendors_drafted=[
                    {
                        "vendor_id": vendor_id,
                        "entry_hash": expected_hash,
                        "criticality": "CRITICAL",
                        "submitted_to": auditor,
                        "submission_status": "submitted",
                    }
                ],
                summary=(
                    "Drafted and cross-submitted 1 CRITICAL vendor entry to "
                    f"{auditor} via Cullis Court federation. Dual-write confirmed."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    report, audit = run(
        report_id=report_id,
        target_auditor_org_id=auditor,
        principal=officer_principal,
        llm=MockLLMClient(script=script),
    )
    assert report.submissions_attempted == 1
    assert report.submissions_succeeded == 1
    # Dual-write evidence chain assertions.
    cross_org_events = [e for e in audit.entries if e.event_type == "cross_org_evidence"]
    assert len(cross_org_events) == 2
    directions = sorted(e.payload["direction"] for e in cross_org_events)
    assert directions == ["inbound_ack", "outbound"]
    # Both half-writes share the same transmission_id.
    transmission_ids = {e.payload["transmission_id"] for e in cross_org_events}
    assert len(transmission_ids) == 1
    # Gate must have granted dora.cross_org_submit explicitly.
    granted = [
        e
        for e in audit.entries
        if e.event_type == "capability_granted"
        and e.payload.get("capability") == "dora.cross_org_submit"
    ]
    assert len(granted) == 1
    assert audit.verify()


def test_capability_gate_denies_cross_org_submit_without_role(
    no_role_principal: Principal,
) -> None:
    """Principal has the capability but NOT the compliance_officer role.
    Gate denies inline; the LLM observes the denial via structured tool
    result and emits `submission_status: skipped:not_authorized`."""

    report_id = "dora_test_003"
    vendor_id = "vendor_cloud_demo"
    auditor = "auditor_org_demo"
    expected_hash = _entry_hash_for_vendor(vendor_id, no_role_principal)
    script = [
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call("list_third_party_vendors", {"criticality_filter": "CRITICAL"}),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call("query_vendor_assessment", {"vendor_id": vendor_id}),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "draft_dora_register_entry",
                    {
                        "vendor_id": vendor_id,
                        "criticality": "CRITICAL",
                        "rto_minutes": 60,
                        "exit_strategy_documented": True,
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "submit_to_auditor_org",
                    {
                        "entry_hash": expected_hash,
                        "vendor_id": vendor_id,
                        "auditor_org_id": auditor,
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                report_id=report_id,
                vendors_drafted=[
                    {
                        "vendor_id": vendor_id,
                        "entry_hash": expected_hash,
                        "criticality": "CRITICAL",
                        "submitted_to": None,
                        "submission_status": "skipped:not_authorized",
                    }
                ],
                summary=(
                    "Drafted 1 CRITICAL vendor entry but cross-submission "
                    f"to {auditor} was blocked: caller principal lacks the "
                    "compliance_officer role required by the capability gate."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    report, audit = run(
        report_id=report_id,
        target_auditor_org_id=auditor,
        principal=no_role_principal,
        llm=MockLLMClient(script=script),
    )
    assert report.submissions_attempted == 1
    assert report.submissions_succeeded == 0
    # The denial event MUST exist in the audit chain so the supervisor can
    # see WHY the cross-submit was blocked.
    denials = [
        e
        for e in audit.entries
        if e.event_type == "capability_denied"
        and e.payload.get("capability") == "dora.cross_org_submit"
    ]
    assert len(denials) == 1
    assert denials[0].payload["reason"] == "missing_role:compliance_officer"
    # No cross_org_evidence dual-write happened.
    cross_org_events = [e for e in audit.entries if e.event_type == "cross_org_evidence"]
    assert cross_org_events == []
    assert audit.verify()
