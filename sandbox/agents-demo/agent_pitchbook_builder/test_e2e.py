"""End-to-end tests for the Pitchbook Builder reference demo agent.

Three scenarios cover the Chinese Wall pattern:

1. **Same-desk happy path**: an `industrials`-desk user drafts a pitch on
   `IndustrialDemoA`, reads `memo_industrials_001` (non-MNPI), generates
   comps + deck. Auto-citation works, audit chain verifies.

2. **Cross-desk attempted read**: same `industrials` user tries to read
   `memo_tech_001` (tagged `tech` desk). The capability gate denies the
   read inline and records a `capability_denied` audit event. The LLM
   observes the structured tool error and produces a final pitch that
   does NOT cite the blocked memo. Critical: the agent completes
   successfully WITHOUT leaking the blocked content.

3. **Same-desk MNPI memo**: a different `industrials` user reads an
   MNPI-tagged memo from their own desk. The MNPI flag is preserved in
   `sources_cited` so the supervisor can see what confidential material
   informed the draft.
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

from agent_pitchbook_builder.main import run  # noqa: E402
from shared.capability_gate import Principal  # noqa: E402
from shared.llm_client import LLMResponse, MockLLMClient, make_tool_call  # noqa: E402


_FULL_CAPS = frozenset(
    {
        "pitchbook.draft",
        "pitchbook.read_comps",
        "pitchbook.read_research",
        "pitchbook.read_news",
        "pitchbook.generate_artifact",
    }
)


@pytest.fixture
def industrials_principal() -> Principal:
    return Principal(
        principal_id="carol_industrials@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=_FULL_CAPS,
        scopes={"desk": "industrials"},
    )


@pytest.fixture
def tech_principal() -> Principal:
    return Principal(
        principal_id="dan_tech@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=_FULL_CAPS,
        scopes={"desk": "tech"},
    )


def _final_json(
    *,
    target: str,
    desk: str,
    comps_artifact_id: str,
    deck_artifact_id: str,
    sources_cited: list[dict[str, object]],
    brief_summary: str,
) -> str:
    return json.dumps(
        {
            "target": target,
            "desk": desk,
            "comps_artifact_id": comps_artifact_id,
            "deck_artifact_id": deck_artifact_id,
            "sources_cited": sources_cited,
            "brief_summary": brief_summary,
        }
    )


def test_same_desk_happy_path(industrials_principal: Principal) -> None:
    """Industrials desk -> reads industrials memo + news + generates deck."""

    target = "IndustrialDemoA"
    script = [
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "query_comps_db",
                    {"industry": "industrials", "size_range": "mid"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "read_internal_research",
                    {"memo_id": "memo_industrials_001"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "news_feed_query",
                    {"target_name": target, "timeframe": "30d"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "generate_excel",
                    {
                        "comps_table": [
                            {"name": "IndustrialDemoA", "ev_revenue": 1.8},
                        ]
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "generate_pptx",
                    {
                        "brief": "Industrials capex cycle pitch",
                        "comps_artifact_id": "xlsx_placeholder",
                        "sections": ["situation", "comps", "process"],
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                target=target,
                desk="industrials",
                comps_artifact_id="xlsx_placeholder",
                deck_artifact_id="pptx_placeholder",
                sources_cited=[
                    {
                        "type": "internal_memo",
                        "memo_id": "memo_industrials_001",
                        "mnpi": False,
                    },
                    {
                        "type": "news",
                        "headline": "IndustrialDemoA capex up 12% YoY",
                    },
                ],
                brief_summary=(
                    "Industrials desk pitch for IndustrialDemoA. Comps cite "
                    "public-side data; one same-desk research memo informed the "
                    "capex narrative; no MNPI material cited."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    out, audit = run(
        target=target,
        principal=industrials_principal,
        llm=MockLLMClient(script=script),
    )
    assert out.desk == "industrials"
    assert out.mnpi_cited is False
    assert any(
        src.get("memo_id") == "memo_industrials_001" for src in out.sources_cited
    )
    assert audit.verify()
    denials = [e for e in audit.entries if e.event_type == "capability_denied"]
    assert denials == []


def test_cross_desk_read_denied(industrials_principal: Principal) -> None:
    """Industrials principal asks to read a tech-desk memo. Gate denies
    inline, agent observes the structured error, and the final pitch
    does NOT cite the blocked memo. The denial event is preserved in
    the audit chain (Information Barrier evidence)."""

    target = "DemoCorpA"
    script = [
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "query_comps_db",
                    {"industry": "industrials", "size_range": "mid"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "read_internal_research",
                    {"memo_id": "memo_tech_001"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "generate_excel",
                    {
                        "comps_table": [
                            {"name": "IndustrialDemoA", "ev_revenue": 1.8}
                        ]
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "generate_pptx",
                    {
                        "brief": (
                            "Cross-industry pitch with public-side comps only "
                            "(internal research access denied by Chinese Wall)"
                        ),
                        "comps_artifact_id": "xlsx_placeholder",
                        "sections": ["situation", "comps"],
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                target=target,
                desk="industrials",
                comps_artifact_id="xlsx_placeholder",
                deck_artifact_id="pptx_placeholder",
                sources_cited=[],
                brief_summary=(
                    "Cross-desk research access denied by Information Barrier; "
                    "deck drafted with public-side comps only. No MNPI cited."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    out, audit = run(
        target=target,
        principal=industrials_principal,
        llm=MockLLMClient(script=script),
    )
    assert out.desk == "industrials"
    # The blocked memo MUST NOT appear in the final citations.
    assert all(
        src.get("memo_id") != "memo_tech_001" for src in out.sources_cited
    )
    # The denial event MUST be in the audit chain for the Information
    # Barrier supervisor to review.
    denials = [
        e
        for e in audit.entries
        if e.event_type == "capability_denied"
        and e.payload.get("capability") == "pitchbook.read_research"
    ]
    assert len(denials) == 1
    assert denials[0].payload["context"]["memo_id"] == "memo_tech_001"
    assert denials[0].payload["context"]["memo_desk"] == "tech"
    assert audit.verify()


def test_same_desk_mnpi_memo_tagged(industrials_principal: Principal) -> None:
    """Industrials desk reads an MNPI-tagged industrials memo. The MNPI
    flag is preserved in the audit chain and in the final citation list
    so the supervisor can review which confidential material informed the
    draft."""

    target = "IndustrialDemoB"
    script = [
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "query_comps_db",
                    {"industry": "industrials", "size_range": "large"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "read_internal_research",
                    {"memo_id": "memo_industrials_002"},
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "generate_excel",
                    {
                        "comps_table": [
                            {"name": "IndustrialDemoB", "ev_revenue": 2.1}
                        ]
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content="",
            tool_calls=(
                make_tool_call(
                    "generate_pptx",
                    {
                        "brief": (
                            "MNPI-informed pitch: carve-out angle from "
                            "same-desk research memo"
                        ),
                        "comps_artifact_id": "xlsx_placeholder",
                        "sections": ["situation", "comps", "process"],
                    },
                ),
            ),
            stop_reason="tool_use",
        ),
        LLMResponse(
            content=_final_json(
                target=target,
                desk="industrials",
                comps_artifact_id="xlsx_placeholder",
                deck_artifact_id="pptx_placeholder",
                sources_cited=[
                    {
                        "type": "internal_memo",
                        "memo_id": "memo_industrials_002",
                        "mnpi": True,
                    },
                ],
                brief_summary=(
                    "Same-desk MNPI memo (memo_industrials_002, carve-out "
                    "rumor) informs the strategic angle; flagged for "
                    "supervisor review per MAR/Information Barrier process."
                ),
            ),
            stop_reason="stop",
        ),
    ]
    out, audit = run(
        target=target,
        principal=industrials_principal,
        llm=MockLLMClient(script=script),
    )
    assert out.mnpi_cited is True
    assert any(
        src.get("memo_id") == "memo_industrials_002" and src.get("mnpi") is True
        for src in out.sources_cited
    )
    # The MNPI flag is also durably recorded in the audit chain.
    mnpi_reads = [
        e
        for e in audit.entries
        if e.event_type == "tool_result"
        and e.payload.get("tool") == "read_internal_research"
        and (e.payload.get("result") or {}).get("mnpi") is True
    ]
    assert len(mnpi_reads) == 1
    assert audit.verify()
