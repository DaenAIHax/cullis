"""Verification for the tool_execute success-path audit detail.

Branch: ``feat/audit-detail-on-success-path``.

Today's success path in ``mcp_proxy.tools.executor.run`` writes an
``audit_log`` row with no ``detail`` column populated — the dashboard
``/proxy/audit`` page therefore renders "No detail attached to this
event." for every successful tool call. This PR extends the helper so
the row carries ``{"parameters": <input>, "result_summary": <result>}``
in canonical JSON, with a per-call size cap and a truncation flag.

These tests pin the helper's output shape, the truncation behaviour,
the non-serialisable fallback (including circular references), the
oversize-parameters fallback (so a 32 KiB params blob can never
trigger a 500 inside ``log_audit`` after the handler has already
committed), the redaction denylist + master switch, the hash-chain
stability when the new detail is attached via the real ``log_audit``
path, the settings override that lets operators tune the cap per
deployment, and a pinned ``row_hash`` digest that protects the
canonical form from silent drift in NDJSON export verification.
"""
from __future__ import annotations

import datetime as _dt
import json

import pytest

from mcp_proxy.tools.executor import (
    _build_success_detail,
    _safe_json_value,
)


# ---------------------------------------------------------------------------
# 1. Happy path — parameters + result_summary land in detail.
# ---------------------------------------------------------------------------
def test_success_detail_contains_parameters_and_result_summary():
    parameters = {"amount": 100, "recipient": "acme-corp"}
    result = {"tx_id": "tx_001", "status": "ok"}

    encoded = _build_success_detail(
        parameters=parameters, result=result, max_bytes=4096,
    )
    decoded = json.loads(encoded)

    assert decoded == {
        "parameters": {"amount": 100, "recipient": "acme-corp"},
        "result_summary": {"status": "ok", "tx_id": "tx_001"},
    }
    # No truncation flag on a small payload.
    assert "detail_truncated" not in decoded
    # Canonical encoding — sort_keys + tight separators — so the chain
    # hash stays stable across Python implementations.
    assert encoded == json.dumps(decoded, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# 2. Oversize payload triggers detail_truncated + size cap honored.
# ---------------------------------------------------------------------------
def test_success_detail_truncates_oversize_payload_and_flags_it():
    parameters = {"query": "small"}
    # 5 KiB string smashes through a 1 KiB budget — exactly the case the
    # truncation strategy is designed for.
    huge_result = {"blob": "x" * 5000}
    max_bytes = 1024

    encoded = _build_success_detail(
        parameters=parameters, result=huge_result, max_bytes=max_bytes,
    )
    decoded = json.loads(encoded)

    assert decoded["detail_truncated"] is True
    assert decoded["parameters"] == {"query": "small"}
    # result_summary collapsed to the omitted marker with the type hint.
    assert decoded["result_summary"] == {"_omitted": True, "type": "dict"}
    # Final payload is under the budget — the chain hash + the outer
    # 16 KiB ``AUDIT_DETAILS_MAX_BYTES`` cap both depend on this.
    assert len(encoded.encode("utf-8")) <= max_bytes


# ---------------------------------------------------------------------------
# 3. Non-JSON-serialisable values fall back to repr + _non_serializable flag.
# ---------------------------------------------------------------------------
def test_success_detail_handles_non_json_serializable_values():
    parameters = {
        "when": _dt.datetime(2026, 5, 22, 12, 0, 0),
        "buf": b"\x00\x01\x02binary",
    }
    result = {"ok": True}

    encoded = _build_success_detail(
        parameters=parameters, result=result, max_bytes=4096,
    )
    decoded = json.loads(encoded)

    # Each non-serializable leaf collapses to the same surrogate shape.
    when_marker = decoded["parameters"]["when"]
    buf_marker = decoded["parameters"]["buf"]
    for marker, type_name in ((when_marker, "datetime"), (buf_marker, "bytes")):
        assert marker["_non_serializable"] is True
        assert marker["type"] == type_name
        # repr is truncated to 512 chars so a giant binary cannot inflate
        # the audit row.
        assert isinstance(marker["repr"], str)
        assert len(marker["repr"]) <= 512

    # The serialisable result still rides through untouched.
    assert decoded["result_summary"] == {"ok": True}


# ---------------------------------------------------------------------------
# 4. Hash-chain integrity holds when the new detail is attached.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_hash_chain_stays_consistent_with_success_detail(audit_test_env):
    """Write two audit rows back-to-back with the new detail payload and
    verify the hash chain is intact end-to-end.

    Regression for the canonical-form requirement: the per-row hash is
    computed over ``detail`` as-is, so any non-determinism in
    ``_build_success_detail`` (key order, separator drift) would break
    ``verify_audit_chain`` on the next boot.
    """
    from mcp_proxy.db import init_db, log_audit, verify_audit_chain

    await init_db(audit_test_env)

    detail_1 = _build_success_detail(
        parameters={"amount": 50},
        result={"tx_id": "row1"},
        max_bytes=4096,
    )
    detail_2 = _build_success_detail(
        parameters={"amount": 75},
        result={"tx_id": "row2"},
        max_bytes=4096,
    )

    await log_audit(
        agent_id="agent-1",
        action="tool_execute",
        status="success",
        tool_name="payments.transfer",
        detail=detail_1,
        request_id="req-1",
        duration_ms=12.0,
    )
    await log_audit(
        agent_id="agent-1",
        action="tool_execute",
        status="success",
        tool_name="payments.transfer",
        detail=detail_2,
        request_id="req-2",
        duration_ms=14.0,
    )

    ok, break_seq, msg = await verify_audit_chain()
    assert ok is True, f"chain broken at seq={break_seq}: {msg}"


# ---------------------------------------------------------------------------
# 5. Operator-supplied cap via MCP_PROXY_AUDIT_DETAIL_MAX_BYTES is honored.
# ---------------------------------------------------------------------------
def test_settings_override_caps_detail_size(monkeypatch):
    """Verify the ``audit_detail_max_bytes`` Settings field is wired to
    the executor success path (the executor reads ``get_settings()`` on
    every success log_audit). We exercise the helper directly here with
    the value the settings layer would have passed in."""
    monkeypatch.setenv("MCP_PROXY_AUDIT_DETAIL_MAX_BYTES", "512")
    # ProxySettings refuses the insecure default in dev too (audit F-A-507),
    # so the test must always set a non-default admin secret.
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default")
    # Reset settings cache so the new env value takes effect.
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.audit_detail_max_bytes == 512

        # Payload larger than 512 must trigger truncation when the cap
        # from settings is the budget passed to the helper.
        encoded = _build_success_detail(
            parameters={"recipient": "acme"},
            result={"blob": "x" * 1000},
            max_bytes=settings.audit_detail_max_bytes,
        )
        decoded = json.loads(encoded)
        assert decoded["detail_truncated"] is True
        assert len(encoded.encode("utf-8")) <= 512
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 6. Helper is defensive — _safe_json_value never raises.
# ---------------------------------------------------------------------------
def test_safe_json_value_passes_serializable_through_unchanged():
    for value in (None, 1, 1.5, "s", True, [1, 2], {"k": "v"}):
        assert _safe_json_value(value) == value


def test_safe_json_value_marks_non_serializable_with_repr():
    class _Custom:
        def __repr__(self) -> str:
            return "<Custom instance xyz>"

    marker = _safe_json_value(_Custom())
    assert marker["_non_serializable"] is True
    assert marker["type"] == "_Custom"
    assert "Custom instance" in marker["repr"]


# ---------------------------------------------------------------------------
# 7. P0 #1 — oversize parameters never bubble up a RuntimeError from
#    log_audit. A 32 KiB parameters blob (legitimate per
#    ``MAX_TOOL_PARAMETERS_BYTES=128 KiB`` in ``mcp_proxy.models``)
#    exceeds the 16 KiB outer ``AUDIT_DETAILS_MAX_BYTES`` cap, so the
#    helper MUST drop ``parameters`` to a structural marker too rather
#    than leaving the raw blob and letting ``_enforce_audit_detail_size``
#    refuse the row (and 500 the request after the handler committed
#    side effects — double-spend territory).
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_oversize_parameters_do_not_break_log_audit(audit_test_env):
    """Reproduce the P0 #1 path: parameters alone overflow the audit cap.

    Pre-fix: ``_build_success_detail`` only truncated ``result_summary``,
    so a 32 KiB parameters payload made it through unchanged → outer
    16 KiB ``_enforce_audit_detail_size`` raised → ``log_audit`` raised
    → caller got 500 → agent retried → side effect duplicated.

    Post-fix: parameters get the ``_parameters_omit_marker`` treatment
    (omit + structural keys + size_bytes), the detail stays under the
    operator-tuned cap, the row lands, no 500.
    """
    from mcp_proxy.db import init_db, log_audit, verify_audit_chain

    await init_db(audit_test_env)

    # 32 KiB of input — well below ``MAX_TOOL_PARAMETERS_BYTES=128 KiB``
    # (an entirely legitimate value at the model boundary) but well above
    # both the 4 KiB per-call cap and the 16 KiB outer cap.
    huge_parameters = {
        "memo": "x" * 32 * 1024,
        "recipient": "acme-corp",
        "amount": 1500,
    }
    result = {"tx_id": "TX-001", "status": "ok"}

    detail = _build_success_detail(
        parameters=huge_parameters,
        result=result,
        max_bytes=4096,
    )

    # Sanity: encoded form fits in the 4 KiB budget, and the row carries
    # the truncated-flag + the parameters omit marker (with the top-level
    # keys + size hint as the forensic anchor).
    assert len(detail.encode("utf-8")) <= 4096
    decoded = json.loads(detail)
    assert decoded["detail_truncated"] is True
    assert decoded["parameters"]["_omitted"] is True
    assert decoded["parameters"]["type"] == "dict"
    assert decoded["parameters"]["size_bytes"] > 32_000
    assert set(decoded["parameters"]["top_level_keys"]) == {
        "amount", "memo", "recipient",
    }
    assert decoded["result_summary"]["_omitted"] is True

    # And the real ``log_audit`` path accepts the row — no RuntimeError
    # propagates, the chain stays intact.
    await log_audit(
        agent_id="agent-oversize",
        action="tool_execute",
        status="success",
        tool_name="payments.transfer",
        detail=detail,
        request_id="req-oversize-1",
        duration_ms=10.0,
    )
    ok, broken_seq, msg = await verify_audit_chain()
    assert ok is True, f"chain broken at seq={broken_seq}: {msg}"


# ---------------------------------------------------------------------------
# 8. P0 #2 — circular references in parameters / result no longer
#    blow the recursion stack inside ``_safe_json_value``. The walker
#    tracks ``id(value)`` so a self-referencing dict collapses to the
#    circular-reference marker rather than driving Python to a
#    RecursionError that propagates through ``log_audit``.
# ---------------------------------------------------------------------------
def test_circular_reference_in_parameters_yields_marker():
    """``d = {}; d['self'] = d`` is the canonical trigger. SQLAlchemy ORM
    objects with ``relationship(backref=...)`` produce the same shape via
    ``__dict__`` when a tool handler hands one back as-is. Either way the
    helper must terminate."""
    parameters: dict[str, object] = {"recipient": "acme"}
    parameters["self"] = parameters
    result = {"ok": True}

    detail = _build_success_detail(
        parameters=parameters,
        result=result,
        max_bytes=4096,
    )
    decoded = json.loads(detail)

    # The outer dict is rebuilt, the cyclic edge collapses to the marker.
    assert decoded["parameters"]["recipient"] == "acme"
    self_marker = decoded["parameters"]["self"]
    assert self_marker["_omitted"] is True
    assert self_marker["reason"] == "circular_reference"
    assert self_marker["type"] == "dict"
    assert decoded["result_summary"] == {"ok": True}


def test_circular_reference_in_result_orm_like_shape():
    """Simulate the SQLAlchemy ORM gotcha: a result object whose
    ``__dict__`` contains a reference back to itself via a backref-style
    relationship. The helper walks containers (dict / list) and falls
    back to a leaf marker for everything else; the bug pre-fix would
    have shown up only on objects whose ``json.dumps`` failure path
    forced the recursive dict walk into the cycle. Here we drive that
    path directly with a self-referencing dict embedded in the result
    structure."""
    inner: dict[str, object] = {"name": "Transaction"}
    inner["parent"] = inner  # ORM backref shape

    parameters = {"k": "v"}
    result = {"row": inner, "siblings": [inner, inner]}

    detail = _build_success_detail(
        parameters=parameters,
        result=result,
        max_bytes=8192,
    )
    decoded = json.loads(detail)

    # The first visit succeeds at the top level; the back-edge collapses.
    assert decoded["result_summary"]["row"]["name"] == "Transaction"
    parent_marker = decoded["result_summary"]["row"]["parent"]
    assert parent_marker["_omitted"] is True
    assert parent_marker["reason"] == "circular_reference"
    # Siblings list — each element is the same object as ``row``. Because
    # ``_seen`` is popped on the way back up (siblings, not ancestors,
    # share the id), they get walked again normally and again collapse
    # internally — they are not falsely flagged at the outer level.
    assert decoded["result_summary"]["siblings"][0]["name"] == "Transaction"
    assert decoded["result_summary"]["siblings"][1]["name"] == "Transaction"


# ---------------------------------------------------------------------------
# 9. P1 #1 — redaction denylist (per-tool) + master switch (all tools).
# ---------------------------------------------------------------------------
def test_redaction_denylist_redacts_parameters_only():
    """``parameters_denylist=['payments.*']`` + tool ``payments.transfer``
    must redact parameters while leaving result_summary captured."""
    detail = _build_success_detail(
        parameters={"recipient": "acme", "amount": 1500, "iban": "IT60X0..."},
        result={"tx_id": "TX-001", "status": "ok"},
        max_bytes=4096,
        tool_name="payments.transfer",
        redaction_settings={
            "capture_parameters": True,
            "capture_result": True,
            "parameters_denylist": ["payments.*"],
            "result_denylist": [],
        },
    )
    decoded = json.loads(detail)
    assert decoded["parameters"] == {
        "_redacted": True, "reason": "tool_denylist",
    }
    # Result is untouched — the deployment captured it.
    assert decoded["result_summary"] == {"status": "ok", "tx_id": "TX-001"}


def test_redaction_master_switch_redacts_all_parameters():
    """``capture_parameters=False`` redacts every tool's parameters
    regardless of the denylist (use case: PII-pervasive deployment that
    can't enumerate tools individually)."""
    detail = _build_success_detail(
        parameters={"query": "natural language user input"},
        result={"answer": "structured output"},
        max_bytes=4096,
        tool_name="search.semantic",
        redaction_settings={
            "capture_parameters": False,
            "capture_result": True,
            "parameters_denylist": [],
            "result_denylist": [],
        },
    )
    decoded = json.loads(detail)
    assert decoded["parameters"] == {
        "_redacted": True, "reason": "capture_disabled",
    }
    assert decoded["result_summary"] == {"answer": "structured output"}


def test_redaction_denylist_no_match_passes_through():
    """A tool that doesn't match any denylist pattern under the default
    capture-on stance gets its full parameters captured (the regression
    guard for "fix #1 doesn't accidentally redact everyone")."""
    detail = _build_success_detail(
        parameters={"recipient": "alice"},
        result={"ok": True},
        max_bytes=4096,
        tool_name="email.send",
        redaction_settings={
            "capture_parameters": True,
            "capture_result": True,
            "parameters_denylist": ["payments.*"],
            "result_denylist": ["trading.*"],
        },
    )
    decoded = json.loads(detail)
    assert decoded["parameters"] == {"recipient": "alice"}
    assert decoded["result_summary"] == {"ok": True}


def test_redaction_settings_parsed_from_env(monkeypatch):
    """The settings layer accepts comma-separated env strings for the
    denylist fields (operator UX) and JSON arrays (programmatic
    config). Both reach ``audit_capture_tool_parameters_denylist`` as
    a Python list."""
    monkeypatch.setenv(
        "MCP_PROXY_AUDIT_CAPTURE_TOOL_PARAMETERS_DENYLIST",
        "payments.*, trading.transfer ,kyc.*",
    )
    monkeypatch.setenv(
        "MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default",
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.audit_capture_tool_parameters_denylist == [
            "payments.*", "trading.transfer", "kyc.*",
        ]
        # Default master switch is True.
        assert settings.audit_capture_tool_parameters is True
        assert settings.audit_capture_tool_result is True
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 10. P1 #3 — pinned ``row_hash`` digest. The chain-self-verification
#     test above is tautological (write rows → verify chain → pass),
#     so a future canonical-form change in ``_build_success_detail``
#     would silently break verification against NDJSON exports created
#     today. This test pins a single ``row_hash`` against a known input
#     so that any drift in the canonical form trips the test (and the
#     operator can then decide: bump ``hash_format`` to v3 + write a
#     migration, or revert the canonical change).
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_known_audit_row_hash_pinned(audit_test_env, monkeypatch):
    """Pin a specific SHA-256 digest for a controlled input.

    The pinned hash protects:
      * the canonical form of ``_build_success_detail`` (sort_keys +
        tight separators),
      * the v2 hash format in ``compute_audit_row_hash`` (the leading
        ``v2|`` literal + the dpop_jkt / on_behalf_of_user_id binding),
      * the field ordering inside ``compute_audit_row_hash``.

    Drift in any of those fails this test — the operator gets a loud
    signal in the diff PR instead of a silent NDJSON-verification
    regression months later.
    """
    from mcp_proxy.db import init_db, log_audit
    from sqlalchemy import text

    # Freeze the wall clock so the timestamp that feeds into
    # ``compute_audit_row_hash`` is deterministic across CI runs. The
    # ``log_audit`` body calls ``datetime.now(timezone.utc).isoformat()``
    # on a module-level ``datetime`` import (``from datetime import
    # datetime, timezone``), so patch that symbol on the ``mcp_proxy.db``
    # module.
    import mcp_proxy.db as _db_mod

    class _FrozenDatetime:
        @classmethod
        def now(cls, tz=None):  # noqa: ARG003 — interface contract
            return _dt.datetime(
                2026, 5, 22, 12, 0, 0, 0, tzinfo=_dt.timezone.utc,
            )

    monkeypatch.setattr(_db_mod, "datetime", _FrozenDatetime)

    await init_db(audit_test_env)

    detail = _build_success_detail(
        parameters={"k": "v"},
        result={"ok": True},
        max_bytes=4096,
    )
    # Sanity: the canonical form of the detail itself is pinned.
    assert detail == '{"parameters":{"k":"v"},"result_summary":{"ok":true}}'

    await log_audit(
        agent_id="test-agent",
        action="tool_execute",
        status="success",
        tool_name="example",
        detail=detail,
        request_id="req-pinned-001",
    )

    # Read the row back and pin its ``row_hash``.
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT row_hash, hash_format, chain_seq, prev_hash, "
            "timestamp FROM audit_log WHERE request_id = :rid"
        ), {"rid": "req-pinned-001"})).first()

    assert row is not None, "audit row did not land"
    assert row[1] == "v2"
    assert row[2] == 1
    assert row[3] == "genesis"
    assert row[4] == "2026-05-22T12:00:00+00:00"

    # The expected hash is computed via ``compute_audit_row_hash`` with
    # the exact inputs above (v2 format, frozen timestamp, the detail
    # pinned earlier, prev_hash="genesis", chain_seq=1, both
    # dpop_jkt and on_behalf_of_user_id NULL). The value is pinned
    # here as a literal so a canonical-form drift in either
    # ``_build_success_detail`` or ``compute_audit_row_hash`` trips
    # the diff PR.
    expected = (
        "3efdd5aece3931c3370a3befb9e9307e134a23a0aa1d59b07b5f43674a3719b4"
    )
    # Recompute via the production helper to catch a divergence between
    # the helper and the SQL-stored value too (defence in depth).
    from mcp_proxy.db import compute_audit_row_hash
    recomputed = compute_audit_row_hash(
        chain_seq=1,
        timestamp="2026-05-22T12:00:00+00:00",
        agent_id="test-agent",
        action="tool_execute",
        tool_name="example",
        status="success",
        detail=detail,
        request_id="req-pinned-001",
        prev_hash="genesis",
        dpop_jkt=None,
        on_behalf_of_user_id=None,
        hash_format="v2",
    )
    assert recomputed == row[0]
    assert row[0] == expected, (
        f"row_hash drift: stored={row[0]} expected={expected}. "
        "If this is intentional, bump hash_format (v2 -> v3), write a "
        "migration, and update the pinned digest."
    )
