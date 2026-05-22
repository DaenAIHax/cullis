"""Verification for the tool_execute success-path audit detail.

Branch: ``feat/audit-detail-on-success-path``.

Today's success path in ``mcp_proxy.tools.executor.run`` writes an
``audit_log`` row with no ``detail`` column populated — the dashboard
``/proxy/audit`` page therefore renders "No detail attached to this
event." for every successful tool call. This PR extends the helper so
the row carries ``{"parameters": <input>, "result_summary": <result>}``
in canonical JSON, with a per-call size cap and a truncation flag.

These tests pin the helper's output shape, the truncation behaviour,
the non-serialisable fallback, the hash-chain stability when the new
detail is attached via the real ``log_audit`` path, and the settings
override that lets operators tune the cap per deployment.
"""
from __future__ import annotations

import datetime
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
        "when": datetime.datetime(2026, 5, 22, 12, 0, 0),
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
