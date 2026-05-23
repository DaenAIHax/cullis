"""Tests for the ``mcp_proxy.policy.try_rego_decision`` helper.

The helper is the single entry point both PDP routes (``/pdp/policy``,
``/v1/data/cullis/policy/*``) consume to decide whether the Rego
layer has an opinion on a request. Its contract is documented in
the docstring; these tests pin:

  * No Rego configured → returns ``None`` (caller falls through to
    legacy allowlist)
  * Malformed base64 in ``rego_wasm_base64`` → returns ``None`` + log
  * Rego runtime error → returns ``None`` + log (fail-OPEN to legacy,
    not fail-closed to deny — operator's broken Rego should not brick
    every decision; the legacy allowlist takes over)
  * Rego returns ``{decision, reason}`` → helper passes through verbatim
"""
from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

from mcp_proxy.policy import try_rego_decision
from mcp_proxy.policy.rego_engine import RegoEvalError


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ── no Rego configured ────────────────────────────────────────────────────


def test_no_rules_returns_none():
    assert try_rego_decision({}, {}, surface="session") is None


def test_non_dict_rules_returns_none():
    assert try_rego_decision("not-a-dict", {}, surface="session") is None  # type: ignore[arg-type]


def test_empty_rego_wasm_returns_none():
    rules = {"rego": "package cullis.policy", "rego_wasm_base64": ""}
    assert try_rego_decision(rules, {}, surface="session") is None


def test_missing_rego_wasm_returns_none():
    """Only ``rego`` source set, no compiled artifact → fall through."""
    rules = {"rego": "package cullis.policy\nallow := true"}
    assert try_rego_decision(rules, {}, surface="session") is None


# ── malformed base64 ──────────────────────────────────────────────────────


def test_malformed_base64_returns_none_and_logs(caplog):
    rules = {"rego_wasm_base64": "not===valid===base64==="}
    import logging
    with caplog.at_level(logging.WARNING, logger="mcp_proxy.policy"):
        out = try_rego_decision(rules, {}, surface="session")
    assert out is None
    assert any("decode failed" in rec.message for rec in caplog.records)


# ── Rego runtime error path ───────────────────────────────────────────────


def test_rego_eval_error_returns_none_and_logs(monkeypatch, caplog):
    """A wedged Rego falls through to legacy, doesn't deny everything."""
    rules = {"rego_wasm_base64": _b64(b"\x00asm\x01\x00\x00\x00fake")}

    def _raise(*a, **kw):
        raise RegoEvalError("simulated wasm trap")

    monkeypatch.setattr(
        "mcp_proxy.policy.evaluate_decision", _raise,
    )

    import logging
    with caplog.at_level(logging.WARNING, logger="mcp_proxy.policy"):
        out = try_rego_decision(rules, {}, surface="session")
    assert out is None
    assert any("eval failed" in rec.message for rec in caplog.records)


# ── happy path: Rego decision passed through ──────────────────────────────


def test_rego_decision_passthrough(monkeypatch):
    rules = {"rego_wasm_base64": _b64(b"\x00asm\x01\x00\x00\x00fake")}

    captured = {}

    def _fake_eval(policy, input_doc, *, entrypoint: str):
        captured["entrypoint"] = entrypoint
        captured["input"] = input_doc
        return {"decision": "deny", "reason": "Treasury wire denied by Rego"}

    monkeypatch.setattr("mcp_proxy.policy.evaluate_decision", _fake_eval)

    out = try_rego_decision(
        rules,
        {"agent_id": "orga::treasurer", "tool_name": "treasury_wire"},
        surface="tool_call",
    )
    assert out == {
        "decision": "deny",
        "reason": "Treasury wire denied by Rego",
    }
    # Helper picks the right entrypoint per surface so the operator's
    # Rego file can hold session + tool_call rules side by side.
    assert captured["entrypoint"] == "cullis/policy/tool_call"
    assert captured["input"]["tool_name"] == "treasury_wire"


def test_rego_decision_passthrough_session_entrypoint(monkeypatch):
    rules = {"rego_wasm_base64": _b64(b"\x00asm\x01\x00\x00\x00fake")}
    captured = {}

    def _fake_eval(policy, input_doc, *, entrypoint: str):
        captured["entrypoint"] = entrypoint
        return {"decision": "allow"}

    monkeypatch.setattr("mcp_proxy.policy.evaluate_decision", _fake_eval)

    out = try_rego_decision(
        rules,
        {"initiator_agent_id": "a", "target_agent_id": "b"},
        surface="session",
    )
    assert out == {"decision": "allow"}
    assert captured["entrypoint"] == "cullis/policy/session"
