"""Caller-facing ``hint`` on GatewayError surfaces *why* an egress call
failed instead of a bare status code.

Motivation: an agent that sent a non-existent model id got a naked
``HTTP 404`` on ``/v1/llm/chat``. The real reason (model id not
recognised) lived only in the proxy logs — ``_map_anthropic_exception``
mapped it to ``provider_not_found`` and the router dropped the detail.

The fix adds ``GatewayError.hint``: a self-authored, caller-safe line
(never ``str(exc)``) that the router puts on the wire. ``detail`` stays
audit/log-only because it may echo upstream chatter (audit H-IO-2).

Covered:
1. ``caller_hint`` maps the caller-actionable reasons and names the model.
2. ``caller_hint`` returns None for reasons where the tag suffices.
3. ``_map_anthropic_exception`` / ``_map_openai_exception`` attach the hint
   for a NotFound-shaped exception and keep ``detail`` separate.
4. ``_gateway_error_detail`` (router body builder) includes ``hint`` only
   when set, and never leaks ``detail``.
"""
from __future__ import annotations

import pytest

from mcp_proxy.egress.ai_gateway import GatewayError, caller_hint
from mcp_proxy.egress.adapters.anthropic import _map_anthropic_exception
from mcp_proxy.egress.adapters.openai import _map_openai_exception
from mcp_proxy.egress.llm_chat_router import _gateway_error_detail


# ── caller_hint (pure) ───────────────────────────────────────────────


def test_caller_hint_not_found_names_model_and_provider() -> None:
    hint = caller_hint("provider_not_found", model="claude-foo", provider="anthropic")
    assert hint is not None
    assert "claude-foo" in hint
    assert "anthropic" in hint
    assert "404" in hint


@pytest.mark.parametrize(
    "reason",
    ["provider_auth_failed", "provider_permission_denied", "provider_bad_request"],
)
def test_caller_hint_set_for_actionable_reasons(reason: str) -> None:
    assert caller_hint(reason, model="m", provider="openai") is not None


def test_caller_hint_none_for_opaque_reasons() -> None:
    # A 502/timeout/unknown class is not something the caller can fix by
    # changing the request; the bare reason tag is enough.
    assert caller_hint("provider_timeout") is None
    assert caller_hint("provider_unknown_error") is None


def test_caller_hint_handles_missing_model() -> None:
    hint = caller_hint("provider_not_found", provider="anthropic")
    assert hint is not None
    assert "the requested model" in hint


# ── adapter exception mappers attach the hint ────────────────────────


class _FakeNotFoundError(Exception):
    """Name matches the Anthropic/OpenAI SDK NotFoundError the mappers key on."""


_FakeNotFoundError.__name__ = "NotFoundError"


def test_anthropic_mapper_attaches_hint_for_not_found() -> None:
    exc = _FakeNotFoundError("Error code: 404 - model: claude-foo not found")
    gw = _map_anthropic_exception(exc, model="claude-foo")
    assert gw.status_code == 404
    assert gw.reason == "provider_not_found"
    assert gw.hint is not None and "claude-foo" in gw.hint
    # detail keeps the (scrubbed) upstream string; hint must not be it.
    assert gw.hint != gw.detail


def test_openai_mapper_attaches_hint_for_not_found() -> None:
    exc = _FakeNotFoundError("Error code: 404 - model gpt-foo does not exist")
    gw = _map_openai_exception(exc, model="gpt-foo")
    assert gw.reason == "provider_not_found"
    assert gw.hint is not None and "gpt-foo" in gw.hint


# ── router error-body builder ────────────────────────────────────────


def test_gateway_error_detail_includes_hint_when_set() -> None:
    exc = GatewayError(404, "provider_not_found", detail="raw upstream chatter",
                       hint="Model 'x' was not recognised.")
    body = _gateway_error_detail(exc, "trace-123")
    assert body == {
        "reason": "provider_not_found",
        "trace_id": "trace-123",
        "hint": "Model 'x' was not recognised.",
    }
    # The raw diagnostic detail must never reach the wire body.
    assert "raw upstream chatter" not in str(body)


def test_gateway_error_detail_omits_hint_when_absent() -> None:
    exc = GatewayError(502, "provider_timeout", detail="upstream timed out")
    body = _gateway_error_detail(exc, "trace-9")
    assert body == {"reason": "provider_timeout", "trace_id": "trace-9"}
    assert "hint" not in body
