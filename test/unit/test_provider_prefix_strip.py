"""The native gateway strips the ``provider/`` routing prefix before the
upstream call (ADR-039 regression: dropping LiteLLM removed the implicit
prefix normalization it did for free).

Symptom that motivated this: an agent that sends the *documented*
``model="anthropic/claude-haiku-4-5-20251001"`` got a bare ``HTTP 404`` on
``/v1/llm/chat``. The Anthropic Messages API only knows ``claude-...``; the
``anthropic/`` prefix exists solely so ``parse_provider_from_model`` can
route the call. LiteLLM used to strip it — the native adapters must now do
it themselves.

Two layers covered:

1. ``strip_provider_prefix`` (pure): strips a prefix only when it maps to
   the already-resolved provider; leaves bare ids and unrelated slashes
   alone; idempotent.
2. ``_normalize_model_for_backend``: strips for ``cullis_native`` only.
   ``litellm_embedded`` / ``portkey`` route on the prefix themselves and
   must keep it.
"""
from __future__ import annotations

import pytest

from mcp_proxy.egress.ai_gateway import _normalize_model_for_backend
from mcp_proxy.egress.provider_catalog import strip_provider_prefix
from mcp_proxy.egress.schemas import ChatCompletionRequest


# ── strip_provider_prefix (pure) ─────────────────────────────────────


@pytest.mark.parametrize(
    "model,provider,expected",
    [
        # The bug: prefixed id resolved to its provider → strip.
        ("anthropic/claude-haiku-4-5-20251001", "anthropic", "claude-haiku-4-5-20251001"),
        ("openai/gpt-4o", "openai", "gpt-4o"),
        ("ollama/llama3.1:8b", "ollama", "llama3.1:8b"),
        ("ollama_chat/llama3.1:8b", "ollama", "llama3.1:8b"),
        # Bare ids (heuristic-routed) pass through untouched.
        ("claude-haiku-4-5-20251001", "anthropic", "claude-haiku-4-5-20251001"),
        ("gpt-4o", "openai", "gpt-4o"),
        # A slash that is NOT the resolved provider's prefix is preserved
        # (e.g. an OpenAI-compatible model id that legitimately has a path).
        ("anthropic/claude-3", "openai", "anthropic/claude-3"),
    ],
)
def test_strip_provider_prefix(model: str, provider: str, expected: str) -> None:
    assert strip_provider_prefix(model, provider) == expected


def test_strip_provider_prefix_idempotent() -> None:
    once = strip_provider_prefix("anthropic/claude-haiku-4-5-20251001", "anthropic")
    assert strip_provider_prefix(once, "anthropic") == once


# ── _normalize_model_for_backend (backend gate) ──────────────────────


def _req(model: str) -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model=model, messages=[{"role": "user", "content": "hi"}]
    )


def test_normalize_strips_under_cullis_native() -> None:
    req = _req("anthropic/claude-haiku-4-5-20251001")
    out = _normalize_model_for_backend(req, "cullis_native", "anthropic")
    assert out.model == "claude-haiku-4-5-20251001"


def test_normalize_keeps_prefix_for_litellm_embedded() -> None:
    """LiteLLM routes on the ``provider/`` prefix; stripping it would break
    that backend, so the prefix must survive."""
    req = _req("anthropic/claude-haiku-4-5-20251001")
    out = _normalize_model_for_backend(req, "litellm_embedded", "anthropic")
    assert out.model == "anthropic/claude-haiku-4-5-20251001"


def test_normalize_keeps_prefix_for_portkey() -> None:
    req = _req("openai/gpt-4o")
    out = _normalize_model_for_backend(req, "portkey", "openai")
    assert out.model == "openai/gpt-4o"


def test_normalize_noop_returns_same_instance() -> None:
    """A bare id has nothing to strip; the common path must not allocate a
    copy."""
    req = _req("claude-haiku-4-5-20251001")
    out = _normalize_model_for_backend(req, "cullis_native", "anthropic")
    assert out is req
