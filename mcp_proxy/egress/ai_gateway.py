"""AI gateway dispatch (ADR-039 refactor).

The dispatcher takes an OpenAI-compatible ChatCompletionRequest plus the
trusted agent identity (already reconstructed from the DPoP-bound cert
by the router), resolves the configured backend's adapter, and delegates
the upstream call. The adapter carries the per-backend wire knowledge
(LiteLLM library, Portkey REST, native provider SDK, raw HTTP) while
this module stays small and generic.

History:

- ADR-017 Phase 1 (2026-Q1) shipped Portkey as the single supported
  backend, in-line in this file.
- ADR-017 Phase 3 (2026-05) added the embedded LiteLLM backend, also
  in-line.
- ADR-039 (this refactor, 2026-05-27) moved both backend bodies behind
  the ``ProviderAdapter`` protocol and prepared the ``cullis_native``
  slot for the upcoming native Anthropic / OpenAI / Ollama adapters.

The shared helpers below (``GatewayResult``, ``StreamingDispatch``,
``GatewayError``, ``scrub_secrets``, ``_resolve_provider_creds``) are
used by every adapter and stay here.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

import httpx

from mcp_proxy.config import ProxySettings as Settings
from mcp_proxy.db import get_ai_provider_creds
from mcp_proxy.egress.adapters import DispatchContext, resolve_adapter
from mcp_proxy.egress.provider_catalog import (
    PROVIDERS,
    parse_provider_from_model,
    strip_provider_prefix,
)
from mcp_proxy.egress.schemas import ChatCompletionRequest, ChatCompletionResponse


_log = logging.getLogger("agent_trust.egress")


# Audit Wave A B2 (2026-05-11) — provider error bodies routinely echo
# back the rejected API key prefix (e.g. ``Incorrect API key provided:
# sk-ant-abc...``). Without scrubbing, those keys land in the immutable
# hash-chained Mastio audit log via ``upstream_detail``. Same class of
# leak as the third-party-gateway pattern flagged in
# ``feedback_third_party_ai_gateway_key_leak.md``. Patterns cover the
# common provider key shapes; the substitution preserves the field
# enough for ops debugging (provider, error class) without keeping
# the live secret.
_SECRET_SCRUB_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Anthropic console keys (``sk-ant-api03-...``) and project keys
    # (``sk-ant-...``). Match the prefix + non-whitespace tail.
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    # OpenAI legacy + project keys.
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{16,}"),
    # Google AI Studio (Gemini) API keys.
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    # AWS Access Key IDs (Bedrock callers paste these into provider
    # creds when misconfiguring the secret as the access key).
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Bearer / Authorization headers leaked verbatim into bodies.
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]{12,}"),
    # Cullis user API tokens.
    re.compile(r"culk_[A-Za-z0-9_\-]{16,}"),
)


def scrub_secrets(text: str | None) -> str | None:
    """Replace API key shapes with ``[REDACTED]`` before persisting text
    that may contain provider error echoes. Idempotent on already-scrubbed
    or secret-free input. Returns the input unchanged when None / empty
    so callers don't need to re-check."""
    if not text:
        return text
    out = text
    for pat in _SECRET_SCRUB_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


@dataclass
class GatewayResult:
    response: ChatCompletionResponse
    latency_ms: int
    upstream_request_id: str | None
    backend: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float | None = None


@dataclass
class StreamingDispatch:
    """Streaming counterpart of ``GatewayResult``.

    The router drives ``aiter()`` to fan-out chunks as SSE frames; once
    the stream drains, ``prompt_tokens`` / ``completion_tokens`` /
    ``cost_usd`` / ``upstream_request_id`` carry the final values used
    for the audit row and the per-principal token-budget consume. The
    backend implementation populates them while iterating.
    """

    backend: str
    provider: str
    model: str
    trace_id: str
    _aiter_factory: object = None  # async generator factory, set by impl
    started_at: float = field(default_factory=time.perf_counter)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float | None = None
    upstream_request_id: str | None = None
    latency_ms: int = 0

    def aiter(self) -> AsyncIterator[dict]:
        if self._aiter_factory is None:
            raise RuntimeError("StreamingDispatch.aiter called before backend wired it")
        return self._aiter_factory()


class GatewayError(Exception):
    """Raised on any non-recoverable failure talking to the gateway.

    `status_code` is the HTTP code Mastio should return to its own
    caller; `reason` is a short tag suitable for the audit row.
    """

    def __init__(self, status_code: int, reason: str, *, detail: str | None = None):
        super().__init__(detail or reason)
        self.status_code = status_code
        self.reason = reason
        self.detail = detail


async def _resolve_provider_creds(
    model: str,
    settings: Settings,
) -> tuple[str, dict[str, str]]:
    """Pick the provider for a model id and return its credentials.

    Resolution:
      1. ``parse_provider_from_model`` maps the request model to a
         provider key (``anthropic``, ``openai``, ...).
      2. ``ai_provider_credentials`` row drives the credential dict.
      3. Backward compat: when the row is missing for ``anthropic`` we
         fall back to ``settings.anthropic_api_key`` so existing
         deployments that have not yet seeded the table keep working.
      4. ``provider_not_configured`` is raised on miss + no fallback;
         ``provider_disabled`` is raised on a row with ``enabled=False``.
    """
    provider = parse_provider_from_model(model)
    if provider not in PROVIDERS:
        raise GatewayError(
            501,
            f"provider_not_implemented:{provider}",
            detail=f"No catalog entry for provider {provider!r}.",
        )

    row = await get_ai_provider_creds(provider)
    if row is None:
        if provider == "anthropic" and settings.anthropic_api_key:
            return provider, {"api_key": settings.anthropic_api_key}
        raise GatewayError(
            503,
            "provider_not_configured",
            detail=(
                f"Provider {provider!r} is not configured. "
                "Add credentials in the Mastio dashboard "
                "(Settings → AI Providers)."
            ),
        )
    if not row["enabled"]:
        raise GatewayError(
            503,
            "provider_disabled",
            detail=f"Provider {provider!r} is configured but disabled.",
        )
    return provider, dict(row["creds"] or {})


def _normalize_model_for_backend(
    req: ChatCompletionRequest,
    backend: str,
    provider: str,
) -> ChatCompletionRequest:
    """Strip the ``provider/`` routing prefix for native adapters.

    Only the ``cullis_native`` backend talks to provider APIs directly, so
    only it needs the bare model id (``claude-...`` rather than
    ``anthropic/claude-...``). ``litellm_embedded`` and ``portkey`` route on
    the prefix themselves and must keep it. Returns ``req`` unchanged when
    there is nothing to strip, so the common bare-id path allocates nothing.
    """
    if backend != "cullis_native":
        return req
    bare = strip_provider_prefix(req.model, provider)
    if bare == req.model:
        return req
    return req.model_copy(update={"model": bare})


async def dispatch(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
    http_client: httpx.AsyncClient | None = None,
) -> GatewayResult:
    backend = settings.ai_gateway_backend.lower()
    # Resolve provider + creds first so the per-provider adapter selection
    # in ``cullis_native`` has the resolved provider key. Legacy backends
    # (``litellm_embedded`` / ``portkey``) ignore the ``provider`` arg.
    provider, creds = await _resolve_provider_creds(req.model, settings)
    adapter = resolve_adapter(backend, provider)
    req = _normalize_model_for_backend(req, backend, provider)
    ctx = DispatchContext(
        agent_id=agent_id,
        org_id=org_id,
        trace_id=trace_id,
        http_client=http_client,
    )
    return await adapter.chat_completion(
        req=req,
        provider=provider,
        creds=creds,
        ctx=ctx,
        settings=settings,
    )


async def dispatch_stream(
    *,
    req: ChatCompletionRequest,
    agent_id: str,
    org_id: str,
    trace_id: str,
    settings: Settings,
) -> StreamingDispatch:
    """Open a streaming dispatch.

    Returns a ``StreamingDispatch`` whose ``aiter()`` yields OpenAI-shape
    chunk dicts (``object=chat.completion.chunk``). The router converts
    them to SSE frames. Token usage + cost land on the dispatch object
    once the iterator drains, so the post-stream audit/rate-limit logic
    can read them without inspecting the chunks itself.
    """
    backend = settings.ai_gateway_backend.lower()
    provider, creds = await _resolve_provider_creds(req.model, settings)
    adapter = resolve_adapter(backend, provider)
    req = _normalize_model_for_backend(req, backend, provider)
    ctx = DispatchContext(
        agent_id=agent_id,
        org_id=org_id,
        trace_id=trace_id,
    )
    return await adapter.stream_chat_completion(
        req=req,
        provider=provider,
        creds=creds,
        ctx=ctx,
        settings=settings,
    )
