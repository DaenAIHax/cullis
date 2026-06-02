"""Native OpenAI adapter (ADR-039 PR-C).

Uses ``openai.AsyncOpenAI`` directly, no LiteLLM. The Mastio's request
shape is already OpenAI ChatCompletion, so this adapter is effectively
passthrough on the request/response wire. The only Cullis-side
responsibilities are:

  - Build the SDK client from the dashboard-stored credentials.
  - Inject ``X-Cullis-{Agent,Org,Trace}`` headers so any upstream
    observability the operator wires up sees the agent identity.
  - Map ``openai.*Error`` to ``GatewayError`` with the same reason tags
    other adapters use, so audit and dashboard counters stay coherent.
  - Drain stream chunks as OpenAI dicts the existing SSE router can
    forward unchanged, and harvest the final ``usage`` chunk for the
    per-call telemetry / audit row.

Out of scope for PR-C, same as PR-B:
  - Cost computation (cost_usd stays None; the Cullis-owned price
    table lands as a separate PR alongside the per-agent cost meter
    in ADR-040 territory).
  - Multi-modal pass-through is fine on OpenAI (the shape is the same
    going in and out); no special handling needed here.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any, AsyncIterator

from mcp_proxy.egress.adapters.base import DispatchContext

if TYPE_CHECKING:
    from mcp_proxy.config import ProxySettings as Settings
    from mcp_proxy.egress.ai_gateway import GatewayResult, StreamingDispatch
    from mcp_proxy.egress.schemas import ChatCompletionRequest


_log = logging.getLogger("agent_trust.egress")


# OpenAI SDK exception class names → (HTTP status, audit reason).
# Comparing by class name keeps the import of ``openai`` lazy. Tags
# match the Anthropic and LiteLLM maps so dashboard error counters and
# audit aggregations stay coherent across adapters.
_OPENAI_ERROR_MAP: dict[str, tuple[int, str]] = {
    "AuthenticationError": (401, "provider_auth_failed"),
    "PermissionDeniedError": (403, "provider_permission_denied"),
    "NotFoundError": (404, "provider_not_found"),
    "RateLimitError": (429, "provider_rate_limited"),
    "BadRequestError": (400, "provider_bad_request"),
    "UnprocessableEntityError": (422, "provider_unprocessable"),
    "ConflictError": (409, "provider_conflict"),
    "APITimeoutError": (504, "provider_timeout"),
    "Timeout": (504, "provider_timeout"),
    "APIConnectionError": (502, "provider_unreachable"),
    "InternalServerError": (502, "provider_internal_error"),
    "APIStatusError": (502, "provider_api_error"),
    "APIError": (502, "provider_api_error"),
    "ContentFilterFinishReasonError": (400, "provider_content_policy"),
    "LengthFinishReasonError": (400, "provider_context_too_long"),
}


def _map_openai_exception(
    exc: Exception, *, model: str | None = None
) -> "GatewayError":
    from mcp_proxy.egress.ai_gateway import GatewayError, caller_hint, scrub_secrets

    cls = type(exc).__name__
    status, reason = _OPENAI_ERROR_MAP.get(cls, (502, "provider_unknown_error"))
    detail = scrub_secrets((str(exc) or cls)[:512])
    hint = caller_hint(reason, model=model, provider="openai")
    return GatewayError(status, reason, detail=detail, hint=hint)


# ── client cache ──────────────────────────────────────────────────────
#
# Same rationale as the AnthropicAdapter (PR-I): ``AsyncOpenAI`` carries
# an internal httpx pool; constructing a new instance per request
# defeats that pool. Cache keyed on the fingerprint of the inputs that
# drive construction so a dashboard-side key / base_url / organization
# rotation invalidates the cache on the next call (miss, rebuild).

_CLIENT_CACHE: dict[str, Any] = {}


def _creds_fingerprint(creds: dict[str, str], settings: "Settings") -> str:
    import hashlib
    import json
    payload = {
        "api_key": creds.get("api_key") or "",
        "base_url": creds.get("api_base") or creds.get("base_url") or "",
        "organization": creds.get("organization") or creds.get("org_id") or "",
        "timeout": float(getattr(settings, "ai_gateway_request_timeout_s", 0) or 0),
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _client(creds: dict[str, str], settings: "Settings") -> Any:
    """Return a cached AsyncOpenAI client for the given credentials.

    Supports the OpenAI-compatible endpoints customers run behind
    enterprise gateways (Azure OpenAI deployment URL, vLLM, etc) via
    ``api_base`` / ``base_url``. ``organization`` is honoured when
    present so enterprise OpenAI accounts that bill per-org work
    out-of-the-box. The internal httpx connection pool of the SDK is
    reused across requests with the same credentials fingerprint.
    """
    from mcp_proxy.egress.ai_gateway import GatewayError

    api_key = creds.get("api_key") or ""
    if not api_key:
        raise GatewayError(503, "provider_key_missing")

    fingerprint = _creds_fingerprint(creds, settings)
    cached = _CLIENT_CACHE.get(fingerprint)
    if cached is not None:
        return cached

    try:
        from openai import AsyncOpenAI
    except ImportError as exc:  # pragma: no cover — openai is a hard dep
        raise GatewayError(
            503,
            "provider_sdk_missing",
            detail=(
                "openai SDK is required for the native OpenAI adapter. "
                "It ships as a top-level dependency in requirements.txt."
            ),
        ) from exc

    kwargs: dict[str, Any] = {"api_key": api_key}
    base_url = creds.get("api_base") or creds.get("base_url")
    if base_url:
        kwargs["base_url"] = base_url
    organization = creds.get("organization") or creds.get("org_id")
    if organization:
        kwargs["organization"] = organization
    timeout = getattr(settings, "ai_gateway_request_timeout_s", None)
    if timeout:
        kwargs["timeout"] = float(timeout)
    # M7 (audit 2026-06-02): give the SDK an httpx client whose transport
    # validates the outbound URL against the SSRF guard and pins the
    # connect to the validated IP. Without this, an operator-set (or
    # DB-row-injected) base_url could be DNS-rebound to an internal/IMDS
    # address at connect time with the provider API key on the wire.
    import httpx as _httpx
    from mcp_proxy.utils.ssrf_transport import (
        SSRFPinnedTransport,
        allow_private_from_settings,
    )
    kwargs["http_client"] = _httpx.AsyncClient(
        transport=SSRFPinnedTransport(
            allow_private=allow_private_from_settings(settings),
        ),
    )
    client = AsyncOpenAI(**kwargs)
    _CLIENT_CACHE[fingerprint] = client
    return client


def _cullis_headers(ctx: DispatchContext) -> dict[str, str]:
    return {
        "X-Cullis-Agent": ctx.agent_id,
        "X-Cullis-Org": ctx.org_id,
        "X-Cullis-Trace": ctx.trace_id,
    }


def _strip_passthrough_body(body: dict[str, Any]) -> dict[str, Any]:
    """Remove fields the SDK manages itself; preserve everything else.

    ``stream`` / ``stream_options`` are set by the adapter explicitly
    for each path so the request body the caller built is normalised.
    """
    out = dict(body)
    out.pop("stream", None)
    out.pop("stream_options", None)
    return out


class OpenAIAdapter:
    """Talk to OpenAI (or OpenAI-compatible) via the official SDK.

    Effectively a passthrough on the wire shape; the value-add is
    identity injection + error mapping + telemetry capture for the
    Cullis audit row.
    """

    backend_name = "cullis_native"

    async def chat_completion(
        self,
        *,
        req: "ChatCompletionRequest",
        provider: str,
        creds: dict[str, str],
        ctx: DispatchContext,
        settings: "Settings",
    ) -> "GatewayResult":
        from mcp_proxy.egress.ai_gateway import GatewayError, GatewayResult
        from mcp_proxy.egress.schemas import ChatCompletionResponse

        body = _strip_passthrough_body(req.model_dump(exclude_none=True))
        model = body.get("model")
        client = _client(creds, settings)

        started = time.perf_counter()
        try:
            response = await client.chat.completions.create(
                **body,
                extra_headers=_cullis_headers(ctx),
            )
        except Exception as exc:
            gw_err = _map_openai_exception(exc, model=model)
            _log.warning(
                "openai_native error agent=%s model=%s reason=%s detail=%s",
                ctx.agent_id, model, gw_err.reason, gw_err.detail,
            )
            raise gw_err from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        payload = response.model_dump() if hasattr(response, "model_dump") else dict(response)
        payload["cullis_trace_id"] = ctx.trace_id
        # Normalise the usage shape so the canonical OpenAI fields are
        # always present even if a non-OpenAI endpoint (Azure deployment,
        # vLLM, LM Studio) returns a slim usage block.
        usage = payload.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        payload["usage"] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }

        try:
            parsed = ChatCompletionResponse.model_validate(payload)
        except Exception as exc:
            from mcp_proxy._http_safety import safe_http_detail
            raise GatewayError(
                502,
                "schema_mismatch",
                detail=safe_http_detail(
                    exc,
                    public_hint="OpenAI response failed Mastio schema",
                    log_context="ai_gateway.openai_native.parse_response",
                ),
            ) from exc

        upstream_request_id = (
            getattr(response, "id", None)
            or payload.get("id")
        )

        _log.info(
            "egress.llm dispatched backend=cullis_native provider=openai "
            "agent=%s org=%s model=%s latency_ms=%d tokens_in=%d tokens_out=%d",
            ctx.agent_id, ctx.org_id, model, latency_ms,
            prompt_tokens, completion_tokens,
        )

        return GatewayResult(
            response=parsed,
            latency_ms=latency_ms,
            upstream_request_id=upstream_request_id,
            backend="cullis_native",
            provider=provider,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=None,
        )

    async def stream_chat_completion(
        self,
        *,
        req: "ChatCompletionRequest",
        provider: str,
        creds: dict[str, str],
        ctx: DispatchContext,
        settings: "Settings",
    ) -> "StreamingDispatch":
        from mcp_proxy.egress.ai_gateway import StreamingDispatch

        body = _strip_passthrough_body(req.model_dump(exclude_none=True))
        model = body.get("model")
        # Always request a final usage chunk so the audit row gets
        # accurate token counts. The OpenAI streaming spec drains this
        # as a final chunk with empty choices and a populated ``usage``.
        body["stream_options"] = {"include_usage": True}

        client = _client(creds, settings)

        dispatch_obj = StreamingDispatch(
            backend="cullis_native",
            provider=provider,
            model=model,
            trace_id=ctx.trace_id,
        )

        async def _aiter() -> AsyncIterator[dict]:
            try:
                stream = await client.chat.completions.create(
                    **body,
                    stream=True,
                    extra_headers=_cullis_headers(ctx),
                )
            except Exception as exc:
                raise _map_openai_exception(exc, model=model) from exc

            try:
                async for chunk in stream:
                    payload = (
                        chunk.model_dump() if hasattr(chunk, "model_dump")
                        else dict(chunk)
                    )
                    payload.setdefault("object", "chat.completion.chunk")
                    if model and not payload.get("model"):
                        payload["model"] = model
                    if dispatch_obj.upstream_request_id is None:
                        cid = payload.get("id")
                        if cid:
                            dispatch_obj.upstream_request_id = cid
                    # The final chunk has empty choices and a populated
                    # ``usage`` block. Harvest it for telemetry and
                    # normalise the wire shape so the OpenAI SSE consumer
                    # always sees the canonical totals.
                    usage = payload.get("usage")
                    if isinstance(usage, dict):
                        pt = int(usage.get("prompt_tokens") or 0)
                        ct = int(usage.get("completion_tokens") or 0)
                        if pt or ct:
                            dispatch_obj.prompt_tokens = pt
                            dispatch_obj.completion_tokens = ct
                            payload["usage"] = {
                                "prompt_tokens": pt,
                                "completion_tokens": ct,
                                "total_tokens": pt + ct,
                            }
                    yield payload
            except Exception as exc:
                raise _map_openai_exception(exc, model=model) from exc
            finally:
                dispatch_obj.latency_ms = int(
                    (time.perf_counter() - dispatch_obj.started_at) * 1000
                )
                _log.info(
                    "egress.llm streamed backend=cullis_native provider=openai "
                    "agent=%s org=%s model=%s latency_ms=%d tokens_in=%d tokens_out=%d",
                    ctx.agent_id, ctx.org_id, model,
                    dispatch_obj.latency_ms,
                    dispatch_obj.prompt_tokens, dispatch_obj.completion_tokens,
                )

        dispatch_obj._aiter_factory = _aiter
        return dispatch_obj
