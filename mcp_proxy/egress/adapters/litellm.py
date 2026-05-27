"""LiteLLM embedded adapter (ADR-017 Phase 3, retained for back-compat).

This module wraps the in-process ``litellm.acompletion`` call path that
``mcp_proxy/egress/ai_gateway.py`` carried directly prior to ADR-039.
The behaviour, log lines, error tags, and audit semantics are unchanged
relative to the pre-refactor code; only the call site moved.

ADR-039 phases out this adapter:
  - v0.7.x — adapter remains the default, native adapters opt-in via
    ``MCP_PROXY_AI_GATEWAY_BACKEND=cullis_native``.
  - v0.7.x +1 — default flips to ``cullis_native``, this adapter emits
    a startup deprecation ``_log.warning`` when explicitly pinned.
  - v0.8.x — ``litellm`` is removed from ``requirements.txt`` and the
    import here becomes a hard failure (operators who explicitly pin
    the legacy backend pip-install the package out-of-band).
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING, AsyncIterator

from mcp_proxy.egress.adapters.base import DispatchContext

if TYPE_CHECKING:
    from mcp_proxy.config import ProxySettings as Settings
    from mcp_proxy.egress.ai_gateway import GatewayResult, StreamingDispatch
    from mcp_proxy.egress.schemas import ChatCompletionRequest


_log = logging.getLogger("agent_trust.egress")


# Map LiteLLM exception class names to (status_code, reason) tuples.
# We compare by class name rather than isinstance() so the import of
# litellm stays lazy (the dispatcher must boot in deployments that pin
# a non-LiteLLM backend without litellm installed).
_LITELLM_ERROR_MAP: dict[str, tuple[int, str]] = {
    "AuthenticationError": (401, "provider_auth_failed"),
    "PermissionDeniedError": (403, "provider_permission_denied"),
    "NotFoundError": (404, "provider_not_found"),
    "RateLimitError": (429, "provider_rate_limited"),
    "BadRequestError": (400, "provider_bad_request"),
    "UnprocessableEntityError": (422, "provider_unprocessable"),
    "Timeout": (504, "provider_timeout"),
    "APIConnectionError": (502, "provider_unreachable"),
    "ContextWindowExceededError": (400, "provider_context_too_long"),
    "ContentPolicyViolationError": (400, "provider_content_policy"),
    "InternalServerError": (502, "provider_internal_error"),
    "ServiceUnavailableError": (502, "provider_unavailable"),
    "APIError": (502, "provider_api_error"),
}


def _map_litellm_exception(exc: Exception) -> "GatewayError":
    from mcp_proxy.egress.ai_gateway import GatewayError, scrub_secrets

    cls = type(exc).__name__
    status, reason = _LITELLM_ERROR_MAP.get(cls, (502, "provider_unknown_error"))
    # B2 — LiteLLM stringifies provider 4xx/5xx into ``str(exc)`` and
    # those bodies frequently echo the rejected API key prefix. Scrub
    # before the detail flows into ``upstream_detail`` on the audit row.
    detail = scrub_secrets((str(exc) or cls)[:512])
    return GatewayError(status, reason, detail=detail)


class LiteLLMAdapter:
    """Embed ``litellm.acompletion`` in-process.

    Holds no per-call state; one instance can serve every dispatch. The
    LiteLLM library handles its own connection pooling internally.
    """

    backend_name = "litellm_embedded"

    async def chat_completion(
        self,
        *,
        req: "ChatCompletionRequest",
        provider: str,
        creds: dict[str, str],
        ctx: DispatchContext,
        settings: "Settings",
    ) -> "GatewayResult":
        """Call the upstream provider via the LiteLLM library, in-process.

        The model id from the request drives provider resolution (done
        by the dispatcher before this point) and the credentials are
        read from the ``ai_provider_credentials`` table. The Mastio
        metadata is attached via the ``metadata`` kwarg so any LiteLLM
        callback the operator wires up (Datadog, Langfuse, Postgres)
        sees the agent identity without extra plumbing.
        """
        from mcp_proxy.egress.ai_gateway import (
            GatewayError,
            GatewayResult,
        )
        from mcp_proxy.egress.provider_catalog import litellm_kwargs
        from mcp_proxy.egress.schemas import ChatCompletionResponse

        body = req.model_dump(exclude_none=True)
        model = body.pop("model")

        try:
            import litellm
            from litellm import acompletion
        except ImportError as exc:
            raise GatewayError(
                503,
                "litellm_not_installed",
                detail=(
                    "ai_gateway_backend='litellm_embedded' requires the litellm "
                    "package. Install it via requirements.txt."
                ),
            ) from exc

        # Drop unsupported params silently rather than raising — keeps the
        # OpenAI-compat contract usable across providers that vary on minor
        # fields (e.g. Anthropic does not accept all OpenAI knobs).
        litellm.drop_params = True

        provider_kwargs = litellm_kwargs(provider, creds)

        metadata = {
            "cullis_agent_id": ctx.agent_id,
            "cullis_org_id": ctx.org_id,
            "cullis_trace_id": ctx.trace_id,
        }

        started = time.perf_counter()
        try:
            response = await acompletion(
                model=model,
                metadata=metadata,
                **provider_kwargs,
                **body,
            )
        except Exception as exc:
            # Only the LiteLLM-shaped exceptions land in the map; anything
            # else (e.g. ValueError on bad input) becomes provider_unknown.
            gw_err = _map_litellm_exception(exc)
            _log.warning(
                "litellm_embedded error agent=%s model=%s reason=%s detail=%s",
                ctx.agent_id, model, gw_err.reason, gw_err.detail,
            )
            raise gw_err from exc

        latency_ms = int((time.perf_counter() - started) * 1000)

        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0

        # response_cost is not on every LiteLLM build; compute it on demand
        # so we always surface a number in the audit row when the model is
        # in the LiteLLM cost catalogue. Failures here are informational —
        # the call succeeded, the cost is just unknown.
        cost_usd: float | None = None
        try:
            cost_usd = litellm.completion_cost(completion_response=response)
        except Exception as exc:
            _log.debug("litellm.completion_cost failed for model=%s: %s", model, exc)

        payload = response.model_dump() if hasattr(response, "model_dump") else dict(response)
        payload.setdefault("id", f"chatcmpl-{uuid.uuid4().hex[:24]}")
        payload.setdefault("object", "chat.completion")
        payload.setdefault("created", int(time.time()))
        payload.setdefault("model", model)
        payload["cullis_trace_id"] = ctx.trace_id
        # Force usage shape so Mastio's schema sees the canonical fields
        # even when LiteLLM adds provider-specific extras (cached_tokens,
        # reasoning_tokens) that our pydantic model would reject.
        payload["usage"] = {
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "total_tokens": int(prompt_tokens + completion_tokens),
        }

        try:
            parsed = ChatCompletionResponse.model_validate(payload)
        except Exception as exc:
            # Audit F-B-119 — LiteLLM payload echoes through pydantic
            # ValidationError ``str()``. Same redaction posture as the
            # portkey branch.
            from mcp_proxy._http_safety import safe_http_detail
            raise GatewayError(
                502,
                "schema_mismatch",
                detail=safe_http_detail(
                    exc,
                    public_hint="LiteLLM response failed Mastio schema",
                    log_context="ai_gateway.litellm.parse_response",
                ),
            ) from exc

        upstream_request_id = (
            getattr(response, "id", None)
            or (response.get("id") if isinstance(response, dict) else None)
        )

        _log.info(
            "egress.llm dispatched backend=litellm_embedded provider=%s agent=%s "
            "org=%s model=%s latency_ms=%d tokens_in=%d tokens_out=%d cost_usd=%s",
            provider, ctx.agent_id, ctx.org_id, model, latency_ms,
            prompt_tokens, completion_tokens,
            f"{cost_usd:.6f}" if cost_usd is not None else "n/a",
        )

        return GatewayResult(
            response=parsed,
            latency_ms=latency_ms,
            upstream_request_id=upstream_request_id,
            backend="litellm_embedded",
            provider=provider,
            prompt_tokens=int(prompt_tokens),
            completion_tokens=int(completion_tokens),
            cost_usd=cost_usd,
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
        """Build a ``StreamingDispatch`` backed by
        ``litellm.acompletion(stream=True)``.

        Resolve the provider + credentials before opening the SSE response
        so configuration errors (provider not configured, disabled, litellm
        not installed) are surfaced as a regular non-stream error. The
        underlying ``acompletion`` call still happens lazily on first
        iteration of ``_aiter`` so the SSE headers can flush immediately.
        """
        from mcp_proxy.egress.ai_gateway import GatewayError, StreamingDispatch
        from mcp_proxy.egress.provider_catalog import litellm_kwargs

        body = req.model_dump(exclude_none=True)
        model = body.pop("model")
        body.pop("stream", None)
        # Ask the upstream for a final usage chunk so we can audit accurate
        # token + cost numbers after the stream drains. Anthropic + OpenAI +
        # most LiteLLM-routed providers honour this OpenAI-spec field.
        stream_options = body.pop("stream_options", None) or {}
        stream_options.setdefault("include_usage", True)

        try:
            import litellm
            from litellm import acompletion
        except ImportError as exc:
            raise GatewayError(
                503,
                "litellm_not_installed",
                detail=(
                    "ai_gateway_backend='litellm_embedded' requires the litellm "
                    "package. Install it via requirements.txt."
                ),
            ) from exc
        litellm.drop_params = True

        provider_kwargs = litellm_kwargs(provider, creds)

        metadata = {
            "cullis_agent_id": ctx.agent_id,
            "cullis_org_id": ctx.org_id,
            "cullis_trace_id": ctx.trace_id,
        }

        dispatch_obj = StreamingDispatch(
            backend="litellm_embedded",
            provider=provider,
            model=model,
            trace_id=ctx.trace_id,
        )

        async def _aiter() -> AsyncIterator[dict]:
            try:
                stream = await acompletion(
                    model=model,
                    metadata=metadata,
                    stream=True,
                    stream_options=stream_options,
                    **provider_kwargs,
                    **body,
                )
            except Exception as exc:
                raise _map_litellm_exception(exc) from exc

            try:
                async for chunk in stream:
                    payload = (
                        chunk.model_dump() if hasattr(chunk, "model_dump")
                        else dict(chunk)
                    )
                    payload.setdefault("object", "chat.completion.chunk")
                    payload.setdefault("model", model)
                    if dispatch_obj.upstream_request_id is None:
                        upstream_id = payload.get("id")
                        if upstream_id:
                            dispatch_obj.upstream_request_id = upstream_id
                    # The final usage chunk has empty choices and a populated
                    # ``usage`` dict; harvest it for the audit row, normalise
                    # the shape so the SSE consumer always sees the canonical
                    # OpenAI usage fields.
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
            except GatewayError:
                raise
            except Exception as exc:
                raise _map_litellm_exception(exc) from exc
            finally:
                dispatch_obj.latency_ms = int(
                    (time.perf_counter() - dispatch_obj.started_at) * 1000
                )
                if dispatch_obj.prompt_tokens or dispatch_obj.completion_tokens:
                    # ``completion_cost`` wants a full response object; in the
                    # streaming path we've already drained it, so go through
                    # ``cost_per_token`` (returns the (input, output) USD
                    # tuple already multiplied by the token counts).
                    try:
                        in_cost, out_cost = litellm.cost_per_token(
                            model=model,
                            prompt_tokens=dispatch_obj.prompt_tokens,
                            completion_tokens=dispatch_obj.completion_tokens,
                        )
                        dispatch_obj.cost_usd = float(in_cost) + float(out_cost)
                    except Exception as exc:  # pragma: no cover — informational
                        _log.debug(
                            "litellm.cost_per_token (stream) failed model=%s: %s",
                            model, exc,
                        )
                _log.info(
                    "egress.llm streamed backend=litellm_embedded provider=%s "
                    "agent=%s org=%s model=%s latency_ms=%d tokens_in=%d "
                    "tokens_out=%d cost_usd=%s",
                    provider, ctx.agent_id, ctx.org_id, model,
                    dispatch_obj.latency_ms,
                    dispatch_obj.prompt_tokens, dispatch_obj.completion_tokens,
                    f"{dispatch_obj.cost_usd:.6f}"
                    if dispatch_obj.cost_usd is not None else "n/a",
                )

        dispatch_obj._aiter_factory = _aiter
        return dispatch_obj
