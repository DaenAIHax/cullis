"""ADR-017 Phase 4 — native AI gateway on Mastio.

Architecture (post-2026-05-06 fix): the Mastio is the AI gateway egress
point for its agents. No Court round trip:

  agent (mTLS+DPoP) → Mastio /v1/chat/completions
                    → mcp_proxy.egress.ai_gateway.dispatch
                    → litellm_embedded (in-process)
                    → upstream provider (Anthropic Haiku 4.5)

The Mastio authenticates the agent via the same mTLS+DPoP pair used by
the rest of ``mcp_proxy.egress.router`` (ADR-014), looks up the
agent's identity (already trusted from the cert), and dispatches the
chat completion in-process via the LiteLLM library. Mastio writes a
local audit row; cross-org dual-write to Court is a federation concern
(future PR), not a precondition for the gateway to work.

Court is never required for LLM calls. The Mastio runs standalone and
serves AI gateway egress for its agents without federating.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from mcp_proxy.auth.builtin_capabilities import LLM_CHAT
from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.auth.rate_limit import get_token_sum_limiter
from mcp_proxy.config import get_settings
from mcp_proxy.db import list_ai_provider_creds, log_audit
from mcp_proxy.egress.budget import effective_budget, get_budget_counter
from mcp_proxy.egress.ai_gateway import (
    GatewayError,
    StreamingDispatch,
    dispatch,
    dispatch_stream,
)
from mcp_proxy.egress.provider_catalog import (
    PROVIDERS,
    list_available_models,
    parse_provider_from_model,
)
from mcp_proxy.egress.schemas import ChatCompletionRequest
from mcp_proxy.models import InternalAgent

logger = logging.getLogger("mcp_proxy.egress.llm_chat")

router = APIRouter(tags=["llm-chat"])


def _token_bucket_key(agent: InternalAgent) -> str:
    return f"principal:{agent.agent_id}:llm_tokens"


# Rough chars-per-token divisor for the estimation fallback (EG-1). The
# point is denying budget evasion, not billing-grade accounting: an
# adapter that only learns usage at full drain reports 0 on a truncated
# stream, so we charge an estimate derived from what actually crossed
# the wire instead of letting the call ride for free.
_CHARS_PER_TOKEN = 4
# Completion-side reservation when the caller did not set ``max_tokens``
# (EG-2). Deliberately a constant, not a setting: it only bounds the
# concurrent-admission overshoot window and is settled against the real
# usage at end of request.
_DEFAULT_COMPLETION_RESERVE = 1024


def _estimate_prompt_tokens(req: ChatCompletionRequest) -> int:
    """Char-count estimate of the prompt size (EG-1 fallback)."""
    chars = 0
    for msg in req.messages:
        content = msg.content
        if isinstance(content, str):
            chars += len(content)
        elif content:
            try:
                chars += len(json.dumps(content, default=str))
            except (TypeError, ValueError):
                pass
    return max(1, chars // _CHARS_PER_TOKEN)


def _reservation_tokens(req: ChatCompletionRequest) -> int:
    """Optimistic admission reservation (EG-2): estimated prompt +
    requested (or default) completion ceiling. Settled to actual usage
    when the request finishes, so over-reservation self-corrects."""
    return _estimate_prompt_tokens(req) + int(
        req.max_tokens or _DEFAULT_COMPLETION_RESERVE
    )


def _gateway_error_detail(exc: GatewayError, trace_id: str) -> dict:
    """Build the JSON error body for a caught :class:`GatewayError`.

    Surfaces ``exc.hint`` — a caller-safe, self-authored explanation —
    when the adapter set one, so the agent learns *why* the call failed
    (e.g. an unrecognised model id) instead of a bare status code. Never
    includes ``exc.detail``, which may carry upstream chatter and stays
    in the audit row only (audit H-IO-2).
    """
    detail: dict = {"reason": exc.reason, "trace_id": trace_id}
    if exc.hint:
        detail["hint"] = exc.hint
    return detail


@router.post("/v1/chat/completions")
@router.post("/v1/llm/chat")
async def chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
):
    settings = get_settings()
    trace_id = f"trace_{uuid.uuid4().hex[:16]}"

    # Capability gate (#22) — fail-closed on missing ``llm.chat``.
    # Phase 1 left this check decorative on the chat path; an agent
    # enrolled without ``llm.chat`` in its capabilities could still
    # reach the LLM provider as long as it was bound and DPoP+mTLS
    # passed. From v0.6.4 the capability is the first gate after
    # auth: the agent envelope MUST carry ``llm.chat`` or the request
    # is denied before any provider dispatch.
    if LLM_CHAT not in (agent.capabilities or []):
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="denied",
            details={
                "event": "llm.chat_completion",
                "principal_id": agent.agent_id,
                "principal_type": agent.principal_type,
                "model": req.model,
                "trace_id": trace_id,
                "reason": "capability_missing",
                "required_capability": LLM_CHAT,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "capability_missing",
                "trace_id": trace_id,
                "required_capability": LLM_CHAT,
            },
        )

    # Wave A PR3 (audit 2026-05-11 Tema A) — enforce ``scope_providers``
    # on culk_-authed callers. Pre-fix this field was stored at mint
    # time and never read; a token "anthropic only" worked on every
    # provider configured on this Mastio. Now: when the caller's
    # InternalAgent envelope carries a non-empty ``scope_providers``,
    # the resolved provider for the request model MUST be in the list,
    # else 403. Cert+DPoP / LOCAL_TOKEN auth leaves
    # ``agent.scope_providers`` as ``None`` so this gate is a no-op
    # for them.
    if agent.scope_providers:
        try:
            req_provider = parse_provider_from_model(req.model)
        except Exception:  # noqa: BLE001 — parse failure → deny
            req_provider = None
        if req_provider is None or req_provider not in agent.scope_providers:
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_llm_chat",
                status="denied",
                details={
                    "event": "llm.chat_completion",
                    "principal_id": agent.agent_id,
                    "principal_type": agent.principal_type,
                    "model": req.model,
                    "trace_id": trace_id,
                    "reason": "token_scope_provider_mismatch",
                    "requested_provider": req_provider,
                    "scope_providers": agent.scope_providers,
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "token_scope_provider_mismatch",
                    "trace_id": trace_id,
                    "requested_provider": req_provider,
                    "allowed_providers": agent.scope_providers,
                },
            )

    if settings.llm_tokens_per_minute > 0:
        token_limiter = get_token_sum_limiter()
        bucket_key = _token_bucket_key(agent)
        current_sum = await token_limiter.peek(bucket_key)
        if current_sum >= settings.llm_tokens_per_minute:
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_llm_chat",
                status="error",
                details={
                    "event": "llm.chat_completion",
                    "principal_id": agent.agent_id,
                    "principal_type": agent.principal_type,
                    "backend": settings.ai_gateway_backend,
                    "provider": settings.ai_gateway_provider,
                    "model": req.model,
                    "trace_id": trace_id,
                    "reason": "local_rate_limited_tokens",
                    "current_window_tokens": current_sum,
                    "limit_tokens_per_minute": settings.llm_tokens_per_minute,
                    "stream": req.stream,
                },
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "reason": "local_rate_limited_tokens",
                    "trace_id": trace_id,
                    "current_window_tokens": current_sum,
                    "limit_tokens_per_minute": settings.llm_tokens_per_minute,
                },
            )

    # Per-agent cumulative token budget (calendar UTC day / month). Skipped
    # entirely when no ceiling is configured (per-agent row or global
    # default), so it is zero-overhead until an operator sets one. The
    # running total is a Redis counter seeded from the audit chain.
    budget_day, budget_month = await effective_budget(agent.agent_id, settings)
    budget_enforced = budget_day > 0 or budget_month > 0
    reserve_tokens = 0
    if budget_enforced:
        now = datetime.now(timezone.utc)
        used_day, used_month = await get_budget_counter().current(agent.agent_id, now)
        over_day = budget_day > 0 and used_day >= budget_day
        over_month = budget_month > 0 and used_month >= budget_month
        if over_day or over_month:
            reason = "daily_budget_exceeded" if over_day else "monthly_budget_exceeded"
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_llm_chat",
                status="denied",
                details={
                    "event": "llm.chat_completion",
                    "principal_id": agent.agent_id,
                    "principal_type": agent.principal_type,
                    "backend": settings.ai_gateway_backend,
                    "provider": settings.ai_gateway_provider,
                    "model": req.model,
                    "trace_id": trace_id,
                    "reason": reason,
                    "used_day_tokens": used_day,
                    "used_month_tokens": used_month,
                    "budget_tokens_per_day": budget_day,
                    "budget_tokens_per_month": budget_month,
                    "stream": req.stream,
                },
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "reason": reason,
                    "trace_id": trace_id,
                    "used_day_tokens": used_day,
                    "used_month_tokens": used_month,
                    "budget_tokens_per_day": budget_day,
                    "budget_tokens_per_month": budget_month,
                },
            )
        # EG-2 — optimistic reservation. The admission check above is
        # read-only, so N concurrent requests at 95% of the ceiling all
        # used to pass and overshoot it together. Charging an estimate
        # up-front makes concurrent admissions see each other; the
        # reservation is settled against actual usage (refund or top-up)
        # in every terminal path below.
        reserve_tokens = _reservation_tokens(req)
        await get_budget_counter().add_delta(
            agent.agent_id, reserve_tokens, now,
        )

    if req.stream:
        return await _handle_stream(
            req=req, agent=agent, settings=settings, trace_id=trace_id,
            enforce_budget=budget_enforced, reserve_tokens=reserve_tokens,
        )

    started = time.perf_counter()

    try:
        result = await dispatch(
            req=req,
            agent_id=agent.agent_id,
            org_id=settings.org_id,
            trace_id=trace_id,
            settings=settings,
        )
    except GatewayError as exc:
        if budget_enforced:
            # Refund the EG-2 reservation in full: a pre-response
            # gateway failure (bad model id, provider auth, timeout
            # before first byte) consumed nothing chargeable.
            await get_budget_counter().add_delta(
                agent.agent_id, -reserve_tokens, datetime.now(timezone.utc),
            )
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            details={
                "event": "llm.chat_completion",
                "principal_id": agent.agent_id,
                "principal_type": agent.principal_type,
                "backend": settings.ai_gateway_backend,
                "provider": settings.ai_gateway_provider,
                "model": req.model,
                "trace_id": trace_id,
                "reason": exc.reason,
                "upstream_detail": exc.detail,
            },
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail=_gateway_error_detail(exc, trace_id),
        ) from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    payload = result.response.model_dump()
    payload.setdefault("cullis_trace_id", trace_id)

    weight = int(result.prompt_tokens) + int(result.completion_tokens)
    if settings.llm_tokens_per_minute > 0:
        await get_token_sum_limiter().consume(_token_bucket_key(agent), weight)
    if budget_enforced:
        # Settle the EG-2 reservation against actual usage.
        await get_budget_counter().add_delta(
            agent.agent_id, weight - reserve_tokens, datetime.now(timezone.utc),
        )

    await log_audit(
        agent_id=agent.agent_id,
        action="egress_llm_chat",
        status="success",
        duration_ms=float(latency_ms),
        details={
            "event": "llm.chat_completion",
            "principal_id": agent.agent_id,
            "principal_type": agent.principal_type,
            "backend": result.backend,
            "provider": result.provider,
            "model": req.model,
            "trace_id": trace_id,
            "upstream_request_id": result.upstream_request_id,
            "latency_ms": latency_ms,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "cost_usd": result.cost_usd,
            "cache_hit": False,
        },
    )

    logger.info(
        "egress_llm_chat agent=%s backend=%s model=%s latency_ms=%d trace_id=%s",
        agent.agent_id, result.backend, req.model, latency_ms, trace_id,
    )

    return payload


async def _handle_stream(
    *,
    req: ChatCompletionRequest,
    agent: InternalAgent,
    settings,
    trace_id: str,
    enforce_budget: bool = False,
    reserve_tokens: int = 0,
) -> StreamingResponse:
    """Open the upstream stream and fan it out as Server-Sent Events.

    The handler is split out so the generator below can ``finally``-write
    the audit row and consume the per-principal token budget regardless
    of how the stream ends (success, upstream error mid-stream, client
    disconnect). The ``data: [DONE]`` sentinel is appended only on the
    happy path; on upstream error we emit a single ``data: {"error":...}``
    frame so OpenAI-shaped clients see a terminal event.

    Terminal accounting (EG-1): a client disconnect used to land in the
    success branch with the adapter's drain-time token counts still at
    0 — no budget charge and a ``success`` audit row claiming 0/0
    tokens, i.e. indefinite evasion of the #1074 ceiling plus a chain
    that under-reports real spend (and poisons the seed-from-chain
    rebuild). Now the stream tracks whether the upstream actually
    drained; a partial drain settles the budget from the adapter's
    incremental counts (or a char-count estimate of what crossed the
    wire) and writes an honest ``truncated`` row instead of ``success``.
    """
    try:
        streamer: StreamingDispatch = await dispatch_stream(
            req=req,
            agent_id=agent.agent_id,
            org_id=settings.org_id,
            trace_id=trace_id,
            settings=settings,
        )
    except GatewayError as exc:
        if enforce_budget:
            # Refund the EG-2 reservation: the stream never opened.
            await get_budget_counter().add_delta(
                agent.agent_id, -reserve_tokens, datetime.now(timezone.utc),
            )
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            details={
                "event": "llm.chat_completion",
                "principal_id": agent.agent_id,
                "principal_type": agent.principal_type,
                "backend": settings.ai_gateway_backend,
                "provider": settings.ai_gateway_provider,
                "model": req.model,
                "trace_id": trace_id,
                "reason": exc.reason,
                "upstream_detail": exc.detail,
                "stream": True,
            },
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail=_gateway_error_detail(exc, trace_id),
        ) from exc

    # P1 Cullis Chat SSE backend — tool_call event emission.
    # ``tool_call_start`` and ``tool_call_end`` are named SSE events the
    # SPA's parser (frontend/cullis-chat/src/lib/sse.ts) listens to so
    # the ``ToolCallIndicator`` chip renders against real traffic, not
    # only against the mock ambassador. LiteLLM normalises every
    # provider (Anthropic, OpenAI, Bedrock, …) to the OpenAI delta
    # shape, so a single parser on ``delta.tool_calls`` covers them
    # all. Per-tool audit rows mirror the local audit conventions
    # established for ``egress_llm_chat`` and reuse the same trace_id.
    tool_state: dict[int, dict] = {}   # index → {name, started_at}
    tools_summary: list[dict] = []     # for the trailing cullis_audit event

    async def _emit_tool_end(idx: int, st: dict):
        latency_ms = int((time.monotonic() - st["started_at"]) * 1000)
        tools_summary.append({"name": st["name"], "latency_ms": latency_ms})
        try:
            await log_audit(
                agent_id=agent.agent_id,
                action="llm.tool_call",
                status="success",
                tool_name=st["name"],
                duration_ms=float(latency_ms),
                details={
                    "event": "llm.tool_call",
                    "principal_id": agent.agent_id,
                    "principal_type": agent.principal_type,
                    "backend": streamer.backend,
                    "provider": streamer.provider,
                    "model": req.model,
                    "trace_id": trace_id,
                    "tool": st["name"],
                    "latency_ms": latency_ms,
                },
            )
        except Exception as exc:
            # Audit failure must not break the SSE stream — the
            # surrounding ``egress_llm_chat`` row will still record
            # the overall request, and the operator will see the
            # log warning. ``audit_fail_deny`` decides whether the
            # individual log_audit raises; we swallow at the boundary
            # so a per-tool hiccup does not 500 the chat.
            logger.warning(
                "log_audit for tool_call %s failed: %s",
                st["name"], exc,
            )
        return latency_ms

    async def sse():
        terminated_with_error: GatewayError | None = None
        # EG-1 bookkeeping: ``upstream_drained`` flips once the adapter's
        # iterator is exhausted (the only point where drain-time usage
        # counts are trustworthy); ``observed_completion_chars`` counts
        # the delta text that actually crossed the wire, feeding the
        # estimation fallback when the adapter reported nothing.
        upstream_drained = False
        observed_completion_chars = 0
        try:
            async for chunk in streamer.aiter():
                # Inject the trace id on every chunk so a downstream
                # audit/observability consumer can correlate even on a
                # mid-stream client disconnect. The backend stays
                # trace-id-agnostic.
                chunk.setdefault("cullis_trace_id", trace_id)

                # Tool-call delta parser. Wrapped in a defensive
                # try/except so a malformed chunk from a misbehaving
                # provider does not poison the user-visible stream;
                # the data: frame is still yielded below regardless.
                try:
                    choices = chunk.get("choices") or []
                    if choices:
                        choice0 = choices[0]
                        delta = choice0.get("delta") or {}
                        content_piece = delta.get("content")
                        if isinstance(content_piece, str):
                            observed_completion_chars += len(content_piece)
                        tc_list = delta.get("tool_calls") or []
                        for tc in tc_list:
                            idx = tc.get("index", 0)
                            fn = tc.get("function") or {}
                            name = fn.get("name")
                            # ``name`` arrives on the first delta of a
                            # tool block; subsequent deltas carry only
                            # ``arguments`` increments. Emit
                            # tool_call_start exactly once per index.
                            if name and idx not in tool_state:
                                tool_state[idx] = {
                                    "name": name,
                                    "started_at": time.monotonic(),
                                }
                                yield (
                                    "event: tool_call_start\n"
                                    f"data: {json.dumps({'tool': name})}\n\n"
                                )

                        # ``finish_reason='tool_calls'`` closes every
                        # active tool block in this assistant turn.
                        finish = choice0.get("finish_reason")
                        if finish == "tool_calls" and tool_state:
                            for idx, st in list(tool_state.items()):
                                latency_ms = await _emit_tool_end(idx, st)
                                yield (
                                    "event: tool_call_end\n"
                                    f"data: {json.dumps({'tool': st['name'], 'latency_ms': latency_ms})}\n\n"
                                )
                                del tool_state[idx]
                except Exception as parser_exc:
                    logger.warning(
                        "tool_call SSE parser skipped chunk: %s",
                        parser_exc,
                    )

                yield f"data: {json.dumps(chunk)}\n\n"

            # The upstream iterator is exhausted — drain-time usage on
            # ``streamer`` is now authoritative. A disconnect on the
            # trailing frames below still counts as drained.
            upstream_drained = True

            # Trailing summary event the SPA uses to populate the
            # audit panel ("3 tools called in 470ms"). Shape mirrors
            # the mock ambassador (frontend/cullis-chat/mock/ambassador.mjs).
            if tools_summary:
                summary = {
                    "trace_id": trace_id,
                    "latency_ms": int(streamer.latency_ms),
                    "tools": tools_summary,
                }
                yield f"event: cullis_audit\ndata: {json.dumps(summary)}\n\n"
            yield "data: [DONE]\n\n"
        except GatewayError as exc:
            terminated_with_error = exc
            # Audit H-IO-2 — ``exc.detail`` comes from str(exc) of the
            # underlying httpx / LiteLLM / pydantic error and would echo
            # provider chatter (timeouts, auth-key fragments, schema
            # mismatch text) back to the SSE consumer. Keep it in the
            # audit row below for ops triage; on the wire emit only the
            # stable reason tag + trace id, plus ``exc.hint`` when set —
            # the hint is a self-authored, caller-safe line (no str(exc)),
            # so it is fine on the wire and tells the consumer why.
            err_frame = {
                "error": {
                    "type": exc.reason,
                    "message": exc.hint or exc.reason,
                    "trace_id": trace_id,
                },
            }
            yield f"data: {json.dumps(err_frame)}\n\n"
        finally:
            # EG-1 settlement — runs on every terminal path: full drain,
            # upstream error mid-stream, client disconnect (GeneratorExit
            # reaches this block when Starlette closes the generator).
            prompt_tokens = int(streamer.prompt_tokens)
            completion_tokens = int(streamer.completion_tokens)
            tokens_estimated = False
            errored = terminated_with_error is not None
            if not upstream_drained:
                # Most adapters only learn usage at full drain, so a cut
                # stream under-reports (often 0/0; Anthropic knows the
                # prompt from message_start but never sees the final
                # message_delta). Estimate each missing component from
                # what provably went through: the full prompt (the
                # provider processed it) and the delta text observed
                # before the cut. A gateway error before the first
                # observed byte is the one case left unestimated — that
                # request consumed nothing chargeable, same policy as
                # the pre-stream error path.
                observed_anything = (
                    prompt_tokens + completion_tokens > 0
                    or observed_completion_chars > 0
                )
                if observed_anything or not errored:
                    if prompt_tokens == 0:
                        prompt_tokens = _estimate_prompt_tokens(req)
                        tokens_estimated = True
                    if completion_tokens == 0 and observed_completion_chars > 0:
                        completion_tokens = (
                            observed_completion_chars // _CHARS_PER_TOKEN
                        )
                        tokens_estimated = True
            weight = prompt_tokens + completion_tokens

            if settings.llm_tokens_per_minute > 0 and weight > 0:
                await get_token_sum_limiter().consume(
                    _token_bucket_key(agent), weight,
                )
            if enforce_budget:
                # Settle the EG-2 reservation against what the stream
                # actually consumed (refund or top-up). Pre-fix the
                # error path never charged at all and the disconnect
                # path charged 0 — both indefinite cap-evasion vectors.
                await get_budget_counter().add_delta(
                    agent.agent_id, weight - reserve_tokens,
                    datetime.now(timezone.utc),
                )

            if errored:
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_llm_chat",
                    status="error",
                    details={
                        "event": "llm.chat_completion",
                        "principal_id": agent.agent_id,
                        "principal_type": agent.principal_type,
                        "backend": streamer.backend,
                        "provider": streamer.provider,
                        "model": req.model,
                        "trace_id": trace_id,
                        "reason": terminated_with_error.reason,
                        "upstream_detail": terminated_with_error.detail,
                        "stream": True,
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "tokens_estimated": tokens_estimated,
                    },
                )
            else:
                # Honest status (EG-1): ``success`` means the upstream
                # stream drained; a client disconnect mid-stream is
                # ``truncated``. The chain consumers
                # (sum_principal_tokens_since, aggregate_llm_usage)
                # filter on action only, so truncated rows keep feeding
                # the budget seed and the usage dashboard.
                status = "success" if upstream_drained else "truncated"
                details = {
                    "event": "llm.chat_completion",
                    "principal_id": agent.agent_id,
                    "principal_type": agent.principal_type,
                    "backend": streamer.backend,
                    "provider": streamer.provider,
                    "model": req.model,
                    "trace_id": trace_id,
                    "upstream_request_id": streamer.upstream_request_id,
                    "latency_ms": streamer.latency_ms,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "cost_usd": streamer.cost_usd,
                    "cache_hit": False,
                    "stream": True,
                }
                if status == "truncated":
                    details["reason"] = "stream_not_drained"
                    details["tokens_estimated"] = tokens_estimated
                await log_audit(
                    agent_id=agent.agent_id,
                    action="egress_llm_chat",
                    status=status,
                    duration_ms=float(streamer.latency_ms),
                    details=details,
                )
                logger.info(
                    "egress_llm_chat (stream) agent=%s backend=%s model=%s "
                    "status=%s latency_ms=%d trace_id=%s",
                    agent.agent_id, streamer.backend, req.model,
                    status, streamer.latency_ms, trace_id,
                )

    return StreamingResponse(
        sse(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Disable nginx response buffering so chunks reach the client
            # as they are produced, not at end-of-response.
            "X-Accel-Buffering": "no",
            "X-Cullis-Trace": trace_id,
        },
    )


@router.get("/v1/egress/models")
@router.get("/v1/models")
async def list_models(
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> dict:
    """OpenAI-compatible model list filtered by configured providers.

    Returns the union of model ids surfaced by every enabled row in
    ``ai_provider_credentials``, plus the static Anthropic catalog when
    a legacy deployment still relies on ``ANTHROPIC_API_KEY`` and has no
    DB row yet. Disabled rows are skipped so the SPA dropdown reflects
    what the gateway will actually accept right now.

    Auth: same mTLS+DPoP cert as the chat-completions endpoint, so the
    Ambassador can fetch the list with the user's principal cert and
    surface only models the org has paid keys for.
    """
    settings = get_settings()
    rows = await list_ai_provider_creds()
    enabled: list[tuple[str, dict[str, str]]] = [
        (r["provider"], dict(r["creds"] or {}))
        for r in rows
        if r["enabled"] and r["provider"] in PROVIDERS
    ]

    # Backward compat: the env-only deployments that have not yet
    # written an ``ai_provider_credentials`` row should still see the
    # Anthropic catalog so existing chat clients keep working.
    has_anthropic_row = any(p == "anthropic" for p, _ in enabled)
    if not has_anthropic_row and settings.anthropic_api_key:
        enabled.append(("anthropic", {"api_key": settings.anthropic_api_key}))

    data = await list_available_models(enabled)
    logger.debug(
        "egress.models served agent=%s providers=%s count=%d",
        agent.agent_id, [p for p, _ in enabled], len(data),
    )
    return {"object": "list", "data": data}
