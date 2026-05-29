"""Anthropic Messages API surface on the Mastio (ADR-038 Path Y agnostic).

Mirror of ``llm_chat_router.py`` for the Anthropic-native shape:

  agent (mTLS+DPoP, vanilla anthropic SDK) → Mastio /v1/messages
                                          → translate to OpenAI shape
                                          → mcp_proxy.egress.ai_gateway.dispatch
                                          → litellm_embedded
                                          → translate response back to Anthropic shape

Why this exists: the vanilla ``anthropic.Anthropic()`` SDK POSTs to
``<base_url>/v1/messages`` and parses an Anthropic-shape response
(``content: [{type:"text", text:...}]``). The existing
``/v1/chat/completions`` endpoint speaks OpenAI shape and the SDK
cannot parse it. Without this router, the ``cullis_sdk.providers_compat``
drop-in helper for the Anthropic SDK 404s on the very first call.

Phase 0 scope:
  * Plain text content (the 99% case for chat).
  * Plain ``system`` string (top-level Anthropic field).
  * Tool definitions translated to OpenAI shape and back.
  * No streaming (``stream=true`` returns 501; ADR-038 Phase 1).
  * Same mTLS+DPoP+capability+rate-limit+audit gates as
    ``/v1/chat/completions``.

Audit row carries the same ``egress_llm_chat`` action so the dashboard
audit list does not fork; ``surface=anthropic_messages`` distinguishes
the two shapes inside the details payload.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_proxy.auth.builtin_capabilities import LLM_CHAT
from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.config import get_settings
from mcp_proxy.db import log_audit
from mcp_proxy.egress.ai_gateway import GatewayError, dispatch
from mcp_proxy.egress.provider_catalog import parse_provider_from_model
from mcp_proxy.egress.schemas import (
    ChatCompletionRequest,
    ChatMessage,
)
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.egress.anthropic_messages")

router = APIRouter(tags=["llm-chat"])


# ── Anthropic Messages API request schema (subset, Phase 0) ─────────────────
#
# Mirrors the public Anthropic SDK ``messages.create()`` arguments.
# Optional fields stay optional; we forward what we know how to translate
# and ignore the rest at this stage. Anything material that arrives and
# we do NOT yet support raises 501 rather than silently dropping (the
# silent-drop path was what burned the very first cold-reader of the
# OpenAI-compat endpoint pre-PR #707).


class _AnthropicTextBlock(BaseModel):
    type: str = "text"
    text: str


class _AnthropicMessage(BaseModel):
    role: str  # "user" | "assistant"
    # Anthropic accepts string OR list of content blocks. Phase 0 only
    # translates text blocks; tool-use / tool-result blocks raise 501.
    content: str | list[dict]


class AnthropicMessagesRequest(BaseModel):
    model: str
    max_tokens: int = Field(..., ge=1, le=8192)
    messages: list[_AnthropicMessage] = Field(..., min_length=1)
    system: str | None = None
    temperature: float | None = Field(None, ge=0.0, le=1.0)
    stop_sequences: list[str] | None = None
    stream: bool = False
    tools: list[dict] | None = None
    tool_choice: dict | None = None
    # Other Anthropic-specific fields (``metadata.user_id``, ``top_p``,
    # ``top_k``) are not forwarded in Phase 0; LiteLLM ``drop_params=True``
    # would discard them anyway if we put them through.


# ── Anthropic Messages API response shape (Phase 0 minimal) ─────────────────


class _AnthropicTextBlockOut(BaseModel):
    type: str = "text"
    text: str


class _AnthropicUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class AnthropicMessagesResponse(BaseModel):
    id: str
    type: str = "message"
    role: str = "assistant"
    model: str
    content: list[_AnthropicTextBlockOut]
    stop_reason: str | None = None  # "end_turn" | "max_tokens" | "stop_sequence"
    stop_sequence: str | None = None
    usage: _AnthropicUsage
    # Mastio extension — same convention as ``/v1/chat/completions``.
    cullis_trace_id: str


# ── Translation helpers ─────────────────────────────────────────────────────


def _flatten_content(content: str | list[dict]) -> str:
    """Anthropic content can be a string or a list of blocks. Phase 0
    flattens to a single text string; multimodal / tool blocks raise."""
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        btype = block.get("type")
        if btype == "text":
            parts.append(block.get("text", ""))
        else:
            raise HTTPException(
                status_code=501,
                detail={
                    "reason": "anthropic_content_block_not_implemented",
                    "block_type": btype,
                    "phase": "ADR-038 Phase 0 supports text blocks only; "
                             "tool_use / tool_result / image blocks land in Phase 1.",
                },
            )
    return "".join(parts)


def _to_chat_completion_request(
    req: AnthropicMessagesRequest,
) -> ChatCompletionRequest:
    """Anthropic Messages → OpenAI ChatCompletion shape.

    Anthropic puts ``system`` as a top-level string and the conversation
    in ``messages``. OpenAI prepends a ``role=system`` message inside
    ``messages``. We collapse the two into the OpenAI shape so LiteLLM
    handles it uniformly across providers.
    """
    chat_messages: list[ChatMessage] = []
    if req.system:
        chat_messages.append(ChatMessage(role="system", content=req.system))

    for m in req.messages:
        chat_messages.append(
            ChatMessage(role=m.role, content=_flatten_content(m.content)),
        )

    return ChatCompletionRequest(
        model=req.model,
        messages=chat_messages,
        max_tokens=req.max_tokens,
        temperature=req.temperature,
        stream=False,  # Phase 0 streaming guard raises before we reach here.
        tools=req.tools,
        tool_choice=req.tool_choice,
    )


_FINISH_TO_STOP = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "content_filter": "stop_sequence",
}


def _to_anthropic_response(
    *,
    openai_payload: dict,
    model: str,
    trace_id: str,
) -> AnthropicMessagesResponse:
    """OpenAI ChatCompletion → Anthropic Messages shape.

    Phase 0 only emits the text path. If the upstream returned tool_calls
    we surface a 502 with a clear message — the SDK customer would have
    expected an Anthropic-shape ``tool_use`` content block and getting an
    empty content array would silently break their tool loop. Better to
    fail loud.
    """
    choices = openai_payload.get("choices") or []
    if not choices:
        raise GatewayError(502, "empty_choices_from_litellm")

    first = choices[0]
    msg = first.get("message") or {}
    text_content = msg.get("content")
    tool_calls = msg.get("tool_calls")

    if tool_calls:
        raise HTTPException(
            status_code=501,
            detail={
                "reason": "tool_use_response_not_implemented",
                "phase": "ADR-038 Phase 0 returns text content only; "
                         "tool_use responses land in Phase 1. The upstream "
                         "model emitted tool_calls — switch to "
                         "/v1/chat/completions until Phase 1 ships.",
            },
        )

    if not isinstance(text_content, str):
        # LiteLLM normally returns a string; defensive cast for the
        # edge case where a provider emits a list-of-blocks the SDK
        # surfaces as-is.
        text_content = str(text_content or "")

    finish_reason = first.get("finish_reason") or "stop"
    stop_reason = _FINISH_TO_STOP.get(finish_reason, "end_turn")

    usage_in = openai_payload.get("usage") or {}

    return AnthropicMessagesResponse(
        id=openai_payload.get("id") or f"msg_{uuid.uuid4().hex[:24]}",
        model=openai_payload.get("model") or model,
        content=[_AnthropicTextBlockOut(text=text_content)],
        stop_reason=stop_reason,
        usage=_AnthropicUsage(
            input_tokens=int(usage_in.get("prompt_tokens") or 0),
            output_tokens=int(usage_in.get("completion_tokens") or 0),
        ),
        cullis_trace_id=trace_id,
    )


# ── Router endpoint ─────────────────────────────────────────────────────────


@router.post("/v1/messages")
async def anthropic_messages(
    req: AnthropicMessagesRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> dict[str, Any]:
    """Anthropic Messages API endpoint (ADR-038 agnostic — Phase 0).

    Same security gates as ``/v1/chat/completions``: mTLS client cert,
    DPoP proof, scope_providers (if set on the principal), rate limits
    (enforced at the LiteLLM dispatch boundary, not duplicated here),
    and an ``egress_llm_chat`` audit row with
    ``surface=anthropic_messages``.
    """
    settings = get_settings()
    trace_id = f"trace_{uuid.uuid4().hex[:16]}"

    # Capability gate (#22) — symmetric to ``/v1/chat/completions``.
    # The docstring above promises "Same security gates as
    # ``/v1/chat/completions``" but pre-v0.6.4 neither the capability
    # gate nor scope_providers was actually applied here. Any agent
    # could egress via the Anthropic shape regardless of its
    # capabilities. Fixed alongside #22 (audit 2026-05-28 BLOCKER B1).
    if LLM_CHAT not in (agent.capabilities or []):
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="denied",
            details={
                "event": "llm.chat_completion",
                "surface": "anthropic_messages",
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

    # scope_providers gate — also previously documented but not
    # enforced on this router. Mirrors the llm_chat_router behaviour.
    if agent.scope_providers:
        try:
            req_provider = parse_provider_from_model(req.model)
        except Exception as exc:  # noqa: BLE001 — parse failure → deny
            _log.warning(
                "parse_provider_from_model failed for %r: %s", req.model, exc,
            )
            req_provider = None
        if req_provider is None or req_provider not in agent.scope_providers:
            await log_audit(
                agent_id=agent.agent_id,
                action="egress_llm_chat",
                status="denied",
                details={
                    "event": "llm.chat_completion",
                    "surface": "anthropic_messages",
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

    if req.stream:
        raise HTTPException(
            status_code=501,
            detail={
                "reason": "streaming_not_implemented",
                "phase": "ADR-038 Phase 0 does not yet wire SSE for "
                         "/v1/messages. Streaming lands in Phase 1; "
                         "until then use /v1/chat/completions (OpenAI "
                         "shape) which has streaming.",
            },
        )

    chat_req = _to_chat_completion_request(req)

    started = time.perf_counter()
    try:
        result = await dispatch(
            req=chat_req,
            agent_id=agent.agent_id,
            org_id=settings.org_id,
            trace_id=trace_id,
            settings=settings,
        )
    except GatewayError as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            details={
                "event": "llm.chat_completion",
                "surface": "anthropic_messages",
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
            detail={"reason": exc.reason, "trace_id": trace_id},
        ) from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    openai_payload = result.response.model_dump()

    anthropic_resp = _to_anthropic_response(
        openai_payload=openai_payload,
        model=req.model,
        trace_id=trace_id,
    )

    await log_audit(
        agent_id=agent.agent_id,
        action="egress_llm_chat",
        status="success",
        duration_ms=float(latency_ms),
        details={
            "event": "llm.chat_completion",
            "surface": "anthropic_messages",
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

    _log.info(
        "anthropic_messages agent=%s backend=%s model=%s latency_ms=%d trace_id=%s",
        agent.agent_id, result.backend, req.model, latency_ms, trace_id,
    )

    return anthropic_resp.model_dump()
