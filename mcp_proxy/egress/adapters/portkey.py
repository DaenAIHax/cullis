"""Portkey REST adapter (legacy, Anthropic-only).

This adapter wraps the Portkey gateway HTTP call path that
``mcp_proxy/egress/ai_gateway.py`` carried directly prior to ADR-039.
Behaviour, log lines, error tags, and audit semantics are unchanged
relative to the pre-refactor ``_call_portkey`` function.

The Portkey backend was the original ADR-017 Phase 1 implementation and
only ever supported Anthropic. It is deprecated alongside the LiteLLM
backend in v0.7.x and removed in v0.8.x. Operators on Portkey today
migrate to ``cullis_native`` (Anthropic via the native SDK adapter).

Portkey does not support streaming through this adapter today;
``stream_chat_completion`` raises 501 just like the pre-refactor code.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import TYPE_CHECKING

import httpx

from mcp_proxy.egress.adapters.base import DispatchContext

if TYPE_CHECKING:
    from mcp_proxy.config import ProxySettings as Settings
    from mcp_proxy.egress.ai_gateway import GatewayResult, StreamingDispatch
    from mcp_proxy.egress.schemas import ChatCompletionRequest


_log = logging.getLogger("agent_trust.egress")


CULLIS_FORWARD_HEADERS = "X-Cullis-Agent,X-Cullis-Org,X-Cullis-Trace"


class PortkeyAdapter:
    """Forward chat completions to a configured Portkey gateway.

    The Portkey path only validates ``provider=anthropic`` against
    Portkey's chat-completions shim. The credential is still sourced
    through the dispatcher's DB-first resolver so deployments that have
    migrated to dashboard-managed keys keep working whichever backend
    they pin.
    """

    backend_name = "portkey"

    async def chat_completion(
        self,
        *,
        req: "ChatCompletionRequest",
        provider: str,
        creds: dict[str, str],
        ctx: DispatchContext,
        settings: "Settings",
    ) -> "GatewayResult":
        from mcp_proxy.egress.ai_gateway import (
            GatewayError,
            GatewayResult,
            scrub_secrets,
        )
        from mcp_proxy.egress.schemas import ChatCompletionResponse

        if provider != "anthropic":
            raise GatewayError(
                501,
                f"provider_not_implemented:{provider}",
                detail="The Portkey backend only supports Anthropic. "
                       "Switch ai_gateway_backend to litellm_embedded.",
            )
        api_key = creds.get("api_key", "")
        if not api_key:
            raise GatewayError(503, "provider_key_missing")

        upstream_url = f"{settings.ai_gateway_url.rstrip('/')}/v1/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "x-portkey-provider": provider,
            "x-portkey-trace-id": ctx.trace_id,
            "x-portkey-forward-headers": CULLIS_FORWARD_HEADERS,
            "x-portkey-metadata": json.dumps(
                {
                    "_user": ctx.agent_id,
                    "org_id": ctx.org_id,
                    "trace_id": ctx.trace_id,
                },
                separators=(",", ":"),
            ),
            "X-Cullis-Agent": ctx.agent_id,
            "X-Cullis-Org": ctx.org_id,
            "X-Cullis-Trace": ctx.trace_id,
        }

        body = req.model_dump(exclude_none=True)

        started = time.perf_counter()
        owns_client = ctx.http_client is None
        client = ctx.http_client or httpx.AsyncClient(
            timeout=settings.ai_gateway_request_timeout_s
        )
        try:
            try:
                resp = await client.post(upstream_url, headers=headers, json=body)
            except httpx.TimeoutException as exc:
                raise GatewayError(504, "upstream_timeout", detail=str(exc)) from exc
            except httpx.HTTPError as exc:
                raise GatewayError(
                    502, "upstream_unreachable", detail=str(exc),
                ) from exc
        finally:
            if owns_client:
                await client.aclose()

        latency_ms = int((time.perf_counter() - started) * 1000)

        if resp.status_code // 100 != 2:
            # Surface the upstream body in the audit detail (capped) so
            # operators can debug without re-running the call. Scrub
            # provider key shapes (B2) so a 401 echo like "Incorrect API
            # key provided: sk-ant-..." doesn't immortalise the rejected
            # key in the hash-chained audit log.
            detail = scrub_secrets(resp.text[:512]) if resp.text else None
            raise GatewayError(
                502,
                f"upstream_status_{resp.status_code}",
                detail=detail,
            )

        try:
            payload = resp.json()
        except ValueError as exc:
            raise GatewayError(
                502, "malformed_upstream_body", detail=str(exc),
            ) from exc

        payload.setdefault("id", f"chatcmpl-{uuid.uuid4().hex[:24]}")
        payload.setdefault("object", "chat.completion")
        payload.setdefault("created", int(time.time()))
        payload.setdefault("model", req.model)
        payload["cullis_trace_id"] = ctx.trace_id

        try:
            parsed = ChatCompletionResponse.model_validate(payload)
        except Exception as exc:  # pydantic ValidationError or similar
            # Audit F-B-119 — pydantic ValidationError ``str()`` interpolates
            # the offending input into the message. The input is the raw
            # upstream response — model output, tool args, conversation
            # context — and must not echo back to the OpenAI-shape caller.
            from mcp_proxy._http_safety import safe_http_detail
            raise GatewayError(
                502,
                "schema_mismatch",
                detail=safe_http_detail(
                    exc,
                    public_hint="upstream payload failed Mastio schema",
                    log_context="ai_gateway.portkey.parse_response",
                ),
            ) from exc

        upstream_request_id = (
            resp.headers.get("x-portkey-request-id")
            or resp.headers.get("x-request-id")
        )

        _log.info(
            "egress.llm dispatched backend=portkey provider=%s agent=%s org=%s "
            "model=%s latency_ms=%d tokens_in=%d tokens_out=%d",
            provider, ctx.agent_id, ctx.org_id, parsed.model, latency_ms,
            parsed.usage.prompt_tokens, parsed.usage.completion_tokens,
        )

        return GatewayResult(
            response=parsed,
            latency_ms=latency_ms,
            upstream_request_id=upstream_request_id,
            backend="portkey",
            provider=provider,
            prompt_tokens=int(parsed.usage.prompt_tokens or 0),
            completion_tokens=int(parsed.usage.completion_tokens or 0),
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
        from mcp_proxy.egress.ai_gateway import GatewayError

        raise GatewayError(
            501,
            "streaming_not_implemented_for_backend:portkey",
            detail=(
                "Streaming on backend 'portkey' is not wired. "
                "Set ai_gateway_backend=litellm_embedded for stream=true."
            ),
        )
