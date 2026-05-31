"""Native Anthropic adapter (ADR-039 PR-B).

Uses ``anthropic.AsyncAnthropic`` directly, no LiteLLM. Translates the
Mastio's OpenAI ChatCompletion request shape to Anthropic Messages API
shape on the way out, then translates the Anthropic response (or
streaming events) back to OpenAI shape on the way in. Identity, audit,
rate limiting, and the rest of the Mastio pipeline stay above this
adapter; the adapter is only the wire boundary to Anthropic.

What this covers
  - Single-turn and multi-turn chat completion (non-stream).
  - Streaming chat completion (SSE → OpenAI chunk format).
  - Tool use (declaration + invocation + tool_result history).
  - Prompt caching (``cache_control`` markers pass through on system
    and user message content blocks).
  - Stop sequences, temperature, top_p, max_tokens.
  - Error mapping per ``_ANTHROPIC_ERROR_MAP``.

What is out of scope for PR-B
  - Multi-modal (image_url content blocks). Returns a 400 with
    ``provider_unsupported_param`` if encountered.
  - ``response_format={"type": "json_object"}``. Returns a 400; the
    customer can land a system-message nudge themselves.
  - Reasoning/thinking blocks. Returns whatever Anthropic emits; the
    OpenAI shape has no canonical place for them yet.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any, AsyncIterator

from mcp_proxy.egress.adapters.base import DispatchContext

if TYPE_CHECKING:
    from mcp_proxy.config import ProxySettings as Settings
    from mcp_proxy.egress.ai_gateway import GatewayResult, StreamingDispatch
    from mcp_proxy.egress.schemas import ChatCompletionRequest


_log = logging.getLogger("agent_trust.egress")


# Anthropic SDK exception class names → (HTTP status, audit reason).
# Comparing by class name keeps the import of ``anthropic`` lazy, same
# pattern as the LiteLLM adapter.
_ANTHROPIC_ERROR_MAP: dict[str, tuple[int, str]] = {
    "AuthenticationError": (401, "provider_auth_failed"),
    "PermissionDeniedError": (403, "provider_permission_denied"),
    "NotFoundError": (404, "provider_not_found"),
    "RateLimitError": (429, "provider_rate_limited"),
    "BadRequestError": (400, "provider_bad_request"),
    "UnprocessableEntityError": (422, "provider_unprocessable"),
    "ConflictError": (409, "provider_conflict"),
    "APITimeoutError": (504, "provider_timeout"),
    "APIConnectionError": (502, "provider_unreachable"),
    "InternalServerError": (502, "provider_internal_error"),
    "APIStatusError": (502, "provider_api_error"),
    "APIError": (502, "provider_api_error"),
}


# Anthropic stop_reason → OpenAI finish_reason.
_STOP_REASON_MAP: dict[str, str] = {
    "end_turn": "stop",
    "max_tokens": "length",
    "stop_sequence": "stop",
    "tool_use": "tool_calls",
}


def _map_anthropic_exception(
    exc: Exception, *, model: str | None = None
) -> "GatewayError":
    from mcp_proxy.egress.ai_gateway import GatewayError, caller_hint, scrub_secrets

    cls = type(exc).__name__
    status, reason = _ANTHROPIC_ERROR_MAP.get(cls, (502, "provider_unknown_error"))
    detail = scrub_secrets((str(exc) or cls)[:512])
    hint = caller_hint(reason, model=model, provider="anthropic")
    return GatewayError(status, reason, detail=detail, hint=hint)


# ── request translation: OpenAI → Anthropic ───────────────────────────


def _translate_tool_choice(tc: Any) -> dict[str, Any] | None:
    """OpenAI tool_choice → Anthropic tool_choice (or None if "none")."""
    if tc is None:
        return None
    if isinstance(tc, str):
        if tc == "auto":
            return {"type": "auto"}
        if tc == "required":
            return {"type": "any"}
        if tc == "none":
            return None  # caller drops tools[] entirely when this is the case
        return {"type": "auto"}  # unknown shorthand, fail-safe to auto
    if isinstance(tc, dict):
        if tc.get("type") == "function":
            name = (tc.get("function") or {}).get("name")
            if name:
                return {"type": "tool", "name": name}
        # Already Anthropic-shape, pass through (advanced callers can do this
        # via OpenAI's extra_body / extra_params)
        if tc.get("type") in {"auto", "any", "tool"}:
            return tc
    return {"type": "auto"}


def _translate_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    """OpenAI tools → Anthropic tools."""
    if not tools:
        return None
    out = []
    for t in tools:
        # OpenAI: {"type": "function", "function": {"name", "description", "parameters"}}
        fn = t.get("function") if isinstance(t, dict) else None
        if not fn:
            # Already Anthropic-shape (advanced callers via extra_body)
            if isinstance(t, dict) and t.get("name") and t.get("input_schema"):
                out.append(t)
            continue
        entry = {
            "name": fn.get("name"),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
        }
        # Preserve cache_control if the caller marked the tool definition.
        if "cache_control" in t:
            entry["cache_control"] = t["cache_control"]
        out.append(entry)
    return out or None


def _translate_messages(
    messages: list[dict[str, Any]],
) -> tuple[Any | None, list[dict[str, Any]]]:
    """Translate the OpenAI ``messages`` array.

    Returns ``(system, anthropic_messages)`` where ``system`` is either
    ``None``, a string, or a list of system content blocks (the latter
    when the caller marks the system prompt with ``cache_control`` to
    take advantage of Anthropic prompt caching).
    """
    system_chunks: list[dict[str, Any]] = []
    out: list[dict[str, Any]] = []
    pending_assistant_tool_calls: list[dict[str, Any]] = []

    def _user_content_blocks(msg: dict[str, Any]) -> list[dict[str, Any]]:
        c = msg.get("content")
        blocks: list[dict[str, Any]] = []
        if isinstance(c, str):
            if c != "":
                block: dict[str, Any] = {"type": "text", "text": c}
                if "cache_control" in msg:
                    block["cache_control"] = msg["cache_control"]
                blocks.append(block)
        elif isinstance(c, list):
            for item in c:
                if not isinstance(item, dict):
                    continue
                itype = item.get("type")
                if itype == "text":
                    block = {"type": "text", "text": item.get("text", "")}
                    if "cache_control" in item:
                        block["cache_control"] = item["cache_control"]
                    blocks.append(block)
                elif itype == "image_url":
                    # Multi-modal: out of scope for PR-B.
                    from mcp_proxy.egress.ai_gateway import GatewayError
                    raise GatewayError(
                        400,
                        "provider_unsupported_param",
                        detail=(
                            "image_url content blocks are not yet wired on "
                            "the native Anthropic adapter (ADR-039 PR-B). "
                            "Pin MCP_PROXY_AI_GATEWAY_BACKEND=litellm_embedded "
                            "to keep the multi-modal path until PR-F lands."
                        ),
                    )
        return blocks

    for msg in messages:
        role = msg.get("role")
        if role == "system":
            # Anthropic system can be a string or list of blocks. We always
            # emit blocks so cache_control passes through cleanly.
            content = msg.get("content")
            if isinstance(content, str) and content:
                block: dict[str, Any] = {"type": "text", "text": content}
                if "cache_control" in msg:
                    block["cache_control"] = msg["cache_control"]
                system_chunks.append(block)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        block = {"type": "text", "text": item.get("text", "")}
                        if "cache_control" in item:
                            block["cache_control"] = item["cache_control"]
                        system_chunks.append(block)
            continue

        if role == "user":
            blocks = _user_content_blocks(msg)
            if blocks:
                out.append({"role": "user", "content": blocks})
            continue

        if role == "assistant":
            content_blocks: list[dict[str, Any]] = []
            c = msg.get("content")
            if isinstance(c, str) and c:
                content_blocks.append({"type": "text", "text": c})
            tcs = msg.get("tool_calls") or []
            for tc in tcs:
                fn = tc.get("function") or {}
                raw_args = fn.get("arguments") or "{}"
                try:
                    parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except json.JSONDecodeError:
                    parsed_args = {}
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id") or f"tool_{uuid.uuid4().hex[:24]}",
                    "name": fn.get("name") or "",
                    "input": parsed_args,
                })
            if content_blocks:
                out.append({"role": "assistant", "content": content_blocks})
            continue

        if role == "tool":
            # OpenAI: separate "tool" message with tool_call_id + content.
            # Anthropic: tool_result block under a user message; we coalesce
            # consecutive tool results into one user message per spec.
            tool_use_id = msg.get("tool_call_id") or ""
            tool_content = msg.get("content")
            if isinstance(tool_content, list):
                result_content: Any = tool_content
            else:
                result_content = str(tool_content) if tool_content is not None else ""
            tr_block = {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": result_content,
            }
            if out and out[-1].get("role") == "user" and isinstance(out[-1]["content"], list):
                # Coalesce into the most recent user message if it's already
                # a tool_result container; otherwise start a fresh one.
                last_blocks = out[-1]["content"]
                if last_blocks and last_blocks[0].get("type") == "tool_result":
                    last_blocks.append(tr_block)
                    continue
            out.append({"role": "user", "content": [tr_block]})
            continue

        # Unknown role — ignore. The Anthropic SDK would reject; we mirror
        # OpenAI's permissive parse and drop silently.

    if not system_chunks:
        system: Any | None = None
    elif len(system_chunks) == 1 and "cache_control" not in system_chunks[0]:
        # Plain single-block system: use the simpler string form.
        system = system_chunks[0].get("text", "")
    else:
        system = system_chunks

    return system, out


def translate_request(req_body: dict[str, Any]) -> dict[str, Any]:
    """OpenAI ChatCompletion body → Anthropic Messages API kwargs.

    Pure function. Test target. ``req_body`` is the ``model_dump`` of a
    ``ChatCompletionRequest`` with ``stream``/``stream_options`` already
    stripped if needed by the caller.
    """
    from mcp_proxy.egress.ai_gateway import GatewayError

    model = req_body.get("model")
    if not model:
        raise GatewayError(400, "provider_bad_request", detail="model is required")

    # Anthropic requires max_tokens; OpenAI defaults to None. We default to a
    # generous-but-bounded value when missing so the call doesn't 400.
    max_tokens = req_body.get("max_tokens") or 4096

    if req_body.get("response_format"):
        raise GatewayError(
            400,
            "provider_unsupported_param",
            detail=(
                "response_format is not natively supported on Anthropic. "
                "Add a system-message JSON nudge, or pin "
                "MCP_PROXY_AI_GATEWAY_BACKEND=litellm_embedded."
            ),
        )

    system, anthropic_messages = _translate_messages(req_body.get("messages") or [])

    out: dict[str, Any] = {
        "model": model,
        "messages": anthropic_messages,
        "max_tokens": int(max_tokens),
    }
    if system is not None:
        out["system"] = system

    # tools + tool_choice
    raw_tool_choice = req_body.get("tool_choice")
    raw_tools = req_body.get("tools")
    drop_tools = isinstance(raw_tool_choice, str) and raw_tool_choice == "none"
    if not drop_tools:
        tools = _translate_tools(raw_tools)
        if tools is not None:
            out["tools"] = tools
        tc = _translate_tool_choice(raw_tool_choice)
        if tc is not None and tools:
            out["tool_choice"] = tc

    # Passthrough sampling params
    for key in ("temperature", "top_p", "top_k"):
        if req_body.get(key) is not None:
            out[key] = req_body[key]

    stop = req_body.get("stop")
    if stop is not None:
        if isinstance(stop, str):
            out["stop_sequences"] = [stop]
        elif isinstance(stop, list):
            out["stop_sequences"] = [s for s in stop if isinstance(s, str)]

    # Stream-specific knobs are handled by the caller (chat_completion vs
    # stream_chat_completion). We don't propagate ``stream`` here.

    return out


# ── response translation: Anthropic → OpenAI ──────────────────────────


def _join_text_blocks(blocks: list[Any]) -> str:
    out: list[str] = []
    for b in blocks:
        bt = getattr(b, "type", None) or (b.get("type") if isinstance(b, dict) else None)
        if bt == "text":
            text = getattr(b, "text", None) or (b.get("text") if isinstance(b, dict) else "")
            if text:
                out.append(text)
    return "".join(out)


def _extract_tool_calls(blocks: list[Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for b in blocks:
        bt = getattr(b, "type", None) or (b.get("type") if isinstance(b, dict) else None)
        if bt != "tool_use":
            continue
        tid = getattr(b, "id", None) or (b.get("id") if isinstance(b, dict) else None)
        name = getattr(b, "name", None) or (b.get("name") if isinstance(b, dict) else None)
        inp = getattr(b, "input", None)
        if inp is None and isinstance(b, dict):
            inp = b.get("input")
        try:
            args_json = json.dumps(inp if inp is not None else {})
        except (TypeError, ValueError):
            args_json = "{}"
        calls.append({
            "id": tid or f"tool_{uuid.uuid4().hex[:24]}",
            "type": "function",
            "function": {"name": name or "", "arguments": args_json},
        })
    return calls


def translate_response(
    message: Any,
    *,
    request_model: str,
    trace_id: str,
) -> dict[str, Any]:
    """Anthropic Messages API response → OpenAI ChatCompletion payload.

    Pure function. Test target. ``message`` is either an
    ``anthropic.types.Message`` SDK object or a dict (the SDK's
    ``.model_dump()`` output also works).
    """
    blocks = getattr(message, "content", None)
    if blocks is None and isinstance(message, dict):
        blocks = message.get("content") or []
    blocks = blocks or []

    text = _join_text_blocks(blocks)
    tool_calls = _extract_tool_calls(blocks)

    msg_payload: dict[str, Any] = {"role": "assistant"}
    msg_payload["content"] = text or None
    if tool_calls:
        msg_payload["tool_calls"] = tool_calls

    stop_reason = (
        getattr(message, "stop_reason", None)
        or (message.get("stop_reason") if isinstance(message, dict) else None)
    )
    finish_reason = _STOP_REASON_MAP.get(stop_reason or "", "stop")

    usage = getattr(message, "usage", None)
    if usage is None and isinstance(message, dict):
        usage = message.get("usage") or {}

    def _u(key: str) -> int:
        val = getattr(usage, key, None)
        if val is None and isinstance(usage, dict):
            val = usage.get(key)
        return int(val or 0)

    prompt_tokens = _u("input_tokens")
    completion_tokens = _u("output_tokens")

    msg_id = (
        getattr(message, "id", None)
        or (message.get("id") if isinstance(message, dict) else None)
        or f"msg_{uuid.uuid4().hex[:24]}"
    )
    response_model = (
        getattr(message, "model", None)
        or (message.get("model") if isinstance(message, dict) else None)
        or request_model
    )

    payload = {
        "id": f"chatcmpl-{msg_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": response_model,
        "choices": [{
            "index": 0,
            "message": msg_payload,
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
        "cullis_trace_id": trace_id,
    }
    return payload


# ── streaming translation ─────────────────────────────────────────────


class _StreamAccumulator:
    """Per-stream state for translating Anthropic events to OpenAI chunks.

    Tracks the running text and tool_use blocks under construction so we
    can emit OpenAI tool_calls deltas as Anthropic delivers
    ``input_json_delta`` fragments.
    """

    def __init__(self, *, model: str, trace_id: str) -> None:
        self.chunk_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        self.created = int(time.time())
        self.model = model
        self.trace_id = trace_id
        # index in Anthropic content_block_start order → openai tool index
        self._tool_index: dict[int, int] = {}
        self._next_tool_index = 0
        # block index → "text" | "tool_use"
        self._block_kind: dict[int, str] = {}
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.stop_reason: str | None = None
        self.upstream_message_id: str | None = None
        self.role_emitted = False

    def _envelope(self, *, choices: list[dict[str, Any]], finish: bool = False,
                  usage: dict[str, Any] | None = None) -> dict[str, Any]:
        chunk = {
            "id": self.chunk_id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": choices,
        }
        if usage is not None:
            chunk["usage"] = usage
        return chunk

    def on_message_start(self, msg: Any) -> dict[str, Any] | None:
        self.upstream_message_id = (
            getattr(msg, "id", None)
            or (msg.get("id") if isinstance(msg, dict) else None)
        )
        usage = getattr(msg, "usage", None)
        if usage is None and isinstance(msg, dict):
            usage = msg.get("usage") or {}
        if usage is not None:
            self.prompt_tokens = int(
                getattr(usage, "input_tokens", None)
                or (usage.get("input_tokens") if isinstance(usage, dict) else 0)
                or 0
            )
        # Emit the first chunk with the role marker so OpenAI consumers see
        # the canonical "role": "assistant" delta they expect at stream open.
        self.role_emitted = True
        return self._envelope(choices=[{
            "index": 0,
            "delta": {"role": "assistant", "content": ""},
            "finish_reason": None,
        }])

    def on_content_block_start(self, block_index: int, block: Any) -> dict[str, Any] | None:
        bt = (
            getattr(block, "type", None)
            or (block.get("type") if isinstance(block, dict) else None)
        )
        if bt == "text":
            self._block_kind[block_index] = "text"
            return None
        if bt == "tool_use":
            self._block_kind[block_index] = "tool_use"
            tidx = self._next_tool_index
            self._next_tool_index += 1
            self._tool_index[block_index] = tidx
            tid = (
                getattr(block, "id", None)
                or (block.get("id") if isinstance(block, dict) else None)
                or f"tool_{uuid.uuid4().hex[:24]}"
            )
            name = (
                getattr(block, "name", None)
                or (block.get("name") if isinstance(block, dict) else None)
                or ""
            )
            return self._envelope(choices=[{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": tidx,
                        "id": tid,
                        "type": "function",
                        "function": {"name": name, "arguments": ""},
                    }],
                },
                "finish_reason": None,
            }])
        return None

    def on_content_block_delta(self, block_index: int, delta: Any) -> dict[str, Any] | None:
        dt = (
            getattr(delta, "type", None)
            or (delta.get("type") if isinstance(delta, dict) else None)
        )
        if dt == "text_delta":
            text = (
                getattr(delta, "text", None)
                or (delta.get("text") if isinstance(delta, dict) else "")
                or ""
            )
            if not text:
                return None
            return self._envelope(choices=[{
                "index": 0,
                "delta": {"content": text},
                "finish_reason": None,
            }])
        if dt == "input_json_delta":
            partial = (
                getattr(delta, "partial_json", None)
                or (delta.get("partial_json") if isinstance(delta, dict) else "")
                or ""
            )
            tidx = self._tool_index.get(block_index)
            if tidx is None or not partial:
                return None
            return self._envelope(choices=[{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": tidx,
                        "function": {"arguments": partial},
                    }],
                },
                "finish_reason": None,
            }])
        # thinking_delta and other future deltas: ignore for now.
        return None

    def on_message_delta(self, delta: Any, usage: Any) -> None:
        stop = (
            getattr(delta, "stop_reason", None)
            or (delta.get("stop_reason") if isinstance(delta, dict) else None)
        )
        if stop:
            self.stop_reason = stop
        if usage is not None:
            out_tokens = (
                getattr(usage, "output_tokens", None)
                or (usage.get("output_tokens") if isinstance(usage, dict) else 0)
                or 0
            )
            in_tokens = (
                getattr(usage, "input_tokens", None)
                or (usage.get("input_tokens") if isinstance(usage, dict) else None)
            )
            self.completion_tokens = int(out_tokens)
            if in_tokens is not None:
                # message_delta may carry the authoritative prompt_tokens
                # including any cached read; honour it over the message_start
                # value.
                self.prompt_tokens = int(in_tokens)

    def build_final_chunk(self) -> dict[str, Any]:
        finish_reason = _STOP_REASON_MAP.get(self.stop_reason or "", "stop")
        return self._envelope(
            choices=[{
                "index": 0,
                "delta": {},
                "finish_reason": finish_reason,
            }],
            usage={
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.prompt_tokens + self.completion_tokens,
            },
        )


# ── adapter ───────────────────────────────────────────────────────────


# ── client cache ──────────────────────────────────────────────────────
#
# The Anthropic SDK's ``AsyncAnthropic`` keeps an internal httpx client
# with connection pooling. Constructing a new instance per request
# (the pre-PR-I behaviour) defeats that pool and forces TCP + TLS
# handshakes on every chat completion. We cache one client per
# credentials fingerprint so back-to-back calls under load reuse the
# warm connection pool, while a dashboard-side key rotation still
# invalidates the cache automatically (different fingerprint, miss,
# rebuild).
#
# Cache is module-level and worker-local: each uvicorn worker has its
# own dict. The cache holds a small, bounded set of entries (1 per
# active credentials configuration) so no LRU eviction is needed; a
# pathological case with N rotations would leak the prior client until
# process exit, which is acceptable given the Python GC will close
# httpx pools on object collection.

_CLIENT_CACHE: dict[str, Any] = {}


def _creds_fingerprint(creds: dict[str, str], settings: "Settings") -> str:
    """Stable hash of the inputs that drive AsyncAnthropic construction.

    Any change to ``api_key`` / ``base_url`` / ``timeout`` (dashboard
    rotation, env reload, settings update) yields a different
    fingerprint, which forces a cache miss + rebuild on the next call.
    """
    import hashlib
    import json
    payload = {
        "api_key": creds.get("api_key") or "",
        "base_url": creds.get("api_base") or creds.get("base_url") or "",
        "timeout": float(getattr(settings, "ai_gateway_request_timeout_s", 0) or 0),
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _client(creds: dict[str, str], settings: "Settings") -> Any:
    """Return a cached AsyncAnthropic client for the given credentials.

    The client lazy-imports the SDK on first call; subsequent calls
    with the same credentials reuse the same instance (and its
    internal httpx connection pool). Credentials rotation invalidates
    the cache via the fingerprint check.
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
        from anthropic import AsyncAnthropic
    except ImportError as exc:  # pragma: no cover — anthropic is a hard dep
        raise GatewayError(
            503,
            "provider_sdk_missing",
            detail=(
                "anthropic SDK is required for the native Anthropic adapter. "
                "It ships as a top-level dependency in requirements.txt."
            ),
        ) from exc

    kwargs: dict[str, Any] = {"api_key": api_key}
    base_url = creds.get("api_base") or creds.get("base_url")
    if base_url:
        kwargs["base_url"] = base_url
    timeout = getattr(settings, "ai_gateway_request_timeout_s", None)
    if timeout:
        kwargs["timeout"] = float(timeout)
    client = AsyncAnthropic(**kwargs)
    _CLIENT_CACHE[fingerprint] = client
    return client


class AnthropicAdapter:
    """Talk to Anthropic via the official SDK, no LiteLLM."""

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

        body = req.model_dump(exclude_none=True)
        body.pop("stream", None)
        body.pop("stream_options", None)
        anthropic_kwargs = translate_request(body)
        request_model = anthropic_kwargs["model"]

        client = _client(creds, settings)
        started = time.perf_counter()
        try:
            message = await client.messages.create(**anthropic_kwargs)
        except Exception as exc:
            gw_err = _map_anthropic_exception(exc, model=request_model)
            _log.warning(
                "anthropic_native error agent=%s model=%s reason=%s detail=%s",
                ctx.agent_id, request_model, gw_err.reason, gw_err.detail,
            )
            raise gw_err from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        payload = translate_response(
            message,
            request_model=request_model,
            trace_id=ctx.trace_id,
        )

        try:
            parsed = ChatCompletionResponse.model_validate(payload)
        except Exception as exc:
            from mcp_proxy._http_safety import safe_http_detail
            raise GatewayError(
                502,
                "schema_mismatch",
                detail=safe_http_detail(
                    exc,
                    public_hint="Anthropic response failed Mastio schema",
                    log_context="ai_gateway.anthropic_native.parse_response",
                ),
            ) from exc

        upstream_request_id = (
            getattr(message, "id", None)
            or (message.get("id") if isinstance(message, dict) else None)
        )

        prompt_tokens = int(payload["usage"]["prompt_tokens"])
        completion_tokens = int(payload["usage"]["completion_tokens"])

        _log.info(
            "egress.llm dispatched backend=cullis_native provider=anthropic "
            "agent=%s org=%s model=%s latency_ms=%d tokens_in=%d tokens_out=%d",
            ctx.agent_id, ctx.org_id, request_model, latency_ms,
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

        body = req.model_dump(exclude_none=True)
        body.pop("stream", None)
        body.pop("stream_options", None)
        anthropic_kwargs = translate_request(body)
        request_model = anthropic_kwargs["model"]

        client = _client(creds, settings)

        dispatch_obj = StreamingDispatch(
            backend="cullis_native",
            provider=provider,
            model=request_model,
            trace_id=ctx.trace_id,
        )

        async def _aiter() -> AsyncIterator[dict]:
            acc = _StreamAccumulator(model=request_model, trace_id=ctx.trace_id)
            try:
                async with client.messages.stream(**anthropic_kwargs) as stream:
                    async for event in stream:
                        et = getattr(event, "type", None)
                        chunk: dict[str, Any] | None = None
                        if et == "message_start":
                            chunk = acc.on_message_start(getattr(event, "message", None))
                        elif et == "content_block_start":
                            chunk = acc.on_content_block_start(
                                getattr(event, "index", 0),
                                getattr(event, "content_block", None),
                            )
                        elif et == "content_block_delta":
                            chunk = acc.on_content_block_delta(
                                getattr(event, "index", 0),
                                getattr(event, "delta", None),
                            )
                        elif et == "message_delta":
                            acc.on_message_delta(
                                getattr(event, "delta", None),
                                getattr(event, "usage", None),
                            )
                        elif et in {"content_block_stop", "message_stop"}:
                            pass
                        if chunk is not None:
                            if dispatch_obj.upstream_request_id is None and acc.upstream_message_id:
                                dispatch_obj.upstream_request_id = acc.upstream_message_id
                            yield chunk
                # Final OpenAI chunk with finish_reason + usage.
                final_chunk = acc.build_final_chunk()
                dispatch_obj.prompt_tokens = acc.prompt_tokens
                dispatch_obj.completion_tokens = acc.completion_tokens
                yield final_chunk
            except Exception as exc:
                raise _map_anthropic_exception(exc, model=request_model) from exc
            finally:
                dispatch_obj.latency_ms = int(
                    (time.perf_counter() - dispatch_obj.started_at) * 1000
                )
                _log.info(
                    "egress.llm streamed backend=cullis_native provider=anthropic "
                    "agent=%s org=%s model=%s latency_ms=%d tokens_in=%d tokens_out=%d",
                    ctx.agent_id, ctx.org_id, request_model,
                    dispatch_obj.latency_ms,
                    dispatch_obj.prompt_tokens, dispatch_obj.completion_tokens,
                )

        dispatch_obj._aiter_factory = _aiter
        return dispatch_obj
