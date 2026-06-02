"""Native Ollama adapter (ADR-039 PR-D).

Talks to a local (or operator-reachable) Ollama daemon via raw httpx,
no third-party SDK. The Ollama HTTP API is small enough that an SDK
would add more dependency surface than it saves: we POST JSON to
``{api_base}/api/chat`` and (for streaming) iterate the JSONL response
body.

What this adapter covers

  - Non-streaming chat completion (single POST, one JSON body back).
  - Streaming chat completion (JSONL body, one JSON object per line).
  - Tool use round-trip. Ollama's ``role: "tool"`` message shape is
    compatible with OpenAI's, so the message list passes through with
    minimal translation; tool_calls in the response have ``id`` synthesised
    when the local model omits one (frequent on small Llama / Qwen tags).
  - Sampling params translation. OpenAI passes ``temperature`` / ``top_p``
    / ``top_k`` / ``max_tokens`` / ``stop`` / ``seed`` at the top level;
    Ollama groups them under ``options`` with one rename (``max_tokens``
    -> ``num_predict``).
  - JSON-mode passthrough. ``response_format={"type": "json_object"}``
    maps to Ollama's ``format: "json"``; structured JSON schema
    (``response_format={"type": "json_schema", ...}``) maps to
    ``format: <schema>``.
  - SSRF guard on every request. Defense-in-depth: validate_creds
    refuses unsafe URLs at admin-write time, this re-checks on each
    call to catch DB-row drift, manual SQL, or schema migrations.
  - Error mapping for HTTP 4xx / 5xx, connection failures, timeouts.

Out of scope for PR-D

  - Cost computation. Ollama is local; cost_usd is always None.
  - Multi-modal ``images`` field. Ollama supports it natively, but the
    OpenAI ``image_url`` shape needs base64 transcoding; deferred to
    a follow-on that also lands multi-modal on Anthropic.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any, AsyncIterator

import httpx

from mcp_proxy.egress.adapters.base import DispatchContext

if TYPE_CHECKING:
    from mcp_proxy.config import ProxySettings as Settings
    from mcp_proxy.egress.ai_gateway import GatewayResult, StreamingDispatch
    from mcp_proxy.egress.schemas import ChatCompletionRequest


_log = logging.getLogger("agent_trust.egress")


# Ollama exposes ``done_reason`` since 0.5.x. The set is small and
# stable. Anything outside this map (or absent on ``done: true``) is
# treated as a normal stop.
_DONE_REASON_MAP: dict[str, str] = {
    "stop": "stop",
    "length": "length",
    "load": "stop",
    "unload": "stop",
}


# Sampling params Ollama accepts under ``options`` plus their OpenAI
# field names. ``num_predict`` is Ollama's ``max_tokens`` analogue.
_OPENAI_TO_OLLAMA_OPTIONS: dict[str, str] = {
    "temperature": "temperature",
    "top_p": "top_p",
    "top_k": "top_k",
    "max_tokens": "num_predict",
    "seed": "seed",
    "frequency_penalty": "frequency_penalty",
    "presence_penalty": "presence_penalty",
}


def _strip_ollama_prefix(model: str) -> str:
    """Drop the routing prefix the Mastio adds for provider resolution.

    The dashboard's curated catalog emits ids like ``ollama_chat/llama3.1:8b``
    so ``parse_provider_from_model`` knows to route them at the Ollama
    provider. The Ollama daemon itself does not understand the prefix.
    """
    for prefix in ("ollama_chat/", "ollama/"):
        if model.startswith(prefix):
            return model[len(prefix):]
    return model


def _safe_api_base(creds: dict[str, str]) -> str:
    """Return the validated Ollama base URL or raise GatewayError(503).

    Defense-in-depth SSRF gate, same pattern as
    ``fetch_ollama_models`` in ``provider_catalog.py``. ``allow_private``
    follows the existing ``policy_webhook_allow_private_ips`` knob so
    dev/sandbox stacks running Ollama on localhost / 192.168.0.0/16
    keep working.
    """
    from mcp_proxy.config import get_settings
    from mcp_proxy.egress.ai_gateway import GatewayError
    from mcp_proxy.utils.url_safety import (
        UnsafeUrlError,
        assert_safe_outbound_url,
    )

    api_base = (creds.get("api_base") or creds.get("base_url") or "").rstrip("/")
    if not api_base:
        raise GatewayError(
            503,
            "provider_not_configured",
            detail=(
                "Ollama api_base is required (e.g. http://localhost:11434). "
                "Set it in the Mastio dashboard (Settings → AI Providers → "
                "Ollama)."
            ),
        )
    allow_private = bool(
        getattr(get_settings(), "policy_webhook_allow_private_ips", False)
    )
    try:
        assert_safe_outbound_url(api_base, allow_private=allow_private)
    except UnsafeUrlError as exc:
        raise GatewayError(
            403,
            "provider_unsafe_endpoint",
            detail=(
                f"Ollama api_base {api_base!r} failed the SSRF gate: {exc}. "
                "Set policy_webhook_allow_private_ips=true on the Mastio "
                "config to allow loopback/RFC1918 endpoints (dev only)."
            ),
        ) from exc
    return api_base


def _cullis_headers(ctx: DispatchContext) -> dict[str, str]:
    return {
        "X-Cullis-Agent": ctx.agent_id,
        "X-Cullis-Org": ctx.org_id,
        "X-Cullis-Trace": ctx.trace_id,
    }


# ── http client cache (PR-I) ──────────────────────────────────────────
#
# Pre-PR-I, ``chat_completion`` and ``stream_chat_completion`` opened a
# fresh ``httpx.AsyncClient`` per request via ``async with``. Under
# load that meant a TCP + TLS handshake per call against the Ollama
# daemon — and on a local daemon "fast" still means dozens of millis
# of unnecessary syscall churn. We now cache one ``AsyncClient`` per
# ``(api_base, timeout)`` so the connection pool stays warm across
# requests.
#
# The cache is module-level and worker-local; each uvicorn worker has
# its own dict. Entries are bounded by the number of distinct Ollama
# endpoints an operator points the catalog at (typically 1). We do
# not close clients explicitly — Python GC + interpreter exit handle
# the httpx pools when the process ends. Long-lived rotation of
# ``api_base`` would leak the prior client until exit, which is
# acceptable for the bounded cardinality.

_HTTP_CLIENT_CACHE: dict[str, httpx.AsyncClient] = {}


def _get_http_client(api_base: str, timeout: float) -> httpx.AsyncClient:
    key = f"{api_base}|{timeout}"
    client = _HTTP_CLIENT_CACHE.get(key)
    if client is not None:
        return client
    # M7/M8 (audit 2026-06-02): pin the connect to the IP the SSRF guard
    # validated, closing the DNS-rebinding TOCTOU. _safe_api_base already
    # validates the base once; the transport re-validates + pins on every
    # request (handles a base that resolves differently at connect time).
    from mcp_proxy.config import get_settings
    from mcp_proxy.utils.ssrf_transport import (
        SSRFPinnedTransport,
        allow_private_from_settings,
    )
    transport = SSRFPinnedTransport(
        allow_private=allow_private_from_settings(get_settings()),
    )
    client = httpx.AsyncClient(timeout=timeout, transport=transport)
    _HTTP_CLIENT_CACHE[key] = client
    return client


# ── request translation: OpenAI → Ollama ──────────────────────────────


def _translate_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Translate one OpenAI message to one Ollama message.

    Returns None if the message has no meaningful content (e.g. an
    assistant turn that was wiped of both content and tool_calls).
    """
    role = msg.get("role")
    if role not in {"system", "user", "assistant", "tool"}:
        return None

    out: dict[str, Any] = {"role": role}

    content = msg.get("content")
    if isinstance(content, str):
        out["content"] = content
    elif isinstance(content, list):
        # OpenAI multi-part content. Flatten the text parts; defer
        # image_url to the multi-modal follow-on.
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text") or "")
        out["content"] = "".join(parts)
    else:
        out["content"] = ""

    if role == "tool":
        # Ollama supports role="tool" natively and reads tool_call_id /
        # name to correlate against the prior assistant tool_use.
        tcid = msg.get("tool_call_id")
        if tcid:
            out["tool_call_id"] = tcid
        name = msg.get("name")
        if name:
            out["name"] = name
        return out

    if role == "assistant":
        tcs = msg.get("tool_calls") or []
        if tcs:
            translated_calls: list[dict[str, Any]] = []
            for tc in tcs:
                fn = tc.get("function") or {}
                raw_args = fn.get("arguments") or "{}"
                if isinstance(raw_args, str):
                    try:
                        parsed_args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        parsed_args = {}
                else:
                    parsed_args = raw_args
                call_entry: dict[str, Any] = {
                    "function": {
                        "name": fn.get("name") or "",
                        "arguments": parsed_args,
                    },
                }
                if tc.get("id"):
                    call_entry["id"] = tc["id"]
                translated_calls.append(call_entry)
            out["tool_calls"] = translated_calls

    return out


def _translate_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if not tools:
        return None
    # Ollama's tools shape matches OpenAI's
    # ({type: "function", function: {name, description, parameters}})
    # since 0.3.0. Pass through after validating the function block.
    out: list[dict[str, Any]] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        fn = t.get("function")
        if isinstance(fn, dict) and fn.get("name"):
            out.append({"type": "function", "function": fn})
    return out or None


def _translate_response_format(rf: Any) -> Any | None:
    """OpenAI response_format -> Ollama ``format`` field."""
    if not rf:
        return None
    if isinstance(rf, dict):
        t = rf.get("type")
        if t == "json_object":
            return "json"
        if t == "json_schema":
            schema_wrap = rf.get("json_schema") or {}
            schema = schema_wrap.get("schema")
            if schema:
                return schema
    return None


def translate_request(req_body: dict[str, Any]) -> dict[str, Any]:
    """OpenAI ChatCompletion body -> Ollama /api/chat body.

    Pure function. Test target. ``req_body`` is the ``model_dump`` of a
    ``ChatCompletionRequest`` with ``stream``/``stream_options`` already
    stripped if needed by the caller.
    """
    from mcp_proxy.egress.ai_gateway import GatewayError

    raw_model = req_body.get("model")
    if not raw_model:
        raise GatewayError(400, "provider_bad_request", detail="model is required")
    model = _strip_ollama_prefix(raw_model)

    messages_in = req_body.get("messages") or []
    messages_out: list[dict[str, Any]] = []
    for m in messages_in:
        if not isinstance(m, dict):
            continue
        translated = _translate_message(m)
        if translated is not None:
            messages_out.append(translated)

    out: dict[str, Any] = {
        "model": model,
        "messages": messages_out,
    }

    # Gather sampling params under ``options``.
    options: dict[str, Any] = {}
    for openai_key, ollama_key in _OPENAI_TO_OLLAMA_OPTIONS.items():
        val = req_body.get(openai_key)
        if val is not None:
            options[ollama_key] = val
    stop = req_body.get("stop")
    if stop is not None:
        if isinstance(stop, str):
            options["stop"] = [stop]
        elif isinstance(stop, list):
            options["stop"] = [s for s in stop if isinstance(s, str)]
    if options:
        out["options"] = options

    tools = _translate_tools(req_body.get("tools"))
    if tools is not None:
        out["tools"] = tools

    fmt = _translate_response_format(req_body.get("response_format"))
    if fmt is not None:
        out["format"] = fmt

    keep_alive = req_body.get("keep_alive")
    if keep_alive is not None:
        out["keep_alive"] = keep_alive

    return out


# ── response translation: Ollama → OpenAI ─────────────────────────────


def _ollama_tool_calls_to_openai(tcs: list[Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not tcs:
        return out
    for tc in tcs:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        name = fn.get("name") or ""
        args = fn.get("arguments")
        if args is None:
            args_str = "{}"
        elif isinstance(args, str):
            args_str = args
        else:
            try:
                args_str = json.dumps(args)
            except (TypeError, ValueError):
                args_str = "{}"
        out.append({
            "id": tc.get("id") or f"tool_{uuid.uuid4().hex[:24]}",
            "type": "function",
            "function": {"name": name, "arguments": args_str},
        })
    return out


def translate_response(
    ollama_payload: dict[str, Any],
    *,
    request_model: str,
    trace_id: str,
) -> dict[str, Any]:
    """Ollama /api/chat response body -> OpenAI ChatCompletion payload.

    Pure function. Test target.
    """
    msg = ollama_payload.get("message") or {}
    content = msg.get("content") or ""
    tool_calls = _ollama_tool_calls_to_openai(msg.get("tool_calls"))

    msg_payload: dict[str, Any] = {"role": "assistant"}
    msg_payload["content"] = content or None
    if tool_calls:
        msg_payload["tool_calls"] = tool_calls

    done_reason = ollama_payload.get("done_reason")
    finish_reason = _DONE_REASON_MAP.get(done_reason or "", "stop")
    if tool_calls and finish_reason == "stop":
        # OpenAI convention: if the assistant emits tool_calls the
        # finish_reason is "tool_calls", regardless of what the upstream
        # called the stop reason.
        finish_reason = "tool_calls"

    prompt_tokens = int(ollama_payload.get("prompt_eval_count") or 0)
    completion_tokens = int(ollama_payload.get("eval_count") or 0)

    response_model = ollama_payload.get("model") or request_model

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
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


# ── streaming translation ─────────────────────────────────────────────


class _StreamAccumulator:
    """Per-stream state for translating Ollama JSONL chunks to OpenAI
    chunk-stream dicts.

    Ollama streams JSONL: each line is a full JSON object with the
    current ``message.content`` delta and a ``done`` flag. Tool calls
    arrive as a fully-formed list on a single non-streaming-style
    chunk (Ollama does not split ``arguments`` across lines today),
    so we do not need to accumulate partial JSON like the Anthropic
    adapter does.
    """

    def __init__(self, *, model: str, trace_id: str) -> None:
        self.chunk_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        self.created = int(time.time())
        self.model = model
        self.trace_id = trace_id
        self.role_emitted = False
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.done_reason: str | None = None
        self.has_tool_calls = False
        self.upstream_request_id: str | None = None

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

    def on_chunk(self, line: dict[str, Any]) -> list[dict[str, Any]]:
        """Translate one Ollama JSONL line. Returns a list of OpenAI
        chunks to emit (may be empty, single, or two when the same line
        carries both a role marker and a content delta)."""
        out: list[dict[str, Any]] = []

        msg = line.get("message") or {}

        # First chunk that carries the assistant role marker: emit the
        # canonical OpenAI {"delta": {"role": "assistant"}} chunk so
        # downstream OpenAI clients see the standard stream opener.
        if not self.role_emitted and msg.get("role") == "assistant":
            self.role_emitted = True
            out.append(self._envelope(choices=[{
                "index": 0,
                "delta": {"role": "assistant", "content": ""},
                "finish_reason": None,
            }]))

        content = msg.get("content")
        if isinstance(content, str) and content:
            out.append(self._envelope(choices=[{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None,
            }]))

        tcs = msg.get("tool_calls")
        if tcs:
            self.has_tool_calls = True
            openai_calls = _ollama_tool_calls_to_openai(tcs)
            # Ollama emits the full tool_call atomically; we mirror the
            # OpenAI streaming convention of one delta with the complete
            # function name + arguments string in a single chunk. The
            # client reassembles the call as it would from incremental
            # arguments deltas; concatenating an empty string after a
            # full string is a no-op.
            tool_delta = [{
                "index": i,
                "id": call["id"],
                "type": "function",
                "function": call["function"],
            } for i, call in enumerate(openai_calls)]
            out.append(self._envelope(choices=[{
                "index": 0,
                "delta": {"tool_calls": tool_delta},
                "finish_reason": None,
            }]))

        if line.get("done") is True:
            self.done_reason = line.get("done_reason") or self.done_reason
            self.prompt_tokens = int(line.get("prompt_eval_count") or 0) \
                or self.prompt_tokens
            self.completion_tokens = int(line.get("eval_count") or 0) \
                or self.completion_tokens

        return out

    def build_final_chunk(self) -> dict[str, Any]:
        finish_reason = _DONE_REASON_MAP.get(self.done_reason or "", "stop")
        if self.has_tool_calls and finish_reason == "stop":
            finish_reason = "tool_calls"
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


class OllamaAdapter:
    """Talk to Ollama via raw httpx, no SDK."""

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
        from mcp_proxy.egress.ai_gateway import (
            GatewayError,
            GatewayResult,
            scrub_secrets,
        )
        from mcp_proxy.egress.schemas import ChatCompletionResponse

        api_base = _safe_api_base(creds)
        body = req.model_dump(exclude_none=True)
        body.pop("stream", None)
        body.pop("stream_options", None)
        ollama_body = translate_request(body)
        # Force non-streaming for this call path; the daemon defaults to
        # stream=true so the body must explicitly turn it off.
        ollama_body["stream"] = False
        request_model = ollama_body["model"]

        url = api_base + "/api/chat"
        timeout = float(getattr(settings, "ai_gateway_request_timeout_s", 60))

        client = _get_http_client(api_base, timeout)
        started = time.perf_counter()
        try:
            resp = await client.post(
                url,
                json=ollama_body,
                headers=_cullis_headers(ctx),
            )
        except httpx.TimeoutException as exc:
            raise GatewayError(504, "provider_timeout", detail=str(exc)) from exc
        except httpx.HTTPError as exc:
            raise GatewayError(502, "provider_unreachable", detail=str(exc)) from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        if resp.status_code // 100 != 2:
            detail = scrub_secrets(resp.text[:512]) if resp.text else None
            # Map common Ollama HTTP codes to the audit reason vocabulary.
            status_to_reason: dict[int, tuple[int, str]] = {
                400: (400, "provider_bad_request"),
                404: (404, "provider_not_found"),  # model not pulled
                429: (429, "provider_rate_limited"),
                503: (502, "provider_unavailable"),
            }
            mapped_status, reason = status_to_reason.get(
                resp.status_code,
                (502, f"upstream_status_{resp.status_code}"),
            )
            raise GatewayError(mapped_status, reason, detail=detail)

        try:
            payload = resp.json()
        except ValueError as exc:
            raise GatewayError(
                502, "malformed_upstream_body", detail=str(exc),
            ) from exc

        openai_payload = translate_response(
            payload,
            request_model=request_model,
            trace_id=ctx.trace_id,
        )

        try:
            parsed = ChatCompletionResponse.model_validate(openai_payload)
        except Exception as exc:
            from mcp_proxy._http_safety import safe_http_detail
            raise GatewayError(
                502,
                "schema_mismatch",
                detail=safe_http_detail(
                    exc,
                    public_hint="Ollama response failed Mastio schema",
                    log_context="ai_gateway.ollama_native.parse_response",
                ),
            ) from exc

        prompt_tokens = int(openai_payload["usage"]["prompt_tokens"])
        completion_tokens = int(openai_payload["usage"]["completion_tokens"])
        upstream_request_id = openai_payload.get("id")

        _log.info(
            "egress.llm dispatched backend=cullis_native provider=ollama "
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
        from mcp_proxy.egress.ai_gateway import GatewayError, StreamingDispatch

        api_base = _safe_api_base(creds)
        body = req.model_dump(exclude_none=True)
        body.pop("stream", None)
        body.pop("stream_options", None)
        ollama_body = translate_request(body)
        ollama_body["stream"] = True
        request_model = ollama_body["model"]

        url = api_base + "/api/chat"
        timeout = float(getattr(settings, "ai_gateway_request_timeout_s", 60))

        dispatch_obj = StreamingDispatch(
            backend="cullis_native",
            provider=provider,
            model=request_model,
            trace_id=ctx.trace_id,
        )

        async def _aiter() -> AsyncIterator[dict]:
            acc = _StreamAccumulator(model=request_model, trace_id=ctx.trace_id)
            try:
                client = _get_http_client(api_base, timeout)
                async with client.stream(
                    "POST", url,
                    json=ollama_body,
                    headers=_cullis_headers(ctx),
                ) as response:
                    if response.status_code // 100 != 2:
                        body_bytes = await response.aread()
                        from mcp_proxy.egress.ai_gateway import scrub_secrets
                        detail = scrub_secrets(body_bytes.decode("utf-8", "replace")[:512])
                        raise GatewayError(
                            502,
                            f"upstream_status_{response.status_code}",
                            detail=detail,
                        )
                    async for raw_line in response.aiter_lines():
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            parsed = json.loads(line)
                        except json.JSONDecodeError:
                            _log.debug(
                                "ollama stream malformed jsonl line dropped: %r",
                                line[:200],
                            )
                            continue
                        for chunk in acc.on_chunk(parsed):
                            yield chunk
                # Final OpenAI chunk with finish_reason + usage.
                dispatch_obj.prompt_tokens = acc.prompt_tokens
                dispatch_obj.completion_tokens = acc.completion_tokens
                yield acc.build_final_chunk()
            except GatewayError:
                raise
            except httpx.TimeoutException as exc:
                raise GatewayError(504, "provider_timeout", detail=str(exc)) from exc
            except httpx.HTTPError as exc:
                raise GatewayError(502, "provider_unreachable", detail=str(exc)) from exc
            finally:
                dispatch_obj.latency_ms = int(
                    (time.perf_counter() - dispatch_obj.started_at) * 1000
                )
                _log.info(
                    "egress.llm streamed backend=cullis_native provider=ollama "
                    "agent=%s org=%s model=%s latency_ms=%d tokens_in=%d tokens_out=%d",
                    ctx.agent_id, ctx.org_id, request_model,
                    dispatch_obj.latency_ms,
                    dispatch_obj.prompt_tokens, dispatch_obj.completion_tokens,
                )

        dispatch_obj._aiter_factory = _aiter
        return dispatch_obj
