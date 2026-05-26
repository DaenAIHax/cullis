"""Tests for the Anthropic Messages API translation helpers (ADR-038
Path Y agnostic, Phase 0).

Covers the two pure translation functions —
``_to_chat_completion_request`` and ``_to_anthropic_response`` — that
sit between the Anthropic-shape Pydantic model and the existing
OpenAI-shape dispatch path. Going through the live endpoint requires
a real Mastio (mTLS + DPoP + AI gateway); the shape conversion is the
part that has historically gone wrong silently (Anthropic's
top-level ``system`` field, content blocks vs string, finish_reason
mapping), so it gets focused unit coverage here.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from mcp_proxy.egress.anthropic_messages_router import (
    AnthropicMessagesRequest,
    _AnthropicMessage,
    _flatten_content,
    _to_anthropic_response,
    _to_chat_completion_request,
)


# ── _flatten_content ────────────────────────────────────────────────────────


def test_flatten_content_string_passthrough() -> None:
    assert _flatten_content("hello") == "hello"


def test_flatten_content_text_blocks_concatenated() -> None:
    blocks = [
        {"type": "text", "text": "hello "},
        {"type": "text", "text": "world"},
    ]
    assert _flatten_content(blocks) == "hello world"


def test_flatten_content_image_block_raises_501() -> None:
    """Phase 0 supports text only — image / tool blocks raise loud."""
    blocks = [{"type": "image", "source": {...}}]
    with pytest.raises(HTTPException) as exc:
        _flatten_content(blocks)
    assert exc.value.status_code == 501
    assert "image" in str(exc.value.detail)


# ── _to_chat_completion_request ─────────────────────────────────────────────


def test_to_chat_request_system_prepended_as_system_message() -> None:
    req = AnthropicMessagesRequest(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system="You are helpful.",
        messages=[_AnthropicMessage(role="user", content="hello")],
    )
    chat = _to_chat_completion_request(req)
    assert chat.messages[0].role == "system"
    assert chat.messages[0].content == "You are helpful."
    assert chat.messages[1].role == "user"
    assert chat.messages[1].content == "hello"
    assert chat.max_tokens == 1024
    assert chat.model == "claude-sonnet-4-6"


def test_to_chat_request_no_system_only_user_message() -> None:
    req = AnthropicMessagesRequest(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[_AnthropicMessage(role="user", content="hi")],
    )
    chat = _to_chat_completion_request(req)
    assert len(chat.messages) == 1
    assert chat.messages[0].role == "user"


def test_to_chat_request_block_content_flattened() -> None:
    req = AnthropicMessagesRequest(
        model="claude-sonnet-4-6",
        max_tokens=256,
        messages=[
            _AnthropicMessage(
                role="user",
                content=[
                    {"type": "text", "text": "part one. "},
                    {"type": "text", "text": "part two."},
                ],
            ),
        ],
    )
    chat = _to_chat_completion_request(req)
    assert chat.messages[0].content == "part one. part two."


# ── _to_anthropic_response ──────────────────────────────────────────────────


def _openai_payload(
    *,
    text: str = "hi back",
    finish: str = "stop",
    prompt: int = 10,
    completion: int = 5,
    model: str = "claude-sonnet-4-6",
) -> dict:
    return {
        "id": "chatcmpl-abc123",
        "object": "chat.completion",
        "created": 1234567890,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": finish,
            }
        ],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    }


def test_to_anthropic_response_basic_text() -> None:
    resp = _to_anthropic_response(
        openai_payload=_openai_payload(text="hi back"),
        model="claude-sonnet-4-6",
        trace_id="trace_test",
    )
    assert resp.id == "chatcmpl-abc123"
    assert resp.type == "message"
    assert resp.role == "assistant"
    assert resp.model == "claude-sonnet-4-6"
    assert len(resp.content) == 1
    assert resp.content[0].type == "text"
    assert resp.content[0].text == "hi back"
    assert resp.stop_reason == "end_turn"
    assert resp.usage.input_tokens == 10
    assert resp.usage.output_tokens == 5
    assert resp.cullis_trace_id == "trace_test"


def test_to_anthropic_response_max_tokens_finish() -> None:
    """OpenAI ``length`` finish_reason maps to Anthropic ``max_tokens``."""
    resp = _to_anthropic_response(
        openai_payload=_openai_payload(finish="length"),
        model="claude-sonnet-4-6",
        trace_id="trace_test",
    )
    assert resp.stop_reason == "max_tokens"


def test_to_anthropic_response_tool_call_raises_501() -> None:
    """When the upstream model emits tool_calls in the OpenAI response,
    Phase 0 raises rather than dropping the call silently."""
    payload = _openai_payload()
    payload["choices"][0]["message"]["tool_calls"] = [
        {"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{}"}},
    ]
    payload["choices"][0]["finish_reason"] = "tool_calls"

    with pytest.raises(HTTPException) as exc:
        _to_anthropic_response(
            openai_payload=payload,
            model="claude-sonnet-4-6",
            trace_id="trace_test",
        )
    assert exc.value.status_code == 501
    assert "tool_use" in str(exc.value.detail)
