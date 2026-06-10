"""Tests for the LLM-chat per-request timeout (2026-06-10 P0).

The client-wide httpx timeout defaults to 10s — sized for
control-plane calls. ``chat_completion`` inherited it, so any
completion that took the model longer than 10s (most non-trivial
ones) died with ``httpx.ReadTimeout``. The fix gives the
``/v1/llm/chat`` path its own per-request budget
(:data:`cullis_sdk._client._ai_gateway.LLM_CHAT_TIMEOUT_S`, 60s,
matching ``providers_compat``) plus a keyword-only ``timeout=``
override on both chat methods.
"""
from __future__ import annotations

import contextlib
from typing import Any
from unittest.mock import MagicMock

import pytest

from cullis_sdk._client._ai_gateway import LLM_CHAT_TIMEOUT_S


class _FakeHttp:
    """httpx.Client stand-in recording post/stream kwargs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    def post(self, url: str, **kwargs: Any) -> Any:
        self.calls.append(("post", url, kwargs))
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = ""
        resp.json.return_value = {"id": "chatcmpl-1", "choices": []}
        resp.raise_for_status = MagicMock()
        return resp

    @contextlib.contextmanager
    def stream(self, method: str, url: str, **kwargs: Any):
        self.calls.append((method, url, kwargs))
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.raise_for_status = MagicMock()
        resp.iter_text.return_value = iter(["data: [DONE]\n\n"])
        yield resp

    def close(self) -> None:
        pass


@pytest.fixture
def client(monkeypatch, tmp_path):
    http = _FakeHttp()
    monkeypatch.setattr(
        "cullis_sdk.client._build_proxy_http_client",
        lambda **_kwargs: http,
    )
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    c = CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=cert,
        key_path=key,
    )
    return c, http


def test_chat_completion_default_timeout_is_llm_budget(client):
    c, http = client
    c.chat_completion(model="m", messages=[{"role": "user", "content": "hi"}])
    _, url, kwargs = http.calls[-1]
    assert url.endswith("/v1/llm/chat")
    assert kwargs["timeout"] == LLM_CHAT_TIMEOUT_S
    assert LLM_CHAT_TIMEOUT_S == 60.0


def test_chat_completion_timeout_override(client):
    c, http = client
    c.chat_completion({"model": "m", "messages": []}, timeout=120.0)
    _, _, kwargs = http.calls[-1]
    assert kwargs["timeout"] == 120.0


def test_chat_completion_timeout_never_lands_in_body(client):
    """``timeout`` is a method parameter, not a request field — the
    kwargs calling convention must not leak it into the JSON body.
    """
    c, http = client
    c.chat_completion(model="m", messages=[], timeout=30.0)
    _, _, kwargs = http.calls[-1]
    assert "timeout" not in kwargs["json"]
    assert kwargs["timeout"] == 30.0


def test_chat_completion_stream_default_timeout(client):
    c, http = client
    frames = list(c.chat_completion_stream(model="m", messages=[]))
    assert frames == ["data: [DONE]\n\n"]
    method, url, kwargs = http.calls[-1]
    assert (method, url.endswith("/v1/llm/chat")) == ("POST", True)
    assert kwargs["timeout"] == LLM_CHAT_TIMEOUT_S
    assert kwargs["json"]["stream"] is True


def test_chat_completion_stream_timeout_override(client):
    c, http = client
    list(c.chat_completion_stream({"model": "m", "messages": []}, timeout=5.0))
    _, _, kwargs = http.calls[-1]
    assert kwargs["timeout"] == 5.0
