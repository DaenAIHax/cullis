"""Tests for the dict-or-kwargs calling convention on ``chat_completion``
(D-8 OpenAI-compat fix).

Pre-fix, ``CullisClient.chat_completion`` only accepted a single dict
argument matching the audit-pinned request envelope::

    client.chat_completion({"model": "...", "messages": [...]})

Cold-readers used to the OpenAI / Anthropic / agent-SDK pattern copy
snippets like ``client.chat_completion(model="...", messages=[...])``
and hit ``TypeError: chat_completion() got an unexpected keyword
argument 'model'`` on the first call. The dict-only signature is fine
for the audit envelope but blocking the kwargs convention is needless
friction.

The fix accepts either shape, raises on ambiguous "both at once"
calls, and routes both forms to the same ``_egress_http`` call so the
downstream wire payload is unchanged. The tests below construct a
minimal ``_AiGatewayMixin`` subclass with a recording stub for
``_egress_http`` so we can assert payload equivalence without standing
up TLS, DPoP or a live Mastio.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from cullis_sdk._client._ai_gateway import _AiGatewayMixin


class _StubClient(_AiGatewayMixin):
    """Bare _AiGatewayMixin host that records ``_egress_http`` calls.

    ``chat_completion`` is the only method exercised here, and it only
    touches ``_egress_http`` on ``self`` (no DPoP / cert / nonce
    plumbing required for the request-shape coercion path under test).
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _egress_http(self, method: str, path: str, **kwargs: Any):
        self.calls.append((method, path, kwargs))
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"id": "chatcmpl-stub", "choices": []}
        return resp


def test_chat_completion_dict_style_works():
    """The historical dict-positional form still produces the exact
    same egress call as before the D-8 fix.
    """
    client = _StubClient()
    request = {
        "model": "claude-sonnet-4-6",
        "messages": [{"role": "user", "content": "hi"}],
    }

    out = client.chat_completion(request)

    assert out == {"id": "chatcmpl-stub", "choices": []}
    assert len(client.calls) == 1
    method, path, kwargs = client.calls[0]
    assert method == "post"
    assert path == "/v1/llm/chat"
    assert kwargs["json"] == request


def test_chat_completion_kwargs_style_works():
    """The new OpenAI / Anthropic-style kwargs form produces an
    identical wire payload to the dict form — same egress method,
    path, and ``json`` body — so customers can pick either style.
    """
    client = _StubClient()

    out = client.chat_completion(
        model="claude-sonnet-4-6",
        messages=[{"role": "user", "content": "hi"}],
    )

    assert out == {"id": "chatcmpl-stub", "choices": []}
    assert len(client.calls) == 1
    method, path, kwargs = client.calls[0]
    assert method == "post"
    assert path == "/v1/llm/chat"
    # Wire payload identical to the dict-style call above so the
    # audit envelope, signing inputs and Mastio-side handling do not
    # depend on which calling convention the customer picked.
    assert kwargs["json"] == {
        "model": "claude-sonnet-4-6",
        "messages": [{"role": "user", "content": "hi"}],
    }


def test_chat_completion_both_dict_and_kwargs_raises():
    """Mixing a positional dict with extra kwargs is ambiguous (which
    half wins?) so the SDK refuses up front rather than silently
    dropping one side. This catches typos like passing a dict and then
    also overriding ``model="..."`` thinking it merges.
    """
    client = _StubClient()
    with pytest.raises(TypeError, match="either a request dict or kwargs"):
        client.chat_completion(
            {"model": "claude-sonnet-4-6", "messages": []},
            model="gpt-4o-mini",
        )
    assert client.calls == [], "no egress call should fire on ambiguous input"


def test_chat_completion_non_dict_request_raises():
    """Defensive: a non-dict positional (e.g. someone passing the
    model name as a string, mirroring some quickstart copy-paste)
    fails fast with a clear TypeError rather than blowing up later
    inside the egress JSON serialiser with an opaque message.
    """
    client = _StubClient()
    with pytest.raises(TypeError, match="must be a dict"):
        client.chat_completion("claude-sonnet-4-6")  # type: ignore[arg-type]
    assert client.calls == [], "no egress call should fire on non-dict input"
