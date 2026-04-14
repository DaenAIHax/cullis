"""Unit tests for the Connector Phase 3 high-level tools.

The three tools (``send_to_agent``, ``await_response``, ``get_audit_trail``)
are tested through a ``_FakeFastMCP`` harness that captures the registered
callables, then invoked with a mocked ``CullisClient`` and stubbed
``httpx.get`` to avoid real network I/O.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from cullis_connector.config import ConnectorConfig
from cullis_connector.state import get_state, reset_state
from cullis_connector.tools import high_level
from cullis_sdk.types import InboxMessage, SessionInfo


class _FakeFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class _FakeClient:
    """Stand-in for ``cullis_sdk.CullisClient`` with canned responses.

    The mock is intentionally permissive — tests poke attributes directly
    rather than driving a full state machine. Each call is recorded for
    assertion.
    """

    def __init__(self) -> None:
        self.token = "fake-token"
        self.opened: list[tuple[str, str, list[str]]] = []
        self.sent: list[dict] = []
        self.closed: list[str] = []
        self.polled: list[str] = []

        self._next_session_id = "sess-abc-1234567890"
        self._open_raises: Exception | None = None
        self._send_raises: Exception | None = None
        self._sessions_queue: list[list[SessionInfo]] = []
        self._poll_queue: list[list[InboxMessage]] = []
        self._proxy_api_key = "sk_local_alice_deadbeef"
        self._proxy_headers_raises: Exception | None = None

    # ── Sessions ──────────────────────────────────────────────────
    def open_session(self, target: str, org: str, caps: list[str]) -> str:
        if self._open_raises is not None:
            raise self._open_raises
        self.opened.append((target, org, caps))
        return self._next_session_id

    def close_session(self, session_id: str) -> None:
        self.closed.append(session_id)

    def list_sessions(self, status: str | None = None) -> list[SessionInfo]:
        if self._sessions_queue:
            return self._sessions_queue.pop(0)
        return []

    def send(self, session_id: str, sender: str, payload: dict,
             recipient_agent_id: str) -> None:
        if self._send_raises is not None:
            raise self._send_raises
        self.sent.append({
            "session_id": session_id,
            "sender": sender,
            "payload": payload,
            "recipient": recipient_agent_id,
        })

    def poll(self, session_id: str) -> list[InboxMessage]:
        self.polled.append(session_id)
        if self._poll_queue:
            return self._poll_queue.pop(0)
        return []

    def proxy_headers(self) -> dict:
        if self._proxy_headers_raises is not None:
            raise self._proxy_headers_raises
        return {"X-API-Key": self._proxy_api_key, "Content-Type": "application/json"}


def _active_session(client: _FakeClient, target: str) -> SessionInfo:
    return SessionInfo(
        session_id=client._next_session_id,
        status="active",
        initiator_agent_id="acme::alice",
        target_agent_id=target,
        initiator_org_id="acme",
        target_org_id="chipfactory",
    )


def _pending_session(client: _FakeClient, target: str) -> SessionInfo:
    s = _active_session(client, target)
    s.status = "pending"
    return s


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path, monkeypatch):
    reset_state()
    state = get_state()
    state.config = ConnectorConfig(
        site_url="https://site.test",
        config_dir=tmp_path,
        verify_tls=True,
        request_timeout_s=2.0,
    )
    state.agent_id = "acme::alice"
    # Avoid real sleeping in polling loops — unit tests shouldn't wait.
    monkeypatch.setattr(high_level.time, "sleep", lambda _s: None)
    # Shrink accept timeout for the "peer never accepts" path.
    monkeypatch.setattr(high_level, "_ACCEPT_TIMEOUT_S", 0.05)
    monkeypatch.setattr(high_level, "_ACCEPT_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(high_level, "_RESPONSE_POLL_INTERVAL_S", 0.01)
    yield
    reset_state()


@pytest.fixture
def tools():
    mcp = _FakeFastMCP()
    high_level.register(mcp)
    return mcp.tools


@pytest.fixture
def client():
    c = _FakeClient()
    get_state().client = c  # type: ignore[assignment]
    return c


# ── send_to_agent ────────────────────────────────────────────────────────


def test_send_to_agent_full_exchange_with_reply(tools, client):
    # First list_sessions call: session is active.
    client._sessions_queue = [[_active_session(client, "chipfactory::sales")]]
    # First poll returns a reply.
    client._poll_queue = [[
        InboxMessage(
            seq=1,
            sender_agent_id="chipfactory::sales",
            payload={"text": "ack received"},
        ),
    ]]

    result = tools["send_to_agent"](
        target_agent_id="chipfactory::sales",
        target_org_id="chipfactory",
        capability="order.write",
        message="please quote 500 wafers",
        await_response=True,
        timeout_s=2,
    )

    assert "exchange complete" in result
    assert "chipfactory::sales" in result
    assert "ack received" in result
    assert len(client.opened) == 1
    assert client.opened[0][0] == "chipfactory::sales"
    assert client.opened[0][2] == ["order.write"]
    assert len(client.sent) == 1
    assert client.sent[0]["recipient"] == "chipfactory::sales"
    assert client.closed == [client._next_session_id]


def test_send_to_agent_peer_never_accepts(tools, client):
    # list_sessions always returns pending → timeout path.
    client._sessions_queue = [
        [_pending_session(client, "chipfactory::sales")]
        for _ in range(10)
    ]

    result = tools["send_to_agent"](
        target_agent_id="chipfactory::sales",
        target_org_id="chipfactory",
        capability="chat",
        message="hi",
        await_response=False,
    )
    assert "did not accept" in result.lower()
    # Session should still be closed to avoid dangling pending.
    assert client.closed == [client._next_session_id]
    assert client.sent == []  # Never sent because accept never happened.


def test_send_to_agent_open_error_is_reported(tools, client):
    client._open_raises = RuntimeError("broker unreachable")
    result = tools["send_to_agent"](
        target_agent_id="x::y",
        target_org_id="x",
        capability="chat",
        message="hello",
    )
    assert "failed to open" in result.lower()
    assert "broker unreachable" in result
    assert client.sent == []
    assert client.closed == []


def test_send_to_agent_without_await_returns_immediately(tools, client):
    client._sessions_queue = [[_active_session(client, "x::y")]]
    result = tools["send_to_agent"](
        target_agent_id="x::y",
        target_org_id="x",
        capability="chat",
        message="hi",
        await_response=False,
        timeout_s=30,
    )
    assert "exchange complete" in result
    assert client.polled == []  # No polling when await_response is False.
    assert client.closed == [client._next_session_id]


def test_send_to_agent_not_connected(tools):
    # No client on state → clean error, not a crash.
    result = tools["send_to_agent"](
        target_agent_id="x::y",
        target_org_id="x",
        capability="chat",
        message="hi",
    )
    assert "not connected" in result.lower()


# ── await_response ───────────────────────────────────────────────────────


def test_await_response_returns_messages(tools, client):
    client._poll_queue = [[
        InboxMessage(seq=1, sender_agent_id="peer::bob", payload={"text": "hi"}),
    ]]
    result = tools["await_response"]("sess-xyz", timeout_s=2)
    assert "[peer::bob]: hi" == result
    assert client.polled == ["sess-xyz"]
    # await_response must NOT touch active_session.
    assert get_state().active_session is None


def test_await_response_timeout(tools, client):
    # Empty queue — every poll returns no messages.
    result = tools["await_response"]("sess-zzz", timeout_s=1)
    assert "no response within" in result.lower()


def test_await_response_poll_error(tools, client):
    class Boom(Exception):
        pass

    def _boom(_sid):
        raise Boom("kaboom")

    client.poll = _boom  # type: ignore[assignment]
    result = tools["await_response"]("sess-err", timeout_s=1)
    assert "failed to poll" in result.lower()
    assert "kaboom" in result


# ── get_audit_trail ──────────────────────────────────────────────────────


def _audit_entry(**kw):
    base = {
        "timestamp": "2026-04-14T12:00:01+00:00",
        "agent_id": "acme::alice",
        "action": "session.open",
        "tool_name": "open_session",
        "status": "ok",
        "detail": None,
        "duration_ms": 12.5,
    }
    base.update(kw)
    return base


def test_get_audit_trail_formats_entries(tools, client, monkeypatch):
    captured: dict[str, Any] = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs.get("headers")
        return httpx.Response(
            status_code=200,
            json=[
                _audit_entry(),
                _audit_entry(
                    timestamp="2026-04-14T12:00:02+00:00",
                    action="session.send",
                    tool_name="send_message",
                    detail="to peer",
                    duration_ms=7.0,
                ),
            ],
        )

    monkeypatch.setattr(high_level.httpx, "get", fake_get)
    result = tools["get_audit_trail"]("sess-abc-1234567890")
    assert "Audit trail for session" in result
    assert "session.open" in result
    assert "session.send" in result
    assert "to peer" in result
    assert captured["url"] == (
        "https://site.test/v1/audit/session/sess-abc-1234567890"
    )
    assert captured["headers"]["X-API-Key"] == client._proxy_api_key


def test_get_audit_trail_404(tools, client, monkeypatch):
    monkeypatch.setattr(
        high_level.httpx,
        "get",
        lambda url, **kw: httpx.Response(status_code=404, json={"detail": "nope"}),
    )
    result = tools["get_audit_trail"]("sess-missing")
    assert "no audit trail" in result.lower()


def test_get_audit_trail_403(tools, client, monkeypatch):
    monkeypatch.setattr(
        high_level.httpx,
        "get",
        lambda url, **kw: httpx.Response(status_code=403, json={"detail": "nope"}),
    )
    result = tools["get_audit_trail"]("sess-foreign")
    assert "not authorized" in result.lower()


def test_get_audit_trail_missing_proxy_api_key(tools, client, monkeypatch):
    client._proxy_headers_raises = RuntimeError("no proxy key")
    result = tools["get_audit_trail"]("sess-abc")
    assert "proxy enrollment" in result.lower()


def test_get_audit_trail_site_unreachable(tools, client, monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(high_level.httpx, "get", boom)
    result = tools["get_audit_trail"]("sess-abc")
    assert "unreachable" in result.lower()


def test_get_audit_trail_non_json(tools, client, monkeypatch):
    monkeypatch.setattr(
        high_level.httpx,
        "get",
        lambda url, **kw: httpx.Response(status_code=200, text="not json"),
    )
    result = tools["get_audit_trail"]("sess-abc")
    assert "non-json" in result.lower()


def test_get_audit_trail_no_site_url(tools):
    get_state().config = ConnectorConfig(site_url="")
    result = tools["get_audit_trail"]("sess-abc")
    assert "site url is not configured" in result.lower()


def test_get_audit_trail_not_connected(tools):
    # state has config but no client.
    result = tools["get_audit_trail"]("sess-abc")
    assert "not connected" in result.lower()
