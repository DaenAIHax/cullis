"""ADR-002 Phase 2b — A2A JSON-RPC endpoint end-to-end.

Covers the three Phase 2b methods wired on /v1/a2a/rpc:
  - message/send    — post a Cullis envelope via A2A Message, get Task back
  - tasks/get       — fetch the Task view of an existing Cullis session
  - tasks/cancel    — transition session → closed/canceled, idempotent

Each test spins the app with A2A_ADAPTER=true, registers two orgs via the
broker API, opens a Cullis session (pending → active), then drives the
A2A RPC surface. We trust the underlying broker checks — signature,
nonce dedup, policy — are covered by the broker's own test suite; the
tests here verify the A2A translation layer + dispatch.
"""
from __future__ import annotations

import uuid
from importlib import reload

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from tests.cert_factory import DPoPHelper, make_encrypted_envelope
from tests.conftest import ADMIN_HEADERS

from app.a2a.adapter import CULLIS_E2E_MEDIATYPE
from app.config import get_settings


pytestmark = pytest.mark.asyncio


# ── fixtures ────────────────────────────────────────────────────────

def _reload_app_with_flag(monkeypatch, *, a2a_enabled: bool):
    monkeypatch.setenv("A2A_ADAPTER", "true" if a2a_enabled else "false")
    get_settings.cache_clear()
    import app.main as _main
    reload(_main)
    return _main.app


@pytest_asyncio.fixture
async def a2a_app(monkeypatch):
    app = _reload_app_with_flag(monkeypatch, a2a_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    monkeypatch.setenv("A2A_ADAPTER", "false")
    get_settings.cache_clear()
    import app.main as _main
    reload(_main)


@pytest.fixture
def dpop():
    return DPoPHelper()


async def _register_and_login(client: AsyncClient, dpop, agent_id: str, org_id: str) -> str:
    """Same shape as tests/test_broker.py helper."""
    from tests.cert_factory import get_org_ca_pem
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["kyc.read"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["kyc.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/policy/rules",
        json={
            "policy_id": f"{org_id}::session-allow-all",
            "org_id": org_id,
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
        },
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


async def _open_active_session(client, dpop, tag: str) -> tuple[str, str, str, str, str]:
    """Provision two agents, open and accept a Cullis session.

    Returns (session_id, agent_a_id, org_a, agent_b_id, token_a).
    """
    org_a = f"{tag}-a"
    org_b = f"{tag}-b"
    a = f"{org_a}::alice"
    b = f"{org_b}::bob"
    token_a = await _register_and_login(client, dpop, a, org_a)
    token_b = await _register_and_login(client, dpop, b, org_b)
    resp = await client.post(
        "/v1/broker/sessions",
        json={
            "target_agent_id": b,
            "target_org_id": org_b,
            "requested_capabilities": ["kyc.read"],
        },
        headers=dpop.headers("POST", "/v1/broker/sessions", token_a),
    )
    assert resp.status_code == 201, resp.text
    session_id = resp.json()["session_id"]
    accept_path = f"/v1/broker/sessions/{session_id}/accept"
    resp = await client.post(accept_path, headers=dpop.headers("POST", accept_path, token_b))
    assert resp.status_code == 200, resp.text
    return session_id, a, org_a, b, token_a


def _a2a_message(session_id: str, envelope: dict) -> dict:
    """Wrap a Cullis MessageEnvelope as an A2A Message dict (what a
    client would post in params.message)."""
    return {
        "kind": "message",
        "messageId": str(uuid.uuid4()),
        "contextId": session_id,
        "taskId": session_id,
        "role": "user",
        "parts": [
            {
                "kind": "data",
                "data": envelope["payload"],
                "metadata": {"mediaType": CULLIS_E2E_MEDIATYPE},
            }
        ],
        "metadata": {
            "cullis": {
                "nonce": envelope["nonce"],
                "timestamp": envelope["timestamp"],
                "signature": envelope["signature"],
                "sender_agent_id": envelope["sender_agent_id"],
            }
        },
    }


# ── dispatch / shape tests ──────────────────────────────────────────

async def test_rpc_requires_auth(a2a_app):
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"id": "x"}},
    )
    assert resp.status_code == 401


async def test_rpc_unknown_method(a2a_app, dpop):
    _, a, org_a, _, token = await _open_active_session(a2a_app, dpop, "rpc-unk")
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 2, "method": "bogus", "params": {}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token),
    )
    body = resp.json()
    assert body["error"]["code"] == -32601


async def test_rpc_invalid_jsonrpc_envelope(a2a_app, dpop):
    _, _, _, _, token = await _open_active_session(a2a_app, dpop, "rpc-env")
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"method": "tasks/get"},  # missing jsonrpc
        headers=dpop.headers("POST", "/v1/a2a/rpc", token),
    )
    body = resp.json()
    assert body["error"]["code"] == -32600


async def test_rpc_flag_off_returns_404(monkeypatch, dpop):
    app = _reload_app_with_flag(monkeypatch, a2a_enabled=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post(
            "/v1/a2a/rpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {}},
        )
        assert resp.status_code == 404


# ── message/send ────────────────────────────────────────────────────

async def test_message_send_routes_to_active_session(a2a_app, dpop):
    session_id, a, org_a, b, token_a = await _open_active_session(a2a_app, dpop, "send-ok")
    nonce = str(uuid.uuid4())
    envelope = make_encrypted_envelope(
        a, org_a, b, org_a.replace("-a", "-b"), session_id, nonce, {"msg": "hello"}
    )
    rpc = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "message/send",
        "params": {"message": _a2a_message(session_id, envelope)},
    }
    resp = await a2a_app.post(
        "/v1/a2a/rpc", json=rpc,
        headers=dpop.headers("POST", "/v1/a2a/rpc", token_a),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "error" not in body, body
    task = body["result"]
    assert task["id"] == session_id
    assert task["contextId"] == session_id
    # A2A TaskState: active session → working
    assert task["status"]["state"] == "working"
    # The message we just sent is in history
    assert len(task["history"]) == 1
    assert task["history"][0]["contextId"] == session_id


async def test_message_send_missing_context_id_rejected(a2a_app, dpop):
    _, _, _, _, token = await _open_active_session(a2a_app, dpop, "send-noctx")
    bad_msg = {
        "kind": "message",
        "messageId": "m1",
        "role": "user",
        "parts": [{"kind": "data", "data": {}, "metadata": {"mediaType": CULLIS_E2E_MEDIATYPE}}],
    }
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "message/send",
              "params": {"message": bad_msg}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token),
    )
    body = resp.json()
    assert body["error"]["code"] == -32602


async def test_message_send_unknown_context_id_returns_task_not_found(a2a_app, dpop):
    _, _, _, _, token = await _open_active_session(a2a_app, dpop, "send-404")
    bogus_id = "sess-does-not-exist-" + uuid.uuid4().hex
    msg = _a2a_message(bogus_id, {
        "payload": {"ciphertext": "x", "iv": "y", "encrypted_key": "z"},
        "nonce": "n", "timestamp": 0, "signature": "s", "sender_agent_id": "x",
    })
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "message/send",
              "params": {"message": msg}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token),
    )
    body = resp.json()
    assert body["error"]["code"] == -32001


async def test_message_send_non_participant_forbidden(a2a_app, dpop):
    session_id, a, org_a, b, _ = await _open_active_session(a2a_app, dpop, "send-nonp")
    # Register a third agent not part of the session
    outsider = "outsider-org::eve"
    token_eve = await _register_and_login(a2a_app, dpop, outsider, "outsider-org")
    envelope = make_encrypted_envelope(
        outsider, "outsider-org", b, org_a.replace("-a", "-b"),
        session_id, str(uuid.uuid4()), {"msg": "spy"},
    )
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "message/send",
              "params": {"message": _a2a_message(session_id, envelope)}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token_eve),
    )
    body = resp.json()
    assert body["error"]["code"] == -32600  # invalid request, not a participant


# ── tasks/get ───────────────────────────────────────────────────────

async def test_tasks_get_returns_task_view(a2a_app, dpop):
    session_id, *_, token_a = await _open_active_session(a2a_app, dpop, "get-ok")
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tasks/get",
              "params": {"id": session_id}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token_a),
    )
    body = resp.json()
    assert "error" not in body, body
    assert body["result"]["id"] == session_id
    assert body["result"]["status"]["state"] == "working"


async def test_tasks_get_history_length_truncates(a2a_app, dpop):
    session_id, a, org_a, b, token_a = await _open_active_session(a2a_app, dpop, "get-trunc")
    # Send 3 messages via the native broker path (faster than 3 RPC calls,
    # same on-the-wire result because adapter reads from DB).
    for _ in range(3):
        nonce = str(uuid.uuid4())
        env = make_encrypted_envelope(
            a, org_a, b, org_a.replace("-a", "-b"),
            session_id, nonce, {"n": nonce},
        )
        path = f"/v1/broker/sessions/{session_id}/messages"
        r = await a2a_app.post(
            path, json=env, headers=dpop.headers("POST", path, token_a),
        )
        assert r.status_code == 202

    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tasks/get",
              "params": {"id": session_id, "historyLength": 1}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token_a),
    )
    task = resp.json()["result"]
    assert len(task["history"]) == 1

    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 2, "method": "tasks/get",
              "params": {"id": session_id, "historyLength": 0}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token_a),
    )
    task = resp.json()["result"]
    assert task["history"] == []


async def test_tasks_get_non_participant_gets_task_not_found(a2a_app, dpop):
    session_id, *_ = await _open_active_session(a2a_app, dpop, "get-priv")
    outsider_token = await _register_and_login(
        a2a_app, dpop, "nosy-org::eve", "nosy-org",
    )
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tasks/get",
              "params": {"id": session_id}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", outsider_token),
    )
    body = resp.json()
    assert body["error"]["code"] == -32001  # masked as not-found


# ── tasks/cancel ────────────────────────────────────────────────────

async def test_tasks_cancel_transitions_to_canceled(a2a_app, dpop):
    session_id, *_, token_a = await _open_active_session(a2a_app, dpop, "cancel-ok")
    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tasks/cancel",
              "params": {"id": session_id}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token_a),
    )
    body = resp.json()
    assert "error" not in body, body
    assert body["result"]["status"]["state"] == "canceled"


async def test_tasks_cancel_is_idempotent(a2a_app, dpop):
    session_id, *_, token_a = await _open_active_session(a2a_app, dpop, "cancel-idem")
    for call_id in (1, 2):
        resp = await a2a_app.post(
            "/v1/a2a/rpc",
            json={"jsonrpc": "2.0", "id": call_id, "method": "tasks/cancel",
                  "params": {"id": session_id}},
            headers=dpop.headers("POST", "/v1/a2a/rpc", token_a),
        )
        body = resp.json()
        assert "error" not in body, body
        assert body["result"]["status"]["state"] == "canceled"


async def test_tasks_cancel_rejects_already_closed_with_other_reason(a2a_app, dpop):
    session_id, *_, token_a = await _open_active_session(a2a_app, dpop, "cancel-blk")
    # Close normally via Cullis-native path
    path = f"/v1/broker/sessions/{session_id}/close"
    r = await a2a_app.post(path, headers=dpop.headers("POST", path, token_a))
    assert r.status_code == 200

    resp = await a2a_app.post(
        "/v1/a2a/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tasks/cancel",
              "params": {"id": session_id}},
        headers=dpop.headers("POST", "/v1/a2a/rpc", token_a),
    )
    body = resp.json()
    assert body["error"]["code"] == -32002  # TaskNotCancelable
