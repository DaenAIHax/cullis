"""M3.6 — router-level queue fallback integration tests.

Verifies that POST /sessions/{id}/messages enqueues via mq.enqueue when
the recipient is not WS-connected locally, and that idempotency replay
collapses to a single queued row.
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.broker import message_queue as mq
from app.broker.db_models import ProxyMessageQueueRecord
from app.db.database import AsyncSessionLocal
from tests.cert_factory import make_encrypted_envelope
from tests.test_broker import _register_and_login

pytestmark = pytest.mark.asyncio


async def _open_session(client, dpop, org_a: str, agent_a: str, org_b: str, agent_b: str):
    token_a = await _register_and_login(client, dpop, agent_a, org_a)
    token_b = await _register_and_login(client, dpop, agent_b, org_b)
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": agent_b, "target_org_id": org_b,
        "requested_capabilities": ["kyc.read"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    sid = resp.json()["session_id"]
    await client.post(
        f"/v1/broker/sessions/{sid}/accept",
        headers=dpop.headers("POST", f"/v1/broker/sessions/{sid}/accept", token_b),
    )
    return sid, token_a, token_b, agent_a, agent_b


async def _count_queue_rows(recipient_agent_id: str) -> int:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ProxyMessageQueueRecord).where(
                ProxyMessageQueueRecord.recipient_agent_id == recipient_agent_id,
            )
        )
        return len(result.scalars().all())


async def test_send_enqueues_when_recipient_offline(client: AsyncClient, dpop):
    sid, token_a, token_b, agent_a, agent_b = await _open_session(
        client, dpop, "m3q-a", "m3q-a::agent", "m3q-b", "m3q-b::agent",
    )
    envelope = make_encrypted_envelope(
        agent_a, "m3q-a", agent_b, "m3q-b", sid, str(uuid.uuid4()), {"hi": "there"},
    )
    path = f"/v1/broker/sessions/{sid}/messages"
    resp = await client.post(
        path, json=envelope,
        headers=dpop.headers("POST", path, token_a),
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert "msg_id" in body
    assert body["deduped"] is False
    assert await _count_queue_rows(agent_b) == 1


async def test_idempotency_key_dedupes_via_query_param(client: AsyncClient, dpop):
    sid, token_a, token_b, agent_a, agent_b = await _open_session(
        client, dpop, "m3qd-a", "m3qd-a::agent", "m3qd-b", "m3qd-b::agent",
    )
    path = f"/v1/broker/sessions/{sid}/messages?idempotency_key=order-42&ttl_seconds=120"

    env1 = make_encrypted_envelope(
        agent_a, "m3qd-a", agent_b, "m3qd-b", sid, str(uuid.uuid4()), {"n": 1},
    )
    r1 = await client.post(path, json=env1, headers=dpop.headers("POST", path, token_a))
    assert r1.status_code == 202 and r1.json()["deduped"] is False
    first_msg_id = r1.json()["msg_id"]

    env2 = make_encrypted_envelope(
        agent_a, "m3qd-a", agent_b, "m3qd-b", sid, str(uuid.uuid4()), {"n": 2},
    )
    r2 = await client.post(path, json=env2, headers=dpop.headers("POST", path, token_a))
    assert r2.status_code == 202
    assert r2.json()["deduped"] is True
    assert r2.json()["msg_id"] == first_msg_id
    assert await _count_queue_rows(agent_b) == 1


async def test_ttl_seconds_query_param_respected(client: AsyncClient, dpop):
    sid, token_a, token_b, agent_a, agent_b = await _open_session(
        client, dpop, "m3qt-a", "m3qt-a::agent", "m3qt-b", "m3qt-b::agent",
    )
    path = f"/v1/broker/sessions/{sid}/messages?ttl_seconds=7200"
    envelope = make_encrypted_envelope(
        agent_a, "m3qt-a", agent_b, "m3qt-b", sid, str(uuid.uuid4()), {"x": 1},
    )
    resp = await client.post(path, json=envelope, headers=dpop.headers("POST", path, token_a))
    assert resp.status_code == 202

    async with AsyncSessionLocal() as db:
        row = (await db.execute(
            select(ProxyMessageQueueRecord).where(
                ProxyMessageQueueRecord.recipient_agent_id == agent_b,
            )
        )).scalar_one()
        delta = (row.ttl_expires_at - row.enqueued_at).total_seconds()
        assert 7100 < delta < 7300  # ~2h window, tolerate clock drift


# ─────────────────────────────────────────────────────────────────────
# Ack endpoint
# ─────────────────────────────────────────────────────────────────────


async def _enqueue_one_and_get_msg_id(client, dpop, org_a, agent_a, org_b, agent_b):
    sid, token_a, token_b, _a, _b = await _open_session(client, dpop, org_a, agent_a, org_b, agent_b)
    envelope = make_encrypted_envelope(
        agent_a, org_a, agent_b, org_b, sid, str(uuid.uuid4()), {"k": 1},
    )
    path = f"/v1/broker/sessions/{sid}/messages"
    resp = await client.post(path, json=envelope, headers=dpop.headers("POST", path, token_a))
    assert resp.status_code == 202 and resp.json()["status"] == "queued"
    return sid, resp.json()["msg_id"], token_b


async def test_ack_happy_path_returns_204(client: AsyncClient, dpop):
    sid, msg_id, token_b = await _enqueue_one_and_get_msg_id(
        client, dpop, "m3ack-a", "m3ack-a::agent", "m3ack-b", "m3ack-b::agent",
    )
    path = f"/v1/broker/sessions/{sid}/messages/{msg_id}/ack"
    resp = await client.post(path, headers=dpop.headers("POST", path, token_b))
    assert resp.status_code == 204


async def test_ack_unknown_msg_returns_404(client: AsyncClient, dpop):
    sid, _, token_b = await _enqueue_one_and_get_msg_id(
        client, dpop, "m3ack2-a", "m3ack2-a::agent", "m3ack2-b", "m3ack2-b::agent",
    )
    bogus = str(uuid.uuid4())
    path = f"/v1/broker/sessions/{sid}/messages/{bogus}/ack"
    resp = await client.post(path, headers=dpop.headers("POST", path, token_b))
    assert resp.status_code == 404


async def test_ack_twice_returns_409(client: AsyncClient, dpop):
    sid, msg_id, token_b = await _enqueue_one_and_get_msg_id(
        client, dpop, "m3ack3-a", "m3ack3-a::agent", "m3ack3-b", "m3ack3-b::agent",
    )
    path = f"/v1/broker/sessions/{sid}/messages/{msg_id}/ack"
    r1 = await client.post(path, headers=dpop.headers("POST", path, token_b))
    assert r1.status_code == 204
    r2 = await client.post(path, headers=dpop.headers("POST", path, token_b))
    assert r2.status_code == 409


async def test_ack_from_non_recipient_returns_404(client: AsyncClient, dpop):
    # Sender tries to ack their own queued message — scoping by recipient_agent_id
    # hides the row so the sender sees a 404, not a 409 (no info leak).
    sid, token_a, token_b, agent_a, agent_b = await _open_session(
        client, dpop, "m3ack4-a", "m3ack4-a::agent", "m3ack4-b", "m3ack4-b::agent",
    )
    envelope = make_encrypted_envelope(
        agent_a, "m3ack4-a", agent_b, "m3ack4-b", sid, str(uuid.uuid4()), {"x": 1},
    )
    path_send = f"/v1/broker/sessions/{sid}/messages"
    r = await client.post(path_send, json=envelope, headers=dpop.headers("POST", path_send, token_a))
    msg_id = r.json()["msg_id"]

    path_ack = f"/v1/broker/sessions/{sid}/messages/{msg_id}/ack"
    resp = await client.post(path_ack, headers=dpop.headers("POST", path_ack, token_a))
    assert resp.status_code == 404


async def test_ack_malformed_msg_id_returns_400(client: AsyncClient, dpop):
    sid, _, token_b = await _enqueue_one_and_get_msg_id(
        client, dpop, "m3ack5-a", "m3ack5-a::agent", "m3ack5-b", "m3ack5-b::agent",
    )
    path = f"/v1/broker/sessions/{sid}/messages/not-a-uuid/ack"
    resp = await client.post(path, headers=dpop.headers("POST", path, token_b))
    assert resp.status_code == 400
