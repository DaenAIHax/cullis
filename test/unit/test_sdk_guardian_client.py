"""ADR-016 Phase 1 — SDK Guardian client (NO-OP + verify_ticket).

The SDK client is the entry point on the agent side. Default OFF —
unless ``CULLIS_GUARDIAN_ENABLED=1`` is set, ``inspect_*`` returns a
synthetic pass without touching the network. Tests cover both paths
plus the ``GuardianBlocked`` exception and the local ticket verifier.
"""
from __future__ import annotations

import json
import time

import httpx
import pytest

from cullis_sdk.guardian import (
    GuardianBlocked,
    GuardianClient,
    InspectionDecision,
    verify_ticket,
)
from mcp_proxy.guardian.ticket import sign_ticket as mastio_sign_ticket


_KEY_HEX = "00112233445566778899aabbccddeeff" * 2


@pytest.mark.asyncio
async def test_no_op_when_env_disabled(monkeypatch):
    monkeypatch.delenv("CULLIS_GUARDIAN_ENABLED", raising=False)
    client = GuardianClient(mastio_url="http://nonexistent")
    decision = await client.inspect_before_send(
        payload=b"hello", peer_agent_id="orgb::bob", msg_id="m-1",
    )
    assert isinstance(decision, InspectionDecision)
    assert decision.decision == "pass"
    assert decision.ticket == ""
    assert decision.audit_id == ""
    await client.aclose()


@pytest.mark.asyncio
async def test_posts_to_mastio_when_enabled(monkeypatch):
    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")

    seen: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "decision": "pass",
            "ticket": "fake-jwt",
            "ticket_exp": int(time.time()) + 30,
            "audit_id": "aud-xyz",
            "redacted_payload_b64": None,
            "reasons": [],
        })

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:
        client = GuardianClient(mastio_url="http://mastio.local", http_client=http)
        decision = await client.inspect_before_send(
            payload=b"hello", peer_agent_id="orgb::bob", msg_id="m-2",
        )

    assert seen["url"].endswith("/v1/guardian/inspect")
    assert seen["body"]["direction"] == "out"
    assert seen["body"]["peer_agent_id"] == "orgb::bob"
    assert seen["body"]["msg_id"] == "m-2"
    assert decision.decision == "pass"
    assert decision.ticket == "fake-jwt"
    assert decision.audit_id == "aud-xyz"


@pytest.mark.asyncio
async def test_block_decision_raises_guardian_blocked(monkeypatch):
    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "decision": "block",
            "ticket": "fake-jwt",
            "ticket_exp": int(time.time()) + 30,
            "audit_id": "aud-block-1",
            "redacted_payload_b64": None,
            "reasons": [{"tool": "secret_leak", "match": "AKIA…"}],
        })

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:
        client = GuardianClient(mastio_url="http://mastio.local", http_client=http)
        with pytest.raises(GuardianBlocked) as exc:
            await client.inspect_before_send(
                payload=b"AKIAEXAMPLE", peer_agent_id="orgb::bob",
                msg_id="m-block",
            )

    assert exc.value.audit_id == "aud-block-1"
    assert exc.value.direction == "out"
    assert exc.value.reasons[0]["tool"] == "secret_leak"


@pytest.mark.asyncio
async def test_redact_decision_carries_redacted_bytes(monkeypatch):
    import base64

    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")
    redacted_bytes = b'{"card":"[REDACTED]"}'

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "decision": "redact",
            "ticket": "fake-jwt",
            "ticket_exp": int(time.time()) + 30,
            "audit_id": "aud-redact-1",
            "redacted_payload_b64": base64.urlsafe_b64encode(redacted_bytes)
                .rstrip(b"=").decode("ascii"),
            "reasons": [{"tool": "pii_egress", "match": "card"}],
        })

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:
        client = GuardianClient(mastio_url="http://mastio.local", http_client=http)
        decision = await client.inspect_before_send(
            payload=b'{"card":"4242"}', peer_agent_id="orgb::bob",
            msg_id="m-redact",
        )

    assert decision.decision == "redact"
    assert decision.redacted_payload == redacted_bytes


@pytest.mark.asyncio
async def test_http_error_surfaces(monkeypatch):
    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream gone")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:
        client = GuardianClient(mastio_url="http://mastio.local", http_client=http)
        with pytest.raises(RuntimeError) as exc:
            await client.inspect_before_send(
                payload=b"x", peer_agent_id="orgb::bob", msg_id="m-503",
            )
    assert "guardian_inspect_http_503" in str(exc.value)


def test_verify_ticket_roundtrip_against_mastio_signer():
    """The SDK's verify_ticket must accept what mcp_proxy.guardian.ticket
    signs — they are the same algorithm but sit in different repos in
    practice, so we lock the byte-level contract here."""
    token, _ = mastio_sign_ticket(
        key=_KEY_HEX,
        agent_id="orga::alice",
        peer_agent_id="orgb::bob",
        msg_id="m-3",
        direction="in",
        decision="pass",
        audit_id="aud-3",
    )
    claims = verify_ticket(token=token, key=_KEY_HEX)
    assert claims["agent_id"] == "orga::alice"
    assert claims["msg_id"] == "m-3"


def test_verify_ticket_msg_id_mismatch_rejects():
    token, _ = mastio_sign_ticket(
        key=_KEY_HEX,
        agent_id="orga::alice", peer_agent_id="orgb::bob",
        msg_id="m-real", direction="in", decision="pass", audit_id="a-1",
    )
    with pytest.raises(ValueError) as exc:
        verify_ticket(token=token, key=_KEY_HEX, expected_msg_id="m-other")
    assert "msg_id_mismatch" in str(exc.value)


def test_verify_ticket_expired_rejects():
    token, _ = mastio_sign_ticket(
        key=_KEY_HEX,
        agent_id="orga::alice", peer_agent_id="orgb::bob",
        msg_id="m-exp", direction="in", decision="pass", audit_id="a-1",
        ttl_s=1,
    )
    time.sleep(1.5)
    with pytest.raises(ValueError) as exc:
        verify_ticket(token=token, key=_KEY_HEX)
    assert "expired" in str(exc.value)
