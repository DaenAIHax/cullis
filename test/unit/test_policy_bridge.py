"""Tests for the policy-bridge integration router.

Covers:

  * OPA Data API binding (``/v1/data/cullis/policy/{path}``)
      - session-open decisions: allow / deny via blocked_agents,
        allowed_orgs, capabilities
      - tool_call decisions: allow / deny via blocked_tools, allowed_tools
      - unknown path returns ``{"result": null}`` per OPA convention
      - malformed body / missing ``input`` returns 400

  * CloudEvents sink (``/v1/integrations/cloudevents``)
      - binary mode (CloudEvent metadata in ``ce-*`` headers, payload
        in body)
      - structured mode (entire envelope in JSON body)
      - missing required attribute → 400 with named list
      - subject lands on ``tool_name`` when present
      - audit row is written via ``log_audit`` with the documented
        column mapping

  * HMAC signature guard (``X-Cullis-Integration-Signature``)
      - secret unset → unsigned calls accepted
      - secret set + mismatched / missing signature → 401 (no body)
      - secret set + matching signature → 200 / 202
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient


# ── shared app fixture ────────────────────────────────────────────────────


@pytest.fixture
def app_under_test(monkeypatch):
    """Build a fresh FastAPI app with only the integrations router mounted.

    The Mastio's main.py app pulls in the entire lifespan (DB init,
    plugin registry, dashboard) which is way more surface than these
    tests need. Mounting the router on a bare FastAPI is sufficient.
    """
    from fastapi import FastAPI
    from mcp_proxy.integrations.policy_bridge import router

    # Patch the config & DB hooks so the router has something to talk
    # to without spinning up the full Mastio.
    state = {"policy_rules": "", "audit_calls": []}

    async def _fake_get_config(key: str) -> str:
        if key == "policy_rules":
            return state["policy_rules"]
        return ""

    async def _fake_log_audit(**kwargs):
        state["audit_calls"].append(kwargs)

    class _FakeSettings:
        integrations_hmac_secret: str = ""
        environment: str = "development"

    def _fake_get_settings():
        return _FakeSettings()

    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.get_config", _fake_get_config,
    )
    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.log_audit", _fake_log_audit,
    )
    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.get_settings", _fake_get_settings,
    )

    app = FastAPI()
    app.include_router(router)
    return app, state


@pytest.fixture
def client(app_under_test) -> TestClient:
    app, _ = app_under_test
    return TestClient(app)


# ── OPA Data API: session ──────────────────────────────────────────────────


def test_opa_session_allow_when_no_rules(client):
    resp = client.post(
        "/v1/data/cullis/policy/session",
        json={"input": {
            "initiator_agent_id": "orga::a",
            "target_agent_id": "orgb::b",
            "session_context": "initiator",
        }},
    )
    assert resp.status_code == 200
    assert resp.json() == {"result": {"decision": "allow"}}


def test_opa_session_deny_when_initiator_blocked(client, app_under_test):
    _, state = app_under_test
    state["policy_rules"] = json.dumps({"blocked_agents": ["orga::a"]})
    resp = client.post(
        "/v1/data/cullis/policy/session",
        json={"input": {
            "initiator_agent_id": "orga::a",
            "target_agent_id": "orgb::b",
            "session_context": "initiator",
        }},
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["decision"] == "deny"
    assert "blocked" in result["reason"].lower()


def test_opa_session_deny_when_org_not_allowed(client, app_under_test):
    _, state = app_under_test
    state["policy_rules"] = json.dumps({"allowed_orgs": ["orga", "orgb"]})
    resp = client.post(
        "/v1/data/cullis/policy/session",
        json={"input": {
            "initiator_agent_id": "orga::a",
            "target_agent_id": "orgc::c",
            "initiator_org_id": "orga",
            "target_org_id": "orgc",
            "session_context": "initiator",  # peer is target → orgc
        }},
    )
    result = resp.json()["result"]
    assert result["decision"] == "deny"
    assert "orgc" in result["reason"]


def test_opa_session_deny_when_capability_not_allowed(client, app_under_test):
    _, state = app_under_test
    state["policy_rules"] = json.dumps({"capabilities": ["kyc.read"]})
    resp = client.post(
        "/v1/data/cullis/policy/session",
        json={"input": {
            "initiator_agent_id": "orga::a",
            "target_agent_id": "orgb::b",
            "session_context": "initiator",
            "capabilities": ["kyc.read", "treasury.transfer"],
        }},
    )
    result = resp.json()["result"]
    assert result["decision"] == "deny"
    assert "treasury.transfer" in result["reason"]


# ── OPA Data API: tool_call ────────────────────────────────────────────────


def test_opa_tool_call_allow_when_no_rules(client):
    resp = client.post(
        "/v1/data/cullis/policy/tool_call",
        json={"input": {"agent_id": "orga::a", "tool_name": "lookup"}},
    )
    assert resp.json()["result"]["decision"] == "allow"


def test_opa_tool_call_deny_when_in_blocklist(client, app_under_test):
    _, state = app_under_test
    state["policy_rules"] = json.dumps({
        "tool_rules": {"blocked_tools": ["treasury_wire"]},
    })
    resp = client.post(
        "/v1/data/cullis/policy/tool_call",
        json={"input": {
            "agent_id": "orga::a", "tool_name": "treasury_wire",
        }},
    )
    result = resp.json()["result"]
    assert result["decision"] == "deny"
    assert "blocklist" in result["reason"]


def test_opa_tool_call_deny_when_not_in_allowlist(client, app_under_test):
    _, state = app_under_test
    state["policy_rules"] = json.dumps({
        "tool_rules": {"allowed_tools": ["kyc_lookup"]},
    })
    resp = client.post(
        "/v1/data/cullis/policy/tool_call",
        json={"input": {
            "agent_id": "orga::a", "tool_name": "treasury_wire",
        }},
    )
    assert resp.json()["result"]["decision"] == "deny"


# ── OPA Data API: misc ─────────────────────────────────────────────────────


def test_opa_unknown_path_returns_null(client):
    """OPA convention — unknown document path returns ``result: null``."""
    resp = client.post(
        "/v1/data/cullis/policy/something_else",
        json={"input": {"foo": "bar"}},
    )
    assert resp.status_code == 200
    assert resp.json() == {"result": None}


def test_opa_missing_input_400(client):
    resp = client.post(
        "/v1/data/cullis/policy/session", json={"no_input": True},
    )
    assert resp.status_code == 400


def test_opa_malformed_body_400(client):
    resp = client.post(
        "/v1/data/cullis/policy/session",
        content="not-json{",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400


# ── CloudEvents sink: binary mode ──────────────────────────────────────────


def test_cloudevents_binary_mode_records_audit_row(client, app_under_test):
    _, state = app_under_test
    resp = client.post(
        "/v1/integrations/cloudevents",
        headers={
            "ce-id": "evt-001",
            "ce-source": "gateway://nyc/cluster-1",
            "ce-type": "io.gateway.tool.allowed",
            "ce-specversion": "1.0",
            "ce-time": "2026-05-23T20:00:00Z",
            "ce-subject": "kyc_lookup",
            "content-type": "application/json",
        },
        json={"agent_id": "orga::kyc", "decision": "allow"},
    )
    assert resp.status_code == 202
    assert resp.json() == {"status": "recorded", "id": "evt-001"}
    assert len(state["audit_calls"]) == 1
    call = state["audit_calls"][0]
    assert call["agent_id"] == "external:gateway://nyc/cluster-1"
    assert call["action"] == "io.gateway.tool.allowed"
    assert call["tool_name"] == "kyc_lookup"
    assert call["status"] == "recorded"
    assert call["request_id"] == "evt-001"
    # detail payload preserves the envelope + data
    details = call["details"]
    assert details["cloudevent"]["id"] == "evt-001"
    assert details["cloudevent"]["time"] == "2026-05-23T20:00:00Z"
    assert details["data"]["decision"] == "allow"


# ── CloudEvents sink: structured mode ──────────────────────────────────────


def test_cloudevents_structured_mode_records_audit_row(client, app_under_test):
    _, state = app_under_test
    envelope = {
        "specversion": "1.0",
        "id": "evt-042",
        "source": "gateway://eu-west-1",
        "type": "io.gateway.tool.denied",
        "subject": "treasury_wire",
        "time": "2026-05-23T20:05:00Z",
        "data": {"agent_id": "orga::treasurer", "reason": "policy"},
    }
    resp = client.post(
        "/v1/integrations/cloudevents",
        headers={"content-type": "application/cloudevents+json"},
        content=json.dumps(envelope),
    )
    assert resp.status_code == 202
    call = state["audit_calls"][0]
    assert call["request_id"] == "evt-042"
    assert call["action"] == "io.gateway.tool.denied"
    assert call["tool_name"] == "treasury_wire"
    assert call["details"]["data"]["reason"] == "policy"


# ── CloudEvents sink: error paths ──────────────────────────────────────────


def test_cloudevents_missing_id_400(client):
    resp = client.post(
        "/v1/integrations/cloudevents",
        headers={
            # ce-id missing on purpose
            "ce-source": "gateway://x",
            "ce-type": "test",
            "ce-specversion": "1.0",
        },
    )
    assert resp.status_code == 400
    assert "id" in resp.json()["detail"].lower()


def test_cloudevents_missing_source_400(client):
    resp = client.post(
        "/v1/integrations/cloudevents",
        headers={
            "ce-id": "x",
            # ce-source missing
            "ce-type": "test",
            "ce-specversion": "1.0",
        },
    )
    assert resp.status_code == 400


# ── HMAC signature guard ───────────────────────────────────────────────────


def test_hmac_unconfigured_accepts_unsigned(client):
    """When integrations_hmac_secret is empty in NON-production, signed and
    unsigned are both accepted (sandbox / dev ergonomics)."""
    resp = client.post(
        "/v1/data/cullis/policy/session",
        json={"input": {
            "initiator_agent_id": "a",
            "target_agent_id": "b",
            "session_context": "initiator",
        }},
    )
    assert resp.status_code == 200


def test_hmac_unconfigured_rejects_unsigned_in_production(
    monkeypatch, app_under_test,
):
    """H10 (audit 2026-06-02) — with no secret the bridge fails CLOSED in
    production: unsigned requests are rejected. The router is mounted
    unconditionally, so an open bridge would let any reachable caller probe
    the policy surface. Runtime default-deny (no boot gate), so a prod
    deploy that didn't wire the optional secret still boots — just refuses
    unsigned bridge traffic."""
    class _Prod:
        integrations_hmac_secret: str = ""
        environment: str = "production"

    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.get_settings", lambda: _Prod(),
    )
    app, _ = app_under_test
    c = TestClient(app)
    resp = c.post(
        "/v1/data/cullis/policy/session",
        json={"input": {
            "initiator_agent_id": "a",
            "target_agent_id": "b",
            "session_context": "initiator",
        }},
    )
    assert resp.status_code == 401


def test_cloudevents_unsigned_rejected_in_production(monkeypatch, app_under_test):
    """H10 — the CloudEvents ingest is the audit_log-injection vector; in
    production without a secret it must reject and write no audit row."""
    _, state = app_under_test

    class _Prod:
        integrations_hmac_secret: str = ""
        environment: str = "production"

    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.get_settings", lambda: _Prod(),
    )
    app, _ = app_under_test
    c = TestClient(app)
    resp = c.post(
        "/v1/integrations/cloudevents",
        headers={
            "ce-id": "evt-attacker",
            "ce-source": "gateway://attacker",
            "ce-type": "io.gateway.tool.allowed",
            "ce-specversion": "1.0",
            "content-type": "application/json",
        },
        json={"agent_id": "victim::forged", "decision": "allow"},
    )
    assert resp.status_code == 401
    assert state["audit_calls"] == []  # no row injected


def test_hmac_configured_rejects_unsigned(monkeypatch, app_under_test):
    _, state = app_under_test

    class _S:
        integrations_hmac_secret: str = "test-secret-32-bytes-long-ok-123"

    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.get_settings", lambda: _S(),
    )
    app, _ = app_under_test
    c = TestClient(app)
    resp = c.post(
        "/v1/data/cullis/policy/session",
        json={"input": {
            "initiator_agent_id": "a",
            "target_agent_id": "b",
            "session_context": "initiator",
        }},
    )
    assert resp.status_code == 401
    # No body — don't leak whether the path would have been accepted.
    assert resp.content == b"" or resp.json() == {"detail": "Unauthorized"}


def test_hmac_configured_accepts_valid_signature(monkeypatch, app_under_test):
    secret = "test-secret-32-bytes-long-ok-123"

    class _S:
        integrations_hmac_secret: str = secret

    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.get_settings", lambda: _S(),
    )
    app, _ = app_under_test
    c = TestClient(app)
    body = json.dumps({"input": {
        "initiator_agent_id": "a",
        "target_agent_id": "b",
        "session_context": "initiator",
    }}).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    resp = c.post(
        "/v1/data/cullis/policy/session",
        content=body,
        headers={
            "content-type": "application/json",
            "x-cullis-integration-signature": sig,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["decision"] == "allow"


def test_hmac_configured_rejects_mismatched_signature(
    monkeypatch, app_under_test,
):
    class _S:
        integrations_hmac_secret: str = "right-secret-32-bytes-long-ok-12"

    monkeypatch.setattr(
        "mcp_proxy.integrations.policy_bridge.get_settings", lambda: _S(),
    )
    app, _ = app_under_test
    c = TestClient(app)
    body = b'{"input": {"a": 1}}'
    wrong_sig = hmac.new(
        b"wrong-secret-32-bytes-long-ok-12", body, hashlib.sha256,
    ).hexdigest()
    resp = c.post(
        "/v1/data/cullis/policy/session",
        content=body,
        headers={
            "content-type": "application/json",
            "x-cullis-integration-signature": wrong_sig,
        },
    )
    assert resp.status_code == 401
