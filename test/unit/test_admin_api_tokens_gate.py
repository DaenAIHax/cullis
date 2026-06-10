"""F-B-15 — admin mint endpoint gating + expiry semantics.

Pins the admin REST half of the claim-alignment PR:

  - mint refuses 403 while ``user_api_tokens_enabled`` is off, with an
    action-oriented message; list / revoke keep working so operators
    can audit and clean up existing tokens;
  - ``expires_in_days`` semantics: omitted → default 90d TTL; ``0`` →
    explicit never-expire; ``N>0`` → now + N days; combined with
    ``expires_at`` → 400.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.admin.api_tokens import router as admin_tokens_router
from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, init_db

_ADMIN_SECRET = "test-admin-secret-tokens"
_PRINCIPAL = "acme::user::alice"


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    get_settings.cache_clear()
    db_path = tmp_path / "admin_tokens.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    from _token_test_helpers import seed_default_test_principals
    await seed_default_test_principals()
    yield
    await dispose_db()
    get_settings.cache_clear()


@pytest.fixture
def client(proxy_db) -> TestClient:
    app = FastAPI()
    app.include_router(admin_tokens_router)
    return TestClient(app)


def _set_flag(monkeypatch, value: str) -> None:
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", value)
    get_settings.cache_clear()


def _mint(client: TestClient, **extra) -> "TestClient.Response":
    return client.post(
        "/v1/admin/api-tokens",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
        json={
            "principal_id": _PRINCIPAL,
            "label": extra.pop("label", "gate-test"),
            **extra,
        },
    )


def test_mint_403_when_disabled(client, monkeypatch):
    _set_flag(monkeypatch, "false")
    resp = _mint(client)
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"]


def test_list_and_revoke_work_when_disabled(client, monkeypatch):
    """Operators must be able to audit + clean up with the surface off."""
    _set_flag(monkeypatch, "true")
    minted = _mint(client, label="to-revoke").json()
    _set_flag(monkeypatch, "false")

    listed = client.get(
        "/v1/admin/api-tokens",
        params={"principal_id": _PRINCIPAL},
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert listed.status_code == 200
    assert any(t["id"] == minted["id"] for t in listed.json()["tokens"])

    revoked = client.delete(
        f"/v1/admin/api-tokens/{minted['id']}",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert revoked.status_code in (200, 204)


def test_mint_default_ttl_in_response(client, monkeypatch):
    _set_flag(monkeypatch, "true")
    resp = _mint(client, label="default-ttl")
    assert resp.status_code == 201
    body = resp.json()
    assert body["expires_at"] is not None
    expiry = datetime.fromisoformat(body["expires_at"])
    expected = datetime.now(timezone.utc) + timedelta(days=90)
    assert abs((expiry - expected).total_seconds()) < 300


def test_mint_expires_in_days_zero_is_never(client, monkeypatch):
    _set_flag(monkeypatch, "true")
    resp = _mint(client, label="never", expires_in_days=0)
    assert resp.status_code == 201
    assert resp.json()["expires_at"] is None


def test_mint_expires_in_days_positive(client, monkeypatch):
    _set_flag(monkeypatch, "true")
    resp = _mint(client, label="week", expires_in_days=7)
    assert resp.status_code == 201
    expiry = datetime.fromisoformat(resp.json()["expires_at"])
    expected = datetime.now(timezone.utc) + timedelta(days=7)
    assert abs((expiry - expected).total_seconds()) < 300


def test_mint_both_expiry_fields_is_400(client, monkeypatch):
    _set_flag(monkeypatch, "true")
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    resp = _mint(
        client, label="conflict", expires_in_days=7, expires_at=future,
    )
    assert resp.status_code == 400
    assert "mutually exclusive" in resp.json()["detail"]
