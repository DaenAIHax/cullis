"""S-3 — enrollment rate-limit 429s carry a Retry-After header.

Prod-shape stress test (2026-06-04): a 40-agent fleet enroll tripped the
per-IP limiter on /v1/enrollment/{start,status,attestation-nonce} and the
server answered a bare 429 with no Retry-After, so the SDK / curl loop kept
hammering instead of backing off. The fix attaches Retry-After to every
enrollment 429 so a fleet enroll degrades gracefully.

These tests force the limiter to deny and assert the header is present and
parses as a positive integer (seconds).
"""
from __future__ import annotations

import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.enrollment.router import router as enrollment_router

# ``mcp_proxy.enrollment`` re-exports the APIRouter as ``.router``, which
# shadows the submodule on attribute access — so reach the real module
# (where ``get_agent_rate_limiter`` is bound) via sys.modules to patch it.
_router_mod = sys.modules["mcp_proxy.enrollment.router"]


class _DenyingRateLimiter:
    """Stand-in limiter whose check always denies, to hit the 429 path."""

    async def check(self, key: str, limit: int) -> bool:  # noqa: ARG002
        return False


@pytest.fixture
def client(monkeypatch) -> TestClient:
    monkeypatch.setattr(
        _router_mod, "get_agent_rate_limiter",
        lambda: _DenyingRateLimiter(),
    )
    app = FastAPI()
    app.include_router(enrollment_router)
    return TestClient(app)


def _assert_retry_after(resp) -> None:
    assert resp.status_code == 429, resp.text
    retry = resp.headers.get("Retry-After")
    assert retry is not None, "429 must carry a Retry-After header (S-3)"
    assert retry.isdigit() and int(retry) > 0, f"Retry-After not a positive int: {retry!r}"


def test_attestation_nonce_429_has_retry_after(client: TestClient) -> None:
    _assert_retry_after(client.get("/v1/enrollment/attestation-nonce"))


def test_status_429_has_retry_after(client: TestClient) -> None:
    # The limiter denies before the session is ever looked up, so an
    # arbitrary session_id is fine — the 429 fires first.
    _assert_retry_after(client.get("/v1/enrollment/whatever-sid/status"))
