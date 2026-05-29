"""Tests for mcp_proxy.dashboard.downloads — public connector download page."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path) -> TestClient:
    from mcp_proxy.dashboard.downloads import router

    app = FastAPI()
    app.include_router(router)

    # Mount the same /static path main.py uses so tailwind.css references
    # in the template don't 404 during the integration test.
    static_dir = Path("mcp_proxy/dashboard/static")
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    return TestClient(app)


# ── Rendering ─────────────────────────────────────────────────────────────


def test_index_renders_three_platform_cards(client):
    r = client.get("/downloads/")
    assert r.status_code == 200
    # Each platform card carries the same class string.
    assert r.text.count('class="group block p-6 rounded-lg') == 3
    assert "macOS" in r.text
    assert "Windows" in r.text
    assert "Linux" in r.text


def test_index_surfaces_public_proxy_url(client):
    r = client.get("/downloads/")
    # Starlette's TestClient defaults to host "testserver"; the URL banner
    # should pick that up automatically so deployments behind ingress
    # just work out of the box.
    assert "testserver" in r.text


def test_index_highlights_detected_os(client):
    r = client.get(
        "/downloads/",
        headers={"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    )
    assert r.status_code == 200
    # The "Detected" pill only appears for the matching card.
    assert "Detected" in r.text


def test_index_works_without_recognizable_user_agent(client):
    r = client.get("/downloads/", headers={"user-agent": "curl/8.0"})
    assert r.status_code == 200
    assert "Detected" not in r.text


# ── Short redirects (/downloads/mac, /win, /linux) ───────────────────────


@pytest.mark.parametrize(
    "alias, expected_asset",
    [
        ("mac", "cullis-connector-macos.zip"),
        ("macos", "cullis-connector-macos.zip"),
        ("darwin", "cullis-connector-macos.zip"),
        ("win", "cullis-connector-windows.zip"),
        ("windows", "cullis-connector-windows.zip"),
        ("linux", "cullis-connector-linux.zip"),
    ],
)
def test_short_redirect_targets_canonical_asset(client, alias, expected_asset):
    r = client.get(f"/downloads/{alias}", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.endswith(expected_asset)


def test_unknown_alias_sends_user_back_to_index(client):
    r = client.get("/downloads/not-a-real-os", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/downloads/"


# ── Helpers ───────────────────────────────────────────────────────────────


def test_normalize_platform_accepts_common_aliases():
    from mcp_proxy.dashboard.downloads import _normalize_platform

    assert _normalize_platform("MAC") == "macos"
    assert _normalize_platform("Darwin") == "macos"
    assert _normalize_platform("Windows") == "windows"
    assert _normalize_platform("linux") == "linux"
    assert _normalize_platform("plan9") is None


def test_detect_os_ignores_unknown_ua():
    from mcp_proxy.dashboard.downloads import _detect_os

    assert _detect_os("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)") == ""
    assert _detect_os("") == ""
