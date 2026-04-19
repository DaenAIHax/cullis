"""M3.3b — dashboard /profiles page and tray-menu wiring.

Covers:
* GET /profiles renders a card per profile found on disk, with an
  "active" badge on the one matching ConnectorConfig.profile_name.
* POST /profiles/create returns a copy-pasteable enrollment snippet
  for a valid name, rejects hostile names with 400.
* Tray submenu builder emits one radio entry per profile plus a
  "Manage profiles…" escape hatch, and returns None when the machine
  has no profiles yet (so the top menu doesn't grow an empty
  submenu).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig


@pytest.fixture
def profile_tree(tmp_path):
    """A realistic ~/.cullis/ tree with two profiles, active = north."""
    root = tmp_path / "cullis"
    (root / "profiles" / "north" / "identity").mkdir(parents=True)
    (root / "profiles" / "south").mkdir(parents=True)
    # Mark north as enrolled, south as pending.
    (root / "profiles" / "north" / "identity" / "agent.crt").write_text("pem")
    return root


@pytest.fixture
def client_on_north(profile_tree, monkeypatch):
    """Boot the dashboard as if the user launched
    `cullis-connector desktop --profile north`."""
    import cullis_connector.web as _web
    monkeypatch.setattr(_web, "has_identity", lambda _: True)

    cfg = ConnectorConfig(
        config_dir=profile_tree / "profiles" / "north",
        profile_name="north",
        site_url="http://mastio.test",
        verify_tls=False,
    )
    from cullis_connector.web import build_app
    return TestClient(build_app(cfg))


def test_profiles_page_lists_profiles_and_flags_active(client_on_north):
    resp = client_on_north.get("/profiles")
    assert resp.status_code == 200
    body = resp.text
    assert "north" in body
    assert "south" in body
    # Active badge only rendered for the currently-loaded profile.
    # Look for the badge span next to "north" but not "south".
    assert body.count("profile-badge") == 1


def test_profiles_page_topbar_shows_active_profile(client_on_north):
    resp = client_on_north.get("/profiles")
    # Base template exposes active_profile via Jinja globals — the
    # linked sub-label renders "Profile · north".
    assert "Profile · north" in resp.text


def test_profiles_create_returns_snippet_for_valid_name(client_on_north):
    resp = client_on_north.post("/profiles/create", data={"name": "east"})
    assert resp.status_code == 200
    text = resp.text
    assert "--profile east" in text
    # Both the enroll command and the desktop relaunch command show up.
    assert "cullis-connector enroll --profile east" in text
    assert "cullis-connector desktop --profile east" in text


def test_profiles_create_rejects_hostile_name(client_on_north):
    resp = client_on_north.post(
        "/profiles/create", data={"name": "../escape"}
    )
    assert resp.status_code == 400
    assert "invalid profile name" in resp.text


def test_profiles_create_rejects_empty_name(client_on_north):
    # FastAPI's Form(...) treats empty string as present, so our own
    # validator catches it. An omitted `name` field gets a 422 from
    # FastAPI's request validation — both are acceptable rejection
    # paths here.
    resp = client_on_north.post("/profiles/create", data={"name": ""})
    assert resp.status_code in (400, 422)


# ── tray-menu wiring (headless — no GUI) ─────────────────────────────


def test_build_profiles_submenu_returns_none_when_no_profiles():
    pystray = pytest.importorskip("pystray")  # noqa: F841
    from cullis_connector.desktop_app import _build_profiles_submenu

    out = _build_profiles_submenu([], active="", open_profiles_page=lambda: None)
    assert out is None


def test_build_profiles_submenu_emits_item_per_profile():
    pystray = pytest.importorskip("pystray")
    from cullis_connector.desktop_app import _build_profiles_submenu

    menu = _build_profiles_submenu(
        ["default", "north", "south"],
        active="north",
        open_profiles_page=lambda: None,
    )
    assert isinstance(menu, pystray.Menu)
    items = list(menu.items)
    # 3 radio entries + separator + "Manage profiles…"
    assert len(items) == 5
    # First three items are the profile radio entries.
    radio_texts = [str(it.text) for it in items[:3]]
    assert radio_texts == ["default", "north", "south"]
    # Only "north" should be marked checked.
    checks = [it.checked(it) if callable(it.checked) else it.checked for it in items[:3]]
    assert checks == [False, True, False]
