"""M3.3c — runtime profile switch from the tray submenu.

Clicking a non-active profile in the tray respawns the Connector with
`--profile <target>` and tears the current process down. The active
profile's entry is a no-op. Subprocess.Popen is patched out so the
tests never actually fork a real binary.
"""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

# PIL needed by desktop_app tray-image helpers transitively via import.
pytest.importorskip("PIL.Image")

from cullis_connector import desktop_app


# ── _relaunch_argv ───────────────────────────────────────────────────


def test_relaunch_argv_uses_console_script_when_available(monkeypatch):
    # Simulate being invoked as the `cullis-connector` console script:
    # sys.argv[0] is an absolute path to the entry-point shim.
    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/cullis-connector", "desktop"])
    argv = desktop_app._relaunch_argv("north")
    assert argv == ["/usr/local/bin/cullis-connector", "desktop", "--profile", "north"]


def test_relaunch_argv_falls_back_to_python_m(monkeypatch):
    # Simulate `python -m cullis_connector` usage: argv[0] ends in .py
    # so we can't just re-exec it verbatim; fall back to sys.executable.
    monkeypatch.setattr(sys, "argv", ["/tmp/cullis_connector/__main__.py", "desktop"])
    monkeypatch.setattr(sys, "executable", "/usr/bin/python3")
    argv = desktop_app._relaunch_argv("south")
    assert argv == [
        "/usr/bin/python3",
        "-m",
        "cullis_connector",
        "desktop",
        "--profile",
        "south",
    ]


def test_relaunch_argv_handles_empty_argv(monkeypatch):
    monkeypatch.setattr(sys, "argv", [])
    monkeypatch.setattr(sys, "executable", "/opt/venv/bin/python")
    argv = desktop_app._relaunch_argv("east")
    assert argv[:3] == ["/opt/venv/bin/python", "-m", "cullis_connector"]


# ── _spawn_detached ──────────────────────────────────────────────────


def test_spawn_detached_uses_start_new_session_on_unix(monkeypatch):
    captured: dict = {}

    def _fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(pid=12345)

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(desktop_app.subprocess, "Popen", _fake_popen)
    desktop_app._spawn_detached(["cullis-connector", "desktop", "--profile", "x"])

    assert captured["argv"][0] == "cullis-connector"
    assert captured["kwargs"].get("start_new_session") is True
    assert captured["kwargs"].get("stdout") is desktop_app.subprocess.DEVNULL
    assert captured["kwargs"].get("stdin") is desktop_app.subprocess.DEVNULL
    # Windows-only flag must NOT leak into Unix spawn.
    assert "creationflags" not in captured["kwargs"]


# ── _build_profiles_submenu: switch_to hook ──────────────────────────


def test_submenu_non_active_click_invokes_switch_to():
    pystray = pytest.importorskip("pystray")
    calls: list[str] = []
    menu = desktop_app._build_profiles_submenu(
        profiles=["north", "south"],
        active="north",
        open_profiles_page=lambda: calls.append("manage"),
        switch_to=lambda name: calls.append(f"switch:{name}"),
    )
    assert isinstance(menu, pystray.Menu)
    items = list(menu.items)
    # The south entry is the 2nd radio item.
    south_item = items[1]
    assert str(south_item.text) == "south"
    # pystray menu items are invoked via __call__ with (icon, item).
    south_item(None, south_item)
    assert calls == ["switch:south"]


def test_submenu_active_click_is_noop():
    pytest.importorskip("pystray")
    calls: list[str] = []
    menu = desktop_app._build_profiles_submenu(
        profiles=["north", "south"],
        active="north",
        open_profiles_page=lambda: calls.append("manage"),
        switch_to=lambda name: calls.append(f"switch:{name}"),
    )
    items = list(menu.items)
    north_item = items[0]
    north_item(None, north_item)
    # Click on the already-active profile does nothing — no switch,
    # no Manage page open.
    assert calls == []


def test_submenu_falls_back_to_manage_when_switch_to_is_none():
    pytest.importorskip("pystray")
    calls: list[str] = []
    menu = desktop_app._build_profiles_submenu(
        profiles=["north", "south"],
        active="north",
        open_profiles_page=lambda: calls.append("manage"),
        switch_to=None,
    )
    items = list(menu.items)
    south_item = items[1]
    south_item(None, south_item)
    # With switch_to missing we honour the pre-M3.3c behaviour: open
    # the Manage profiles page for the user to act on.
    assert calls == ["manage"]


def test_submenu_manage_entry_always_opens_manage_page():
    pytest.importorskip("pystray")
    calls: list[str] = []
    menu = desktop_app._build_profiles_submenu(
        profiles=["north", "south"],
        active="north",
        open_profiles_page=lambda: calls.append("manage"),
        switch_to=lambda name: calls.append(f"switch:{name}"),
    )
    items = list(menu.items)
    # Last non-separator item is "Manage profiles…"
    manage_item = items[-1]
    assert "Manage profiles" in str(manage_item.text)
    manage_item(None, manage_item)
    assert calls == ["manage"]
