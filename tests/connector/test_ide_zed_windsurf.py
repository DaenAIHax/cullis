"""M3.5 — Zed + Windsurf IDE autoconfig.

Zed is the odd one out: its MCP servers live under the
``context_servers`` top-level key in ``settings.json`` (not
``mcpServers`` like everyone else). Windsurf follows the standard
shape but under a different path under ``~/.codeium/``.

These tests exercise both ends of the file-backed installer for the
two new IDEs: first-write behaviour, merge into an existing config,
idempotency, and — for Zed — the non-standard servers_key round-trip.
"""
from __future__ import annotations

import json

import pytest

from cullis_connector import ide_config
from cullis_connector.ide_config import (
    IDEDescriptor,
    IDEStatus,
    KNOWN_IDES,
    detect_ide_status,
    install_mcp,
    uninstall_mcp,
)


@pytest.fixture
def isolated_ides(monkeypatch, tmp_path):
    """Redirect every file-backed IDE to a dedicated tmp path,
    preserving the per-descriptor servers_key / kind / detect_binary
    so the richer descriptor fields don't silently revert to defaults
    (the original test_ide_config.py fixture predates those fields).
    """
    paths: dict[str, object] = {}
    fake = {}
    for ide_id, desc in KNOWN_IDES.items():
        if desc.kind is ide_config.InstallerKind.FILE:
            p = tmp_path / f"{ide_id}.json"
            paths[ide_id] = p
            fake[ide_id] = IDEDescriptor(
                id=desc.id,
                display_name=desc.display_name,
                paths={"darwin": str(p), "win32": str(p), "linux": str(p)},
                servers_key=desc.servers_key,
                kind=desc.kind,
                detect_binary=desc.detect_binary,
            )
        else:
            # Command-kind entries round-trip untouched so they stay
            # mocked via the other seams (_which_claude / _run_claude).
            fake[ide_id] = desc
    monkeypatch.setattr(ide_config, "KNOWN_IDES", fake)
    return paths


# ── Zed ────────────────────────────────────────────────────────────


def test_zed_install_creates_file_with_context_servers_key(isolated_ides):
    target = isolated_ides["zed"]
    result = install_mcp("zed")
    assert result.status == "installed"
    assert target.exists()

    data = json.loads(target.read_text())
    # Zed's distinctive servers key — NOT mcpServers.
    assert "context_servers" in data
    assert data["context_servers"]["cullis"] == {
        "command": "cullis-connector",
        "args": ["serve"],
    }
    assert "mcpServers" not in data


def test_zed_install_merges_into_existing_settings(isolated_ides):
    target = isolated_ides["zed"]
    # A realistic Zed settings.json with unrelated user preferences.
    target.write_text(
        json.dumps(
            {
                "theme": "One Dark",
                "vim_mode": False,
                "context_servers": {
                    "filesystem": {"command": "fs", "args": ["--root", "/"]},
                },
            }
        )
    )

    result = install_mcp("zed")
    assert result.status == "installed"

    data = json.loads(target.read_text())
    # User's other settings survive untouched.
    assert data["theme"] == "One Dark"
    assert data["vim_mode"] is False
    # Both the pre-existing entry and ours are present.
    assert "filesystem" in data["context_servers"]
    assert "cullis" in data["context_servers"]


def test_zed_install_is_idempotent(isolated_ides):
    first = install_mcp("zed")
    second = install_mcp("zed")
    assert first.status == "installed"
    assert second.status == "already_configured"


def test_zed_uninstall_round_trips(isolated_ides):
    install_mcp("zed")
    out = uninstall_mcp("zed")
    assert out.status == "installed"  # module's verbiage: "done"
    data = json.loads(isolated_ides["zed"].read_text())
    # The key itself stays (empty dict) — removing it could surprise
    # the IDE per the existing ``uninstall_mcp`` comment.
    assert data["context_servers"] == {}


def test_zed_detect_configured_when_entry_present(isolated_ides):
    install_mcp("zed")
    r = detect_ide_status("zed")
    assert r.status is IDEStatus.CONFIGURED


# ── Windsurf ───────────────────────────────────────────────────────


def test_windsurf_install_creates_file_with_mcp_servers_key(isolated_ides):
    target = isolated_ides["windsurf"]
    result = install_mcp("windsurf")
    assert result.status == "installed"
    assert target.exists()

    data = json.loads(target.read_text())
    assert data["mcpServers"]["cullis"] == {
        "command": "cullis-connector",
        "args": ["serve"],
    }


def test_windsurf_install_merges_existing_mcp_config(isolated_ides):
    target = isolated_ides["windsurf"]
    target.write_text(
        json.dumps({"mcpServers": {"github": {"command": "gh-mcp"}}})
    )
    result = install_mcp("windsurf")
    assert result.status == "installed"

    data = json.loads(target.read_text())
    assert "github" in data["mcpServers"]
    assert "cullis" in data["mcpServers"]


def test_windsurf_install_is_idempotent(isolated_ides):
    install_mcp("windsurf")
    second = install_mcp("windsurf")
    assert second.status == "already_configured"


# ── Descriptor sanity ──────────────────────────────────────────────


def test_zed_descriptor_uses_context_servers_key():
    assert KNOWN_IDES["zed"].servers_key == "context_servers"


def test_zed_windows_is_deliberately_unsupported():
    # Zed's Windows build was still preview at release time and its
    # settings path hadn't stabilised, so we leave the slot off.
    assert "win32" not in KNOWN_IDES["zed"].paths


def test_windsurf_descriptor_supports_all_three_oses():
    paths = KNOWN_IDES["windsurf"].paths
    assert set(paths) == {"darwin", "linux", "win32"}
