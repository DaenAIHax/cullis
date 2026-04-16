"""Tests for cullis_connector.ide_config — IDE MCP config writer."""
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
    mcp_entry_snippet,
    uninstall_mcp,
)


@pytest.fixture
def patched_ides(monkeypatch, tmp_path):
    """Redirect each known IDE to a unique temp file we own for the test."""
    paths = {
        ide_id: tmp_path / f"{ide_id}.json" for ide_id in KNOWN_IDES
    }
    fake = {}
    for ide_id, desc in KNOWN_IDES.items():
        p = str(paths[ide_id])
        fake[ide_id] = IDEDescriptor(
            id=desc.id,
            display_name=desc.display_name,
            paths={"darwin": p, "win32": p, "linux": p},
            servers_key=desc.servers_key,
        )
    monkeypatch.setattr(ide_config, "KNOWN_IDES", fake)
    return paths


@pytest.fixture
def backup_dir(tmp_path):
    return tmp_path / "backups"


# ── install_mcp ────────────────────────────────────────────────────


def test_install_creates_file_when_missing(patched_ides, backup_dir):
    target = patched_ides["claude-desktop"]
    assert not target.exists()

    result = install_mcp("claude-desktop", backup_dir=backup_dir)

    assert result.status == "installed"
    assert target.exists()
    assert result.backup_path is None  # nothing to back up
    data = json.loads(target.read_text())
    assert data["mcpServers"]["cullis"] == {
        "command": "cullis-connector",
        "args": ["serve"],
    }


def test_install_merges_existing_config(patched_ides, backup_dir):
    target = patched_ides["cursor"]
    target.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {"command": "fs", "args": ["--root", "/"]},
                },
                "someOtherKey": 42,
            }
        )
    )

    result = install_mcp("cursor", backup_dir=backup_dir)

    assert result.status == "installed"
    assert result.backup_path is not None
    assert result.backup_path.exists()
    data = json.loads(target.read_text())
    # Other entries survived.
    assert data["mcpServers"]["filesystem"]["command"] == "fs"
    assert data["someOtherKey"] == 42
    assert data["mcpServers"]["cullis"]["command"] == "cullis-connector"


def test_install_is_idempotent(patched_ides, backup_dir):
    first = install_mcp("cline", backup_dir=backup_dir)
    assert first.status == "installed"

    second = install_mcp("cline", backup_dir=backup_dir)
    assert second.status == "already_configured"
    assert second.backup_path is None


def test_install_rejects_malformed_existing_json(patched_ides, backup_dir):
    target = patched_ides["cursor"]
    original = "{this is not json"
    target.write_text(original)

    result = install_mcp("cursor", backup_dir=backup_dir)

    assert result.status == "error"
    assert "JSON" in (result.error or "")
    # Critically: we did not overwrite the user's file.
    assert target.read_text() == original


def test_install_rejects_non_dict_top_level(patched_ides, backup_dir):
    target = patched_ides["cursor"]
    target.write_text(json.dumps(["wrong", "shape"]))

    result = install_mcp("cursor", backup_dir=backup_dir)

    assert result.status == "error"
    assert "object" in (result.error or "")


def test_install_rejects_non_dict_servers_key(patched_ides, backup_dir):
    target = patched_ides["cursor"]
    target.write_text(json.dumps({"mcpServers": ["wrong"]}))

    result = install_mcp("cursor", backup_dir=backup_dir)

    assert result.status == "error"


def test_install_unknown_ide_errors():
    result = install_mcp("not-a-real-ide")
    assert result.status == "error"
    assert "Unknown" in (result.error or "")


def test_install_does_not_touch_other_cullis_metadata(patched_ides, backup_dir):
    """A pre-existing cullis entry with extra fields (env, cwd) must be
    updated in-place without losing fields the user added."""
    target = patched_ides["cursor"]
    target.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "cullis": {
                        "command": "cullis-connector",
                        "args": ["serve"],
                        "env": {"CULLIS_LOG_LEVEL": "debug"},
                    }
                }
            }
        )
    )

    result = install_mcp("cursor", backup_dir=backup_dir)

    # Entry already matches core command+args → no-op.
    assert result.status == "already_configured"
    data = json.loads(target.read_text())
    # User's env dict is still there untouched.
    assert data["mcpServers"]["cullis"]["env"] == {"CULLIS_LOG_LEVEL": "debug"}


# ── uninstall_mcp ──────────────────────────────────────────────────


def test_uninstall_removes_cullis_preserves_others(patched_ides, backup_dir):
    target = patched_ides["claude-desktop"]
    target.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "cullis": {"command": "cullis-connector", "args": ["serve"]},
                    "keeper": {"command": "k", "args": []},
                }
            }
        )
    )

    result = uninstall_mcp("claude-desktop", backup_dir=backup_dir)

    assert result.status == "installed"
    assert result.backup_path is not None
    data = json.loads(target.read_text())
    assert "cullis" not in data["mcpServers"]
    assert data["mcpServers"]["keeper"]["command"] == "k"


def test_uninstall_is_idempotent_when_no_cullis(patched_ides, backup_dir):
    target = patched_ides["cursor"]
    target.write_text(json.dumps({"mcpServers": {}}))
    result = uninstall_mcp("cursor", backup_dir=backup_dir)
    assert result.status == "already_configured"


def test_uninstall_on_missing_file_is_noop(patched_ides, backup_dir):
    result = uninstall_mcp("cline", backup_dir=backup_dir)
    assert result.status == "already_configured"


# ── detect_ide_status ─────────────────────────────────────────────


def test_detect_missing_when_parent_dir_absent(patched_ides):
    # patched_ides puts configs under tmp_path/ which exists, so the
    # "parent dir exists" branch fires → DETECTED. To get MISSING we
    # need the parent dir to not exist. Point to a deeper nonexistent dir.
    import cullis_connector.ide_config as m
    desc = m.KNOWN_IDES["cursor"]
    nowhere = "/nonexistent/deeply/nested/cursor.json"
    m.KNOWN_IDES["cursor"] = IDEDescriptor(
        id=desc.id, display_name=desc.display_name,
        paths={"darwin": nowhere, "win32": nowhere, "linux": nowhere},
    )
    r = detect_ide_status("cursor")
    assert r.status == IDEStatus.MISSING


def test_detect_detected_when_dir_exists_but_no_config(patched_ides):
    # patched_ides points at tmp_path/cursor.json — tmp_path exists, file doesn't
    r = detect_ide_status("cursor")
    assert r.status == IDEStatus.DETECTED


def test_detect_configured_after_install(patched_ides, backup_dir):
    install_mcp("cline", backup_dir=backup_dir)
    r = detect_ide_status("cline")
    assert r.status == IDEStatus.CONFIGURED


def test_detect_detected_when_config_has_other_entries(patched_ides):
    target = patched_ides["claude-desktop"]
    target.write_text(json.dumps({"mcpServers": {"other": {"command": "x", "args": []}}}))
    r = detect_ide_status("claude-desktop")
    assert r.status == IDEStatus.DETECTED


def test_detect_error_on_malformed_json(patched_ides):
    target = patched_ides["cursor"]
    target.write_text("not json")
    r = detect_ide_status("cursor")
    assert r.status == IDEStatus.ERROR


# ── mcp_entry_snippet ─────────────────────────────────────────────


def test_snippet_is_valid_json():
    parsed = json.loads(mcp_entry_snippet())
    assert parsed["mcpServers"]["cullis"]["command"] == "cullis-connector"
    assert parsed["mcpServers"]["cullis"]["args"] == ["serve"]


def test_snippet_respects_custom_args():
    parsed = json.loads(mcp_entry_snippet(args=["serve", "--log-level", "debug"]))
    assert parsed["mcpServers"]["cullis"]["args"] == ["serve", "--log-level", "debug"]
