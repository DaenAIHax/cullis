"""M3.4 — dashboard autoconfig for Claude Code CLI.

Claude Code CLI stores its MCP servers behind the `claude mcp add`
command rather than in a JSON file we can diff-and-merge. This
module tests the COMMAND-kind install path:

* detection branches on `shutil.which("claude")` + `claude mcp list`.
* install shells out to `claude mcp add cullis --scope user -- ...`.
* idempotency: already-registered → ``already_configured``.
* profile propagation: an active profile threads ``--profile <name>``
  through to the subprocess invocation.

subprocess is never actually spawned — we patch the two seams
(`_which_claude`, `_run_claude`) the module exposes for tests.
"""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

from cullis_connector import ide_config as ic


def _mk_completed(returncode: int, stdout: str = "", stderr: str = ""):
    """Minimal stand-in for subprocess.CompletedProcess that only has
    the attributes our detect/install code reads."""
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ── Detection ────────────────────────────────────────────────────────


def test_detect_claude_cli_missing_when_binary_not_on_path(monkeypatch):
    monkeypatch.setattr(ic, "_which_claude", lambda: None)
    r = ic.detect_ide_status("claude-code-cli")
    assert r.status is ic.IDEStatus.MISSING
    assert "not on PATH" in (r.note or "")


def test_detect_claude_cli_configured_when_cullis_in_list(monkeypatch):
    monkeypatch.setattr(ic, "_which_claude", lambda: "/usr/local/bin/claude")
    monkeypatch.setattr(
        ic, "_run_claude",
        lambda args, timeout=5: _mk_completed(0, stdout="cullis: cullis-connector serve\n"),
    )
    r = ic.detect_ide_status("claude-code-cli")
    assert r.status is ic.IDEStatus.CONFIGURED


def test_detect_claude_cli_detected_when_list_lacks_cullis(monkeypatch):
    monkeypatch.setattr(ic, "_which_claude", lambda: "/usr/local/bin/claude")
    monkeypatch.setattr(
        ic, "_run_claude",
        lambda args, timeout=5: _mk_completed(0, stdout="someoneelse: foo\n"),
    )
    r = ic.detect_ide_status("claude-code-cli")
    assert r.status is ic.IDEStatus.DETECTED
    assert "not registered yet" in (r.note or "")


def test_detect_claude_cli_gracefully_downgrades_on_probe_failure(monkeypatch):
    monkeypatch.setattr(ic, "_which_claude", lambda: "/usr/local/bin/claude")

    def _boom(args, timeout=5):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr(ic, "_run_claude", _boom)
    r = ic.detect_ide_status("claude-code-cli")
    # A probe failure should NOT bubble up as ERROR — worst case the
    # user clicks install and sees the real error there.
    assert r.status is ic.IDEStatus.DETECTED


# ── Install ──────────────────────────────────────────────────────────


def test_install_claude_cli_missing_reports_cleanly(monkeypatch):
    monkeypatch.setattr(ic, "_which_claude", lambda: None)
    res = ic.install_mcp("claude-code-cli")
    assert res.status == "missing"
    assert "not installed" in (res.error or "").lower()


def test_install_claude_cli_already_configured_is_noop(monkeypatch):
    monkeypatch.setattr(ic, "_which_claude", lambda: "/usr/local/bin/claude")
    monkeypatch.setattr(
        ic, "_run_claude",
        lambda args, timeout=5: _mk_completed(0, stdout="cullis: running\n"),
    )
    res = ic.install_mcp("claude-code-cli")
    assert res.status == "already_configured"


def test_install_claude_cli_happy_path_shells_out(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(args, timeout=15):
        calls.append(list(args))
        if "list" in args:
            # Pre-install probe sees no existing entry.
            return _mk_completed(0, stdout="")
        # Actual `mcp add` invocation succeeds.
        return _mk_completed(0, stdout="Added MCP server 'cullis'.\n")

    monkeypatch.setattr(ic, "_which_claude", lambda: "/usr/local/bin/claude")
    monkeypatch.setattr(ic, "_run_claude", _fake_run)

    res = ic.install_mcp("claude-code-cli")
    assert res.status == "installed"

    # Two subprocess calls: list (idempotency probe) + add.
    assert any("list" in c for c in calls)
    add_call = next(c for c in calls if "add" in c)
    assert add_call[:5] == ["claude", "mcp", "add", "cullis", "--scope"]
    assert add_call[5] == "user"
    assert "--" in add_call
    # Command + default args appear after the `--` separator.
    sep = add_call.index("--")
    assert add_call[sep + 1:] == ["cullis-connector", "serve"]


def test_install_claude_cli_propagates_profile(monkeypatch):
    """When the dashboard is running with --profile north, the web
    layer threads ``args=["serve", "--profile", "north"]`` through,
    and we expect that to land verbatim after the `--` separator."""
    calls: list[list[str]] = []

    def _fake_run(args, timeout=15):
        calls.append(list(args))
        if "list" in args:
            return _mk_completed(0, stdout="")
        return _mk_completed(0, stdout="Added MCP server 'cullis'.\n")

    monkeypatch.setattr(ic, "_which_claude", lambda: "/usr/local/bin/claude")
    monkeypatch.setattr(ic, "_run_claude", _fake_run)

    res = ic.install_mcp(
        "claude-code-cli",
        args=["serve", "--profile", "north"],
    )
    assert res.status == "installed"

    add_call = next(c for c in calls if "add" in c)
    sep = add_call.index("--")
    assert add_call[sep + 1:] == [
        "cullis-connector", "serve", "--profile", "north",
    ]


def test_install_claude_cli_surfaces_subprocess_error(monkeypatch):
    def _fake_run(args, timeout=15):
        if "list" in args:
            return _mk_completed(0, stdout="")
        return _mk_completed(
            2,
            stdout="",
            stderr="error: invalid scope 'user'\n",
        )

    monkeypatch.setattr(ic, "_which_claude", lambda: "/usr/local/bin/claude")
    monkeypatch.setattr(ic, "_run_claude", _fake_run)

    res = ic.install_mcp("claude-code-cli")
    assert res.status == "error"
    assert "invalid scope" in (res.error or "")


# ── Uninstall guard ──────────────────────────────────────────────────


def test_uninstall_claude_cli_refuses_and_hints(monkeypatch):
    """We deliberately don't uninstall COMMAND-kind entries from the
    dashboard — surfacing the CLI command is safer than silently
    rewriting the user's registered MCP servers."""
    res = ic.uninstall_mcp("claude-code-cli")
    assert res.status == "error"
    assert "claude mcp remove cullis" in (res.error or "")


# ── Descriptor registration ──────────────────────────────────────────


def test_claude_cli_shows_up_in_known_ides():
    assert "claude-code-cli" in ic.KNOWN_IDES
    d = ic.KNOWN_IDES["claude-code-cli"]
    assert d.kind is ic.InstallerKind.COMMAND
    assert d.detect_binary == "claude"
