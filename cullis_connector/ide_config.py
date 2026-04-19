"""IDE MCP-config writer — teach Claude Desktop, Cursor, and Cline about us.

Each MCP client keeps its list of servers in a JSON file at a well-known
path. This module knows those paths for every major OS and can:

* Detect whether the IDE is installed (its config dir exists).
* Detect whether the Cullis entry is already present and correct.
* Merge our entry in without destroying the user's other servers.
* Back up the original file atomically before writing.

Rules we follow religiously:

1. Never destroy existing config. If parsing fails we stop and report —
   the user edits by hand rather than losing setup.
2. Always back up the pre-write file to ``<config_dir>/backups/`` with a
   timestamp. A missing file is not backed up (there's nothing to save).
3. Idempotent: running install twice is a no-op the second time.
4. Atomic writes — tmp file + os.replace — so a crash never leaves a
   half-written JSON.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


MCP_ENTRY_NAME = "cullis"
MCP_SERVERS_KEY = "mcpServers"

# The connector binary name installed by `pip install cullis-agent-sdk[connector]`.
# We bet on it being on the user's PATH; if not, the user sees a clear
# "command not found" in the IDE and knows to reinstall. We don't embed
# an absolute path because the user might move the install (e.g. Homebrew
# vs pipx vs system pip).
DEFAULT_COMMAND = "cullis-connector"
DEFAULT_ARGS = ["serve"]


class InstallerKind(str, Enum):
    """How a given MCP client accepts server registrations.

    ``FILE`` — the client keeps its servers in a JSON file at a
    well-known path (Claude Desktop, Cursor, Cline).
    ``COMMAND`` — the client exposes a CLI to register servers and
    stores them somewhere of its own (Claude Code CLI, which uses
    ``claude mcp add``). We never touch that storage directly;
    we just shell out to the binary.
    """
    FILE = "file"
    COMMAND = "command"


class IDEStatus(str, Enum):
    CONFIGURED = "configured"  # file exists AND cullis entry present & correct
    DETECTED = "detected"      # IDE installed, but cullis not configured yet
    MISSING = "missing"        # IDE not installed on this machine
    ERROR = "error"            # config file exists but unreadable/malformed


@dataclass(frozen=True)
class IDEDescriptor:
    id: str
    display_name: str
    # Per-OS path to the MCP config file (empty dict for COMMAND kind).
    # Missing OS key means "not supported".
    paths: dict[str, str] = field(default_factory=dict)
    # Top-level JSON key inside the config file where servers live
    # (ignored for COMMAND kind). All three file-based IDEs use
    # "mcpServers".
    servers_key: str = MCP_SERVERS_KEY
    # How install/detect work for this client.
    kind: InstallerKind = InstallerKind.FILE
    # For COMMAND kind: name of the binary we probe on PATH (e.g.
    # "claude"). None for FILE kind.
    detect_binary: str | None = None


KNOWN_IDES: dict[str, IDEDescriptor] = {
    "claude-desktop": IDEDescriptor(
        id="claude-desktop",
        display_name="Claude Desktop",
        paths={
            "darwin": "~/Library/Application Support/Claude/claude_desktop_config.json",
            "win32":  "%APPDATA%\\Claude\\claude_desktop_config.json",
            "linux":  "~/.config/Claude/claude_desktop_config.json",
        },
    ),
    "cursor": IDEDescriptor(
        id="cursor",
        display_name="Cursor",
        paths={
            "darwin": "~/.cursor/mcp.json",
            "win32":  "%USERPROFILE%\\.cursor\\mcp.json",
            "linux":  "~/.cursor/mcp.json",
        },
    ),
    "cline": IDEDescriptor(
        id="cline",
        display_name="Cline (VS Code)",
        # The extension stores its MCP config deep inside VS Code's per-user
        # extension storage. The exact path is stable across recent Cline
        # versions (saoudrizwan.claude-dev publisher ID).
        paths={
            "darwin": "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            "win32":  "%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json",
            "linux":  "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        },
    ),
    "claude-code-cli": IDEDescriptor(
        id="claude-code-cli",
        display_name="Claude Code CLI",
        kind=InstallerKind.COMMAND,
        detect_binary="claude",
    ),
    "zed": IDEDescriptor(
        id="zed",
        display_name="Zed",
        paths={
            # Zed follows XDG on every OS it supports today; the
            # settings file is the same place on macOS and Linux.
            # Windows support is still preview and hasn't published a
            # stable config path, so we leave that slot off and let
            # detection fall through to MISSING.
            "darwin": "~/.config/zed/settings.json",
            "linux":  "~/.config/zed/settings.json",
        },
        # Zed uses its own key for MCP servers — `context_servers`
        # in settings.json, not the `mcpServers` that Claude Desktop /
        # Cursor / Cline / Windsurf standardised on.
        servers_key="context_servers",
    ),
    "windsurf": IDEDescriptor(
        id="windsurf",
        display_name="Windsurf",
        paths={
            "darwin": "~/.codeium/windsurf/mcp_config.json",
            "linux":  "~/.codeium/windsurf/mcp_config.json",
            "win32":  "%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json",
        },
    ),
}


# Exposed for the tests / web layer so they can stub subprocess / which.
def _run_claude(args: list[str], *, timeout: float = 15.0) -> subprocess.CompletedProcess:
    """Invoke the `claude` CLI. Isolated so tests can monkey-patch it."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _which_claude() -> str | None:
    """Locate the `claude` binary on PATH. Isolated for the same reason."""
    return shutil.which("claude")


@dataclass
class InstallResult:
    ide_id: str
    status: str  # "installed", "already_configured", "error", "missing"
    config_path: Path | None = None
    backup_path: Path | None = None
    error: str | None = None


@dataclass
class DetectResult:
    ide_id: str
    display_name: str
    status: IDEStatus
    config_path: Path | None = None
    note: str | None = None


# ── Public API ──────────────────────────────────────────────────────────


def list_ides() -> list[IDEDescriptor]:
    return list(KNOWN_IDES.values())


def resolve_config_path(ide_id: str) -> Path | None:
    """Return the resolved Path for this IDE on the current OS, or None.

    None is returned when the IDE is unknown OR not supported on the
    current platform. Callers should treat both as "can't configure".
    """
    ide = KNOWN_IDES.get(ide_id)
    if ide is None:
        return None
    os_key = _os_key()
    raw = ide.paths.get(os_key)
    if raw is None:
        return None
    return _expand(raw)


def detect_ide_status(ide_id: str) -> DetectResult:
    """Best-effort check whether the IDE is installed and whether we're in
    its MCP config already."""
    ide = KNOWN_IDES.get(ide_id)
    if ide is None:
        return DetectResult(ide_id, ide_id, IDEStatus.MISSING, note="Unknown IDE.")

    if ide.kind is InstallerKind.COMMAND:
        return _detect_command_ide(ide)

    path = resolve_config_path(ide_id)
    if path is None:
        return DetectResult(
            ide_id,
            ide.display_name,
            IDEStatus.MISSING,
            note=f"Not supported on {_os_key()}.",
        )

    # Config file present → inspect contents.
    if path.exists():
        try:
            data = _read_json(path)
        except _ConfigError as exc:
            return DetectResult(
                ide_id, ide.display_name, IDEStatus.ERROR,
                config_path=path, note=str(exc),
            )
        servers = _get_servers(data, ide)
        entry = servers.get(MCP_ENTRY_NAME)
        if _entry_matches(entry):
            return DetectResult(
                ide_id, ide.display_name, IDEStatus.CONFIGURED,
                config_path=path,
            )
        return DetectResult(
            ide_id, ide.display_name, IDEStatus.DETECTED,
            config_path=path,
            note="Config file exists, Cullis entry not set yet.",
        )

    # No file — IDE might or might not be installed. Fall back to checking
    # the parent directory: if the IDE has ever been launched on this box,
    # its user-config dir exists.
    if path.parent.exists():
        return DetectResult(
            ide_id, ide.display_name, IDEStatus.DETECTED,
            config_path=path,
            note="IDE present, no MCP config yet.",
        )
    return DetectResult(
        ide_id, ide.display_name, IDEStatus.MISSING,
        config_path=path,
        note="IDE not detected on this machine.",
    )


def detect_all() -> list[DetectResult]:
    return [detect_ide_status(i) for i in KNOWN_IDES]


def install_mcp(
    ide_id: str,
    *,
    backup_dir: Path | None = None,
    command: str = DEFAULT_COMMAND,
    args: list[str] | None = None,
) -> InstallResult:
    """Merge the Cullis MCP entry into the given IDE's config file.

    Creates the file (and parent dir) if missing. Backs up any pre-existing
    content to ``backup_dir`` before overwriting. Idempotent — if we are
    already the right entry, status is ``already_configured`` and no write
    happens.
    """
    ide = KNOWN_IDES.get(ide_id)
    if ide is None:
        return InstallResult(ide_id, "error", error=f"Unknown IDE: {ide_id}")

    if ide.kind is InstallerKind.COMMAND:
        return _install_command_ide(ide, command=command, args=args)

    path = resolve_config_path(ide_id)
    if path is None:
        return InstallResult(
            ide_id, "error",
            error=f"{ide.display_name} not supported on {_os_key()}.",
        )

    args_list = list(args) if args is not None else list(DEFAULT_ARGS)
    desired_entry = {"command": command, "args": args_list}

    # ── Load existing, or start fresh ────────────────────────────────────
    if path.exists():
        try:
            data = _read_json(path)
        except _ConfigError as exc:
            return InstallResult(
                ide_id, "error",
                config_path=path,
                error=(
                    f"Existing config at {path} is not valid JSON: {exc}. "
                    "Fix it manually before running install-mcp again."
                ),
            )
    else:
        data = {}

    if not isinstance(data, dict):
        return InstallResult(
            ide_id, "error",
            config_path=path,
            error=(
                f"Top-level JSON in {path} must be an object, got {type(data).__name__}."
            ),
        )

    servers = data.setdefault(ide.servers_key, {})
    if not isinstance(servers, dict):
        return InstallResult(
            ide_id, "error",
            config_path=path,
            error=(
                f"'{ide.servers_key}' in {path} must be an object, got "
                f"{type(servers).__name__}."
            ),
        )

    existing = servers.get(MCP_ENTRY_NAME)
    if _entry_matches(existing):
        # Entry already has the right command+args. Even if the user
        # tacked on extra keys (env, cwd, …) we leave the file alone so
        # that running install twice never clobbers hand-tuning.
        return InstallResult(
            ide_id, "already_configured",
            config_path=path,
        )

    # ── Backup (only if the file existed) ────────────────────────────────
    backup_path: Path | None = None
    if path.exists() and backup_dir is not None:
        backup_path = _write_backup(path, backup_dir, ide_id)

    # ── Merge + atomic write ─────────────────────────────────────────────
    servers[MCP_ENTRY_NAME] = desired_entry
    data[ide.servers_key] = servers

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_json_atomic(path, data)
    except OSError as exc:
        return InstallResult(
            ide_id, "error",
            config_path=path,
            backup_path=backup_path,
            error=f"Could not write {path}: {exc}",
        )

    return InstallResult(
        ide_id, "installed",
        config_path=path,
        backup_path=backup_path,
    )


# ── COMMAND-kind client helpers ─────────────────────────────────────────


def _detect_command_ide(ide: IDEDescriptor) -> DetectResult:
    """Detect a CLI-backed MCP client (currently Claude Code CLI).

    Two probes:
      1. ``shutil.which(detect_binary)`` — is the binary on PATH?
      2. ``<bin> mcp list`` — parse stdout to check whether a
         server named ``cullis`` is already registered.

    The second probe is best-effort: if the CLI's output format
    changes we downgrade from CONFIGURED to DETECTED rather than
    surfacing an ERROR, because a wrong status here is fixable by
    the user but a spurious ERROR would hide the install card.
    """
    binary = ide.detect_binary
    if not binary:
        return DetectResult(
            ide.id, ide.display_name, IDEStatus.MISSING,
            note="No detect_binary configured.",
        )
    if _which_claude() is None and binary == "claude":
        return DetectResult(
            ide.id, ide.display_name, IDEStatus.MISSING,
            note=f"`{binary}` not on PATH.",
        )

    # Probe with `claude mcp list`. If that fails, still surface
    # DETECTED — the user can click install and see the real error
    # from the write path.
    try:
        res = _run_claude([binary, "mcp", "list"], timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return DetectResult(
            ide.id, ide.display_name, IDEStatus.DETECTED,
            note=f"`{binary}` installed; MCP list query failed.",
        )

    output = (res.stdout or "") + (res.stderr or "")
    if res.returncode == 0 and MCP_ENTRY_NAME in output:
        return DetectResult(
            ide.id, ide.display_name, IDEStatus.CONFIGURED,
            note="`cullis` is registered as an MCP server.",
        )
    return DetectResult(
        ide.id, ide.display_name, IDEStatus.DETECTED,
        note=f"`{binary}` installed; `cullis` not registered yet.",
    )


def _install_command_ide(
    ide: IDEDescriptor,
    *,
    command: str = DEFAULT_COMMAND,
    args: list[str] | None = None,
) -> InstallResult:
    """Register Cullis as an MCP server in a CLI-backed client.

    For Claude Code CLI we use:
        claude mcp add cullis --scope user -- <command> [args...]

    ``--scope user`` makes the registration persist across projects
    on this machine, which matches the UX the dashboard's other
    cards give (configure once per machine, not once per repo).
    """
    binary = ide.detect_binary
    if not binary:
        return InstallResult(
            ide.id, "error",
            error="Descriptor missing detect_binary.",
        )

    if _which_claude() is None and binary == "claude":
        return InstallResult(
            ide.id, "missing",
            error=f"`{binary}` CLI not installed or not on PATH.",
        )

    # Idempotency: if `claude mcp list` already mentions cullis we
    # skip the add rather than letting it fail with "already exists".
    existing = _detect_command_ide(ide)
    if existing.status is IDEStatus.CONFIGURED:
        return InstallResult(ide.id, "already_configured")

    args_list = list(args) if args is not None else list(DEFAULT_ARGS)
    cmd = [
        binary, "mcp", "add", MCP_ENTRY_NAME,
        "--scope", "user",
        "--",
        command,
    ] + args_list

    try:
        res = _run_claude(cmd, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return InstallResult(
            ide.id, "error",
            error=f"Failed to invoke `{binary} mcp add`: {exc}",
        )
    if res.returncode != 0:
        message = (res.stderr or res.stdout or "").strip()
        return InstallResult(
            ide.id, "error",
            error=f"`{binary} mcp add` exited {res.returncode}: {message}",
        )
    return InstallResult(ide.id, "installed")


def uninstall_mcp(
    ide_id: str,
    *,
    backup_dir: Path | None = None,
) -> InstallResult:
    """Remove the Cullis entry. Intentionally symmetric with install_mcp."""
    ide = KNOWN_IDES.get(ide_id)
    if ide is None:
        return InstallResult(ide_id, "error", error=f"Unknown IDE: {ide_id}")

    if ide.kind is InstallerKind.COMMAND:
        # Command-backed clients get a hand-wave for now: we surface
        # the CLI invocation the user should run rather than running
        # it ourselves. Removing someone's Claude Code CLI MCP
        # entries from a background dashboard click is exactly the
        # flavour of surprise we want to avoid.
        return InstallResult(
            ide_id, "error",
            error=(
                "Removal via dashboard isn't supported for "
                f"{ide.display_name}. Run `{ide.detect_binary} mcp "
                f"remove {MCP_ENTRY_NAME}` yourself."
            ),
        )

    path = resolve_config_path(ide_id)
    if path is None or not path.exists():
        return InstallResult(ide_id, "already_configured", config_path=path)

    try:
        data = _read_json(path)
    except _ConfigError as exc:
        return InstallResult(
            ide_id, "error", config_path=path, error=str(exc),
        )

    if not isinstance(data, dict):
        return InstallResult(ide_id, "already_configured", config_path=path)
    servers = data.get(ide.servers_key)
    if not isinstance(servers, dict) or MCP_ENTRY_NAME not in servers:
        return InstallResult(ide_id, "already_configured", config_path=path)

    backup_path: Path | None = None
    if backup_dir is not None:
        backup_path = _write_backup(path, backup_dir, ide_id)

    del servers[MCP_ENTRY_NAME]
    if not servers:
        # Leave the empty mcpServers key in place — removing it could
        # surprise the user if the IDE treats the key specially.
        data[ide.servers_key] = {}
    _write_json_atomic(path, data)

    return InstallResult(
        ide_id, "installed",
        config_path=path, backup_path=backup_path,
    )


def mcp_entry_snippet(command: str = DEFAULT_COMMAND, args: list[str] | None = None) -> str:
    """Return the exact JSON the user would paste by hand — useful for the
    "copy MCP config" button when the auto-writer can't reach the file."""
    snippet = {
        MCP_SERVERS_KEY: {
            MCP_ENTRY_NAME: {
                "command": command,
                "args": list(args) if args is not None else list(DEFAULT_ARGS),
            }
        }
    }
    return json.dumps(snippet, indent=2)


# ── Internals ───────────────────────────────────────────────────────────


class _ConfigError(Exception):
    """Internal: raised when a config file is unreadable or malformed."""


def _os_key() -> str:
    """sys.platform gives us 'darwin' / 'win32' / 'linux' directly."""
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p.startswith("win"):
        return "win32"
    if p == "darwin":
        return "darwin"
    # BSDs, Haiku, etc — treat like linux for config-dir purposes.
    return "linux"


def _expand(raw_path: str) -> Path:
    """Expand ``~`` and environment variables like %APPDATA% consistently."""
    expanded = os.path.expandvars(raw_path)
    expanded = os.path.expanduser(expanded)
    return Path(expanded).resolve() if Path(expanded).exists() else Path(expanded)


def _read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise _ConfigError(f"cannot read: {exc}") from exc
    if not text.strip():
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ConfigError(f"invalid JSON at line {exc.lineno}: {exc.msg}") from exc


def _get_servers(data: Any, ide: IDEDescriptor) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    servers = data.get(ide.servers_key)
    if not isinstance(servers, dict):
        return {}
    return servers


def _entry_matches(entry: Any) -> bool:
    """Accept any entry whose command + args match — we don't demand that
    every field round-trip byte-identical. Users may add env / workingDir
    and we should not clobber those."""
    if not isinstance(entry, dict):
        return False
    if entry.get("command") != DEFAULT_COMMAND:
        return False
    args = entry.get("args")
    if args != DEFAULT_ARGS:
        return False
    return True


def _write_json_atomic(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _write_backup(src: Path, backup_dir: Path, ide_id: str) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    dest = backup_dir / f"{ide_id}-{stamp}.json"
    # Copy-in-chunks is overkill for a file that's usually <10 KB.
    dest.write_bytes(src.read_bytes())
    return dest
