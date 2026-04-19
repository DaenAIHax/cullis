"""Per-install bearer token for the Connector statusline endpoints.

The dashboard exposes ``GET /status/inbox`` + ``POST /status/inbox/seen``
on ``127.0.0.1:7777`` so external statusline scripts (Claude Code, etc.)
can render a "N unread from <sender>" badge. Without auth any local
process on the machine could read inbox metadata (sender + preview) and
reset the unread counter — a small but real info-disclosure + tamper
surface. This module manages a small random token stored under
``<config_dir>/identity/statusline.token`` (chmod 0600) that both
endpoints require via ``Authorization: Bearer <token>``.

The token is generated on first use and persists across Connector
restarts. Callers that can read the user's ``identity/`` directory
already hold the private key, so this adds no new trust assumption —
it just closes the gap for "other local process, same user, no disk
read of identity/".
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

STATUSLINE_TOKEN_FILENAME = "statusline.token"

_TOKEN_BYTES = 32  # 256-bit, urlsafe_b64 → 43 char string


def _token_path(config_dir: Path) -> Path:
    return config_dir / "identity" / STATUSLINE_TOKEN_FILENAME


def _write_token(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic-ish: write to sibling + rename. Matches the pattern used
    # by identity/store.py for the private key.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(token)
    try:
        tmp.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 — owner only
    except (OSError, NotImplementedError):
        # Windows filesystems don't honour POSIX bits; best-effort only.
        pass
    os.replace(tmp, path)


def ensure_statusline_token(config_dir: Path) -> str:
    """Return the statusline bearer token, generating + persisting it
    on first call.

    Idempotent: repeat calls return the same token. If the file exists
    but has wider-than-owner permissions on POSIX, we tighten them
    defensively — prevents an earlier misconfigured write from
    silently undermining the check.
    """
    path = _token_path(config_dir)
    if path.exists():
        token = path.read_text().strip()
        if token:
            # Re-assert 0600 — cheap and avoids a surprise if someone
            # edits the file out-of-band with a wider umask.
            try:
                current = stat.S_IMODE(path.stat().st_mode)
                if current & 0o077:
                    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except (OSError, NotImplementedError):
                pass
            return token
        # Empty file → treat as unset, regenerate below.

    token = secrets.token_urlsafe(_TOKEN_BYTES)
    _write_token(path, token)
    return token


def read_statusline_token(config_dir: Path) -> str | None:
    """Return the persisted token or ``None`` if it has not been
    generated yet. Used by CLI helpers that want to print the snippet
    without forcing a fresh write."""
    path = _token_path(config_dir)
    if not path.exists():
        return None
    token = path.read_text().strip()
    return token or None
