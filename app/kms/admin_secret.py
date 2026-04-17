"""
Admin secret management — stores the admin password hash in the KMS backend.

First-boot flow (shake-out P0-06 + audit F-B-4 + F-D-3):
  A fresh deploy stores no hash and no "user-set" flag.  Startup
  generates a one-shot bootstrap token (``secrets.token_urlsafe(32)``),
  logs it prominently to stderr, and persists it in the KMS backend. The
  ``/dashboard/setup`` POST requires that token as a form field — only
  someone with access to the broker startup logs (or the
  ``certs/.admin_bootstrap_token`` file, 0600 perms) can submit it.

  Token consumption is atomic:
    * Local backend uses ``os.rename`` (POSIX-atomic) of the token file.
    * Vault backend uses a CAS write that flips
      ``admin_bootstrap_token``, ``admin_secret_hash``, and
      ``admin_password_user_set`` in one round-trip.
  Both guarantee that only one POST wins on a concurrent double-submit
  (closes F-D-3 TOCTOU).

  Once the admin submits ``/dashboard/setup`` successfully the chosen
  password is bcrypt-hashed, persisted, the "user-set" flag is marked
  true, and the bootstrap token is invalidated — from that moment on
  .env ADMIN_SECRET is no longer accepted for dashboard login.

  ADMIN_SECRET remains useful for other purposes (bootstrap automation,
  CI where the full dashboard setup is skipped, and initial access when a
  deploy's Vault is unreachable): callers that need the plaintext secret
  still read it from settings.admin_secret directly.

The dashboard "change admin password" feature calls set_admin_secret_hash()
which updates both the backend and the in-memory cache atomically.
"""
import hmac
import logging
import os
import pathlib
import secrets as _pysecrets

import bcrypt
import httpx

_log = logging.getLogger("agent_trust.admin_secret")

_cached_hash: str | None = None
_cached_user_set: bool | None = None
_VAULT_TIMEOUT = 10
_LOCAL_HASH_PATH = pathlib.Path("certs/.admin_secret_hash")
_LOCAL_USER_SET_PATH = pathlib.Path("certs/.admin_password_user_set")
_LOCAL_BOOTSTRAP_TOKEN_PATH = pathlib.Path("certs/.admin_bootstrap_token")
_VAULT_BOOTSTRAP_TOKEN_FIELD = "admin_bootstrap_token"

# Dummy hash for constant-time verification when no hash is available.
_DUMMY_HASH: str = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12)).decode()


# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

async def _vault_headers() -> dict[str, str]:
    from app.config import get_settings
    return {"X-Vault-Token": get_settings().vault_token, "Content-Type": "application/json"}


async def _read_vault_secret() -> dict | None:
    """Read the full secret dict from Vault KV v2.  Returns None on failure."""
    from app.config import get_settings
    s = get_settings()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_secret_path}"
    try:
        async with httpx.AsyncClient(timeout=_VAULT_TIMEOUT) as client:
            resp = await client.get(url, headers=await _vault_headers())
            if resp.status_code != 200:
                _log.warning("Vault read returned HTTP %d", resp.status_code)
                return None
            return resp.json()["data"]
    except Exception as exc:
        _log.warning("Vault read failed: %s", exc)
        return None


async def _write_vault_field(field: str, value: str) -> bool:
    """Merge-write a single field into the existing Vault secret (KV v2).

    KV v2 PUT replaces the entire secret, so we must read first, merge,
    then write back using check-and-set (cas) to prevent race conditions.
    """
    from app.config import get_settings
    s = get_settings()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_secret_path}"
    headers = await _vault_headers()
    try:
        async with httpx.AsyncClient(timeout=_VAULT_TIMEOUT) as client:
            # Read current secret + metadata
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                payload = resp.json()["data"]
                current_data = payload.get("data", {})
                version = payload.get("metadata", {}).get("version", 0)
                current_data[field] = value
                body: dict = {"options": {"cas": version}, "data": current_data}
            else:
                # Secret path doesn't exist yet — first write (no CAS)
                body = {"data": {field: value}}

            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code in (200, 204):
                _log.info("Vault field '%s' written successfully", field)
                return True
            _log.error("Vault write returned HTTP %d: %s", resp.status_code, resp.text)
            return False
    except Exception as exc:
        _log.error("Vault write failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Local file helpers
# ---------------------------------------------------------------------------

def _read_local_hash() -> str | None:
    if _LOCAL_HASH_PATH.exists():
        return _LOCAL_HASH_PATH.read_text().strip()
    return None


def _write_local_hash(hash_str: str) -> None:
    _LOCAL_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_HASH_PATH.write_text(hash_str + "\n")
    os.chmod(_LOCAL_HASH_PATH, 0o600)


def _read_local_user_set() -> bool:
    if _LOCAL_USER_SET_PATH.exists():
        return _LOCAL_USER_SET_PATH.read_text().strip().lower() == "true"
    return False


def _write_local_user_set(value: bool) -> None:
    _LOCAL_USER_SET_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_USER_SET_PATH.write_text(("true" if value else "false") + "\n")
    os.chmod(_LOCAL_USER_SET_PATH, 0o600)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def get_admin_secret_hash() -> str | None:
    """Return the cached admin secret bcrypt hash, fetching from backend if needed."""
    global _cached_hash
    if _cached_hash is not None:
        return _cached_hash

    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        secret = await _read_vault_secret()
        if secret and "data" in secret:
            _cached_hash = secret["data"].get("admin_secret_hash")
    else:
        _cached_hash = _read_local_hash()

    return _cached_hash


async def set_admin_secret_hash(new_hash: str) -> None:
    """Persist a new admin secret hash and update the in-memory cache.

    This function only stores the hash — the "user-set" flag is set
    explicitly by mark_admin_password_user_set() after a successful
    first-boot setup form submission.
    """
    global _cached_hash
    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        ok = await _write_vault_field("admin_secret_hash", new_hash)
        if not ok:
            raise RuntimeError("Failed to write admin_secret_hash to Vault")
    else:
        _write_local_hash(new_hash)

    _cached_hash = new_hash
    _log.info("Admin secret hash updated in %s backend", backend)


async def is_admin_password_user_set() -> bool:
    """Return True if the admin explicitly set a password via the setup form.

    A hash may exist in the backend from a previous deploy even when the
    user never went through the setup flow on *this* instance — that is
    why we track the "user set" state as a separate flag rather than
    inferring it from hash presence.
    """
    global _cached_user_set
    if _cached_user_set is not None:
        return _cached_user_set

    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        secret = await _read_vault_secret()
        if secret and "data" in secret:
            raw = secret["data"].get("admin_password_user_set", "false")
            _cached_user_set = str(raw).strip().lower() == "true"
        else:
            _cached_user_set = False
    else:
        _cached_user_set = _read_local_user_set()

    return _cached_user_set


async def mark_admin_password_user_set() -> None:
    """Flip the "user has picked a password" flag to true and cache it."""
    global _cached_user_set
    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        ok = await _write_vault_field("admin_password_user_set", "true")
        if not ok:
            raise RuntimeError(
                "Failed to write admin_password_user_set to Vault"
            )
    else:
        _write_local_user_set(True)

    _cached_user_set = True
    _log.info("Admin password marked as user-set in %s backend", backend)


async def ensure_bootstrapped() -> None:
    """First-boot hook — generate a one-shot bootstrap token if needed.

    Historically this hashed the .env ADMIN_SECRET and stored it in the
    KMS backend, which meant a fresh operator never had to set a password
    — they simply inherited whatever was in .env.  Shake-out P0-06 made
    that a P0 UX problem: a stranger who cloned the repo had no on-screen
    hint about credentials and had to grep the .env file.

    Audit F-B-4: the /dashboard/setup endpoint was otherwise reachable by
    the first attacker with network access to the broker during the
    first-boot window. Now we mint a random bootstrap token at startup
    and require it on the setup POST — attacker without the token (i.e.
    without access to the broker's stderr or its ``certs/`` directory)
    cannot impersonate the legitimate operator.
    """
    if await is_admin_password_user_set():
        _log.info(
            "Admin secret bootstrap: skipping — password already user-set."
        )
        return

    token = await generate_bootstrap_token_if_needed()
    if token is None:
        _log.info(
            "Admin secret bootstrap: existing bootstrap token kept."
        )
        return

    _log.warning(
        "\n"
        "================================================================\n"
        "  ADMIN BOOTSTRAP TOKEN (one-shot — use at /dashboard/setup):\n"
        "  %s\n"
        "  Also stored at %s (0600).\n"
        "  Audit F-B-4: required on the /dashboard/setup form.\n"
        "================================================================",
        token,
        _LOCAL_BOOTSTRAP_TOKEN_PATH,
    )


async def _read_bootstrap_token() -> str | None:
    """Return the current bootstrap token from the active backend, or None."""
    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        secret = await _read_vault_secret()
        if secret and "data" in secret:
            raw = secret["data"].get(_VAULT_BOOTSTRAP_TOKEN_FIELD, "")
            return raw or None
        return None

    if _LOCAL_BOOTSTRAP_TOKEN_PATH.exists():
        content = _LOCAL_BOOTSTRAP_TOKEN_PATH.read_text().strip()
        return content or None
    return None


async def _write_bootstrap_token(token: str) -> None:
    """Persist a freshly-generated bootstrap token."""
    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        ok = await _write_vault_field(_VAULT_BOOTSTRAP_TOKEN_FIELD, token)
        if not ok:
            raise RuntimeError("Failed to write bootstrap token to Vault")
        return

    _LOCAL_BOOTSTRAP_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_BOOTSTRAP_TOKEN_PATH.write_text(token + "\n")
    os.chmod(_LOCAL_BOOTSTRAP_TOKEN_PATH, 0o600)


async def generate_bootstrap_token_if_needed() -> str | None:
    """Ensure a bootstrap token exists when the admin has not set a password.

    Returns the newly-generated token (caller should log it) or ``None``
    if a token was already present or the admin has already set a password.
    Idempotent: a second call with an existing token returns ``None`` so
    a restart does not regenerate and invalidate the previously-logged
    value.
    """
    if await is_admin_password_user_set():
        return None
    if await _read_bootstrap_token() is not None:
        return None
    token = _pysecrets.token_urlsafe(32)
    await _write_bootstrap_token(token)
    return token


async def _vault_atomic_consume_and_set(
    provided_token: str, new_hash: str,
) -> bool:
    """Single CAS round-trip that re-checks the token, writes the hash,
    flips ``admin_password_user_set=true``, and blanks the bootstrap
    token. Returns True on success; False if the token mismatches or the
    CAS round-trip loses the race.
    """
    from app.config import get_settings
    s = get_settings()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_secret_path}"
    headers = await _vault_headers()
    try:
        async with httpx.AsyncClient(timeout=_VAULT_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                _log.error(
                    "Vault read during consume returned HTTP %d", resp.status_code,
                )
                return False
            payload = resp.json()["data"]
            current_data: dict = payload.get("data", {}) or {}
            version = payload.get("metadata", {}).get("version", 0)

            # Re-check the token under the version we're about to CAS on —
            # timing-safe comparison.
            stored_token = current_data.get(_VAULT_BOOTSTRAP_TOKEN_FIELD, "") or ""
            if not stored_token or not hmac.compare_digest(
                provided_token, stored_token,
            ):
                return False
            # Belt-and-braces: never overwrite an already-user-set state.
            if str(current_data.get("admin_password_user_set", "false")).lower() == "true":
                return False

            current_data[_VAULT_BOOTSTRAP_TOKEN_FIELD] = ""
            current_data["admin_secret_hash"] = new_hash
            current_data["admin_password_user_set"] = "true"

            body = {"options": {"cas": version}, "data": current_data}
            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code not in (200, 204):
                _log.error(
                    "Vault CAS write during consume returned HTTP %d: %s",
                    resp.status_code, resp.text,
                )
                return False
    except Exception as exc:
        _log.error("Vault atomic consume failed: %s", exc)
        return False

    global _cached_hash, _cached_user_set
    _cached_hash = new_hash
    _cached_user_set = True
    return True


async def consume_bootstrap_token_and_set_password(
    provided_token: str, new_hash: str,
) -> bool:
    """Atomically consume the one-shot bootstrap token and persist the
    new admin password hash + user-set flag.

    Returns True only if THIS call won the race and committed all three
    mutations. Returns False for every other case:
      * admin password already user-set
      * bootstrap token missing or mismatched
      * local rename lost to another process (F-D-3)
      * Vault CAS lost to another process

    Caller maps False to HTTP 403 ("Invalid or expired bootstrap token").
    """
    if await is_admin_password_user_set():
        return False

    expected = await _read_bootstrap_token()
    if not expected or not provided_token:
        return False
    if not hmac.compare_digest(provided_token, expected):
        return False

    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        return await _vault_atomic_consume_and_set(provided_token, new_hash)

    # Local backend: POSIX os.rename is atomic on the same filesystem.
    consumed_path = _LOCAL_BOOTSTRAP_TOKEN_PATH.with_suffix(
        _LOCAL_BOOTSTRAP_TOKEN_PATH.suffix + ".consumed"
    )
    try:
        os.rename(_LOCAL_BOOTSTRAP_TOKEN_PATH, consumed_path)
    except FileNotFoundError:
        # Another process consumed it first.
        return False
    except OSError as exc:
        _log.error("Bootstrap token rename failed: %s", exc)
        return False

    # Winner — commit the hash and flag. If anything below raises we've
    # burned the token without completing setup; surface that as False
    # and let the caller show a 5xx. A subsequent operator restart will
    # mint a new token since is_admin_password_user_set() is still False.
    try:
        await set_admin_secret_hash(new_hash)
        await mark_admin_password_user_set()
    except Exception as exc:
        _log.error(
            "Bootstrap token consumed but password commit failed: %s", exc,
        )
        return False

    # Best-effort cleanup of the consumed-token marker. Not critical —
    # leave it for forensics.
    return True


def reset_bootstrap_token_for_tests() -> None:
    """Test-only helper: clear the local bootstrap token state.

    Does not touch Vault (Vault tests stub ``_write_vault_field`` etc.).
    """
    for path in (
        _LOCAL_BOOTSTRAP_TOKEN_PATH,
        _LOCAL_BOOTSTRAP_TOKEN_PATH.with_suffix(
            _LOCAL_BOOTSTRAP_TOKEN_PATH.suffix + ".consumed"
        ),
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def verify_admin_password(password: str, stored_hash: str | None = None) -> bool:
    """Verify a password against the stored bcrypt hash (constant-time)."""
    if stored_hash is None:
        bcrypt.checkpw(password.encode(), _DUMMY_HASH.encode())
        return False
    return bcrypt.checkpw(password.encode(), stored_hash.encode())
