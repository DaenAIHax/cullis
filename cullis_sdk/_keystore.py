"""At-rest envelope for SDK-held agent key material (F5).

``key.pem`` (mTLS private key) and ``dpop.jwk`` (DPoP private JWK) shipped
as plaintext files protected only by ``chmod 0600``. That leaves the agent
identity exposed to disk theft, a leaked VM snapshot or backup, and the
``identity-bundle.zip`` in transit. This module wraps those secrets in the
``enc:sec:v1:`` envelope so they are encrypted at rest.

Format compatibility: the envelope is structurally identical to the
Mastio's ``mcp_proxy.kms.pki_at_rest`` — ``enc:sec:v1:`` prefix, Fernet
body, a PBKDF2-HMAC-SHA256 600k-iteration master — so a future shared
``cullis_keystore`` library and its test vectors line up across the two
surfaces. The salt is per-domain (``cullis-sdk-identity-v1``): the SDK and
the Mastio custody different material under different passphrases and must
not cross-decrypt.

Root-of-trust ladder (first provider that yields a passphrase wins):

    1. OS keychain        (pluggable hook — not wired in step 1)
    2. age-encrypted file (pluggable hook — not wired in step 1)
    3. env CULLIS_IDENTITY_PASSPHRASE
    4. None               -> plaintext fallback (dev / back-compat)

Only the env provider is active today. The ladder is an ordered list of
callables so keychain / age / TPM providers slot in later without changing
the wrap/unwrap call sites or the on-disk format.
"""
from __future__ import annotations

import base64
import logging
import os
from functools import lru_cache
from typing import Callable

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_log = logging.getLogger("cullis_sdk.keystore")

_ENVELOPE_PREFIX = "enc:sec:v1:"
_SALT = b"cullis-sdk-identity-v1"
_ITERATIONS = 600_000
_ENV_VAR = "CULLIS_IDENTITY_PASSPHRASE"


class IdentityKeyLockedError(RuntimeError):
    """An enveloped secret was found but no root passphrase is available.

    Raised on read when ``key.pem`` / ``dpop.jwk`` is encrypted at rest but
    no root-of-trust provider yields the passphrase (e.g. the operator set
    ``CULLIS_IDENTITY_PASSPHRASE`` once, encrypted the identity, then lost
    it). Failing loud beats returning a wrong/empty key.
    """


# ── envelope primitives ─────────────────────────────────────────────


def is_secret_envelope(value: str) -> bool:
    """True when ``value`` is an :func:`encrypt_secret` envelope.

    Lets a reader tell a wrapped secret from a legacy plaintext PEM/JWK:
    a PEM begins ``-----BEGIN``, a JWK is JSON (``{``), the envelope begins
    ``enc:sec:v1:`` — all unambiguous.
    """
    return value.startswith(_ENVELOPE_PREFIX)


@lru_cache(maxsize=8)
def _derive(passphrase: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase))


def encrypt_secret(plaintext: str, passphrase: str) -> str:
    """Wrap ``plaintext`` in the ``enc:sec:v1:`` envelope under ``passphrase``."""
    if not plaintext:
        raise ValueError("encrypt_secret: plaintext must be non-empty")
    if not passphrase:
        raise ValueError("encrypt_secret: passphrase must be non-empty")
    master = _derive(passphrase.encode("utf-8"))
    token = Fernet(master).encrypt(plaintext.encode("utf-8")).decode("utf-8")
    return _ENVELOPE_PREFIX + token


def decrypt_secret(envelope: str, passphrase: str) -> str:
    """Reverse of :func:`encrypt_secret`. Returns the plaintext string."""
    if not envelope.startswith(_ENVELOPE_PREFIX):
        raise ValueError(
            f"decrypt_secret: value does not start with {_ENVELOPE_PREFIX!r}; "
            "refusing to interpret as plaintext."
        )
    master = _derive(passphrase.encode("utf-8"))
    token = envelope[len(_ENVELOPE_PREFIX):]
    try:
        return Fernet(master).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise IdentityKeyLockedError(
            f"identity secret cannot be decrypted with the current "
            f"{_ENV_VAR}. Either the passphrase changed, or the file came "
            "from a different host."
        ) from exc


# ── root-of-trust ladder ────────────────────────────────────────────


def _env_passphrase() -> str | None:
    raw = os.environ.get(_ENV_VAR, "").strip()
    return raw or None


# Ordered providers; first non-None wins. Keychain / age / TPM providers
# append here later without touching the call sites or the on-disk format.
_ROOT_PROVIDERS: list[Callable[[], "str | None"]] = [
    # _keychain_passphrase,   # step 2: OS keychain (Secret Service / Keychain)
    # _age_file_passphrase,   # step 2: age-encrypted key file
    _env_passphrase,
]


def resolve_root_passphrase() -> str | None:
    """Return the first passphrase the ladder yields, or None (plaintext)."""
    for provider in _ROOT_PROVIDERS:
        value = provider()
        if value:
            return value
    return None


# ── high-level wrap / unwrap used by the SDK call sites ──────────────


def wrap_identity_secret(plaintext: str) -> str:
    """Encrypt ``plaintext`` when a root is available, else return it as-is.

    Mirrors the Mastio's dev fallback: with no passphrase configured the
    SDK keeps the legacy plaintext-0600 behaviour so existing workflows and
    dev iteration are unaffected. Configure ``CULLIS_IDENTITY_PASSPHRASE``
    (or a future keychain/age provider) to turn on at-rest encryption.
    """
    passphrase = resolve_root_passphrase()
    if not passphrase:
        # Make the dev fallback observable: writing key material unencrypted
        # is a deliberate no-root posture, not an accident. Never logs the
        # secret itself.
        _log.warning(
            "identity material written UNENCRYPTED at rest: no root-of-trust "
            "configured (set %s to enable the enc:sec:v1 envelope).", _ENV_VAR,
        )
        return plaintext
    return encrypt_secret(plaintext, passphrase)


def unwrap_identity_secret(value: str) -> str:
    """Decrypt ``value`` when it is an envelope, else pass it through.

    Legacy plaintext (pre-F5, or written without a root) is returned
    untouched. An enveloped value with no available root raises
    :class:`IdentityKeyLockedError` rather than silently failing.
    """
    if not is_secret_envelope(value):
        return value
    passphrase = resolve_root_passphrase()
    if not passphrase:
        raise IdentityKeyLockedError(
            f"identity material is encrypted at rest but {_ENV_VAR} is not "
            "set (and no keychain/age provider yielded a passphrase). Set "
            "the passphrase the identity was encrypted with."
        )
    return decrypt_secret(value, passphrase)


# ── key.pem (mTLS) at rest — native encrypted-PEM, not the Fernet envelope ──
#
# key.pem is consumed by ``ssl.SSLContext.load_cert_chain`` which loads the
# key from a FILE PATH (stdlib ssl cannot load a key from memory). So instead
# of the enc:sec:v1 Fernet envelope used for the in-memory DPoP key, key.pem
# is wrapped in the STANDARD PKCS#8 encrypted-PEM format
# (``-----BEGIN ENCRYPTED PRIVATE KEY-----``), which ssl decrypts natively
# via the ``password=`` argument — no tempfile, no memfd. Same root-of-trust
# ladder; the passphrase is the wrapping key.

_ENCRYPTED_PEM_MARKER = "ENCRYPTED PRIVATE KEY"


def is_encrypted_pem(pem: str) -> bool:
    """True when ``pem`` is a PKCS#8 encrypted private key."""
    return _ENCRYPTED_PEM_MARKER in pem


def wrap_key_pem(plaintext_pem: str) -> str:
    """Re-serialise an unencrypted private-key PEM as PKCS#8 encrypted-PEM
    under the ladder passphrase. Returns the plaintext unchanged when no
    root is configured (dev fallback) or when it is already encrypted."""
    if is_encrypted_pem(plaintext_pem):
        return plaintext_pem
    passphrase = resolve_root_passphrase()
    if not passphrase:
        _log.warning(
            "agent key.pem written UNENCRYPTED at rest: no root-of-trust "
            "configured (set %s to enable PKCS#8 encrypted-PEM).", _ENV_VAR,
        )
        return plaintext_pem
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(
        plaintext_pem.encode("utf-8"), password=None,
    )
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    ).decode("utf-8")


def unwrap_key_pem(pem: str) -> str:
    """Return a plaintext private-key PEM, decrypting an encrypted-PEM with
    the ladder passphrase. Plaintext passes through. Raises
    :class:`IdentityKeyLockedError` when the key is encrypted but no root
    is available."""
    if not is_encrypted_pem(pem):
        return pem
    passphrase = resolve_root_passphrase()
    if not passphrase:
        raise IdentityKeyLockedError(
            f"agent key.pem is encrypted at rest but {_ENV_VAR} is not set "
            "(and no keychain/age provider yielded a passphrase)."
        )
    from cryptography.hazmat.primitives import serialization

    try:
        key = serialization.load_pem_private_key(
            pem.encode("utf-8"), password=passphrase.encode("utf-8"),
        )
    except (ValueError, TypeError) as exc:
        raise IdentityKeyLockedError(
            f"agent key.pem cannot be decrypted with the current {_ENV_VAR}."
        ) from exc
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def key_pem_load_password() -> "bytes | None":
    """Password bytes for ``ssl.SSLContext.load_cert_chain(..., password=)``.

    Returns the ladder passphrase encoded, or ``None`` when no root is
    configured. ssl ignores the password for an unencrypted key, so this is
    always safe to pass; an encrypted key with no root surfaces as an ssl
    error at load time (fail-closed)."""
    passphrase = resolve_root_passphrase()
    return passphrase.encode("utf-8") if passphrase else None


def _reset_cache_for_tests() -> None:
    """Test/rotation hook: drop derived Fernet masters from the LRU.

    Symmetric with the Mastio's ``pki_at_rest._reset_cache_for_tests``. A
    future caller can also use it to scrub derived masters on logout / key
    rotation so they do not linger in process memory.
    """
    _derive.cache_clear()


__all__ = [
    "IdentityKeyLockedError",
    "decrypt_secret",
    "encrypt_secret",
    "is_encrypted_pem",
    "is_secret_envelope",
    "key_pem_load_password",
    "resolve_root_passphrase",
    "unwrap_identity_secret",
    "unwrap_key_pem",
    "wrap_identity_secret",
    "wrap_key_pem",
]
