"""
Symmetric secret encryption using a key derived from the broker private key.

Uses HKDF-SHA256 to derive a 32-byte Fernet key from the broker RSA private
key PEM, then Fernet (AES-128-CBC + HMAC-SHA256) for authenticated encryption.

Encrypted values are prefixed with ``enc:v1:`` so legacy plaintext values
can be detected and handled gracefully (transparent migration).
"""
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

_ENC_PREFIX = "enc:v1:"
_HKDF_INFO = b"atn-secret-encryption-v1"
_SALT_LENGTH = 16


def _derive_fernet_key(private_key_pem: str, salt: bytes | None = None) -> bytes:
    """Derive a 32-byte Fernet key from the broker private key PEM via HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO,
    )
    derived = hkdf.derive(private_key_pem.encode())
    return base64.urlsafe_b64encode(derived)


def encrypt_secret(private_key_pem: str, plaintext: str) -> str:
    """Encrypt a secret string, returning ``enc:v1:<salt_hex>:<fernet_token>``."""
    salt = os.urandom(_SALT_LENGTH)
    key = _derive_fernet_key(private_key_pem, salt=salt)
    token = Fernet(key).encrypt(plaintext.encode()).decode()
    return f"{_ENC_PREFIX}{salt.hex()}:{token}"


def decrypt_secret(private_key_pem: str, stored: str) -> str:
    """Decrypt a stored secret.

    If the value does not carry the ``enc:v1:`` prefix it is assumed to be
    legacy plaintext and returned as-is (transparent migration).

    Supports both formats:
      - ``enc:v1:<salt_hex>:<fernet_token>`` (new, salted)
      - ``enc:v1:<fernet_token>`` (legacy, no salt — backward compat)
    """
    if not stored.startswith(_ENC_PREFIX):
        return stored  # legacy plaintext — return unchanged
    payload = stored[len(_ENC_PREFIX):]

    # Detect salted vs legacy format: salted has exactly 32 hex chars then ':'
    parts = payload.split(":", 1)
    if len(parts) == 2 and len(parts[0]) == _SALT_LENGTH * 2:
        try:
            salt = bytes.fromhex(parts[0])
            token = parts[1]
            key = _derive_fernet_key(private_key_pem, salt=salt)
            return Fernet(key).decrypt(token.encode()).decode()
        except (ValueError, InvalidToken) as exc:
            raise ValueError("Failed to decrypt secret — wrong key or corrupted data") from exc
    else:
        # Legacy format: enc:v1:<fernet_token> (no salt)
        key = _derive_fernet_key(private_key_pem, salt=None)
        try:
            return Fernet(key).decrypt(payload.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("Failed to decrypt secret — wrong key or corrupted data") from exc


def is_encrypted(stored: str) -> bool:
    """Check if a stored value is encrypted."""
    return stored.startswith(_ENC_PREFIX)
