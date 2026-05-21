"""Hash-chained append-only audit log for the reference demo agents.

Mirrors the production Mastio audit chain (`app/db/audit_log.py`):

- every entry is signed with the agent certificate (here: deterministic
  RSA-PSS over the canonical JSON of the entry, key loaded at start);
- entries form a hash chain (`prev_hash` = SHA-256 of the previous entry's
  signed bytes), so any tampering with a past record breaks the chain;
- the log is append-only, both in memory and on disk (JSONL).

The demo log is local to each agent run and is intentionally NOT integrated
with the Mastio shared chain or the Court TSA anchor (ADR-033). When the
agents are wired into a real Cullis stack via `./stack/demo.sh`, the
production audit chain takes over via the MCP reverse-proxy.

EU AI Act mapping: Art. 12 (logging), Art. 13 (technical documentation),
DORA Art. 28 (cryptographic identity per action, cross-org evidence).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_log = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64
_AUDIT_VERSION = 1


class AuditVerificationError(Exception):
    """Raised when the audit chain fails integrity verification."""


@dataclass(frozen=True)
class AuditEntry:
    """Single audit chain entry.

    `signature` is the base64 RSA-PSS-SHA256 signature over the canonical
    JSON of the entry with `signature` field removed. `prev_hash` is the
    SHA-256 of the previous entry's signed canonical bytes (hex).
    """

    version: int
    sequence: int
    timestamp: float
    agent_id: str
    org_id: str
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_json(self, *, include_signature: bool) -> bytes:
        data = self.to_dict()
        if not include_signature:
            data.pop("signature", None)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _generate_agent_key() -> rsa.RSAPrivateKey:
    """Return a fresh RSA-2048 key for the demo. The production Mastio
    loads the agent's PEM from `cert_factory` + Vault KMS."""

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _sign(key: rsa.RSAPrivateKey, payload: bytes) -> bytes:
    return key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def _verify(public_key: rsa.RSAPublicKey, payload: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


class AuditChain:
    """Append-only hash-chained audit log scoped to a single agent run.

    Usage:

        chain = AuditChain(agent_id="kyc-screener-01", org_id="bank-it-01")
        chain.append("tool_call", {"tool": "screen_sanctions", "args": {...}})
        chain.append("decision", {"score": 12, "outcome": "auto_approve"})
        assert chain.verify()
        chain.persist(Path("/tmp/audit.jsonl"))
    """

    def __init__(
        self,
        *,
        agent_id: str,
        org_id: str,
        private_key: rsa.RSAPrivateKey | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.org_id = org_id
        self._key = private_key or _generate_agent_key()
        self._entries: list[AuditEntry] = []
        self._next_prev_hash = _GENESIS_HASH

    @property
    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEntry:
        unsigned = AuditEntry(
            version=_AUDIT_VERSION,
            sequence=len(self._entries),
            timestamp=time.time(),
            agent_id=self.agent_id,
            org_id=self.org_id,
            event_type=event_type,
            payload=payload,
            prev_hash=self._next_prev_hash,
        )
        signature_bytes = _sign(self._key, unsigned.canonical_json(include_signature=False))
        signed = AuditEntry(
            version=unsigned.version,
            sequence=unsigned.sequence,
            timestamp=unsigned.timestamp,
            agent_id=unsigned.agent_id,
            org_id=unsigned.org_id,
            event_type=unsigned.event_type,
            payload=unsigned.payload,
            prev_hash=unsigned.prev_hash,
            signature=signature_bytes.hex(),
        )
        self._entries.append(signed)
        self._next_prev_hash = hashlib.sha256(
            signed.canonical_json(include_signature=True)
        ).hexdigest()
        _log.info(
            "audit append seq=%d agent=%s event=%s",
            signed.sequence,
            signed.agent_id,
            signed.event_type,
        )
        return signed

    def verify(self) -> bool:
        """Re-walk the chain and check every signature + every prev_hash link."""

        public_key = self._key.public_key()
        expected_prev = _GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != expected_prev:
                raise AuditVerificationError(
                    f"prev_hash mismatch at seq={entry.sequence}: "
                    f"expected {expected_prev}, got {entry.prev_hash}"
                )
            signature = bytes.fromhex(entry.signature)
            if not _verify(public_key, entry.canonical_json(include_signature=False), signature):
                raise AuditVerificationError(
                    f"signature verification failed at seq={entry.sequence}"
                )
            expected_prev = hashlib.sha256(
                entry.canonical_json(include_signature=True)
            ).hexdigest()
        return True

    def persist(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for entry in self._entries:
                fh.write(json.dumps(entry.to_dict(), sort_keys=True))
                fh.write("\n")

    @classmethod
    def load(cls, path: Path, *, public_key_pem: bytes) -> AuditChain:
        """Load a chain for verification only (signing key not required)."""

        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise AuditVerificationError("public key is not RSA")
        entries: list[AuditEntry] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                data = json.loads(line)
                entries.append(AuditEntry(**data))

        chain = cls.__new__(cls)
        chain.agent_id = entries[0].agent_id if entries else ""
        chain.org_id = entries[0].org_id if entries else ""
        chain._key = None  # type: ignore[assignment]
        chain._entries = entries
        chain._next_prev_hash = (
            hashlib.sha256(entries[-1].canonical_json(include_signature=True)).hexdigest()
            if entries
            else _GENESIS_HASH
        )
        # Verify with the supplied public key.
        expected_prev = _GENESIS_HASH
        for entry in entries:
            if entry.prev_hash != expected_prev:
                raise AuditVerificationError(
                    f"prev_hash mismatch at seq={entry.sequence}"
                )
            if not _verify(
                public_key,
                entry.canonical_json(include_signature=False),
                bytes.fromhex(entry.signature),
            ):
                raise AuditVerificationError(
                    f"signature mismatch at seq={entry.sequence}"
                )
            expected_prev = hashlib.sha256(
                entry.canonical_json(include_signature=True)
            ).hexdigest()
        return chain


def audit_path_for(agent_id: str) -> Path:
    """Default on-disk location for a chain (gitignored under `.data/`)."""

    root = Path(os.environ.get("CULLIS_DEMO_AUDIT_ROOT", ".data/agents-demo"))
    return root / agent_id / "audit.jsonl"
