"""In-process idempotency cache for
``POST /v1/onboarding/orgs/{org_id}/mastio-pubkey/rotate``.

A legitimate operator who retries a rotation (network blip, proxy
restart, UI double-click) sends the same continuity proof twice within
the 600-second freshness window. Without a dedupe layer the Court
re-runs the full ECDSA verify *and* appends a fresh audit row for the
replay, polluting the hash chain that SOC/compliance relies on.

The cache keys on ``(org_id, signature_b64u)`` — the proof signature is
the natural idempotency token because it's derived from the old private
key over a canonical envelope (issued_at + new_kid + new_pubkey_pem +
old_kid) that is content-unique per rotation attempt. A hit returns
the original response body verbatim so the client sees an identical
200 on retry.

TTL matches the proof freshness window (600s): proofs older than that
are rejected by ``verify_proof`` regardless, so keeping them in cache
longer would not help a legitimate retry and would just enlarge the
memory footprint.

TODO(#282): Redis-backed variant when we support HA multi-replica
brokers. The in-process map is fine for the current single-replica
Court topology but would split-brain across replicas (each would
allow one successful rotation, though the Court's single-row
``organizations.mastio_pubkey`` column still converges after the
winner commits).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any


_TTL_SECONDS = 600.0  # matches proof freshness window in mastio_rotation.py


@dataclass(frozen=True)
class _CachedResponse:
    """Response payload snapshot. Stored so a replayed proof returns
    exactly what the first call returned, including ``rotated_at`` —
    a retry that sees a ``rotated_at`` later than its own ``issued_at``
    is valid; a retry that sees a totally different ``new_kid`` would
    be a bug.
    """
    body: dict[str, Any]
    inserted_at: float


class RotateDedupeCache:
    """Process-local (org_id, signature) → response cache."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], _CachedResponse] = {}
        self._lock = asyncio.Lock()

    async def get(self, org_id: str, signature_b64u: str) -> dict[str, Any] | None:
        """Return the cached response body for this proof, or None.

        Lazily evicts expired entries when keys are probed — no
        background sweeper required, and a cold cache after a long
        idle period costs nothing.
        """
        key = (org_id, signature_b64u)
        now = time.monotonic()
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if now - entry.inserted_at > _TTL_SECONDS:
                self._entries.pop(key, None)
                return None
            return dict(entry.body)

    async def store(
        self, org_id: str, signature_b64u: str, body: dict[str, Any],
    ) -> None:
        """Record the response for future retries within the TTL.

        Called only after a successful commit + audit — a failed
        rotation must NOT be cached, because a second attempt should
        get a fresh verify pass (the first failure might have been a
        transient rowcount glitch or the DB lock retry loop).
        """
        key = (org_id, signature_b64u)
        async with self._lock:
            self._entries[key] = _CachedResponse(
                body=dict(body), inserted_at=time.monotonic(),
            )

    async def reset(self) -> None:
        """Test helper — drop all entries. Not called by production code."""
        async with self._lock:
            self._entries.clear()


# Shared module-level cache. One entry per in-flight rotation
# (org_id, signature_b64u); max cardinality is tiny because rotations
# are rate-limited to 5/min/IP × 600s TTL = ~50 entries per org under
# load, so unbounded growth is not a concern.
rotate_dedupe = RotateDedupeCache()
