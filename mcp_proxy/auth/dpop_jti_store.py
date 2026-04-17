"""
DPoP JTI store — short-lived nonce tracking for DPoP proof replay protection.

Two backends:
  - InMemoryDpopJtiStore  — single-worker only (default when Redis is unavailable)
  - RedisDpopJtiStore     — multi-worker safe via SET NX EX (atomic check+insert)

The active backend is selected at startup by ``get_dpop_jti_store()``, which
checks if Redis is available. ``dpop.verify_dpop_proof`` calls
``consume_jti()`` — a single atomic operation that checks and registers
the JTI in one step (no race window).

TTL defaults to 300s (5 min): covers the proof iat acceptance window plus
clock-skew slack.

Ported from ``app/auth/dpop_jti_store.py`` (audit F-E-04). The Mastio
(``mcp_proxy``) side of the same finding lived unguarded until this
port — see issue #182 for context.
"""
import asyncio
import logging
import time
from typing import Protocol

_log = logging.getLogger("mcp_proxy")

_DEFAULT_TTL = 300  # seconds


class DpopJtiStore(Protocol):
    """Interface for DPoP JTI stores."""

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        """Atomically check if the JTI has been seen, and register it if not.

        Returns True if newly consumed (first use).
        Returns False if already seen (replay).
        """
        ...


class InMemoryDpopJtiStore:
    """Async-safe in-memory JTI store with TTL and lazy cleanup.

    Not suitable for multi-worker deployments — each worker has its own
    dict, which defeats replay protection across workers.
    """

    def __init__(self) -> None:
        self._store: dict[str, float] = {}  # jti -> expires_at (monotonic)
        self._lock = asyncio.Lock()

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        now = time.monotonic()
        expires_at = now + ttl_seconds

        async with self._lock:
            expired = [k for k, v in self._store.items() if v < now]
            for k in expired:
                del self._store[k]

            if jti in self._store:
                return False  # replay
            self._store[jti] = expires_at
            return True  # new


class RedisDpopJtiStore:
    """Redis-backed JTI store — multi-worker safe.

    Uses SET NX EX for atomic check+insert with automatic TTL expiry.
    """

    _PREFIX = "mcp_proxy:dpop:jti:"

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        result = await self._redis.set(
            f"{self._PREFIX}{jti}", "1", nx=True, ex=ttl_seconds,
        )
        return result is not None


_store: DpopJtiStore | None = None


def _init_store() -> DpopJtiStore:
    """Select the best available backend.

    Mastio has a legitimate single-instance production mode (single-tenant
    intra-org, SQLite + in-memory) where Redis is unnecessary. That differs
    from the multi-tenant broker (``app/``), which *always* requires Redis
    in production. So the factory does not refuse in-memory in production —
    it only logs a warning. ``validate_config`` surfaces the same warning
    at startup.

    Operators running Mastio multi-worker (HA) MUST set
    ``MCP_PROXY_REDIS_URL``; otherwise each worker holds an independent
    JTI dict and a captured DPoP proof can be replayed N× across workers
    within the ``iat`` window (RFC 9449).
    """
    from mcp_proxy.redis.pool import get_redis
    from mcp_proxy.config import get_settings

    redis = get_redis()
    if redis is not None:
        _log.info("DPoP JTI store: Redis")
        return RedisDpopJtiStore(redis)

    if get_settings().environment == "production":
        _log.warning(
            "DPoP JTI store: Redis unavailable in production — using "
            "in-memory. This is safe only for single-instance/single-worker "
            "deployments. Multi-worker/HA deploys MUST set "
            "MCP_PROXY_REDIS_URL (see audit F-B-12)."
        )

    _log.info("DPoP JTI store: in-memory")
    return InMemoryDpopJtiStore()


def get_dpop_jti_store() -> DpopJtiStore:
    """Return the active JTI store, initializing on first call."""
    global _store
    if _store is None:
        _store = _init_store()
    return _store


def reset_dpop_jti_store() -> None:
    """Reset the store (used by tests to force re-initialization)."""
    global _store
    _store = None
