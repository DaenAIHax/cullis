"""
Redis connection pool — shared async client for the Mastio (mcp_proxy) process.

Usage:
    from mcp_proxy.redis.pool import get_redis

    redis = get_redis()          # returns the shared client (or None if disabled)
    if redis:
        await redis.set("key", "value", ex=300)

The pool is initialized at startup (main.py lifespan) and closed at shutdown.
If MCP_PROXY_REDIS_URL is empty or the connection fails, Redis is disabled
gracefully: callers get None and fall back to in-memory implementations.

Mastio default (single-instance intra-org) does not require Redis. Operators
who run Mastio with multiple workers or replicas MUST configure
MCP_PROXY_REDIS_URL so that the DPoP JTI store and agent rate limiter share
state across workers (RFC 9449 replay protection + advertised rate limits).
``validate_config`` refuses production startup when REDIS_URL is empty.
"""
import logging

import redis.asyncio as aioredis

_log = logging.getLogger("mcp_proxy")

_client: aioredis.Redis | None = None


async def init_redis(redis_url: str) -> bool:
    """Initialize the shared Redis async client.

    Returns True if the connection succeeded, False otherwise.
    """
    global _client

    if not redis_url:
        _log.info("Redis disabled — MCP_PROXY_REDIS_URL is empty")
        return False

    try:
        client = aioredis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        await client.ping()
        _client = client
        _log.info("Redis connected: %s", redis_url)
        return True
    except Exception as exc:
        _log.warning(
            "Redis connection failed (%s) — falling back to in-memory: %s",
            redis_url,
            exc,
        )
        _client = None
        return False


async def close_redis() -> None:
    """Close the Redis connection pool. Safe to call even if Redis is disabled."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
        _log.info("Redis connection closed")


def get_redis() -> aioredis.Redis | None:
    """Return the shared Redis client, or None if Redis is disabled.

    Callers must check for None and fall back to in-memory.
    """
    return _client


def reset_redis_for_tests() -> None:
    """Drop the module singleton without closing the connection.

    Tests that monkeypatch ``get_redis`` want a clean slate on teardown;
    async close from a sync test hook is brittle, so we just forget the
    reference. Never call in production code.
    """
    global _client
    _client = None
