"""
Sliding window rate limiter — dual backend (in-memory / Redis).

In-memory: single-process, counters reset on restart.
Redis: multi-worker safe, sorted sets with automatic TTL cleanup.

The active backend is selected at first use based on Redis availability.
"""
import logging
import time
import uuid
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, status

from app.telemetry_metrics import RATE_LIMIT_REJECT_COUNTER

_log = logging.getLogger("agent_trust")


_MAX_SUBJECTS = 50_000  # maximum unique subjects in memory — LRU eviction


class SlidingWindowLimiter:
    """
    Async sliding window rate limiter with dual backend.

    Bucket configs are registered at module load (below).
    On first check(), the backend is selected based on Redis availability.
    """

    def __init__(self) -> None:
        self._configs: dict[str, tuple[int, int]] = {}
        # In-memory backend
        self._windows: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = Lock()
        # Backend selection
        self._use_redis: bool | None = None  # None = not yet decided
        self._redis = None

    def register(self, bucket: str, window_seconds: int, max_requests: int) -> None:
        """Register the configuration for a bucket. Called at startup."""
        self._configs[bucket] = (window_seconds, max_requests)

    def _select_backend(self) -> None:
        """Lazily select backend on first use."""
        if self._use_redis is not None:
            return
        from app.redis.pool import get_redis
        self._redis = get_redis()
        self._use_redis = self._redis is not None
        backend = "Redis" if self._use_redis else "in-memory"
        _log.info("Rate limiter backend: %s", backend)

    async def check(self, subject: str, bucket: str) -> None:
        """
        Check if subject has exceeded the limit for bucket.
        Raises HTTP 429 if over limit.
        """
        config = self._configs.get(bucket)
        if config is None:
            return

        self._select_backend()

        if self._use_redis:
            await self._check_redis(subject, bucket, config)
        else:
            self._check_memory(subject, bucket, config)

    def _check_memory(self, subject: str, bucket: str,
                      config: tuple[int, int]) -> None:
        """In-memory sliding window check (single-worker only)."""
        window_seconds, max_requests = config
        now = time.monotonic()
        cutoff = now - window_seconds
        key = (subject, bucket)

        with self._lock:
            # LRU eviction: if too many unique subjects, drop oldest entries
            if key not in self._windows and len(self._windows) >= _MAX_SUBJECTS:
                oldest_key = next(iter(self._windows))
                del self._windows[oldest_key]

            dq = self._windows[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= max_requests:
                RATE_LIMIT_REJECT_COUNTER.add(1, {"bucket": bucket})
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for '{bucket}': max {max_requests} req/{window_seconds}s",
                    headers={"Retry-After": str(window_seconds)},
                )
            dq.append(now)

    # Lua script for atomic sliding window check + add.
    # Returns 1 if the request is allowed, 0 if rate limited.
    _LUA_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local cutoff = tonumber(ARGV[2])
    local max_requests = tonumber(ARGV[3])
    local request_id = ARGV[4]
    local ttl = tonumber(ARGV[5])

    redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
    local count = redis.call('ZCARD', key)
    if count >= max_requests then
        return 0
    end
    redis.call('ZADD', key, now, request_id)
    redis.call('EXPIRE', key, ttl)
    return 1
    """
    _lua_sha: str | None = None

    async def _check_redis(self, subject: str, bucket: str,
                           config: tuple[int, int]) -> None:
        """
        Redis sorted set sliding window (multi-worker safe).

        Uses an atomic Lua script to avoid the TOCTOU race condition
        between ZCARD (count) and ZADD (register).
        """
        window_seconds, max_requests = config
        now = time.time()
        cutoff = now - window_seconds
        redis_key = f"ratelimit:{subject}:{bucket}"
        request_id = uuid.uuid4().hex
        ttl = window_seconds + 10

        # Load the script once, then use EVALSHA for efficiency
        if self._lua_sha is None:
            self._lua_sha = await self._redis.script_load(self._LUA_SCRIPT)

        allowed = await self._redis.evalsha(
            self._lua_sha, 1, redis_key,
            str(now), str(cutoff), str(max_requests), request_id, str(ttl),
        )

        if not allowed:
            RATE_LIMIT_REJECT_COUNTER.add(1, {"bucket": bucket})
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for '{bucket}': max {max_requests} req/{window_seconds}s",
                headers={"Retry-After": str(window_seconds)},
            )


# Shared global instance
rate_limiter = SlidingWindowLimiter()

# ── Bucket configuration ──────────────────────────────────────────────────────
rate_limiter.register("auth.token",       window_seconds=60,  max_requests=10)
rate_limiter.register("broker.session",   window_seconds=60,  max_requests=20)
rate_limiter.register("broker.message",   window_seconds=60,  max_requests=60)
rate_limiter.register("dashboard.login",  window_seconds=300, max_requests=5)
