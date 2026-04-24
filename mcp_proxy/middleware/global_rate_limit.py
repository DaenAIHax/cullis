"""Global Mastio rate limit — ADR-013 layer 2.

Token bucket shared across every inbound request to the Mastio. Does not
look at the agent identity — the per-agent limiter (``auth.rate_limit``)
keeps that role. This layer exists to cap **aggregate** load so a
coordinated compromise across N stolen credentials, or an infrastructure
hiccup that makes every agent retry at once, cannot saturate the Mastio
→ DB pipeline.

Design constraints from the ADR:
- Runs **before** the auth dep and before any state-mutating handler, so
  a shed does not consume a DPoP nonce or open a session.
- Deterministic: over-limit returns 503 + ``Retry-After: 1``. No
  probabilistic behaviour, no per-agent state.
- Observability endpoints are bypassed so a load spike never hides the
  Mastio's own metrics/health from operators.
- In-memory only for this cut. Multi-worker deployments need a Redis
  backend (phase 2.1 follow-up); until then the advertised global rate
  is per-worker, which matches how the per-agent limiter degrades
  without Redis.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_log = logging.getLogger("mcp_proxy")

# Paths the shed never applies to. Observability + key distribution: if
# Mastio is under load the last thing we want is to hide /metrics or
# /health from a scraper — that would turn a degraded state into a
# blackout. JWKS endpoints are cheap key lookups and must keep serving
# so dependent verifiers don't cascade-fail.
_BYPASS_PREFIXES: tuple[str, ...] = (
    "/health",
    "/metrics",
    "/.well-known/",
)


class TokenBucket:
    """Async-safe token bucket. One instance guards the whole Mastio."""

    def __init__(self, rate_per_sec: float, burst: int) -> None:
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError(
                f"rate_per_sec and burst must be positive — got "
                f"rate={rate_per_sec}, burst={burst}"
            )
        self._rate = float(rate_per_sec)
        self._burst = float(burst)
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def try_acquire(self, cost: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            if elapsed > 0:
                self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
                self._last_refill = now
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False

    @property
    def available(self) -> float:
        return self._tokens


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that sheds with 503 when the shared bucket is empty."""

    def __init__(
        self,
        app,
        bucket: TokenBucket,
        bypass_prefixes: tuple[str, ...] = _BYPASS_PREFIXES,
    ) -> None:
        super().__init__(app)
        self._bucket = bucket
        self._bypass_prefixes = bypass_prefixes
        self._shed_count = 0  # incremented on every shed; surfaced via metric

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in self._bypass_prefixes):
            return await call_next(request)

        if await self._bucket.try_acquire(1.0):
            return await call_next(request)

        self._shed_count += 1
        _log.warning(
            "global rate limit shed: path=%s method=%s total_shed=%d",
            path, request.method, self._shed_count,
        )
        body = json.dumps({
            "detail": "Mastio is shedding load — retry shortly",
            "error": "global_rate_limit_exceeded",
        }).encode()
        return Response(
            content=body,
            status_code=503,
            media_type="application/json",
            headers={
                "Retry-After": "1",
                "X-Cullis-Shed-Reason": "global_rate_limit",
            },
        )

    @property
    def shed_count(self) -> int:
        """Total requests shed since process start. Exposed for tests +
        metrics integration."""
        return self._shed_count
