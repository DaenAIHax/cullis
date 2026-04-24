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

Implemented as a pure ASGI middleware rather than ``BaseHTTPMiddleware``.
That's what Starlette's own docs recommend for middleware with side
effects (logging, counters, custom headers): ``__call__`` runs directly
in the request's task without the extra wrapper task
BaseHTTPMiddleware creates, which avoids a known performance overhead
plus a class of subtle streaming-response edge cases.

## cullis-enterprise#11 — log visibility

Shed events are emitted as raw JSON on ``sys.stderr`` rather than
through ``logging.Logger.warning``. Reason: at runtime the
``mcp_proxy`` logger is silently muted for records emitted from inside
the middleware ``__call__`` — diagnostic traces at ``dispatch`` time
showed the logger had the right handler (StreamHandler wrapping
``sys.stderr``), ``propagate=False``, effective level INFO, yet
``_log.warning`` produced no output in ``docker compose logs`` while
``print(..., file=sys.stderr, flush=True)`` on the same code path
worked every time. Suspected cause is uvicorn's logging reinit after
the lifespan hook repointing the handler stream in a subtle way, but
the payoff of full debug isn't worth blocking the fix. The JSON shape
below matches ``mcp_proxy.logging_setup.JSONFormatter`` so any log
aggregator sees a normal ``WARNING`` record regardless of how it got
onto stderr. ``PYTHONUNBUFFERED=1`` in ``mcp_proxy/Dockerfile`` keeps
the write flush-on-newline in container stdio.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone

_log = logging.getLogger("mcp_proxy")


def _emit_shed_log(path: str, method: str, count: int) -> None:
    """Write a WARNING record straight to stderr, matching the JSON
    shape of ``mcp_proxy.logging_setup.JSONFormatter``. See the module
    docstring — the ``mcp_proxy`` logger is muted inside the ASGI
    dispatch path at runtime.
    """
    record = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "WARNING",
        "logger": "mcp_proxy",
        "message": (
            f"global rate limit shed: path={path} method={method} "
            f"total_shed={count}"
        ),
    }, default=str)
    print(record, file=sys.stderr, flush=True)

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

_SHED_BODY = json.dumps({
    "detail": "Mastio is shedding load — retry shortly",
    "error": "global_rate_limit_exceeded",
}).encode()

_SHED_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-type", b"application/json"),
    (b"content-length", str(len(_SHED_BODY)).encode()),
    (b"retry-after", b"1"),
    (b"x-cullis-shed-reason", b"global_rate_limit"),
]


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


class GlobalRateLimitMiddleware:
    """Pure ASGI middleware that sheds with 503 when the shared bucket is empty.

    Instantiated with ``app.add_middleware(GlobalRateLimitMiddleware,
    bucket=...)``. Starlette wraps the class in its ASGI chain exactly
    like any other middleware — just without the ``BaseHTTPMiddleware``
    task wrapper that caused the log-visibility bug.
    """

    def __init__(
        self,
        app,
        bucket: TokenBucket,
        bypass_prefixes: tuple[str, ...] = _BYPASS_PREFIXES,
    ) -> None:
        self.app = app
        self._bucket = bucket
        self._bypass_prefixes = bypass_prefixes
        self._shed_count = 0  # incremented on every shed; surfaced via metric

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            # websockets + lifespan pass through untouched
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(p) for p in self._bypass_prefixes):
            await self.app(scope, receive, send)
            return

        if await self._bucket.try_acquire(1.0):
            await self.app(scope, receive, send)
            return

        # Shed. Log + emit a canned 503 directly on the ASGI send channel
        # so we skip the whole handler chain (no state mutated).
        self._shed_count += 1
        method = scope.get("method", "?")
        _emit_shed_log(path, method, self._shed_count)
        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": _SHED_HEADERS,
        })
        await send({
            "type": "http.response.body",
            "body": _SHED_BODY,
        })

    @property
    def shed_count(self) -> int:
        """Total requests shed since process start. Exposed for tests +
        metrics integration."""
        return self._shed_count
