"""DB latency tracking — ADR-013 layer 6 (circuit breaker input).

The circuit breaker reads one number from here: "what's the p99 of DB
operations right now?" Getting that number honest under every failure
mode is the whole point.

We combine two sources and take the max:

1. **Active probe** (``_ActiveProbe``) — background asyncio task
   executing ``SELECT 1`` at a fixed cadence using the **shared
   engine pool**, not a dedicated connection. That's deliberate: the
   probe's wall time includes both the pool-acquire wait and the
   query, so pool saturation (the common shape of silent DoS) shows
   up immediately. A trivial ``SELECT 1`` on a dedicated connection
   would stay fast while every real request piled up in the pool —
   the breaker would never fire and the Mastio would die smiling.

2. **Passive sampler** (``_PassiveSampler``) — SQLAlchemy
   before_cursor_execute / after_cursor_execute event listener that
   times every real query the application runs. Honest signal for
   pool latency + slow queries under the actual workload shape. Costs
   a few microseconds per query.

Probe alone lies under pool saturation. Passive alone has lag (no
sample = no data, breaker can't react until a request happens). The
``max(probe_p99, passive_p99)`` trick gives us the one that's
currently honest and ignores the one that isn't.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, NamedTuple

from sqlalchemy import event, text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

_log = logging.getLogger("mcp_proxy")

# A source needs at least this many samples in-window before its p99
# is returned. With fewer, p99 is statistically meaningless and would
# make the breaker flap on single outliers.
_MIN_SAMPLES_FOR_P99 = 3


class LatencySample(NamedTuple):
    ts: float
    latency_ms: float


class _RingBuffer:
    """Latency samples trimmed to a sliding time window.

    Thread-safety: a single ``asyncio.Lock`` guards mutations. The
    passive sampler's event listener runs on the SQLAlchemy thread
    (async engine offloads sync driver work), so record() is called
    from multiple contexts and must be safe. The lock is held only
    for cheap ops (append + deque pop-left), never blocking.
    """

    def __init__(self, window_s: float) -> None:
        self._window_s = float(window_s)
        self._samples: deque[LatencySample] = deque()
        self._lock = asyncio.Lock()

    def record_nowait(self, latency_ms: float) -> None:
        """Record without awaiting the lock — safe when the caller
        can't yield to an event loop (SQLAlchemy sync event handlers).
        Uses a small race window that's acceptable because samples
        are statistical; an occasional lost/extra sample doesn't
        break p99.
        """
        self._samples.append(LatencySample(time.monotonic(), latency_ms))
        self._trim_nolock()

    async def record(self, latency_ms: float) -> None:
        async with self._lock:
            self._samples.append(LatencySample(time.monotonic(), latency_ms))
            self._trim_nolock()

    def _trim_nolock(self) -> None:
        cutoff = time.monotonic() - self._window_s
        while self._samples and self._samples[0].ts < cutoff:
            self._samples.popleft()

    def p99_or_none(self) -> float | None:
        self._trim_nolock()
        values = [s.latency_ms for s in self._samples]
        if len(values) < _MIN_SAMPLES_FOR_P99:
            return None
        return _percentile(values, 0.99)

    def sample_count(self) -> int:
        self._trim_nolock()
        return len(self._samples)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    vs = sorted(values)
    idx = min(len(vs) - 1, max(0, int(len(vs) * pct) - 1))
    return vs[idx]


class _ActiveProbe:
    """Background task: measure pool-acquire + SELECT 1 at an interval."""

    def __init__(
        self,
        engine: "AsyncEngine",
        buffer: _RingBuffer,
        interval_s: float,
        timeout_s: float,
    ) -> None:
        self._engine = engine
        self._buffer = buffer
        self._interval_s = interval_s
        self._timeout_s = timeout_s
        self._task: asyncio.Task | None = None
        self._stopped = asyncio.Event()

    async def start(self) -> None:
        self._stopped.clear()
        self._task = asyncio.create_task(self._run(), name="cullis-db-latency-probe")

    async def stop(self) -> None:
        self._stopped.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self) -> None:
        while not self._stopped.is_set():
            await self._probe_once()
            try:
                await asyncio.wait_for(
                    self._stopped.wait(),
                    timeout=self._interval_s,
                )
                return  # stopped event fired
            except asyncio.TimeoutError:
                pass  # normal path — tick elapsed, probe again

    async def _probe_once(self) -> None:
        start = time.monotonic()
        try:
            await asyncio.wait_for(self._do_select(), timeout=self._timeout_s)
            elapsed_ms = (time.monotonic() - start) * 1000.0
        except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001
            # Probe couldn't complete within the timeout window — for
            # breaker purposes that's as bad as latency can get. Using
            # a huge finite sentinel instead of ``inf`` so math on
            # downstream lerps stays well-defined.
            elapsed_ms = 10_000.0
            _log.debug("db latency probe failed/timed out: %s", exc)
        await self._buffer.record(elapsed_ms)

    async def _do_select(self) -> None:
        # Include pool-acquire time in the measurement. ``connect()``
        # blocks when the pool is saturated; that's exactly the signal
        # the breaker needs.
        async with self._engine.connect() as conn:
            await conn.execute(text("SELECT 1"))


class _PassiveSampler:
    """Wraps SQLAlchemy before/after cursor-execute events to record
    wall-clock latency of every real query the app runs.
    """

    def __init__(self, buffer: _RingBuffer) -> None:
        self._buffer = buffer
        self._attached = False
        self._engine_ref = None
        # A unique per-context attribute name so we don't collide with
        # other middleware/instrumentation that might already be
        # hanging data off ``ExecutionContext`` subclasses.
        self._attr = "_cullis_db_latency_start"

    def attach(self, engine: "AsyncEngine") -> None:
        if self._attached:
            return
        # Async engines expose the sync engine the event system hooks
        # into; that's the supported path per SQLAlchemy 2.x docs.
        sync_engine = engine.sync_engine
        event.listen(sync_engine, "before_cursor_execute", self._before)
        event.listen(sync_engine, "after_cursor_execute", self._after)
        self._attached = True
        self._engine_ref = sync_engine

    def detach(self) -> None:
        if not self._attached or self._engine_ref is None:
            return
        try:
            event.remove(self._engine_ref, "before_cursor_execute", self._before)
            event.remove(self._engine_ref, "after_cursor_execute", self._after)
        except Exception:  # noqa: BLE001 — detach is best-effort at shutdown
            pass
        self._attached = False
        self._engine_ref = None

    def _before(self, conn, cursor, statement, parameters, context, executemany):
        setattr(context, self._attr, time.monotonic())

    def _after(self, conn, cursor, statement, parameters, context, executemany):
        start = getattr(context, self._attr, None)
        if start is None:
            return
        latency_ms = (time.monotonic() - start) * 1000.0
        # Synchronous event callback — cannot await the lock. Use the
        # nowait variant that does a best-effort trim. Samples are
        # statistical so an occasional race is fine.
        self._buffer.record_nowait(latency_ms)


class DbLatencyTracker:
    """Combined probe + passive latency source for the circuit breaker.

    Exposes the minimal surface the middleware needs:
      - ``p99_ms()`` returns (probe_p99, passive_p99, effective_p99)
        with ``None`` for any not-yet-ready source. ``effective`` is
        the max of the ready sources or ``None`` if neither is ready.
      - ``start()`` / ``stop()`` manage the background probe task +
        event listener attachment.
    """

    def __init__(
        self,
        engine: "AsyncEngine",
        *,
        window_s: float = 5.0,
        probe_interval_s: float = 1.0,
        probe_timeout_s: float = 2.0,
    ) -> None:
        self._probe_buffer = _RingBuffer(window_s)
        self._passive_buffer = _RingBuffer(window_s)
        self._probe = _ActiveProbe(
            engine, self._probe_buffer,
            interval_s=probe_interval_s,
            timeout_s=probe_timeout_s,
        )
        self._passive = _PassiveSampler(self._passive_buffer)
        self._engine = engine
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        self._passive.attach(self._engine)
        await self._probe.start()
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        await self._probe.stop()
        self._passive.detach()
        self._started = False

    def p99_ms(self) -> tuple[float | None, float | None, float | None]:
        """Returns (probe, passive, effective)."""
        probe = self._probe_buffer.p99_or_none()
        passive = self._passive_buffer.p99_or_none()
        ready = [v for v in (probe, passive) if v is not None]
        effective = max(ready) if ready else None
        return probe, passive, effective

    def sample_counts(self) -> tuple[int, int]:
        """Diagnostic: (probe_samples_in_window, passive_samples_in_window)."""
        return self._probe_buffer.sample_count(), self._passive_buffer.sample_count()
