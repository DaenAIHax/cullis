"""Anomaly evaluator + cycle-level meta-circuit-breaker — ADR-013 Phase 4.

Runs every 30 s. For each agent seen in the last 5 minutes:

1. Compute the current 5-min rate (req/sec).
2. If the baseline is mature (≥ 7 days of data), require **both**:
   - ``current_rate * 60 / baseline_rpm > RATIO_THRESHOLD`` (default 10×),
   - ``current_rate > ABS_THRESHOLD_SOFT`` (default 5 rps).
   AND not OR: either alone produces too many false positives.
3. If the baseline is immature, fall back to the absolute signal alone:
   ``current_rate > ABS_THRESHOLD`` (default 100 rps).

Triggers must stay tripped for ``sustained_ticks_required`` consecutive
evaluations (default 3 = 90 s) before a quarantine candidate is
emitted. A single transient spike never quarantines.

## Meta-circuit-breaker (cycle-level, fail-closed)

The classical "first-3-succeed" implementation of a ceiling has a
failure mode specific to detectors: if 50 agents trip simultaneously
because of an infra event (DB hiccup briefly pushing everyone over
threshold, bad baseline deployment, time-skew making 'now' look like a
high-baseline hour), the first-3-succeed variant quarantines 3
effectively-random customer agents. That's worse than quarantining
none.

Fail-closed at the cycle boundary: if the batch ``projected ceiling
consumption + new candidates`` exceeds the ceiling, **zero**
quarantines land this cycle + one aggregate alert fires. Under any
infra event the detector does zero harm, only reports it.

The suppressed candidates are not retried on the next cycle — the
sustained-tick counter reset ensures that if the event was transient
the detector re-enters the 90 s detection window from scratch, and if
it was real the operator saw the aggregate alert and can investigate
out-of-band.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Callable,
    Optional,
)

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

_log = logging.getLogger("mcp_proxy")


@dataclass(frozen=True)
class TriggerInfo:
    """A single agent's trigger context at evaluation time.

    Carried through from ``_evaluate_agent`` → candidate collection →
    apply hook. The apply hook in commit 5 turns this into a DB
    quarantine event + notification.
    """

    agent_id: str
    current_rate_rps: float
    baseline_rpm: Optional[float]  # None if immature or no bucket for hour
    ratio: Optional[float]         # None if immature or baseline absent
    hour_of_week: Optional[int]    # None if immature (no hour context)
    mature: bool
    sustained_ticks: int = 0


class MetaCircuitBreaker:
    """Rolling 60 s count of quarantine events for the ceiling check.

    Not to be confused with the DB latency circuit breaker (layer 6,
    commit from PR #308). That one sheds inbound requests; this one
    suppresses detector outputs. Shared name, very different role.
    """

    def __init__(
        self,
        *,
        ceiling_per_min: int,
        window_s: float = 60.0,
    ) -> None:
        if ceiling_per_min <= 0:
            raise ValueError(
                f"ceiling_per_min must be positive, got {ceiling_per_min}"
            )
        self.ceiling_per_min = ceiling_per_min
        self._window_s = float(window_s)
        self._events: deque[float] = deque()
        self.ceiling_trips_total: int = 0

    def recent_count(self) -> int:
        self._trim()
        return len(self._events)

    def record(self) -> None:
        self._events.append(time.monotonic())
        self._trim()

    def record_ceiling_trip(self) -> None:
        self.ceiling_trips_total += 1

    def _trim(self) -> None:
        cutoff = time.monotonic() - self._window_s
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


def _emit_shadow_log(trigger: TriggerInfo, mode: str) -> None:
    """Structured WARNING record on stderr for every quarantine decision.

    Shape mirrors ``mcp_proxy.logging_setup.JSONFormatter`` and the
    other ADR-013 layers (see global_rate_limit / db_latency_circuit_
    breaker) so an operator grep for ``anomaly_quarantine`` finds every
    decision in one tail. ``mode`` is ``shadow`` or ``enforce`` — the
    field name is the same as the DB row's and as the config setting.
    """
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "WARNING",
        "logger": "mcp_proxy",
        "message": (
            f"anomaly_quarantine mode={mode} agent={trigger.agent_id} "
            f"rate_rps={trigger.current_rate_rps:.2f} "
            f"ratio={trigger.ratio if trigger.ratio is None else f'{trigger.ratio:.2f}'} "
            f"baseline_rpm={trigger.baseline_rpm if trigger.baseline_rpm is None else f'{trigger.baseline_rpm:.2f}'} "
            f"hour_of_week={trigger.hour_of_week} "
            f"mature={trigger.mature} "
            f"sustained_ticks={trigger.sustained_ticks}"
        ),
    }
    print(json.dumps(payload, default=str), file=sys.stderr, flush=True)


def _emit_aggregate_alert(candidates: list[TriggerInfo]) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "ERROR",
        "logger": "mcp_proxy",
        "message": (
            f"anomaly_quarantine ceiling exceeded: suppressed "
            f"{len(candidates)} decision(s) — candidates="
            + ",".join(t.agent_id for t in candidates)
        ),
    }
    print(json.dumps(payload, default=str), file=sys.stderr, flush=True)


async def _fetch_recent_agents(
    engine: "AsyncEngine", since_iso: str
) -> list[str]:
    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT DISTINCT agent_id FROM agent_traffic_samples "
                    "WHERE bucket_ts >= :since"
                ),
                {"since": since_iso},
            )
        ).all()
    return [r[0] for r in rows]


async def _fetch_current_rate_rps(
    engine: "AsyncEngine", agent_id: str, since_iso: str, window_seconds: float
) -> float:
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT COALESCE(SUM(req_count), 0) FROM agent_traffic_samples "
                    "WHERE agent_id = :a AND bucket_ts >= :since"
                ),
                {"a": agent_id, "since": since_iso},
            )
        ).first()
    total = int(row[0]) if row else 0
    return total / window_seconds if window_seconds > 0 else 0.0


async def _fetch_earliest_sample(
    engine: "AsyncEngine", agent_id: str
) -> str | None:
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT MIN(bucket_ts) FROM agent_traffic_samples "
                    "WHERE agent_id = :a"
                ),
                {"a": agent_id},
            )
        ).first()
    return row[0] if row and row[0] else None


async def _fetch_baseline(
    engine: "AsyncEngine", agent_id: str, hour_of_week: int
) -> float | None:
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT req_per_min_avg FROM agent_hourly_baselines "
                    "WHERE agent_id = :a AND hour_of_week = :h"
                ),
                {"a": agent_id, "h": hour_of_week},
            )
        ).first()
    return float(row[0]) if row and row[0] is not None else None


class AnomalyEvaluator:
    """The 30 s tick + detection math + meta-breaker.

    The apply/alert hooks are injectable so commit 5 can plug in the
    DB quarantine + notification without touching the detection math.
    The default hooks run the stderr shadow-log emit only, which is
    exactly the shadow-mode contract: detector evaluates, emits
    structured logs, does not touch is_active.
    """

    def __init__(
        self,
        engine: "AsyncEngine",
        *,
        mode: str = "shadow",
        ratio_threshold: float = 10.0,
        abs_threshold_rps: float = 100.0,
        abs_threshold_rps_soft: float = 5.0,
        sustained_ticks_required: int = 3,
        interval_s: float = 30.0,
        ceiling_per_min: int = 3,
        baseline_min_days: int = 7,
        evaluation_window_s: float = 300.0,  # 5-min rate
        apply_hook: Callable[[TriggerInfo, str], Awaitable[None]] | None = None,
        alert_hook: Callable[[list[TriggerInfo]], Awaitable[None]] | None = None,
    ) -> None:
        if mode not in ("shadow", "enforce", "off"):
            raise ValueError(
                f"mode must be 'shadow'|'enforce'|'off', got {mode!r}"
            )
        self._engine = engine
        self.mode = mode
        self.ratio_threshold = ratio_threshold
        self.abs_threshold_rps = abs_threshold_rps
        self.abs_threshold_rps_soft = abs_threshold_rps_soft
        self.sustained_ticks_required = sustained_ticks_required
        self.interval_s = interval_s
        self.baseline_min_days = baseline_min_days
        self.evaluation_window_s = evaluation_window_s
        self.meta_breaker = MetaCircuitBreaker(
            ceiling_per_min=ceiling_per_min
        )
        self._apply_hook = apply_hook
        self._alert_hook = alert_hook
        self._hot_counter: dict[str, int] = {}
        self._task: asyncio.Task | None = None
        self._stopped = False
        self.startup_ts: str = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        # Surfaces for observability endpoint + tests.
        self.cycles_run: int = 0
        self.quarantines_applied_total: int = 0
        self.quarantines_shadow_total: int = 0
        self.quarantines_enforce_total: int = 0

    # ── evaluation core ───────────────────────────────────────────

    async def _evaluate_agent(
        self, agent_id: str, now: datetime
    ) -> TriggerInfo | None:
        window_start = now - timedelta(seconds=self.evaluation_window_s)
        since_iso = window_start.isoformat().replace("+00:00", "Z")
        rate_rps = await _fetch_current_rate_rps(
            self._engine, agent_id, since_iso, self.evaluation_window_s
        )

        earliest = await _fetch_earliest_sample(self._engine, agent_id)
        mature = False
        if earliest:
            earliest_dt = datetime.fromisoformat(
                earliest.replace("Z", "+00:00")
            )
            mature = (now - earliest_dt).days >= self.baseline_min_days

        if not mature:
            # Immature: only absolute signal. Catches new-enrollment
            # runaway cases that no baseline could have predicted.
            if rate_rps > self.abs_threshold_rps:
                return TriggerInfo(
                    agent_id=agent_id,
                    current_rate_rps=rate_rps,
                    baseline_rpm=None,
                    ratio=None,
                    hour_of_week=None,
                    mature=False,
                )
            return None

        how = now.weekday() * 24 + now.hour
        baseline_rpm = await _fetch_baseline(self._engine, agent_id, how)

        # Mature agent, no baseline row for THIS hour-of-week — new
        # hour that the rollup cron hasn't seen data for yet. Fall
        # back to absolute-signal-only so we aren't blind during the
        # first week of operation in a given hour-of-week bucket.
        if baseline_rpm is None or baseline_rpm <= 0:
            if rate_rps > self.abs_threshold_rps:
                return TriggerInfo(
                    agent_id=agent_id,
                    current_rate_rps=rate_rps,
                    baseline_rpm=None,
                    ratio=None,
                    hour_of_week=how,
                    mature=True,
                )
            return None

        current_rpm = rate_rps * 60.0
        ratio = current_rpm / baseline_rpm

        # Dual test: ratio AND soft-absolute. AND not OR to keep
        # legitimate fan-out / retry-storm patterns out of the signal.
        if (
            ratio > self.ratio_threshold
            and rate_rps > self.abs_threshold_rps_soft
        ):
            return TriggerInfo(
                agent_id=agent_id,
                current_rate_rps=rate_rps,
                baseline_rpm=baseline_rpm,
                ratio=ratio,
                hour_of_week=how,
                mature=True,
            )
        # Absolute-signal backstop still valid for mature agents:
        # nothing legit sustains 100 rps for 90 s on one credential.
        if rate_rps > self.abs_threshold_rps:
            return TriggerInfo(
                agent_id=agent_id,
                current_rate_rps=rate_rps,
                baseline_rpm=baseline_rpm,
                ratio=ratio,
                hour_of_week=how,
                mature=True,
            )
        return None

    # ── cycle orchestration ───────────────────────────────────────

    async def run_cycle(self, *, now: datetime | None = None) -> dict[str, int]:
        """One detection + meta-breaker cycle. Returns a stats dict
        suitable for logging + the observability endpoint.
        """
        if self.mode == "off":
            return {
                "candidates": 0, "applied": 0, "suppressed": 0,
                "disabled": 1,
            }
        now = now or datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.evaluation_window_s)
        since_iso = window_start.isoformat().replace("+00:00", "Z")
        recent_agents = await _fetch_recent_agents(self._engine, since_iso)

        candidates: list[TriggerInfo] = []
        for agent_id in recent_agents:
            trigger = await self._evaluate_agent(agent_id, now)
            if trigger is None:
                # Recovery: reset hot counter so a future event starts
                # from zero and has to re-sustain for 90 s.
                self._hot_counter.pop(agent_id, None)
                continue
            ticks = self._hot_counter.get(agent_id, 0) + 1
            self._hot_counter[agent_id] = ticks
            if ticks >= self.sustained_ticks_required:
                # Build a fresh trigger with the sustained count so
                # the downstream emit has the real tick count.
                candidates.append(
                    TriggerInfo(
                        agent_id=trigger.agent_id,
                        current_rate_rps=trigger.current_rate_rps,
                        baseline_rpm=trigger.baseline_rpm,
                        ratio=trigger.ratio,
                        hour_of_week=trigger.hour_of_week,
                        mature=trigger.mature,
                        sustained_ticks=ticks,
                    )
                )

        self.cycles_run += 1

        if not candidates:
            return {"candidates": 0, "applied": 0, "suppressed": 0}

        # Cycle-level fail-closed ceiling. ``recent_count()`` includes
        # sheds from past cycles that still fall inside the 60 s
        # window, so a slow-build wave of 3 in a row still trips.
        projected = self.meta_breaker.recent_count() + len(candidates)
        if projected > self.meta_breaker.ceiling_per_min:
            self.meta_breaker.record_ceiling_trip()
            _emit_aggregate_alert(candidates)
            if self._alert_hook is not None:
                try:
                    await self._alert_hook(candidates)
                except Exception:
                    _log.exception(
                        "alert_hook raised — continuing cycle (ceiling path)"
                    )
            # Reset the hot counters for suppressed candidates — the
            # next cycle re-enters the 90 s window from scratch, so a
            # transient infra spike does not silently re-trip.
            for trigger in candidates:
                self._hot_counter.pop(trigger.agent_id, None)
            return {
                "candidates": len(candidates),
                "applied": 0,
                "suppressed": len(candidates),
            }

        applied = 0
        for trigger in candidates:
            self.meta_breaker.record()
            _emit_shadow_log(trigger, self.mode)
            if self._apply_hook is not None:
                try:
                    await self._apply_hook(trigger, self.mode)
                except Exception:
                    _log.exception(
                        "apply_hook raised for agent=%s — continuing cycle",
                        trigger.agent_id,
                    )
            if self.mode == "shadow":
                self.quarantines_shadow_total += 1
            else:  # enforce
                self.quarantines_enforce_total += 1
            applied += 1
            # Reset after successful application so a second incident
            # on the same identity must sustain 90 s again.
            self._hot_counter.pop(trigger.agent_id, None)

        self.quarantines_applied_total += applied
        return {
            "candidates": len(candidates),
            "applied": applied,
            "suppressed": 0,
        }

    # ── background loop ───────────────────────────────────────────

    async def start(self) -> None:
        if self._task is not None:
            return
        if self.mode == "off":
            _log.info(
                "anomaly evaluator disabled (mode=off) — no background "
                "task will be started"
            )
            return
        self._stopped = False
        self._task = asyncio.create_task(self._loop(), name="anomaly-evaluator")

    async def stop(self) -> None:
        self._stopped = True
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _loop(self) -> None:
        try:
            while not self._stopped:
                try:
                    await asyncio.sleep(self.interval_s)
                except asyncio.CancelledError:
                    break
                if self._stopped:
                    break
                try:
                    await self.run_cycle()
                except Exception:
                    _log.exception(
                        "anomaly evaluator cycle raised — will retry in "
                        "%.0f s",
                        self.interval_s,
                    )
        except asyncio.CancelledError:
            return
