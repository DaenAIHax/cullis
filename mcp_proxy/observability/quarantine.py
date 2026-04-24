"""Quarantine apply + expiry + reactivation — ADR-013 Phase 4 commit 5.

Three pieces that together close the loop between the anomaly
evaluator (commit 4) and the agent identity store:

1. ``quarantine_apply_hook`` — plugged into the evaluator's
   ``apply_hook``. Writes a row to ``agent_quarantine_events`` and,
   in enforce mode, flips ``internal_agents.is_active = 0``.
   Shadow mode only writes the audit row — the flag is never touched.

2. ``QuarantineExpiryScheduler`` — hourly cron that hard-DELETEs
   expired enforce-mode rows (see ADR safeguard §3.2: no auto-
   re-enable, re-enrollment required).

3. ``reactivate_agent`` — operator action to clear an active
   quarantine. Admin endpoint in ``mcp_proxy.admin.agents`` wraps it.

## Why hard-delete on expiry, not soft re-enable

The ADR section on safeguard §3.2 motivates this at length. Summary:

- A quarantine event means "potential credential compromise". The
  security-valid reset is a fresh identity + fresh keypair, not a
  rotated secret on the same row.
- Without hard-delete, ``internal_agents`` accumulates one orphan-
  disabled row per quarantine forever. Over months that's thousands
  of rows every enrollment script + migration has to iterate.
- Single source of truth: the row exists ⇔ the identity is valid.
  No "exists but disabled and expired" third state for downstream
  readers to reason about.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable

from sqlalchemy import text

from mcp_proxy.observability.anomaly_evaluator import TriggerInfo

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

_log = logging.getLogger("mcp_proxy")


def _now_iso(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.isoformat().replace("+00:00", "Z")


async def _insert_quarantine_event(
    engine: "AsyncEngine",
    *,
    agent_id: str,
    mode: str,
    trigger: TriggerInfo,
    expires_at_iso: str | None,
    now_iso: str,
) -> int:
    """Insert one event row and return its primary key id."""
    async with engine.begin() as conn:
        # Use a parametrized INSERT then fetch last inserted id — the
        # RETURNING clause is Postgres-only, we stay dialect-agnostic.
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, trigger_ratio, "
                " trigger_abs_rate, expires_at) "
                "VALUES (:agent, :ts, :mode, :ratio, :abs_rate, :expires)"
            ),
            {
                "agent": agent_id,
                "ts": now_iso,
                "mode": mode,
                "ratio": trigger.ratio,
                "abs_rate": trigger.current_rate_rps,
                "expires": expires_at_iso,
            },
        )
        # Read it back. This is only used by tests + the notification
        # path; not a hot spot.
        row = (
            await conn.execute(
                text(
                    "SELECT id FROM agent_quarantine_events "
                    "WHERE agent_id = :agent AND quarantined_at = :ts"
                ),
                {"agent": agent_id, "ts": now_iso},
            )
        ).first()
    return int(row[0]) if row and row[0] is not None else -1


async def _deactivate_agent(
    engine: "AsyncEngine", agent_id: str
) -> bool:
    """Set ``is_active = 0`` on the agent row. Returns True if updated.

    Idempotent: if the row is already inactive (operator already
    disabled it, or the same trigger fired twice in quick succession),
    this returns False. The event row is still written — we record
    every decision the detector made.
    """
    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                "UPDATE internal_agents SET is_active = 0 "
                "WHERE agent_id = :a AND is_active = 1"
            ),
            {"a": agent_id},
        )
    return (result.rowcount or 0) > 0


def make_quarantine_apply_hook(
    engine: "AsyncEngine",
    *,
    ttl_hours: int = 24,
    notification_dispatch: Callable[[dict], None] | None = None,
) -> Callable:
    """Build an apply_hook closure for the AnomalyEvaluator.

    ``notification_dispatch``: a sync callable that receives the
    notification dict. Defaults to the stderr-JSON fallback already
    emitted by ``anomaly_evaluator._emit_shadow_log``. Customer-
    specific webhook wiring plugs in here in a follow-up.
    """
    async def _hook(trigger: TriggerInfo, mode: str) -> None:
        now = datetime.now(timezone.utc)
        now_iso = _now_iso(now)
        expires_iso: str | None = None
        if mode == "enforce":
            expires_iso = _now_iso(now + timedelta(hours=ttl_hours))

        # Write the event row first. If the is_active update races
        # with an operator-triggered deactivation, we still want the
        # audit trail that records the detector fired.
        event_id = await _insert_quarantine_event(
            engine,
            agent_id=trigger.agent_id,
            mode=mode,
            trigger=trigger,
            expires_at_iso=expires_iso,
            now_iso=now_iso,
        )

        if mode == "enforce":
            try:
                deactivated = await _deactivate_agent(engine, trigger.agent_id)
            except Exception:
                _log.exception(
                    "quarantine apply: failed to deactivate agent=%s "
                    "(event_id=%d) — event row persists for audit",
                    trigger.agent_id,
                    event_id,
                )
                deactivated = False
            if not deactivated:
                _log.warning(
                    "quarantine apply: agent=%s was already inactive "
                    "at enforce time (event_id=%d) — concurrent "
                    "operator action or duplicate trigger",
                    trigger.agent_id,
                    event_id,
                )

        # Notification. Default path is the stderr shadow-log the
        # evaluator already wrote; this extra dispatch lets a future
        # webhook hook receive the full context without re-parsing the
        # log line.
        if notification_dispatch is not None:
            try:
                notification_dispatch(
                    {
                        "event_id": event_id,
                        "agent_id": trigger.agent_id,
                        "mode": mode,
                        "quarantined_at": now_iso,
                        "expires_at": expires_iso,
                        "ratio": trigger.ratio,
                        "current_rate_rps": trigger.current_rate_rps,
                        "baseline_rpm": trigger.baseline_rpm,
                        "hour_of_week": trigger.hour_of_week,
                        "mature": trigger.mature,
                    }
                )
            except Exception:
                _log.exception(
                    "notification_dispatch raised for agent=%s — "
                    "continuing (event already persisted)",
                    trigger.agent_id,
                )

    return _hook


# ── Expiry cron ───────────────────────────────────────────────────


@dataclass
class ExpiryStats:
    scanned: int = 0
    deleted: int = 0
    resolved: int = 0


async def run_expiry_once(
    engine: "AsyncEngine", *, now: datetime | None = None
) -> ExpiryStats:
    """One expiry pass. Exposed for tests + the scheduler.

    Contract:
      * Scans ``agent_quarantine_events`` rows where mode='enforce',
        resolved_at IS NULL, expires_at < now.
      * For each: DELETE the internal_agents row if still present,
        then UPDATE the event row with resolved_at + resolved_by='expired'.
      * The order matters: DELETE first so a concurrent reactivate
        cannot race us into an inconsistent "row deleted, event still
        open" state (the event update's WHERE clause guards that
        anyway, but belt-and-suspenders).
    """
    now = now or datetime.now(timezone.utc)
    now_iso = _now_iso(now)

    stats = ExpiryStats()

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT id, agent_id FROM agent_quarantine_events "
                    "WHERE mode = 'enforce' "
                    "  AND resolved_at IS NULL "
                    "  AND expires_at IS NOT NULL "
                    "  AND expires_at < :now"
                ),
                {"now": now_iso},
            )
        ).all()

    stats.scanned = len(rows)
    for event_id, agent_id in rows:
        async with engine.begin() as conn:
            del_result = await conn.execute(
                text("DELETE FROM internal_agents WHERE agent_id = :a"),
                {"a": agent_id},
            )
            if (del_result.rowcount or 0) > 0:
                stats.deleted += 1

            upd_result = await conn.execute(
                text(
                    "UPDATE agent_quarantine_events SET "
                    "resolved_at = :now, resolved_by = 'expired' "
                    "WHERE id = :id AND resolved_at IS NULL"
                ),
                {"now": now_iso, "id": event_id},
            )
            if (upd_result.rowcount or 0) > 0:
                stats.resolved += 1

    if stats.deleted:
        _log.info(
            "quarantine expiry: scanned=%d hard-deleted=%d resolved=%d",
            stats.scanned, stats.deleted, stats.resolved,
        )
    return stats


class QuarantineExpiryScheduler:
    """Hourly background task that runs ``run_expiry_once``."""

    def __init__(
        self,
        engine: "AsyncEngine",
        *,
        interval_s: float = 3600.0,
    ) -> None:
        self._engine = engine
        self.interval_s = interval_s
        self._task: asyncio.Task | None = None
        self._stopped = False
        self.runs_completed: int = 0
        self.last_stats: ExpiryStats | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopped = False
        self._task = asyncio.create_task(
            self._loop(), name="quarantine-expiry"
        )

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
                    stats = await run_expiry_once(self._engine)
                    self.last_stats = stats
                    self.runs_completed += 1
                except Exception:
                    _log.exception(
                        "quarantine expiry cron raised — retry at next tick"
                    )
        except asyncio.CancelledError:
            return


# ── Operator reactivation ─────────────────────────────────────────


@dataclass
class ReactivationResult:
    """Return type for the admin endpoint. ``ok=False`` signals no
    active quarantine event was found (the endpoint turns that into
    404)."""
    ok: bool
    agent_id: str
    resolved_event_id: int | None = None
    message: str = ""


def _operator_fingerprint(admin_secret: str) -> str:
    """Non-reversible identifier of the operator for the
    ``resolved_by`` column. The raw secret never reaches the audit
    trail; a truncated hash is enough to distinguish "same operator
    resolving multiple events" from "different operator".
    """
    digest = hashlib.sha256(admin_secret.encode("utf-8")).hexdigest()
    return f"operator:{digest[:12]}"


async def reactivate_agent(
    engine: "AsyncEngine",
    agent_id: str,
    *,
    admin_secret: str,
    now: datetime | None = None,
) -> ReactivationResult:
    """Clear an active quarantine.

    Steps:
      1. Refuse if no quarantine event row exists with
         ``resolved_at IS NULL AND mode='enforce'`` — the caller is
         trying to reactivate something that isn't quarantined.
      2. ``UPDATE internal_agents SET is_active = 1``. If the row is
         missing (the expiry cron already hard-deleted it), return
         ``ok=False`` with the "must re-enroll" message.
      3. ``UPDATE agent_quarantine_events SET resolved_at = now,
         resolved_by = 'operator:<hash>' WHERE id = :id``.
      4. Emit an INFO audit line.

    Refuses to reactivate if the most recent event was mode='shadow' —
    shadow events never quarantined anyone, there's nothing to clear.
    """
    now = now or datetime.now(timezone.utc)
    now_iso = _now_iso(now)

    async with engine.begin() as conn:
        event = (
            await conn.execute(
                text(
                    "SELECT id, mode FROM agent_quarantine_events "
                    "WHERE agent_id = :a AND resolved_at IS NULL "
                    "ORDER BY quarantined_at DESC LIMIT 1"
                ),
                {"a": agent_id},
            )
        ).first()

    if event is None:
        return ReactivationResult(
            ok=False,
            agent_id=agent_id,
            message="no active quarantine event for this agent",
        )
    event_id, mode = int(event[0]), str(event[1])
    if mode != "enforce":
        return ReactivationResult(
            ok=False,
            agent_id=agent_id,
            message=(
                f"most recent event is mode={mode!r} — "
                "shadow events never quarantined the agent, nothing to clear"
            ),
        )

    async with engine.begin() as conn:
        updated = await conn.execute(
            text(
                "UPDATE internal_agents SET is_active = 1 "
                "WHERE agent_id = :a"
            ),
            {"a": agent_id},
        )
        row_exists = (updated.rowcount or 0) > 0
        if not row_exists:
            # Row was hard-deleted by the expiry cron already.
            return ReactivationResult(
                ok=False,
                agent_id=agent_id,
                resolved_event_id=event_id,
                message=(
                    "agent row no longer exists (quarantine expired + "
                    "hard-deleted) — re-enrollment required"
                ),
            )

        await conn.execute(
            text(
                "UPDATE agent_quarantine_events SET "
                "resolved_at = :now, resolved_by = :who "
                "WHERE id = :id AND resolved_at IS NULL"
            ),
            {
                "now": now_iso,
                "who": _operator_fingerprint(admin_secret),
                "id": event_id,
            },
        )

    _log.info(
        "quarantine reactivated: agent=%s event_id=%d by=%s",
        agent_id, event_id, _operator_fingerprint(admin_secret),
    )
    return ReactivationResult(
        ok=True,
        agent_id=agent_id,
        resolved_event_id=event_id,
        message="agent reactivated",
    )
