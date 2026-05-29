"""Anomaly evaluator + meta-circuit-breaker tests — ADR-013 Phase 4 c4.

Covers:
- Immature agent: absolute signal only.
- Mature agent with baseline: dual test (ratio AND abs-soft).
- Hot-counter hysteresis: single tick does not quarantine, 3 does.
- Meta-circuit-breaker: cycle-level fail-closed when projected > ceiling.
- Shadow vs enforce mode accounting.
- apply_hook / alert_hook are awaited; their exceptions do not abort
  the cycle.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.observability.anomaly_evaluator import (
    AnomalyEvaluator,
    MetaCircuitBreaker,
    TriggerInfo,
)


@pytest.fixture
async def engine(tmp_path):
    db_file = tmp_path / "anomaly.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    eng: AsyncEngine = create_async_engine(url, future=True)
    yield eng
    await eng.dispose()
    await dispose_db()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _insert_sample(
    engine: AsyncEngine, agent_id: str, ts: datetime, count: int
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_traffic_samples "
                "(agent_id, bucket_ts, req_count) VALUES (:a, :b, :c) "
                "ON CONFLICT(agent_id, bucket_ts) DO UPDATE SET "
                "req_count = excluded.req_count"
            ),
            {"a": agent_id, "b": _iso(ts), "c": count},
        )


async def _insert_baseline(
    engine: AsyncEngine,
    agent_id: str,
    hour_of_week: int,
    avg_rpm: float,
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_hourly_baselines "
                "(agent_id, hour_of_week, req_per_min_avg, req_per_min_p95, "
                " sample_count, updated_at) "
                "VALUES (:a, :h, :avg, :p95, :n, :u)"
            ),
            {
                "a": agent_id,
                "h": hour_of_week,
                "avg": avg_rpm,
                "p95": avg_rpm * 1.2,
                "n": 10,
                "u": _iso(datetime.now(timezone.utc)),
            },
        )


# ── MetaCircuitBreaker ────────────────────────────────────────────


def test_meta_breaker_rejects_zero_or_negative_ceiling():
    with pytest.raises(ValueError):
        MetaCircuitBreaker(ceiling_per_min=0)


def test_meta_breaker_records_within_window():
    mb = MetaCircuitBreaker(ceiling_per_min=3, window_s=60.0)
    for _ in range(5):
        mb.record()
    assert mb.recent_count() == 5


def test_meta_breaker_trims_old_entries():
    mb = MetaCircuitBreaker(ceiling_per_min=3, window_s=0.05)
    mb.record()
    import time

    time.sleep(0.1)
    # 0.1 s > 0.05 window → trimmed out.
    assert mb.recent_count() == 0


# ── Immature-agent path ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_immature_agent_only_absolute_fires(engine):
    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)

    # 3000 reqs in a single 10-min bucket — 3000 / 300 = 10 rps exactly,
    # below threshold. Bump it to 3001 for a hair over.
    await _insert_sample(engine, "new-agent", now - timedelta(minutes=2), 3001)

    out = await ev.run_cycle(now=now)
    assert out == {"candidates": 1, "applied": 1, "suppressed": 0}
    assert ev.quarantines_shadow_total == 1


@pytest.mark.asyncio
async def test_immature_agent_low_rate_does_not_fire(engine):
    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "new-agent", now - timedelta(minutes=2), 100)

    out = await ev.run_cycle(now=now)
    assert out == {"candidates": 0, "applied": 0, "suppressed": 0}


# ── Mature-agent dual-test ────────────────────────────────────────


@pytest.mark.asyncio
async def test_mature_agent_dual_test_fires(engine):
    """current_rpm / baseline_rpm > ratio AND current_rps > soft_abs."""
    ev = AnomalyEvaluator(
        engine,
        ratio_threshold=10.0,
        abs_threshold_rps=100.0,
        abs_threshold_rps_soft=5.0,
        sustained_ticks_required=1,
    )
    now = datetime(2026, 4, 22, 14, 0, 0, tzinfo=timezone.utc)
    # Earliest sample 10 days ago → mature.
    await _insert_sample(
        engine, "a", now - timedelta(days=10), 1
    )
    # Current 5-min window: 3000 reqs / 300 s = 10 rps = 600 rpm.
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 3000)

    # Baseline: 1 rpm → ratio = 600 → > 10, and 10 rps > 5 soft.
    how = now.weekday() * 24 + now.hour  # Wed 14:00 = 2*24+14 = 62
    await _insert_baseline(engine, "a", how, 1.0)

    out = await ev.run_cycle(now=now)
    assert out == {"candidates": 1, "applied": 1, "suppressed": 0}


@pytest.mark.asyncio
async def test_mature_agent_ratio_high_but_abs_below_soft_does_not_fire(engine):
    ev = AnomalyEvaluator(
        engine,
        ratio_threshold=10.0,
        abs_threshold_rps=100.0,
        abs_threshold_rps_soft=5.0,
        sustained_ticks_required=1,
    )
    now = datetime(2026, 4, 22, 14, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", now - timedelta(days=10), 1)
    # 600 reqs / 300 s = 2 rps → below soft (5).
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 600)
    how = now.weekday() * 24 + now.hour
    await _insert_baseline(engine, "a", how, 0.1)  # ratio would be huge

    out = await ev.run_cycle(now=now)
    assert out == {"candidates": 0, "applied": 0, "suppressed": 0}


@pytest.mark.asyncio
async def test_mature_agent_abs_backstop_fires_even_with_low_ratio(engine):
    """If current_rps > abs_threshold the agent is quarantined regardless
    of ratio. Nothing legit sustains that rate on one credential.
    """
    ev = AnomalyEvaluator(
        engine,
        ratio_threshold=10.0,
        abs_threshold_rps=100.0,
        abs_threshold_rps_soft=5.0,
        sustained_ticks_required=1,
    )
    now = datetime(2026, 4, 22, 14, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", now - timedelta(days=10), 1)
    # 45000 reqs / 300 s = 150 rps > 100 abs.
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 45000)
    how = now.weekday() * 24 + now.hour
    # High baseline → ratio 150 * 60 / 500 = 18 > 10 — actually fires
    # both paths. Use an even higher baseline to *only* fire the abs
    # backstop.
    await _insert_baseline(engine, "a", how, 5000.0)  # ratio = 150*60/5000 = 1.8

    out = await ev.run_cycle(now=now)
    assert out == {"candidates": 1, "applied": 1, "suppressed": 0}


# ── Hot-counter hysteresis ────────────────────────────────────────


@pytest.mark.asyncio
async def test_hot_counter_requires_sustained_ticks(engine):
    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=3,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 30001)

    # Tick 1 + 2: no quarantine.
    out1 = await ev.run_cycle(now=now)
    out2 = await ev.run_cycle(now=now)
    assert out1 == {"candidates": 0, "applied": 0, "suppressed": 0}
    assert out2 == {"candidates": 0, "applied": 0, "suppressed": 0}

    # Tick 3: quarantines.
    out3 = await ev.run_cycle(now=now)
    assert out3 == {"candidates": 1, "applied": 1, "suppressed": 0}


@pytest.mark.asyncio
async def test_hot_counter_resets_on_recovery(engine):
    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=3,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    # One trip.
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 30001)
    await ev.run_cycle(now=now)
    assert ev._hot_counter.get("a") == 1

    # Rate drops — reset.
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 10)
    await ev.run_cycle(now=now)
    assert "a" not in ev._hot_counter


# ── Meta-circuit-breaker cycle-level ──────────────────────────────


@pytest.mark.asyncio
async def test_meta_breaker_suppresses_all_when_projected_exceeds_ceiling(
    engine,
):
    """If len(candidates) > ceiling, zero quarantines apply (fail-closed)."""
    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
        ceiling_per_min=3,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    # 5 agents all over threshold in one cycle.
    for i in range(5):
        await _insert_sample(
            engine, f"agent-{i}", now - timedelta(minutes=2), 30001
        )

    out = await ev.run_cycle(now=now)
    assert out == {
        "candidates": 5,
        "applied": 0,
        "suppressed": 5,
    }
    assert ev.meta_breaker.ceiling_trips_total == 1
    assert ev.quarantines_shadow_total == 0


@pytest.mark.asyncio
async def test_meta_breaker_allows_batch_below_ceiling(engine):
    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
        ceiling_per_min=3,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        await _insert_sample(
            engine, f"agent-{i}", now - timedelta(minutes=2), 30001
        )

    out = await ev.run_cycle(now=now)
    assert out == {"candidates": 3, "applied": 3, "suppressed": 0}


@pytest.mark.asyncio
async def test_meta_breaker_accumulates_across_cycles(engine):
    """Sheds from past cycles count toward the projected total."""
    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
        ceiling_per_min=3,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        await _insert_sample(
            engine, f"agent-{i}", now - timedelta(minutes=2), 30001
        )
    # Cycle 1: 3 applied (fills ceiling).
    out1 = await ev.run_cycle(now=now)
    assert out1["applied"] == 3

    # Drop the high-rate samples for the first three so they stop
    # firing; only the new agent should be a candidate in cycle 2.
    async with engine.begin() as conn:
        for i in range(3):
            await conn.execute(
                text(
                    "UPDATE agent_traffic_samples SET req_count = 1 "
                    "WHERE agent_id = :a"
                ),
                {"a": f"agent-{i}"},
            )
    # Cycle 2: one new candidate. projected = 3 + 1 = 4 > 3 → suppressed.
    await _insert_sample(engine, "agent-extra", now - timedelta(minutes=2), 30001)
    out2 = await ev.run_cycle(now=now)
    assert out2 == {"candidates": 1, "applied": 0, "suppressed": 1}
    assert ev.meta_breaker.ceiling_trips_total == 1


# ── Mode behaviour ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mode_off_runs_no_cycle(engine):
    ev = AnomalyEvaluator(engine, mode="off", sustained_ticks_required=1)
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 30001)
    out = await ev.run_cycle(now=now)
    assert out["disabled"] == 1
    assert ev.quarantines_shadow_total == 0


@pytest.mark.asyncio
async def test_mode_enforce_accounts_separately(engine):
    ev = AnomalyEvaluator(
        engine,
        mode="enforce",
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 30001)

    await ev.run_cycle(now=now)
    assert ev.quarantines_enforce_total == 1
    assert ev.quarantines_shadow_total == 0


# ── Hooks ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apply_hook_is_awaited(engine):
    received: list[tuple[str, str]] = []

    async def hook(trigger: TriggerInfo, mode: str) -> None:
        received.append((trigger.agent_id, mode))

    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
        apply_hook=hook,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 30001)

    await ev.run_cycle(now=now)
    assert received == [("a", "shadow")]


@pytest.mark.asyncio
async def test_apply_hook_exception_does_not_abort_cycle(engine):
    async def hook(trigger: TriggerInfo, mode: str) -> None:
        raise RuntimeError("hook failure")

    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
        apply_hook=hook,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", now - timedelta(minutes=2), 30001)
    await _insert_sample(engine, "b", now - timedelta(minutes=2), 30001)

    out = await ev.run_cycle(now=now)
    # Both candidates counted as applied even if hook raised.
    assert out == {"candidates": 2, "applied": 2, "suppressed": 0}


@pytest.mark.asyncio
async def test_alert_hook_fires_on_ceiling_trip(engine):
    received: list[list[str]] = []

    async def alert(candidates):
        received.append([c.agent_id for c in candidates])

    ev = AnomalyEvaluator(
        engine,
        abs_threshold_rps=10.0,
        sustained_ticks_required=1,
        ceiling_per_min=3,
        alert_hook=alert,
    )
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        await _insert_sample(
            engine, f"agent-{i}", now - timedelta(minutes=2), 30001
        )
    await ev.run_cycle(now=now)

    assert len(received) == 1
    assert sorted(received[0]) == [f"agent-{i}" for i in range(5)]


# ── Background loop ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_stop_runs_cycles(engine):
    ev = AnomalyEvaluator(
        engine, interval_s=0.05, sustained_ticks_required=1
    )
    await ev.start()
    await asyncio.sleep(0.15)
    await ev.stop()
    assert ev.cycles_run >= 1


@pytest.mark.asyncio
async def test_start_noop_when_mode_off(engine):
    ev = AnomalyEvaluator(engine, mode="off")
    await ev.start()
    assert ev._task is None
    await ev.stop()
