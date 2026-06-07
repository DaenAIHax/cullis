"""Per-agent cumulative LLM token budget counter (calendar day / month).

Companion to the per-minute token rate limiter
(:mod:`mcp_proxy.auth.rate_limit`). Where that bounds burst *rate* over a
60s sliding window, this bounds *cumulative* spend over the calendar UTC
day and month — the budget an org sets per agent.

The source of truth is the audit chain. On a cold key the counter is
seeded from the chain's token sum for the current period
(``sum_principal_tokens_since``), then advanced by ``INCRBY`` per call. A
counter lost to a restart is rebuilt from the same signed rows an auditor
re-derives — the number that blocks a call is always chain-derivable,
never a free-floating tally.

Backends:
  * Redis (shared across workers) — ``INCRBY`` + ``EXPIRE`` on a
    date-stamped key. New period → fresh key automatically; the TTL only
    garbage-collects the previous one.
  * In-memory per-process dict — when Redis is unconfigured / down.

Fail-mode: individual Redis errors fail **open** (a cost ceiling must not
halt the fleet on a Redis blip — distinct from the fail-closed auth
path). The readyz Redis gate (#1057) already drains a worker whose Redis
is down, so a degraded per-worker count does not silently under-count the
live pool while still serving traffic.
"""
from __future__ import annotations

import logging
from datetime import datetime

_log = logging.getLogger("mcp_proxy.egress.budget")

_PREFIX = "mcp_proxy:budget:"
# Date-stamped keys make a new period use a fresh key, so these TTLs only
# garbage-collect the previous period's key — they need only outlive it.
_DAY_TTL = 60 * 60 * 36          # 36h
_MONTH_TTL = 60 * 60 * 24 * 40   # 40d


def _day_token(now: datetime) -> str:
    return now.strftime("%Y%m%d")


def _month_token(now: datetime) -> str:
    return now.strftime("%Y%m")


def _day_start_iso(now: datetime) -> str:
    return now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def _month_start_iso(now: datetime) -> str:
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()


def _day_key(agent_id: str, now: datetime) -> str:
    return f"{_PREFIX}{agent_id}:day:{_day_token(now)}"


def _month_key(agent_id: str, now: datetime) -> str:
    return f"{_PREFIX}{agent_id}:month:{_month_token(now)}"


async def _seed_from_chain(agent_id: str, period_start_iso: str) -> int:
    from mcp_proxy.db import sum_principal_tokens_since

    try:
        return await sum_principal_tokens_since(agent_id, period_start_iso)
    except Exception as exc:  # fail-open: seed 0 rather than block on a read error
        _log.warning(
            "budget seed-from-chain failed for %s — seeding 0: %s", agent_id, exc
        )
        return 0


class _PeriodBudgetCounter:
    """Calendar-period cumulative token counter, seeded from the audit chain."""

    def __init__(self) -> None:
        # In-memory fallback: {redis_key: tokens}. Bounded by agents × live
        # periods; a process restart clears it (re-seeded from the chain on
        # next touch). ``_seeded`` tracks which keys were warmed from the
        # chain so we seed exactly once per key.
        self._mem: dict[str, int] = {}
        self._seeded: set[str] = set()

    async def current(self, agent_id: str, now: datetime) -> tuple[int, int]:
        """Return ``(day_tokens, month_tokens)`` already spent this period."""
        day = await self._get(
            agent_id, _day_key(agent_id, now), _day_start_iso(now), _DAY_TTL
        )
        month = await self._get(
            agent_id, _month_key(agent_id, now), _month_start_iso(now), _MONTH_TTL
        )
        return day, month

    async def add(self, agent_id: str, amount: int, now: datetime) -> None:
        """Advance both period counters by ``amount`` (no-op when <= 0).

        Callers MUST have run :meth:`current` first (the enforcement check),
        which seeds the key from the chain — so ``add`` never creates an
        un-seeded key that a later :meth:`current` would trust as complete.
        """
        if amount <= 0:
            return
        await self._add(_day_key(agent_id, now), amount, _DAY_TTL)
        await self._add(_month_key(agent_id, now), amount, _MONTH_TTL)

    async def _get(
        self, agent_id: str, key: str, period_start_iso: str, ttl: int
    ) -> int:
        from mcp_proxy.redis.pool import get_redis

        redis = get_redis()
        if redis is not None:
            try:
                val = await redis.get(key)
                if val is not None:
                    return int(val)
                # Cold key — seed from the chain, then SET NX so a racing
                # seeder (or a concurrent INCRBY that already created the
                # key) is never clobbered.
                seed = await _seed_from_chain(agent_id, period_start_iso)
                await redis.set(key, seed, ex=ttl, nx=True)
                got = await redis.get(key)
                return int(got) if got is not None else seed
            except Exception as exc:  # fail-open
                _log.warning(
                    "budget counter Redis read failed (%s) — failing open: %s",
                    key,
                    exc,
                )
                return 0

        # In-memory fallback (single-process). Seed once per key.
        if key not in self._seeded:
            self._mem[key] = await _seed_from_chain(agent_id, period_start_iso)
            self._seeded.add(key)
        return self._mem.get(key, 0)

    async def _add(self, key: str, amount: int, ttl: int) -> None:
        from mcp_proxy.redis.pool import get_redis

        redis = get_redis()
        if redis is not None:
            try:
                await redis.incrby(key, int(amount))
                await redis.expire(key, ttl)
            except Exception as exc:  # fail-open
                _log.warning(
                    "budget counter Redis incr failed (%s) — skipped: %s", key, exc
                )
            return
        self._mem[key] = self._mem.get(key, 0) + int(amount)
        self._seeded.add(key)


_counter: _PeriodBudgetCounter | None = None


def get_budget_counter() -> _PeriodBudgetCounter:
    """Return the process-wide budget counter, initialising on first call."""
    global _counter
    if _counter is None:
        _counter = _PeriodBudgetCounter()
    return _counter


def reset_budget_counter() -> None:
    """Test hook — drop the singleton (and its in-memory state)."""
    global _counter
    _counter = None


async def effective_budget(agent_id: str, settings) -> tuple[int, int]:
    """Resolve ``(tokens_per_day, tokens_per_month)`` for an agent.

    An *enabled* per-agent row wins; otherwise the global
    ``llm_tokens_per_day`` / ``llm_tokens_per_month`` settings apply. ``0``
    for a period means "no ceiling for that period". When both are 0 the
    budget path is skipped entirely by the caller (zero overhead).
    """
    from mcp_proxy.db import get_agent_budget

    row = await get_agent_budget(agent_id)
    if row is not None and row["enabled"]:
        return row["tokens_per_day"], row["tokens_per_month"]
    return int(settings.llm_tokens_per_day), int(settings.llm_tokens_per_month)
