"""Operational helpers for the federation cache (ADR-001 Phase 4c).

Kept in `sync/` rather than `cli/` so unit tests can exercise the
truncate logic without touching argparse.
"""
from __future__ import annotations

from sqlalchemy import text

from mcp_proxy.db import get_db


async def drop_federation_cache() -> dict[str, int]:
    """Truncate the four federation cache tables and return the per-table
    row counts that were removed.

    Safe to call on a live proxy: the subscriber will reopen its SSE
    connection (or hit the next reconnect tick), see cursor=0, and
    re-apply the full broker history. While the cache is empty,
    intra-org decisions that consult it will see "agent unknown" and
    behave as the proxy did before Phase 4 — the broker remains
    authoritative for any decision the cache was only accelerating.
    """
    counts: dict[str, int] = {}
    async with get_db() as conn:
        # Order matters only for foreign-key consistency, of which we
        # have none; alphabetize for determinism.
        for table, key in (
            ("cached_federated_agents", "agents"),
            ("cached_policies", "policies"),
            ("cached_bindings", "bindings"),
            ("federation_cursor", "cursor"),
        ):
            n = (
                await conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
            ).scalar_one()
            await conn.execute(text(f"DELETE FROM {table}"))
            counts[key] = int(n)
    return counts
