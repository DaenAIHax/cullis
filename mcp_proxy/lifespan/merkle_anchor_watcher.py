"""Background loop that batches contiguous audit_log row_hash ranges
into Merkle anchors (ADR-037 Phase 1).

Where ``audit_anchor_watcher`` anchors one chain head per tick, this
watcher walks forward through ``audit_log`` and emits one
``audit_merkle_anchors`` row per contiguous batch. The Merkle root
binds every row in the batch via SHA-256 inclusion paths
(``mcp_proxy.audit.merkle.compute_merkle_root``), so:

  * Inclusion proof scales O(log batch_size) instead of an O(n)
    chain walk. At batch_size 1024 that is at most 10 sibling
    digests per proof.
  * TSA anchoring (optional, ``audit_merkle_tsa_enabled``) is
    amortised: one TSA call per batch instead of one per row, while
    every individual row still inherits tamper-evidence through the
    Merkle path.

Concurrency: leader-elected via ``mcp_proxy.lifespan.get_leader`` so
only one worker per Mastio process runs the loop (same pattern as
``audit_anchor_watcher``, ``intermediate_ca_watcher``, etc).

Idempotency: the watcher computes the next batch start as
``MAX(chain_seq_end) + 1`` from existing ``audit_merkle_anchors``
rows. A worker that crashes mid-batch leaves no half-written state
(the INSERT is atomic; the chain_seq_start derivation is consistent
with whatever the previous successful insert wrote). The next tick
picks up exactly where the previous one stopped.

Backpressure: the watcher pulls ``audit_merkle_batch_size`` rows
per tick and emits a single anchor. If audit_log produces rows
faster than the watcher emits batches, the gap simply grows and
the next tick covers the new range. The watcher never blocks on
TSA availability: a TSA HTTP error logs a warning and the batch
row is written without the TSA token (NULL). The retry is "next
batch", not "stop the loop".
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from mcp_proxy.audit.merkle import compute_merkle_root
from mcp_proxy.audit.tsa_client import (
    DEFAULT_TSA_URL,
    TSAAnchorError,
    anchor_row_hash,
)
from mcp_proxy.db import get_db


logger = logging.getLogger("mcp_proxy.lifespan.merkle_anchor_watcher")


_DEFAULT_TICK_SECONDS = 300  # 5 minutes
_DEFAULT_BATCH_SIZE = 1024
_DEFAULT_MIN_BATCH = 256


async def _last_anchored_seq() -> int:
    """Return the highest ``chain_seq_end`` already covered by an
    existing Merkle anchor, or 0 when the table is empty.

    The watcher walks forward only: the next batch starts at
    ``last_anchored_seq + 1``. Returning 0 on empty makes the first
    batch start at chain_seq=1, which matches the audit_log chain
    numbering (chain_seq starts at 1 in the F-A-402 trigger).
    """
    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT chain_seq_end FROM audit_merkle_anchors "
            "ORDER BY chain_seq_end DESC LIMIT 1"
        ))).first()
    if row is None:
        return 0
    return int(row[0])


async def _fetch_next_batch(
    *, start_seq: int, batch_size: int,
) -> list[tuple[int, str]]:
    """Return up to ``batch_size`` rows from audit_log with chain_seq
    >= start_seq, ordered ascending. Each tuple is ``(chain_seq,
    row_hash)``. Empty list means the watcher has caught up.

    We pull both columns even though only row_hash feeds the tree —
    chain_seq drives the contiguity guarantee that the anchor's
    [chain_seq_start, chain_seq_end] range encodes.
    """
    async with get_db() as conn:
        rows = (await conn.execute(text(
            "SELECT chain_seq, row_hash "
            "FROM audit_log "
            "WHERE chain_seq IS NOT NULL "
            "  AND row_hash IS NOT NULL "
            "  AND chain_seq >= :start_seq "
            "ORDER BY chain_seq ASC "
            "LIMIT :batch_size"
        ), {"start_seq": start_seq, "batch_size": batch_size})).all()
    return [(int(r[0]), str(r[1])) for r in rows]


async def _insert_anchor(
    *,
    org_id: str,
    chain_seq_start: int,
    chain_seq_end: int,
    leaf_count: int,
    merkle_root_hex: str,
    tsa_url: str | None,
    tsa_token: bytes | None,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_merkle_anchors "
                "(created_at, org_id, chain_seq_start, chain_seq_end, "
                " leaf_count, merkle_root, tsa_url, tsa_token) "
                "VALUES (:created_at, :org_id, :chain_seq_start, "
                ":chain_seq_end, :leaf_count, :merkle_root, "
                ":tsa_url, :tsa_token)"
            ),
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "org_id": org_id,
                "chain_seq_start": chain_seq_start,
                "chain_seq_end": chain_seq_end,
                "leaf_count": leaf_count,
                "merkle_root": merkle_root_hex,
                "tsa_url": tsa_url,
                "tsa_token": tsa_token,
            },
        )


def _row_hashes_to_leaves(row_hashes: list[str]) -> list[bytes]:
    """Convert the audit_log.row_hash hex strings to the 32-byte
    leaves the Merkle module expects. Caller validated that every
    row_hash is a non-empty SHA-256 hex string (selected with
    ``row_hash IS NOT NULL`` in the SQL above).
    """
    return [bytes.fromhex(h) for h in row_hashes]


async def _tick(
    *,
    org_id: str,
    batch_size: int,
    min_batch: int,
    tsa_enabled: bool,
    tsa_url: str,
    tsa_timeout: float,
) -> None:
    """One iteration: read last anchored seq, pull next batch, emit
    Merkle anchor (with optional TSA token over the root).
    """
    last_seq = await _last_anchored_seq()
    start_seq = last_seq + 1
    batch = await _fetch_next_batch(
        start_seq=start_seq, batch_size=batch_size,
    )

    if len(batch) < min_batch:
        logger.debug(
            "merkle_anchor_watcher: only %d rows in [%d, ...] "
            "(min=%d) — defer to next tick",
            len(batch), start_seq, min_batch,
        )
        return

    chain_seq_start = batch[0][0]
    chain_seq_end = batch[-1][0]
    leaf_count = len(batch)

    # Compute Merkle root over the row_hash bytes. The pure tree
    # math validates input shape (32 bytes each); we rely on that
    # to catch any non-SHA-256 hex slipping through SELECT.
    leaves = _row_hashes_to_leaves([rh for (_, rh) in batch])
    root_bytes = compute_merkle_root(leaves)
    root_hex = root_bytes.hex()

    # Optionally anchor the root at a TSA. Failure does NOT block
    # the batch row from being written — the local Merkle tree is
    # sound without the TSA, and the next batch retries.
    persisted_tsa_url: str | None = None
    persisted_tsa_token: bytes | None = None
    if tsa_enabled:
        try:
            result = await asyncio.to_thread(
                anchor_row_hash, root_hex,
                tsa_url=tsa_url, timeout_seconds=tsa_timeout,
            )
            persisted_tsa_url = result.tsa_url
            persisted_tsa_token = result.token_bytes
        except TSAAnchorError as exc:
            logger.warning(
                "merkle_anchor_watcher: TSA call failed (%s) for "
                "batch [%d, %d] — persisting anchor without TSA "
                "token, retry on next tick",
                exc, chain_seq_start, chain_seq_end,
            )

    try:
        await _insert_anchor(
            org_id=org_id,
            chain_seq_start=chain_seq_start,
            chain_seq_end=chain_seq_end,
            leaf_count=leaf_count,
            merkle_root_hex=root_hex,
            tsa_url=persisted_tsa_url,
            tsa_token=persisted_tsa_token,
        )
    except Exception as exc:  # noqa: BLE001 — defensive long-running loop
        logger.error(
            "merkle_anchor_watcher: persist failed for batch "
            "[%d, %d]: %s",
            chain_seq_start, chain_seq_end, exc,
        )
        return

    logger.info(
        "merkle_anchor_watcher: anchored batch [%d, %d] "
        "(leaves=%d, root=%s..., tsa=%s)",
        chain_seq_start, chain_seq_end, leaf_count, root_hex[:12],
        "yes" if persisted_tsa_token else "no",
    )


async def merkle_anchor_watcher_loop(
    *,
    org_id: str,
    stop_event: asyncio.Event,
    batch_size: int = _DEFAULT_BATCH_SIZE,
    min_batch: int = _DEFAULT_MIN_BATCH,
    tsa_enabled: bool = True,
    tsa_url: str = DEFAULT_TSA_URL,
    tick_seconds: int = _DEFAULT_TICK_SECONDS,
    tsa_timeout_seconds: float = 10.0,
) -> None:
    """Run the watcher until ``stop_event`` is set.

    Args:
        org_id: Mastio's own org id, stored on each anchor for
            self-describing NDJSON exports.
        stop_event: signalled by the lifespan shutdown handler.
        batch_size: maximum rows per Merkle batch.
        min_batch: minimum rows required before a batch is emitted.
            Until the chain has at least this many un-anchored rows,
            the watcher defers — avoids emitting trivially small
            trees on idle Mastios.
        tsa_enabled: whether to anchor each Merkle root at a TSA.
            False keeps the math purely local — useful for air-gapped
            deployments.
        tsa_url: HTTP(S) URL of the TSA (default DigiCert public).
        tick_seconds: anchor cadence. Default 5 minutes.
        tsa_timeout_seconds: per-anchor TSA HTTP timeout.
    """
    logger.info(
        "merkle_anchor_watcher: starting (tick=%ds, batch_size=%d, "
        "min_batch=%d, tsa=%s)",
        tick_seconds, batch_size, min_batch,
        tsa_url if tsa_enabled else "disabled",
    )

    while not stop_event.is_set():
        try:
            await _tick(
                org_id=org_id,
                batch_size=batch_size,
                min_batch=min_batch,
                tsa_enabled=tsa_enabled,
                tsa_url=tsa_url,
                tsa_timeout=tsa_timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "merkle_anchor_watcher: tick raised %s — continuing", exc,
            )

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=tick_seconds)
        except asyncio.TimeoutError:
            pass

    logger.info("merkle_anchor_watcher: loop stopped")
