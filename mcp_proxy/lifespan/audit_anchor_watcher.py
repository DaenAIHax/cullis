"""Background loop that anchors the audit_log hash chain head to an
external RFC 3161 TSA on a configurable cadence.

Why this exists: the in-tree hash chain (``audit_log.row_hash`` +
F-A-402 trigger) proves consistency, not provenance. An operator with
DB write access could rewrite history end-to-end and
``verify_audit_chain`` would still pass — the chain has no witness
outside the org. This loop fixes that by periodically asking a public
TSA (default ``http://timestamp.digicert.com``) to sign a timestamp
over the current chain head's ``row_hash``. The signed token is
persisted in ``audit_chain_anchors`` and rides along in every NDJSON
audit export, where the standalone verifier
``cullis-audit-verify.py`` re-checks it offline.

Forging the chain end-to-end now requires forging the TSA's signature
— a much higher bar than database write. The audit trail becomes
**tamper-evident even against the operator**, which is the cross-
cutting "Audit log integrity" claim the threat model relies on.

Pattern follows the existing PKI watchers
(``intermediate_ca_watcher``, ``cert_expiry_watcher``,
``agent_cert_grace_cleanup``): leader-elected via
``mcp_proxy.lifespan.get_leader`` so only one worker per Mastio
process runs the loop; non-leaders skip silently. The loop wakes on
``stop_event`` so SIGTERM teardown does not wait a full tick.

Failure semantics: a TSA HTTP error, a TSA refusal, or an imprint
mismatch logs at warning level and the loop resumes on the next
tick. We do NOT block the Mastio's audit path on TSA availability —
the local chain stays intact regardless. The threat model documents
that residual: an operator who keeps the TSA endpoint blocked at the
network layer gets a chain WITHOUT external anchors during the
outage window. The audit export will reveal the gap (anchors stop
appearing at chain_seq N), which is itself a forensic signal.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from mcp_proxy.audit.tsa_client import (
    DEFAULT_TSA_URL,
    TSAAnchorError,
    anchor_row_hash,
)
from mcp_proxy.db import get_db


logger = logging.getLogger("mcp_proxy.lifespan.audit_anchor_watcher")


_DEFAULT_TICK_SECONDS = 3600  # one anchor per hour by default


async def _read_chain_head() -> tuple[int, str] | None:
    """Return ``(chain_seq, row_hash)`` of the most recent audited row.

    Returns ``None`` when the chain is empty (no audit_log rows yet, or
    all rows are pre-chain legacy ``chain_seq IS NULL``). The watcher
    is silent in that case — there is nothing to anchor.
    """
    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT chain_seq, row_hash "
            "FROM audit_log "
            "WHERE chain_seq IS NOT NULL AND row_hash IS NOT NULL "
            "ORDER BY chain_seq DESC LIMIT 1"
        ))).first()
    if row is None:
        return None
    return int(row[0]), str(row[1])


async def _already_anchored(chain_seq: int) -> bool:
    """Skip when the latest anchor already binds this seq."""
    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT chain_seq FROM audit_chain_anchors "
            "ORDER BY chain_seq DESC LIMIT 1"
        ))).first()
    return row is not None and int(row[0]) >= chain_seq


async def _insert_anchor(
    *,
    org_id: str,
    chain_seq: int,
    row_hash: str,
    tsa_url: str,
    tsa_token: bytes,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_chain_anchors "
                "(anchored_at, org_id, chain_seq, row_hash, tsa_url, tsa_token) "
                "VALUES (:anchored_at, :org_id, :chain_seq, :row_hash, "
                ":tsa_url, :tsa_token)"
            ),
            {
                "anchored_at": datetime.now(timezone.utc).isoformat(),
                "org_id": org_id,
                "chain_seq": chain_seq,
                "row_hash": row_hash,
                "tsa_url": tsa_url,
                "tsa_token": tsa_token,
            },
        )


async def _tick(*, tsa_url: str, org_id: str, tsa_timeout: float) -> None:
    """One iteration of the watcher: read head, anchor if new, persist."""
    head = await _read_chain_head()
    if head is None:
        logger.debug("audit_anchor_watcher: chain empty, nothing to anchor")
        return
    chain_seq, row_hash = head

    if await _already_anchored(chain_seq):
        logger.debug(
            "audit_anchor_watcher: chain_seq=%d already anchored — skip",
            chain_seq,
        )
        return

    try:
        # Bridge the synchronous TSA HTTP call to asyncio so the event
        # loop is not blocked on the TSA RTT (~50-300ms typical).
        result = await asyncio.to_thread(
            anchor_row_hash, row_hash,
            tsa_url=tsa_url, timeout_seconds=tsa_timeout,
        )
    except TSAAnchorError as exc:
        logger.warning(
            "audit_anchor_watcher: TSA call failed (%s) — chain_seq=%d "
            "not anchored this tick, will retry next tick",
            exc, chain_seq,
        )
        return

    try:
        await _insert_anchor(
            org_id=org_id,
            chain_seq=chain_seq,
            row_hash=row_hash,
            tsa_url=result.tsa_url,
            tsa_token=result.token_bytes,
        )
    except Exception as exc:  # noqa: BLE001 — defensive long-running loop
        logger.error(
            "audit_anchor_watcher: persist failed for chain_seq=%d: %s",
            chain_seq, exc,
        )
        return

    logger.info(
        "audit_anchor_watcher: anchored chain_seq=%d row_hash=%s... "
        "(tsa=%s, token=%dB)",
        chain_seq, row_hash[:12], result.tsa_url, len(result.token_bytes),
    )


async def audit_anchor_watcher_loop(
    *,
    org_id: str,
    stop_event: asyncio.Event,
    tsa_url: str = DEFAULT_TSA_URL,
    tick_seconds: int = _DEFAULT_TICK_SECONDS,
    tsa_timeout_seconds: float = 10.0,
) -> None:
    """Run the watcher until ``stop_event`` is set.

    Args:
        org_id: the Mastio's own org id (read once at lifespan
            startup from agent_manager). Stored on each anchor row so
            the NDJSON export is self-describing.
        stop_event: signalled by the lifespan shutdown handler.
            ``asyncio.wait_for(stop_event.wait(), timeout=tick)``
            wakes early on SIGTERM.
        tsa_url: HTTP(S) URL of the TSA. Default DigiCert public TSA.
        tick_seconds: anchor cadence. Default 1h — anchoring is
            forensic, not real-time, so a one-hour interval keeps the
            TSA query rate well below their rate limits while
            bounding the tamper window an attacker has between
            anchors.
        tsa_timeout_seconds: per-anchor HTTP timeout.
    """
    logger.info(
        "audit_anchor_watcher: starting (tsa=%s, tick=%ds)",
        tsa_url, tick_seconds,
    )

    while not stop_event.is_set():
        try:
            await _tick(
                tsa_url=tsa_url,
                org_id=org_id,
                tsa_timeout=tsa_timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "audit_anchor_watcher: tick raised %s — continuing", exc,
            )

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=tick_seconds)
        except asyncio.TimeoutError:
            pass

    logger.info("audit_anchor_watcher: loop stopped")
