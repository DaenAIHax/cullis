"""Admin NDJSON export of the audit chains for offline verification.

``GET /v1/admin/audit/export`` — the endpoint the offline verifier's
docstring always promised. Streams the audit store in the exact bundle
shape ``scripts/cullis-audit-verify.py::load_bundle`` consumes, so the
auditor workflow is two commands with no SQL in between:

    curl -H "X-Admin-Secret: $SECRET" \\
        "https://mastio:9443/v1/admin/audit/export?chain=both" \\
        -o bundle.ndjson
    python scripts/cullis-audit-verify.py --bundle bundle.ndjson

Query parameters:

* ``chain`` — ``audit_log`` (primary global chain, v2 rows bind
  dpop_jkt + on_behalf_of_user_id), ``local_audit`` (per-org chain),
  or ``both`` (default). Every entry row carries an explicit
  ``"chain"`` key so the verifier never has to guess the schema.
* ``org_id`` — optional filter on **local_audit** rows only (the
  audit_log chain is global per Mastio and has no org column);
  combining it with ``chain=audit_log`` is a 400.
* ``since_seq`` / ``until_seq`` — inclusive ``chain_seq`` bounds,
  applied to each chain independently. A window export that does not
  start at the genesis is forward-verified only (the verifier prints
  an explicit NOTE, qualifies the verdict, and ``--require-genesis``
  refuses it). When a bound is set, pre-migration audit_log rows with
  ``chain_seq IS NULL`` are omitted (they have no position on the seq
  axis). NB: seq windows are designed for the audit_log chain — on
  ``local_audit`` (per-org sequences) a window that starts past an
  org's first row makes that org's chain fail verification, since the
  local_audit walker has no forward-only mode. For local_audit,
  export org-complete (``org_id`` filter, no seq bounds).
* ``include_anchors`` — default true; emits ``kind="anchor"`` rows
  from ``audit_chain_anchors`` (RFC 3161, tagged ``chain=audit_log``
  because the anchor watcher runs over that chain) plus
  ``kind="merkle_anchor"`` rows from ``audit_merkle_anchors``.
  ``load_bundle`` ignores kinds it does not know, so older verifiers
  skip the merkle rows harmlessly.

Streaming: the tables grow to 100k+ rows in a real deploy (the 48h
soak wrote 98k), so the response is a ``StreamingResponse`` over
keyset-paginated batches — ``WHERE chain_seq > :last ORDER BY
chain_seq LIMIT N`` — with each batch in its own ``get_db()`` context
so no transaction (and on SQLite, no lock) is held for the lifetime
of a slow download. OFFSET pagination is deliberately avoided: it
degrades quadratically on deep pages.

Auth: shared ``X-Admin-Secret`` (same contract as the rest of
``mcp_proxy/admin/``). The rows are the product's own audit trail —
no field beyond the table columns is exposed.
"""
from __future__ import annotations

import base64
import hmac
import json
import logging
from typing import Any, AsyncIterator

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import text

from mcp_proxy.config import get_settings
from mcp_proxy.db import get_db

logger = logging.getLogger("mcp_proxy.admin.audit_export")

router = APIRouter(prefix="/v1/admin/audit", tags=["admin", "audit"])

# Rows per keyset batch. Large enough to amortise the per-batch
# round-trip, small enough that a batch never holds a meaningful
# SQLite lock window.
_BATCH_SIZE = 1000

# Column lists are explicit (not ``SELECT *``) and ordered to match
# the table definitions, so the export shape is pinned independently
# of any future column additions — a new column must be added here
# deliberately, with the verifier impact considered.
_AUDIT_LOG_COLS = (
    "id", "timestamp", "agent_id", "action", "tool_name", "status",
    "detail", "request_id", "duration_ms", "chain_seq", "prev_hash",
    "row_hash", "hash_format", "dpop_jkt", "on_behalf_of_user_id",
)
_LOCAL_AUDIT_COLS = (
    "id", "timestamp", "event_type", "agent_id", "session_id", "org_id",
    "details", "result", "entry_hash", "previous_hash", "chain_seq",
    "peer_org_id", "peer_row_hash", "hash_format",
)


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


def _entry_line(chain: str, cols: tuple[str, ...], mapping: Any) -> str:
    obj: dict[str, Any] = {"kind": "entry", "chain": chain}
    for c in cols:
        obj[c] = mapping[c]
    return json.dumps(obj, separators=(",", ":")) + "\n"


async def _iter_audit_log(
    since_seq: int | None, until_seq: int | None,
) -> AsyncIterator[str]:
    """Yield audit_log entry lines: unhashed pre-migration rows first
    (keyset on ``id``; only for unbounded exports — they have no seq
    position), then the chained rows keyset-paginated on ``chain_seq``.
    """
    cols_sql = ", ".join(_AUDIT_LOG_COLS)
    if since_seq is None and until_seq is None:
        last_id = 0
        while True:
            async with get_db() as conn:
                rows = (await conn.execute(
                    text(
                        f"SELECT {cols_sql} FROM audit_log "
                        " WHERE chain_seq IS NULL AND id > :last "
                        " ORDER BY id ASC LIMIT :n"
                    ),
                    {"last": last_id, "n": _BATCH_SIZE},
                )).all()
            if not rows:
                break
            for r in rows:
                yield _entry_line("audit_log", _AUDIT_LOG_COLS, r._mapping)
            last_id = int(rows[-1]._mapping["id"])

    last_seq = (since_seq - 1) if since_seq is not None else 0
    upper_clause = " AND chain_seq <= :upper" if until_seq is not None else ""
    while True:
        params: dict[str, Any] = {"last": last_seq, "n": _BATCH_SIZE}
        if until_seq is not None:
            params["upper"] = until_seq
        async with get_db() as conn:
            rows = (await conn.execute(
                text(
                    f"SELECT {cols_sql} FROM audit_log "
                    f" WHERE chain_seq > :last{upper_clause} "
                    f" ORDER BY chain_seq ASC LIMIT :n"
                ),
                params,
            )).all()
        if not rows:
            break
        for r in rows:
            yield _entry_line("audit_log", _AUDIT_LOG_COLS, r._mapping)
        last_seq = int(rows[-1]._mapping["chain_seq"])


async def _iter_local_audit(
    org_id: str | None, since_seq: int | None, until_seq: int | None,
) -> AsyncIterator[str]:
    """Yield local_audit entry lines, keyset-paginated on ``id``.

    ``id`` (not ``chain_seq``) is the keyset axis because chain_seq is
    only unique per org; the verifier re-sorts per ``(org, chain_seq)``
    itself, so emission order only needs to be stable and complete.
    Rows with ``chain_seq IS NULL`` (legacy global chain) ride along
    unless a seq window is set.
    """
    cols_sql = ", ".join(_LOCAL_AUDIT_COLS)
    filters = []
    base_params: dict[str, Any] = {"n": _BATCH_SIZE}
    if org_id:
        filters.append("org_id = :org_id")
        base_params["org_id"] = org_id
    if since_seq is not None:
        filters.append("chain_seq >= :lo")
        base_params["lo"] = since_seq
    if until_seq is not None:
        filters.append("chain_seq <= :hi")
        base_params["hi"] = until_seq
    filter_sql = "".join(f" AND {f}" for f in filters)

    last_id = 0
    while True:
        async with get_db() as conn:
            rows = (await conn.execute(
                text(
                    f"SELECT {cols_sql} FROM local_audit "
                    f" WHERE id > :last{filter_sql} "
                    f" ORDER BY id ASC LIMIT :n"
                ),
                {**base_params, "last": last_id},
            )).all()
        if not rows:
            break
        for r in rows:
            yield _entry_line("local_audit", _LOCAL_AUDIT_COLS, r._mapping)
        last_id = int(rows[-1]._mapping["id"])


async def _iter_anchors(
    since_seq: int | None, until_seq: int | None,
) -> AsyncIterator[str]:
    """Yield RFC 3161 chain anchors + Merkle batch anchors.

    Both watcher tables are small (one row per anchor interval /
    batch), so a single query each is fine — no keyset needed. Chain
    anchors honour the seq window exactly; Merkle anchors are included
    when their ``[start, end]`` range intersects it, because a window
    that covers any leaf of the batch can still replay the inclusion
    proof for that leaf.
    """
    clauses = []
    params: dict[str, Any] = {}
    if since_seq is not None:
        clauses.append("chain_seq >= :lo")
        params["lo"] = since_seq
    if until_seq is not None:
        clauses.append("chain_seq <= :hi")
        params["hi"] = until_seq
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT anchored_at, org_id, chain_seq, row_hash, "
                "       tsa_url, tsa_token "
                f"FROM audit_chain_anchors{where} ORDER BY chain_seq ASC"
            ),
            params,
        )).all()
    for r in rows:
        m = r._mapping
        token = m["tsa_token"]
        yield json.dumps({
            "kind": "anchor",
            "chain": "audit_log",
            "anchored_at": m["anchored_at"],
            "org_id": m["org_id"],
            "chain_seq": m["chain_seq"],
            "row_hash": m["row_hash"],
            "tsa_url": m["tsa_url"],
            "tsa_token_b64": (
                base64.b64encode(token).decode("ascii")
                if token is not None else None
            ),
        }, separators=(",", ":")) + "\n"

    m_clauses = []
    m_params: dict[str, Any] = {}
    if since_seq is not None:
        m_clauses.append("chain_seq_end >= :lo")
        m_params["lo"] = since_seq
    if until_seq is not None:
        m_clauses.append("chain_seq_start <= :hi")
        m_params["hi"] = until_seq
    m_where = (" WHERE " + " AND ".join(m_clauses)) if m_clauses else ""
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT id, created_at, org_id, chain_seq_start, "
                "       chain_seq_end, leaf_count, merkle_root, "
                "       tsa_url, tsa_token "
                f"FROM audit_merkle_anchors{m_where} "
                "ORDER BY chain_seq_start ASC"
            ),
            m_params,
        )).all()
    for r in rows:
        m = r._mapping
        token = m["tsa_token"]
        yield json.dumps({
            "kind": "merkle_anchor",
            "chain": "audit_log",
            "anchor_id": m["id"],
            "created_at": m["created_at"],
            "org_id": m["org_id"],
            "chain_seq_start": m["chain_seq_start"],
            "chain_seq_end": m["chain_seq_end"],
            "leaf_count": m["leaf_count"],
            "merkle_root": m["merkle_root"],
            "tsa_url": m["tsa_url"],
            "tsa_token_b64": (
                base64.b64encode(token).decode("ascii")
                if token is not None else None
            ),
        }, separators=(",", ":")) + "\n"


@router.get(
    "/export",
    dependencies=[Depends(_require_admin_secret)],
    response_class=StreamingResponse,
)
async def export_audit(
    chain: str = Query(
        "both",
        pattern="^(audit_log|local_audit|both)$",
        description=(
            "Which chain(s) to export: the primary global audit_log "
            "chain, the per-org local_audit chain, or both."
        ),
    ),
    org_id: str | None = Query(
        None,
        description=(
            "Filter local_audit rows to one org. The audit_log chain "
            "is global per Mastio — combining this with "
            "chain=audit_log is a 400."
        ),
    ),
    since_seq: int | None = Query(None, ge=0),
    until_seq: int | None = Query(None, ge=0),
    include_anchors: bool = Query(True),
) -> StreamingResponse:
    """Stream the audit store as a verifier-ready NDJSON bundle."""
    if org_id and chain == "audit_log":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "org_id only filters the per-org local_audit chain; the "
                "audit_log chain is global per Mastio. Use "
                "chain=local_audit or chain=both, or drop org_id."
            ),
        )
    if (
        since_seq is not None
        and until_seq is not None
        and since_seq > until_seq
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="since_seq must be <= until_seq",
        )

    async def _stream() -> AsyncIterator[str]:
        if chain in ("audit_log", "both"):
            async for line in _iter_audit_log(since_seq, until_seq):
                yield line
        if chain in ("local_audit", "both"):
            async for line in _iter_local_audit(org_id, since_seq, until_seq):
                yield line
        if include_anchors and chain in ("audit_log", "both"):
            async for line in _iter_anchors(since_seq, until_seq):
                yield line

    return StreamingResponse(
        _stream(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition":
                'attachment; filename="cullis-audit-export.ndjson"',
        },
    )
