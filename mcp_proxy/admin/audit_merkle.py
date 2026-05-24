"""Admin endpoints for the Merkle batch audit anchor (ADR-037 Phase 2).

Two read-only endpoints, both gated by the shared ``X-Admin-Secret``
header (same pattern as the rest of ``mcp_proxy/admin/``):

* ``GET /v1/admin/audit/merkle/anchors`` — list anchors with their
  ``(chain_seq_start, chain_seq_end, leaf_count, merkle_root)`` and
  optional TSA metadata. Used by the dashboard and by the offline
  verifier to fetch the trusted roots before walking proofs.
* ``GET /v1/admin/audit/merkle/proof/{chain_seq}`` — return the
  inclusion proof for the audit_log row at ``chain_seq``. Response
  carries the matched anchor id, the merkle root, the leaf hash,
  and the bottom-up sibling list with ``L``/``R`` positions, so the
  caller (offline verifier, auditor, dashboard) can replay
  ``mcp_proxy.audit.merkle.verify_inclusion`` without any DB
  access of its own.

The proof is computed lazily by rebuilding the tree over the
``audit_log.row_hash`` rows in the anchor's covered range. The
anchor row stores only the root; sibling material is recomputed on
demand. This keeps the storage cost flat (one row per batch) while
the per-request CPU is bounded by the batch size (1024 rows ≈ 1024
SHA-256 ops, single-digit milliseconds).
"""
from __future__ import annotations

import hmac
import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import text

from mcp_proxy.audit.merkle import inclusion_proof
from mcp_proxy.config import get_settings
from mcp_proxy.db import get_db


logger = logging.getLogger("mcp_proxy.admin.audit_merkle")

router = APIRouter(
    prefix="/v1/admin/audit/merkle",
    tags=["admin", "audit", "merkle"],
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


class MerkleAnchorEntry(BaseModel):
    """One row of ``audit_merkle_anchors`` flattened for JSON.

    Field names mirror the table schema 1:1 so the offline verifier
    can map directly. ``tsa_token_b64`` is base64-encoded when
    present (the table stores raw bytes); ``None`` when the worker
    persisted the anchor without an external TSA witness (TSA
    disabled, TSA unreachable at batch time, etc).
    """
    id: int
    created_at: str
    org_id: str
    chain_seq_start: int
    chain_seq_end: int
    leaf_count: int
    merkle_root: str
    tsa_url: str | None
    tsa_token_b64: str | None


class MerkleAnchorListResponse(BaseModel):
    anchors: list[MerkleAnchorEntry]
    count: int


class InclusionProofStep(BaseModel):
    """One sibling on the path from leaf to root.

    ``position`` is ``"L"`` if the sibling sits on the LEFT of the
    current node (verifier hashes ``sibling || current``) and
    ``"R"`` if on the right (``current || sibling``). The verifier
    walks the steps bottom-up.
    """
    sibling_hex: str
    position: str  # "L" or "R"


class InclusionProofResponse(BaseModel):
    """Everything an offline verifier needs to assert that a given
    ``chain_seq`` row is included in the anchored Merkle root.

    The verifier does not need to trust the Mastio: it can
    independently compute the leaf hash from the row content,
    rebuild the root by walking the proof, and compare against
    the ``merkle_root`` it pulled from the anchor list (or from
    the NDJSON export bundle).
    """
    anchor_id: int
    chain_seq: int
    chain_seq_start: int
    chain_seq_end: int
    leaf_count: int
    merkle_root: str
    leaf_hex: str
    proof: list[InclusionProofStep]


def _row_to_entry(row) -> MerkleAnchorEntry:
    import base64

    tsa_token = row[7]
    if isinstance(tsa_token, memoryview):
        tsa_token = bytes(tsa_token)
    return MerkleAnchorEntry(
        id=int(row[0]),
        created_at=str(row[1]),
        org_id=str(row[2]),
        chain_seq_start=int(row[3]),
        chain_seq_end=int(row[4]),
        leaf_count=int(row[5]),
        merkle_root=str(row[6]),
        tsa_url=str(row[7 - 0]) if False else (str(row[8]) if row[8] is not None else None),
        tsa_token_b64=(base64.b64encode(tsa_token).decode("ascii")
                       if tsa_token else None),
    )


@router.get(
    "/anchors",
    response_model=MerkleAnchorListResponse,
    dependencies=[Depends(_require_admin_secret)],
)
async def list_merkle_anchors(
    org_id: str | None = Query(
        default=None,
        description="Filter to a single org_id. Empty returns all anchors.",
    ),
    limit: int = Query(
        default=100, ge=1, le=1000,
        description="Cap rows returned. Most recent first.",
    ),
) -> MerkleAnchorListResponse:
    """List recent Merkle batch anchors, most recent first.

    Bounded by ``limit`` (default 100, max 1000) so a single
    request cannot serialise unbounded rows.
    """
    sql_base = (
        "SELECT id, created_at, org_id, chain_seq_start, chain_seq_end, "
        "       leaf_count, merkle_root, tsa_url, tsa_token "
        "FROM audit_merkle_anchors "
    )
    params: dict[str, object] = {"limit": limit}
    if org_id:
        sql = sql_base + "WHERE org_id = :org_id ORDER BY id DESC LIMIT :limit"
        params["org_id"] = org_id
    else:
        sql = sql_base + "ORDER BY id DESC LIMIT :limit"

    async with get_db() as conn:
        rows = (await conn.execute(text(sql), params)).all()

    import base64

    entries = []
    for r in rows:
        tsa_token = r[8]
        if isinstance(tsa_token, memoryview):
            tsa_token = bytes(tsa_token)
        entries.append(MerkleAnchorEntry(
            id=int(r[0]),
            created_at=str(r[1]),
            org_id=str(r[2]),
            chain_seq_start=int(r[3]),
            chain_seq_end=int(r[4]),
            leaf_count=int(r[5]),
            merkle_root=str(r[6]),
            tsa_url=str(r[7]) if r[7] is not None else None,
            tsa_token_b64=(base64.b64encode(tsa_token).decode("ascii")
                           if tsa_token else None),
        ))

    return MerkleAnchorListResponse(anchors=entries, count=len(entries))


@router.get(
    "/proof/{chain_seq}",
    response_model=InclusionProofResponse,
    dependencies=[Depends(_require_admin_secret)],
)
async def get_inclusion_proof(chain_seq: int) -> InclusionProofResponse:
    """Return the inclusion proof for the audit_log row at
    ``chain_seq``.

    Locates the anchor covering ``chain_seq``, replays the tree
    over the anchor's full chain_seq range, and returns the
    bottom-up sibling list plus the matched ``merkle_root``. The
    caller can verify by replaying
    ``mcp_proxy.audit.merkle.verify_inclusion(leaf_bytes,
    proof_steps, root_bytes)``.

    404 when no anchor covers the chain_seq (either not anchored
    yet, or chain_seq predates the first anchor).
    """
    async with get_db() as conn:
        anchor = (await conn.execute(text(
            "SELECT id, chain_seq_start, chain_seq_end, leaf_count, "
            "       merkle_root "
            "FROM audit_merkle_anchors "
            "WHERE chain_seq_start <= :chain_seq "
            "  AND chain_seq_end >= :chain_seq "
            "ORDER BY id DESC LIMIT 1"
        ), {"chain_seq": chain_seq})).first()

        if anchor is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"no Merkle anchor covers chain_seq={chain_seq}; "
                    "either the row predates the first anchor or the "
                    "batch covering it has not yet been emitted by "
                    "the watcher (defaults to one batch every 5 min)"
                ),
            )

        anchor_id, start, end, leaf_count, root_hex = anchor
        start, end, leaf_count = int(start), int(end), int(leaf_count)
        anchor_id = int(anchor_id)
        root_hex = str(root_hex)

        # Pull every row_hash in the anchor's covered range, in the
        # SAME chain_seq order the watcher used at anchor time. The
        # leaf index relative to the batch is (chain_seq - start).
        rows = (await conn.execute(text(
            "SELECT chain_seq, row_hash FROM audit_log "
            "WHERE chain_seq IS NOT NULL "
            "  AND row_hash IS NOT NULL "
            "  AND chain_seq >= :start AND chain_seq <= :end "
            "ORDER BY chain_seq ASC"
        ), {"start": start, "end": end})).all()

    if len(rows) != leaf_count:
        # The anchored batch and the current audit_log range disagree
        # on leaf count. Either audit_log rows have been deleted
        # (forbidden by the F-A-402 append-only trigger but worth
        # surfacing) or chain_seq numbering is non-monotonic. Refuse
        # to compute a proof against a known-inconsistent input.
        logger.error(
            "merkle proof: anchor id=%d covers [%d, %d] (leaf_count=%d) "
            "but audit_log returned %d rows — chain integrity broken",
            anchor_id, start, end, leaf_count, len(rows),
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "audit_log row count disagrees with anchored leaf_count — "
                "chain integrity broken; refusing to emit proof"
            ),
        )

    leaves = [bytes.fromhex(str(r[1])) for r in rows]
    target_index = chain_seq - start
    leaf_hex = leaves[target_index].hex()
    proof_steps = inclusion_proof(leaves, target_index)

    return InclusionProofResponse(
        anchor_id=anchor_id,
        chain_seq=chain_seq,
        chain_seq_start=start,
        chain_seq_end=end,
        leaf_count=leaf_count,
        merkle_root=root_hex,
        leaf_hex=leaf_hex,
        proof=[
            InclusionProofStep(
                sibling_hex=sibling.hex(),
                position=position,
            )
            for sibling, position in proof_steps
        ],
    )
