"""
Transaction tokens — single-use, short-lived tokens that authorize a specific
operation after human approval via the dashboard.

Flow:
  1. Human approves a quote in the dashboard
  2. Broker issues a transaction token (30-60s TTL, bound to action + payload hash)
  3. Agent uses the token to send a message in a 1:1 session
  4. Broker validates and consumes the token (single-use)
  5. Audit log records the full chain: RFQ → approval → execution
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.auth.models import TokenPayload

import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.transaction_db import TransactionTokenRecord
from app.config import get_settings
from app.spiffe import internal_id_to_spiffe

_log = logging.getLogger("agent_trust")


async def create_transaction_token(
    db: AsyncSession,
    *,
    agent_id: str,
    org_id: str,
    txn_type: str,
    resource_id: str | None = None,
    payload_hash: str,
    approved_by: str,
    parent_jti: str | None = None,
    target_agent_id: str | None = None,
    rfq_id: str | None = None,
    ttl_seconds: int = 60,
) -> tuple[str, TransactionTokenRecord]:
    """Issue a transaction token JWT and persist the record for single-use enforcement."""
    settings = get_settings()

    from app.auth.jwt import _get_broker_keys
    priv_pem, pub_pem = await _get_broker_keys(settings)
    from app.auth.jwks import compute_kid
    kid = compute_kid(pub_pem)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)
    jti = str(uuid.uuid4())

    spiffe_id = internal_id_to_spiffe(agent_id, settings.trust_domain)

    claims = {
        "iss": "cullis-broker",
        "aud": "cullis",
        "sub": spiffe_id,
        "agent_id": agent_id,
        "org": org_id,
        "scope": [],
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": jti,
        "cnf": {},  # no DPoP binding for transaction tokens
        "token_type": "transaction",
        "act": {"sub": approved_by},
        "txn_type": txn_type,
        "resource_id": resource_id,
        "payload_hash": payload_hash,
        "parent_jti": parent_jti,
    }

    token = jwt.encode(claims, priv_pem, algorithm="RS256", headers={"kid": kid})

    record = TransactionTokenRecord(
        jti=jti,
        txn_type=txn_type,
        agent_id=agent_id,
        org_id=org_id,
        resource_id=resource_id,
        payload_hash=payload_hash,
        approved_by=approved_by,
        parent_jti=parent_jti,
        rfq_id=rfq_id,
        target_agent_id=target_agent_id,
        status="active",
        created_at=now,
        expires_at=expires_at,
    )
    db.add(record)
    await db.commit()

    return token, record


async def validate_and_consume_transaction_token(
    db: AsyncSession,
    token_payload: "TokenPayload",
    actual_payload_hash: str,
) -> TransactionTokenRecord:
    """Validate a transaction token and mark it as consumed (single-use).

    Raises ValueError if validation fails.
    """
    if token_payload.token_type != "transaction":
        raise ValueError("Not a transaction token")

    from sqlalchemy import update as sa_update

    now = datetime.now(timezone.utc)

    # Atomic consume: UPDATE ... WHERE status='active' RETURNING *
    # This prevents TOCTOU race: only one concurrent request succeeds.
    stmt = (
        sa_update(TransactionTokenRecord)
        .where(
            TransactionTokenRecord.jti == token_payload.jti,
            TransactionTokenRecord.status == "active",
        )
        .values(status="consumed", consumed_at=now)
        .returning(TransactionTokenRecord)
    )
    result = await db.execute(stmt)
    record = result.scalar_one_or_none()

    if not record:
        # Either not found or already consumed/expired — check which
        check = await db.execute(
            select(TransactionTokenRecord).where(
                TransactionTokenRecord.jti == token_payload.jti
            )
        )
        existing = check.scalar_one_or_none()
        if not existing:
            raise ValueError("Transaction token not found")
        raise ValueError(f"Transaction token already {existing.status}")

    if now > record.expires_at:
        record.status = "expired"
        await db.commit()
        raise ValueError("Transaction token expired")

    if record.payload_hash != actual_payload_hash:
        # Rollback consumption — payload doesn't match
        record.status = "active"
        record.consumed_at = None
        await db.commit()
        raise ValueError("Payload hash mismatch — message does not match approved payload")

    await db.commit()
    return record


def compute_payload_hash(payload: dict) -> str:
    """Compute SHA-256 hash of a canonical JSON payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
