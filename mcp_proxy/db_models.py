"""
MCP Proxy — SQLAlchemy table definitions.

Schema lives here, CRUD stays in db.py. Metadata is separate from the broker's
Base (app/db/database.py) on purpose: proxy and broker can diverge freely,
no accidental cross-imports.

Tables grouped in two families:
  - Legacy (Phase 0): internal_agents, audit_log, proxy_config. Already
    populated on live deployments.
  - Local-* (Phase 1 ADR-001): local_agents, local_sessions, local_messages,
    local_policies, local_audit. Created empty here; wiring lands Phase 4.

Column types picked to render identically on SQLite and PostgreSQL. Integer
primary keys use plain Integer + primary_key=True — SQLAlchemy picks SERIAL
on Postgres and INTEGER on SQLite.
"""
from sqlalchemy import (
    Column,
    Index,
    Integer,
    MetaData,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base

metadata = MetaData()
Base = declarative_base(metadata=metadata)


# ── Legacy tables (schema frozen by migration 0001) ──────────────────────────


class InternalAgent(Base):
    __tablename__ = "internal_agents"

    agent_id = Column(Text, primary_key=True)
    display_name = Column(Text, nullable=False)
    capabilities = Column(Text, nullable=False, default="[]")  # JSON array
    api_key_hash = Column(Text, nullable=False)
    cert_pem = Column(Text, nullable=True)
    created_at = Column(Text, nullable=False)
    is_active = Column(Integer, nullable=False, default=1)


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Text, nullable=False)
    agent_id = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    tool_name = Column(Text, nullable=True)
    status = Column(Text, nullable=False)
    detail = Column(Text, nullable=True)
    request_id = Column(Text, nullable=True)
    duration_ms = Column(String, nullable=True)  # REAL in SQLite — stored as text-safe numeric

    __table_args__ = (
        Index("idx_audit_log_agent_id", "agent_id"),
        Index("idx_audit_log_timestamp", "timestamp"),
        Index("idx_audit_log_request_id", "request_id"),
    )


class ProxyConfig(Base):
    __tablename__ = "proxy_config"

    key = Column(Text, primary_key=True)
    value = Column(Text, nullable=False)


# ── Local-* tables (ADR-001 Phase 1, unused until Phase 4) ───────────────────
#
# Minimal forward-compatible columns. Each table exists so that Phase 4 work
# can assume the schema is already deployed, without requiring another
# migration round-trip on live proxies.


class LocalAgent(Base):
    """Agents with scope=local. Owned by the proxy, broker never sees them."""
    __tablename__ = "local_agents"

    agent_id = Column(Text, primary_key=True)
    display_name = Column(Text, nullable=False)
    capabilities = Column(Text, nullable=False, default="[]")  # JSON array
    cert_pem = Column(Text, nullable=True)
    api_key_hash = Column(Text, nullable=True)
    scope = Column(Text, nullable=False, default="local")  # reserved: "local" | "federated-cache"
    created_at = Column(Text, nullable=False)
    is_active = Column(Integer, nullable=False, default=1)


class LocalSession(Base):
    """Intra-org sessions. Phase 4 wires routing; Phase 1 schema-only."""
    __tablename__ = "local_sessions"

    session_id = Column(Text, primary_key=True)
    initiator_agent_id = Column(Text, nullable=False)
    responder_agent_id = Column(Text, nullable=False)
    status = Column(Text, nullable=False)  # pending | active | closed
    created_at = Column(Text, nullable=False)
    last_activity_at = Column(Text, nullable=True)
    close_reason = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_local_sessions_initiator", "initiator_agent_id"),
        Index("idx_local_sessions_responder", "responder_agent_id"),
        Index("idx_local_sessions_status", "status"),
    )


class LocalMessage(Base):
    """M3-twin queue for intra-org messages (Phase 4)."""
    __tablename__ = "local_messages"

    msg_id = Column(Text, primary_key=True)
    session_id = Column(Text, nullable=False)
    sender_agent_id = Column(Text, nullable=False)
    recipient_agent_id = Column(Text, nullable=False)
    payload_ciphertext = Column(Text, nullable=False)
    idempotency_key = Column(Text, nullable=True)
    status = Column(Text, nullable=False)  # queued | delivered | expired
    enqueued_at = Column(Text, nullable=False)
    delivered_at = Column(Text, nullable=True)
    expires_at = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_local_messages_session", "session_id"),
        Index("idx_local_messages_recipient_status", "recipient_agent_id", "status"),
        Index("idx_local_messages_idempotency", "idempotency_key"),
    )


class LocalPolicy(Base):
    """Local-only policy records (intra-org scope)."""
    __tablename__ = "local_policies"

    policy_id = Column(Text, primary_key=True)
    name = Column(Text, nullable=False)
    scope = Column(Text, nullable=False, default="intra")  # reserved: "intra" | "egress"
    rules_json = Column(Text, nullable=False, default="{}")
    enabled = Column(Integer, nullable=False, default=1)
    created_at = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)


class LocalAudit(Base):
    """Append-only, hash-chained intra-org audit log.

    Hash chain (computed Phase 4): row_hash = SHA-256(prev_hash || canonical_json(row)).
    Phase 1 defines the columns; chain enforcement happens later with a DB
    trigger / application-level guard.
    """
    __tablename__ = "local_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Text, nullable=False)
    actor_agent_id = Column(Text, nullable=True)
    action = Column(Text, nullable=False)
    subject = Column(Text, nullable=True)
    detail_json = Column(Text, nullable=True)
    prev_hash = Column(Text, nullable=True)
    row_hash = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_local_audit_timestamp", "timestamp"),
        Index("idx_local_audit_actor", "actor_agent_id"),
    )
