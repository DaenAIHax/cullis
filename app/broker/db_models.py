"""
SQLAlchemy models for session, message, and RFQ persistence.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, DateTime, Integer, UniqueConstraint

from app.db.database import Base


class SessionRecord(Base):
    __tablename__ = "sessions"

    session_id          = Column(String(128), primary_key=True)
    initiator_agent_id  = Column(String(128), nullable=False)
    initiator_org_id    = Column(String(128), nullable=False)
    target_agent_id     = Column(String(128), nullable=False)
    target_org_id       = Column(String(128), nullable=False)
    status              = Column(String(16),  nullable=False, index=True)
    requested_capabilities = Column(Text, nullable=False)   # JSON list
    created_at          = Column(DateTime(timezone=True), nullable=False)
    expires_at          = Column(DateTime(timezone=True), nullable=True)
    closed_at           = Column(DateTime(timezone=True), nullable=True)
    last_activity_at    = Column(DateTime(timezone=True), nullable=True)
    close_reason        = Column(String(32),  nullable=True)


class SessionMessageRecord(Base):
    __tablename__ = "session_messages"
    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_session_seq"),
    )

    id              = Column(Integer, primary_key=True, autoincrement=True)
    session_id      = Column(String(128), nullable=False, index=True)
    seq             = Column(Integer, nullable=False)
    sender_agent_id = Column(String(128), nullable=False)
    payload         = Column(Text, nullable=False)          # JSON dict
    nonce           = Column(String(128), nullable=False, unique=True)
    timestamp       = Column(DateTime(timezone=True), nullable=False,
                             default=lambda: datetime.now(timezone.utc))
    signature       = Column(Text, nullable=True)   # base64 RSA-PKCS1v15-SHA256
    client_seq      = Column(Integer, nullable=True)


class RfqRecord(Base):
    __tablename__ = "rfq_requests"

    rfq_id              = Column(String(128), primary_key=True)
    initiator_agent_id  = Column(String(256), nullable=False, index=True)
    initiator_org_id    = Column(String(128), nullable=False, index=True)
    capability_filter   = Column(Text, nullable=False)              # JSON list
    payload_json        = Column(Text, nullable=False)              # The RFQ payload
    status              = Column(String(16), nullable=False, index=True)  # open | closed | timeout
    timeout_seconds     = Column(Integer, nullable=False, default=30)
    matched_agents_json = Column(Text, nullable=False, default="[]")  # JSON list of agent_ids
    created_at          = Column(DateTime(timezone=True), nullable=False)
    closed_at           = Column(DateTime(timezone=True), nullable=True)


class RfqResponseRecord(Base):
    __tablename__ = "rfq_responses"
    __table_args__ = (
        UniqueConstraint("rfq_id", "responder_agent_id", name="uq_rfq_responder"),
    )

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    rfq_id              = Column(String(128), nullable=False, index=True)
    responder_agent_id  = Column(String(256), nullable=False)
    responder_org_id    = Column(String(128), nullable=False)
    response_payload    = Column(Text, nullable=False)              # JSON
    received_at         = Column(DateTime(timezone=True), nullable=False)
