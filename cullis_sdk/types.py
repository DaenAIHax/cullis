"""
Data types for Cullis SDK API responses.

Uses stdlib dataclasses (no Pydantic dependency).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentInfo:
    """Agent record from the registry."""
    agent_id: str
    org_id: str
    display_name: str
    capabilities: list[str] = field(default_factory=list)
    description: str | None = None
    status: str | None = None
    agent_uri: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> AgentInfo:
        return cls(
            agent_id=d["agent_id"],
            org_id=d["org_id"],
            display_name=d.get("display_name", ""),
            capabilities=d.get("capabilities", []),
            description=d.get("description"),
            status=d.get("status"),
            agent_uri=d.get("agent_uri"),
        )


@dataclass
class SessionInfo:
    """Broker session."""
    session_id: str
    status: str  # "pending" | "active" | "closed" | "denied"
    initiator_agent_id: str
    target_agent_id: str
    initiator_org_id: str = ""
    target_org_id: str = ""
    created_at: str = ""
    expires_at: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> SessionInfo:
        return cls(
            session_id=d["session_id"],
            status=d["status"],
            initiator_agent_id=d["initiator_agent_id"],
            target_agent_id=d["target_agent_id"],
            initiator_org_id=d.get("initiator_org_id", ""),
            target_org_id=d.get("target_org_id", ""),
            created_at=d.get("created_at", ""),
            expires_at=d.get("expires_at"),
        )


@dataclass
class InboxMessage:
    """Message received from a session inbox."""
    seq: int
    sender_agent_id: str
    payload: dict[str, Any]
    nonce: str = ""
    timestamp: str = ""
    signature: str | None = None
    client_seq: int | None = None

    @classmethod
    def from_dict(cls, d: dict) -> InboxMessage:
        return cls(
            seq=d.get("seq", 0),
            sender_agent_id=d.get("sender_agent_id", ""),
            payload=d.get("payload", {}),
            nonce=d.get("nonce", ""),
            timestamp=d.get("timestamp", ""),
            signature=d.get("signature"),
            client_seq=d.get("client_seq"),
        )


@dataclass
class RfqQuote:
    """A quote submitted in response to an RFQ."""
    agent_id: str
    org_id: str
    payload: dict[str, Any]
    submitted_at: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> RfqQuote:
        return cls(
            agent_id=d.get("agent_id", ""),
            org_id=d.get("org_id", ""),
            payload=d.get("payload", {}),
            submitted_at=d.get("submitted_at", ""),
        )


@dataclass
class RfqResult:
    """Result of a Request For Quote."""
    rfq_id: str
    status: str
    matched_agents: list[str] = field(default_factory=list)
    quotes: list[RfqQuote] = field(default_factory=list)
    created_at: str = ""
    closed_at: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> RfqResult:
        return cls(
            rfq_id=d["rfq_id"],
            status=d["status"],
            matched_agents=d.get("matched_agents", []),
            quotes=[RfqQuote.from_dict(q) for q in d.get("quotes", [])],
            created_at=d.get("created_at", ""),
            closed_at=d.get("closed_at"),
        )
