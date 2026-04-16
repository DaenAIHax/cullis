"""Pydantic schemas for the enrollment API."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EnrollmentStartRequest(BaseModel):
    """Initial request from a Connector to begin enrollment.

    The Connector generates its keypair locally, extracts the public key in
    PEM, and submits it along with the self-declared identity. The private
    key never leaves the caller's machine.
    """

    pubkey_pem: str = Field(..., min_length=100, max_length=8192)
    requester_name: str = Field(..., min_length=1, max_length=200)
    requester_email: str = Field(..., min_length=3, max_length=320)
    reason: str | None = Field(None, max_length=1000)

    @field_validator("requester_email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        # Lightweight check — admin does the real vetting during approval.
        # Keeps us off the ``email-validator`` dependency for a v1 MVP.
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            raise ValueError("requester_email is not a valid email address")
        return value
    device_info: str | None = Field(
        None,
        max_length=500,
        description=(
            "Free-form device/client info (OS, hostname, Connector version)."
            " Not used for auth — helps admin decide and appears in audit."
        ),
    )
    api_key_hash: str | None = Field(
        None,
        min_length=20,
        max_length=200,
        description=(
            "bcrypt hash of the X-API-Key the Connector generated locally."
            " The raw key never leaves the requester's machine. On approve,"
            " this hash is copied to internal_agents.api_key_hash so the"
            " Connector can authenticate to /v1/egress/* immediately."
            " Optional for backward compat — omitting it makes the server"
            " generate its own key during approval (legacy behaviour)."
        ),
    )


class EnrollmentStartResponse(BaseModel):
    session_id: str
    status: Literal["pending"]
    poll_url: str
    enroll_url: str
    poll_interval_s: int
    expires_at: str


class EnrollmentStatusResponse(BaseModel):
    session_id: str
    status: Literal["pending", "approved", "rejected", "expired"]
    # Populated only when status == "approved"
    agent_id: str | None = None
    cert_pem: str | None = None
    capabilities: list[str] | None = None
    # Populated only when status == "rejected"
    rejection_reason: str | None = None


class EnrollmentApproveRequest(BaseModel):
    """Admin decision to approve a pending enrollment."""

    agent_id: str = Field(..., min_length=1, max_length=200)
    capabilities: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)


class EnrollmentRejectRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class PendingEnrollmentSummary(BaseModel):
    """Single item in the admin list of pending enrollments."""

    session_id: str
    requester_name: str
    requester_email: str
    reason: str | None
    device_info: str | None
    pubkey_fingerprint: str
    created_at: str
    expires_at: str
