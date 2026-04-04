from datetime import datetime
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Policy rules (conditions schema)
# ---------------------------------------------------------------------------

class SessionConditions(BaseModel):
    target_org_id: list[str] = Field(
        default_factory=list,
        description="[Legacy] Organizations allowed. Empty = any. Usato solo per policy org-specifiche.",
    )
    capabilities: list[str] = Field(
        default_factory=list,
        description="Permitted capabilities. Empty list = any.",
    )
    max_active_sessions: int | None = Field(
        default=None,
        description="Maximum number of concurrent active sessions for this org.",
    )


class SessionRule(BaseModel):
    effect: str = "allow"
    conditions: SessionConditions = Field(default_factory=SessionConditions)


class MessageConditions(BaseModel):
    max_payload_size_bytes: int | None = Field(
        default=None,
        description="Maximum size of the serialized JSON payload in bytes.",
    )
    required_fields: list[str] = Field(
        default_factory=list,
        description="Fields that must be present in the payload.",
    )
    blocked_fields: list[str] = Field(
        default_factory=list,
        description="Fields that must NOT be present in the payload.",
    )


class MessageRule(BaseModel):
    effect: str = "allow"
    conditions: MessageConditions = Field(default_factory=MessageConditions)


# ---------------------------------------------------------------------------
# Request / Response API
# ---------------------------------------------------------------------------

class PolicyCreateRequest(BaseModel):
    policy_id: str = Field(..., description="Unique policy ID, e.g. 'banca-a::session-v1'")
    org_id: str
    policy_type: str = Field(..., description="'session' | 'message'")
    rules: dict = Field(..., description="Rules object — see SessionRule or MessageRule")

    @field_validator("rules")
    @classmethod
    def limit_rules_size(cls, v: dict) -> dict:
        import json
        if len(json.dumps(v, default=str)) > 32768:
            raise ValueError("rules exceeds 32 KB limit")
        return v


class PolicyResponse(BaseModel):
    id: int
    policy_id: str
    org_id: str
    policy_type: str
    rules: dict
    is_active: bool
    created_at: datetime
