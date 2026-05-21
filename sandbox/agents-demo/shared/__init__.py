"""Cullis governance primitives shared across the 3 reference demo agents.

This package is intentionally self-contained and does NOT import from the
Cullis core (`app/`, `mcp_proxy/`, `cullis_sdk/`). It demonstrates the
*primitives* (per-agent identity, capability gate, hash-chained audit log)
in a form that mirrors what the production Cullis stack enforces, without
coupling the demo to a running Mastio + Court deployment.

Mapping to production primitives:

- `audit_hooks.AuditChain`     -> Mastio `app/db/audit_log.py` append-only
                                   hash-chained log + ADR-033 TSA anchor.
- `capability_gate.*`          -> Mastio PDP (`mcp_proxy/policy/`) +
                                   per-agent capability binding enforced at
                                   MCP tool-call time (`mcp_proxy/tools/executor.py`).
- `llm_client.*`               -> Mastio embedded LiteLLM gateway (ADR-017).
- `test_fixtures`              -> synthetic mock data only. No real PII.
"""

from .audit_hooks import (
    AuditChain,
    AuditEntry,
    AuditVerificationError,
    audit_path_for,
)
from .capability_gate import (
    CapabilityDenied,
    CapabilityGate,
    Principal,
)
from .llm_client import (
    LLMClient,
    LLMResponse,
    LiteLLMClient,
    MockLLMClient,
    ToolCall,
    default_client,
    make_tool_call,
)

__all__ = [
    "AuditChain",
    "AuditEntry",
    "AuditVerificationError",
    "audit_path_for",
    "CapabilityDenied",
    "CapabilityGate",
    "Principal",
    "LLMClient",
    "LLMResponse",
    "LiteLLMClient",
    "MockLLMClient",
    "ToolCall",
    "default_client",
    "make_tool_call",
]
