"""MCP-style tool handlers for the KYC Screener.

Each handler is the demo equivalent of an MCP tool exposed by a downstream
identity provider (Onfido/Veriff), sanctions list provider (Refinitiv,
Dow Jones), corporate registry (OpenCorporates) and the internal compliance
escalation queue. In production these would be reverse-proxied by Mastio.

Every handler:

1. takes the canonical (principal, gate, audit, args) signature so the
   capability gate fires *before* the tool runs;
2. records the tool call AND the tool result into the audit chain;
3. returns a plain dict that the LLM consumes as the tool message content.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable

from shared.audit_hooks import AuditChain
from shared.capability_gate import CapabilityDenied, CapabilityGate, Principal
from shared.test_fixtures import (
    KYC_DOCUMENTS,
    PEP_LIST,
    SANCTIONS_LIST,
)

# JSON schema for each tool, in the format LiteLLM / Anthropic / OpenAI all
# accept (OpenAI-style tool envelope). Used by the agent loop when calling
# the LLM.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "verify_identity",
            "description": "Verify an identity document against the (mocked) Onfido / Veriff provider.",
            "parameters": {
                "type": "object",
                "properties": {
                    "document_id": {"type": "string"},
                },
                "required": ["document_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "screen_sanctions",
            "description": "Screen a (family_name, given_name, dob) tuple against the (mocked) OFAC + EU consolidated lists.",
            "parameters": {
                "type": "object",
                "properties": {
                    "family_name": {"type": "string"},
                    "given_name": {"type": "string"},
                    "dob": {"type": "string", "description": "ISO date YYYY-MM-DD"},
                },
                "required": ["family_name", "dob"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_beneficial_owners",
            "description": "Look up beneficial owners for a corporate entity (mock OpenCorporates).",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_name": {"type": "string"},
                },
                "required": ["entity_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "escalate_to_compliance",
            "description": "Hand the case to a human compliance officer queue. Always required when score >= 30 or any sanctions/PEP hit.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "reason": {"type": "string"},
                    "score": {"type": "integer"},
                },
                "required": ["case_id", "reason"],
            },
        },
    },
]


def _document_hash(document_id: str) -> str:
    return hashlib.sha256(document_id.encode("utf-8")).hexdigest()


def verify_identity(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(principal, capability="kyc.read", context={"tool": "verify_identity"})
    audit.append("tool_call", {"tool": "verify_identity", "args": args})

    doc_id = args["document_id"]
    doc = KYC_DOCUMENTS.get(doc_id)
    if doc is None:
        result: dict[str, Any] = {"ok": False, "reason": "document_not_found"}
    else:
        result = {
            "ok": True,
            "doc_id": doc_id,
            "document_hash": _document_hash(doc_id),
            "verified": doc["image_quality"] > 0.85,
            "image_quality": doc["image_quality"],
            "given_name": doc["given_name"],
            "family_name": doc["family_name"],
            "dob": doc["dob"],
            "country": doc["country"],
        }
    audit.append("tool_result", {"tool": "verify_identity", "args": args, "result": result})
    return result


def screen_sanctions(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(principal, capability="kyc.read", context={"tool": "screen_sanctions"})
    audit.append("tool_call", {"tool": "screen_sanctions", "args": args})

    family = args.get("family_name", "")
    dob = args.get("dob", "")
    hit = None
    for entry in SANCTIONS_LIST:
        if entry["family_name"] == family and entry["dob"] == dob:
            hit = entry
            break
    pep_hit = None
    for entry in PEP_LIST:
        if entry["family_name"] == family and entry["dob"] == dob:
            pep_hit = entry
            break
    result = {
        "hit": hit is not None,
        "list_name": hit["list_name"] if hit else None,
        "reason": hit["reason"] if hit else None,
        "pep_hit": pep_hit is not None,
        "pep_role": pep_hit["role"] if pep_hit else None,
    }
    audit.append("tool_result", {"tool": "screen_sanctions", "args": args, "result": result})
    return result


def query_beneficial_owners(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(principal, capability="kyc.read", context={"tool": "query_beneficial_owners"})
    audit.append("tool_call", {"tool": "query_beneficial_owners", "args": args})
    # Demo always returns a single synthetic UBO with 100% ownership.
    result = {
        "entity_name": args.get("entity_name", ""),
        "ultimate_beneficial_owners": [
            {
                "name": "Synthetic-UBO-Test",
                "ownership_percent": 100.0,
                "country": "IT",
            }
        ],
    }
    audit.append(
        "tool_result", {"tool": "query_beneficial_owners", "args": args, "result": result}
    )
    return result


def escalate_to_compliance(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    # Escalation REQUIRES kyc.escalate, which is a fail-closed gate. If a
    # principal has kyc.read+submit but not kyc.escalate, the agent cannot
    # park the case with a human, which is itself a compliance violation.
    gate.require(principal, capability="kyc.escalate", context={"tool": "escalate_to_compliance"})
    audit.append("tool_call", {"tool": "escalate_to_compliance", "args": args})
    result = {
        "case_id": args["case_id"],
        "status": "ESCALATED",
        "queue": "human_compliance_review",
        "reason": args.get("reason", "unspecified"),
        "score": args.get("score"),
    }
    audit.append(
        "tool_result", {"tool": "escalate_to_compliance", "args": args, "result": result}
    )
    return result


HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "verify_identity": verify_identity,
    "screen_sanctions": screen_sanctions,
    "query_beneficial_owners": query_beneficial_owners,
    "escalate_to_compliance": escalate_to_compliance,
}


def dispatch(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    """Look up a handler and run it. Capability errors are surfaced as a
    structured tool result so the LLM can see them and (correctly) escalate."""

    handler = HANDLERS.get(tool_name)
    if handler is None:
        result = {"ok": False, "error": "unknown_tool", "tool": tool_name}
        audit.append("tool_error", {"tool": tool_name, "args": arguments, "error": result})
        return result
    try:
        return handler(arguments, principal=principal, gate=gate, audit=audit)
    except CapabilityDenied as exc:
        # Audit was already appended by the gate itself. We propagate as
        # a structured result so the LLM can react inside the conversation.
        return {
            "ok": False,
            "error": "capability_denied",
            "capability": exc.capability,
            "reason": exc.reason,
        }
