"""MCP-style tool handlers for the DORA Vendor/TPA Compliance Reporter.

This is the cross-organisation A2A agent in the demo set. The
`submit_to_auditor_org` handler is the key trust boundary: it dual-writes
the entry to the caller's Mastio audit chain AND the auditor's Mastio
audit chain (over the Cullis Court federation). In the demo this is a
mock; with a running `./stack/demo.sh` (Court + 2 Mastios) it would be
the real federated A2A path.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Callable

from shared.audit_hooks import AuditChain, AuditEntry
from shared.capability_gate import CapabilityDenied, CapabilityGate, Principal
from shared.test_fixtures import (
    FEDERATED_AUDITOR_ORGS,
    VENDOR_ASSESSMENTS,
    VENDOR_REGISTRY,
)

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_third_party_vendors",
            "description": "List ICT third-party vendors from the Mastio vendor registry.",
            "parameters": {
                "type": "object",
                "properties": {
                    "criticality_filter": {
                        "type": "string",
                        "description": "Optional filter (CRITICAL|IMPORTANT|NON_IMPORTANT).",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_vendor_assessment",
            "description": "Pull the latest risk assessment for a vendor.",
            "parameters": {
                "type": "object",
                "properties": {"vendor_id": {"type": "string"}},
                "required": ["vendor_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "draft_dora_register_entry",
            "description": "Produce a DORA Art. 28 register entry from a vendor assessment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vendor_id": {"type": "string"},
                    "criticality": {"type": "string"},
                    "rto_minutes": {"type": "integer"},
                    "exit_strategy_documented": {"type": "boolean"},
                },
                "required": ["vendor_id", "criticality"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_to_auditor_org",
            "description": "Cross-organisation submit of a drafted entry via Cullis Court federation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entry_hash": {"type": "string"},
                    "vendor_id": {"type": "string"},
                    "auditor_org_id": {"type": "string"},
                },
                "required": ["entry_hash", "vendor_id", "auditor_org_id"],
            },
        },
    },
]


def list_third_party_vendors(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(principal, capability="dora.read", context={"tool": "list_third_party_vendors"})
    audit.append("tool_call", {"tool": "list_third_party_vendors", "args": args})
    crit_filter = args.get("criticality_filter")
    rows = [v for v in VENDOR_REGISTRY if crit_filter is None or v["criticality"] == crit_filter]
    result = {"count": len(rows), "vendors": rows}
    audit.append(
        "tool_result", {"tool": "list_third_party_vendors", "args": args, "result": result}
    )
    return result


def query_vendor_assessment(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(principal, capability="dora.read", context={"tool": "query_vendor_assessment"})
    audit.append("tool_call", {"tool": "query_vendor_assessment", "args": args})
    vendor_id = args["vendor_id"]
    assessment = VENDOR_ASSESSMENTS.get(vendor_id)
    if assessment is None:
        result: dict[str, Any] = {"ok": False, "error": "assessment_not_found", "vendor_id": vendor_id}
    else:
        result = {"ok": True, "vendor_id": vendor_id, "assessment": assessment}
    audit.append(
        "tool_result", {"tool": "query_vendor_assessment", "args": args, "result": result}
    )
    return result


def _entry_hash(entry: dict[str, Any]) -> str:
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _vendor_was_assessed(audit: AuditChain, vendor_id: str) -> bool:
    for entry in audit.entries:
        if entry.event_type != "tool_result":
            continue
        if entry.payload.get("tool") != "query_vendor_assessment":
            continue
        result = entry.payload.get("result") or {}
        if result.get("ok") and result.get("vendor_id") == vendor_id:
            return True
    return False


def draft_dora_register_entry(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(
        principal,
        capability="dora.draft_report",
        context={"tool": "draft_dora_register_entry", "vendor_id": args.get("vendor_id")},
    )
    audit.append("tool_call", {"tool": "draft_dora_register_entry", "args": args})

    vendor_id = args["vendor_id"]
    if not _vendor_was_assessed(audit, vendor_id):
        result: dict[str, Any] = {
            "ok": False,
            "error": "draft_requires_prior_assessment",
            "vendor_id": vendor_id,
        }
        audit.append(
            "tool_result",
            {"tool": "draft_dora_register_entry", "args": args, "result": result},
        )
        return result

    entry = {
        "schema": "DORA_Art28_Register_v1",
        "vendor_id": vendor_id,
        "criticality": args["criticality"],
        "rto_minutes": args.get("rto_minutes"),
        "exit_strategy_documented": args.get("exit_strategy_documented"),
        "drafted_by_principal": principal.principal_id,
        "drafted_by_org": principal.org_id,
    }
    result = {
        "ok": True,
        "vendor_id": vendor_id,
        "entry_hash": _entry_hash(entry),
        "entry": entry,
    }
    audit.append(
        "tool_result",
        {"tool": "draft_dora_register_entry", "args": args, "result": result},
    )
    return result


def submit_to_auditor_org(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    # The gate enforces the `compliance_officer` role; the handler additionally
    # enforces the auditor-org federation enrolment.
    gate.require(
        principal,
        capability="dora.cross_org_submit",
        context={
            "tool": "submit_to_auditor_org",
            "auditor_org_id": args.get("auditor_org_id"),
        },
    )
    audit.append("tool_call", {"tool": "submit_to_auditor_org", "args": args})

    auditor_org_id = args["auditor_org_id"]
    auditor = FEDERATED_AUDITOR_ORGS.get(auditor_org_id)
    if auditor is None:
        result: dict[str, Any] = {
            "ok": False,
            "error": "auditor_org_unknown",
            "auditor_org_id": auditor_org_id,
        }
        audit.append(
            "tool_result",
            {"tool": "submit_to_auditor_org", "args": args, "result": result},
        )
        return result
    if not auditor.get("enrolled"):
        result = {
            "ok": False,
            "error": "auditor_org_not_federated",
            "auditor_org_id": auditor_org_id,
        }
        audit.append(
            "tool_result",
            {"tool": "submit_to_auditor_org", "args": args, "result": result},
        )
        return result

    # Mocked cross-org dual-write. In a real Cullis stack this is a sealed
    # A2A envelope through the Court federation, with each side appending
    # a `cross_org_evidence` entry to its own Mastio audit chain.
    transmission_id = f"a2a_{uuid.uuid4().hex[:12]}"
    audit.append(
        "cross_org_evidence",
        {
            "direction": "outbound",
            "transmission_id": transmission_id,
            "entry_hash": args["entry_hash"],
            "vendor_id": args["vendor_id"],
            "caller_org": principal.org_id,
            "auditor_org_id": auditor_org_id,
            "court_anchor": auditor["court_anchor"],
        },
    )
    # Mocked acknowledgement from the auditor org's Mastio.
    audit.append(
        "cross_org_evidence",
        {
            "direction": "inbound_ack",
            "transmission_id": transmission_id,
            "entry_hash": args["entry_hash"],
            "vendor_id": args["vendor_id"],
            "auditor_org_id": auditor_org_id,
            "status": "accepted",
        },
    )
    result = {
        "ok": True,
        "transmission_id": transmission_id,
        "vendor_id": args["vendor_id"],
        "auditor_org_id": auditor_org_id,
        "dual_write_confirmed": True,
    }
    audit.append(
        "tool_result", {"tool": "submit_to_auditor_org", "args": args, "result": result}
    )
    return result


HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "list_third_party_vendors": list_third_party_vendors,
    "query_vendor_assessment": query_vendor_assessment,
    "draft_dora_register_entry": draft_dora_register_entry,
    "submit_to_auditor_org": submit_to_auditor_org,
}


def dispatch(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    handler = HANDLERS.get(tool_name)
    if handler is None:
        result = {"ok": False, "error": "unknown_tool", "tool": tool_name}
        audit.append("tool_error", {"tool": tool_name, "args": arguments, "error": result})
        return result
    try:
        return handler(arguments, principal=principal, gate=gate, audit=audit)
    except CapabilityDenied as exc:
        return {
            "ok": False,
            "error": "capability_denied",
            "capability": exc.capability,
            "reason": exc.reason,
        }
