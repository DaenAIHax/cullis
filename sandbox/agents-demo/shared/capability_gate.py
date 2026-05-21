"""Capability gate evaluator for the reference demo agents.

Mirrors the Mastio PDP (`mcp_proxy/policy/`) + per-agent capability binding
defined in `mcp_proxy/registry/` and enforced at MCP tool-call time by
`mcp_proxy/tools/executor.py`.

Two layers of gating:

1. **Coarse** -- `Principal.capabilities` is a set of named capabilities
   declared at enrollment (e.g. `kyc.read`, `kyc.submit`, `dora.draft_report`).
   `CapabilityGate.require()` does a fail-closed check.

2. **Fine** -- scope-bound capabilities like `desk:<desk_name>` (Pitchbook
   Chinese Wall) or `role:compliance_officer` (DORA cross-org submit).
   These are evaluated by helpers on the `Principal` object.

Tool-handler convention: the first thing a handler MUST do is call
`gate.require(principal, capability=..., context=...)`. If the gate denies,
it raises `CapabilityDenied` AND appends a `capability_denied` audit entry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .audit_hooks import AuditChain

_log = logging.getLogger(__name__)


class CapabilityDenied(Exception):
    """Raised when the capability gate denies a tool invocation."""

    def __init__(self, capability: str, principal_id: str, reason: str) -> None:
        super().__init__(f"capability denied: {capability} for {principal_id} ({reason})")
        self.capability = capability
        self.principal_id = principal_id
        self.reason = reason


@dataclass(frozen=True)
class Principal:
    """Authenticated identity invoking the agent.

    Maps 1:1 to the typed principals introduced by the Mastio MCP capability
    gate (PR #730): `agent`, `user`, `workload`. For the demo we use `user`
    for U2A flows and `agent` for A2A flows; the gate logic is identical.
    """

    principal_id: str
    principal_type: str  # "user" | "agent" | "workload"
    org_id: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    scopes: dict[str, str] = field(default_factory=dict)
    # e.g. {"desk": "industrials"} for Pitchbook Chinese Wall.

    def has(self, capability: str) -> bool:
        return capability in self.capabilities

    def in_scope(self, scope_name: str, scope_value: str) -> bool:
        return self.scopes.get(scope_name) == scope_value

    def has_role(self, role: str) -> bool:
        return role in self.roles


class CapabilityGate:
    """Fail-closed evaluator backed by a YAML capability definition file."""

    def __init__(self, definitions: dict[str, Any], *, audit: AuditChain | None = None) -> None:
        self._definitions = definitions
        self._audit = audit

    @classmethod
    def from_yaml(cls, path: Path, *, audit: AuditChain | None = None) -> CapabilityGate:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict) or "capabilities" not in data:
            raise ValueError(f"invalid capability definition at {path}")
        return cls(data, audit=audit)

    @property
    def declared_capabilities(self) -> set[str]:
        return set(self._definitions.get("capabilities", {}).keys())

    def require(
        self,
        principal: Principal,
        *,
        capability: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Fail-closed coarse + fine check. Raises `CapabilityDenied` on deny."""

        ctx = context or {}
        cap_def = self._definitions.get("capabilities", {}).get(capability)
        if cap_def is None:
            self._deny(principal, capability, "capability_not_declared", ctx)
            raise CapabilityDenied(capability, principal.principal_id, "capability_not_declared")

        # Coarse check.
        if not principal.has(capability):
            self._deny(principal, capability, "principal_lacks_capability", ctx)
            raise CapabilityDenied(
                capability, principal.principal_id, "principal_lacks_capability"
            )

        # Fine check: required_roles (ALL of).
        required_roles = cap_def.get("required_roles", [])
        for role in required_roles:
            if not principal.has_role(role):
                self._deny(principal, capability, f"missing_role:{role}", ctx)
                raise CapabilityDenied(
                    capability, principal.principal_id, f"missing_role:{role}"
                )

        # Fine check: required_scopes (each scope must match either a fixed
        # value or a ctx field).
        required_scopes = cap_def.get("required_scopes", {})
        for scope_name, scope_spec in required_scopes.items():
            expected = scope_spec
            if isinstance(scope_spec, dict) and "from_context" in scope_spec:
                expected = ctx.get(scope_spec["from_context"])
            if expected is None or not principal.in_scope(scope_name, expected):
                self._deny(principal, capability, f"scope_mismatch:{scope_name}", ctx)
                raise CapabilityDenied(
                    capability, principal.principal_id, f"scope_mismatch:{scope_name}"
                )

        # Allow.
        if self._audit is not None:
            self._audit.append(
                "capability_granted",
                {
                    "capability": capability,
                    "principal_id": principal.principal_id,
                    "principal_type": principal.principal_type,
                    "context": ctx,
                },
            )

    def _deny(
        self,
        principal: Principal,
        capability: str,
        reason: str,
        context: dict[str, Any],
    ) -> None:
        _log.warning(
            "capability_denied principal=%s capability=%s reason=%s",
            principal.principal_id,
            capability,
            reason,
        )
        if self._audit is not None:
            self._audit.append(
                "capability_denied",
                {
                    "capability": capability,
                    "principal_id": principal.principal_id,
                    "principal_type": principal.principal_type,
                    "reason": reason,
                    "context": context,
                },
            )
