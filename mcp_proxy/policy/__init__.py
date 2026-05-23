"""Cullis Mastio policy engine surface.

Two layers, evaluated in order on every PDP-style decision call
(``/pdp/policy``, ``/v1/policy/tool-call``,
``/v1/data/cullis/policy/*``):

  1. **Rego engine** (:mod:`mcp_proxy.policy.rego_engine`) — when the
     operator has saved a Rego policy on the dashboard Policies page,
     the compiled WASM bundle is consulted first. A
     ``{"decision": "allow"|"deny", "reason": ...}`` returned by Rego
     short-circuits the legacy allowlist below.

  2. **Legacy allowlist** — the ``blocked_agents`` / ``allowed_orgs`` /
     ``capabilities`` / ``tool_rules`` shape the dashboard wrote
     before the Rego surface existed. Continues to back-stop
     deployments that never adopted Rego.

The :func:`try_rego_decision` helper is the single entry point both
the in-tree PDP routes and the external policy-bridge (:mod:`
mcp_proxy.integrations.policy_bridge`) consume — keeps the two-layer
contract DRY across the four call sites.
"""
from __future__ import annotations

import base64
import logging
from typing import Optional

from mcp_proxy.policy.rego_engine import (
    CompiledPolicy,
    RegoCompileError,
    RegoEvalError,
    evaluate_decision,
)

__all__ = [
    "RegoCompileError",
    "RegoEvalError",
    "try_rego_decision",
]


_log = logging.getLogger("mcp_proxy.policy")


def try_rego_decision(
    rules: dict,
    input_doc: dict,
    *,
    surface: str,
) -> Optional[dict]:
    """Evaluate the operator's Rego policy if one is configured.

    Args:
        rules: the decoded ``policy_rules`` config (the JSON document
            ``get_config('policy_rules')`` returns). Two fields drive
            the Rego layer:

              * ``rego`` — the operator's source. Informational only
                here; the compiled artifact is what runs.
              * ``rego_wasm_base64`` — the WASM bundle, base64-encoded
                (because the surrounding container is JSON). Produced
                by ``mcp_proxy.policy.rego_engine.compile_rego`` when
                the operator clicks Save in the dashboard.

        input_doc: the OPA-shaped ``input`` for this decision — the
            same dict the caller would put under ``{"input": ...}``
            in the OPA Data API request body.

        surface: one of ``"session"`` or ``"tool_call"``. Selects the
            Rego entrypoint (``cullis/policy/session`` or
            ``cullis/policy/tool_call``).

    Returns:
        The decision dict (``{"decision": "allow"|"deny",
        "reason"?}``) when the Rego layer produced one. ``None`` when:

          * no Rego is configured (``rego_wasm_base64`` missing /
            empty);
          * the configured WASM is unreadable (base64 decode error);
          * the Rego runtime raised an eval error (the caller treats
            the absence as a signal to **fall through** to the legacy
            allowlist, NOT as a deny — the failure already gets logged
            here, and a soft-fail-open on Rego runtime errors matches
            the pre-Rego posture so an operator's broken Rego doesn't
            silently brick every previously-allowed call).

        Callers that need fail-closed semantics on a Rego runtime
        error should layer that on top — the policy-bridge HTTP
        handlers do exactly this when the operator has explicitly
        opted into strict mode (future work; today the legacy
        fall-through is the only mode).
    """
    if not isinstance(rules, dict):
        return None
    wasm_b64 = rules.get("rego_wasm_base64") or ""
    if not wasm_b64:
        return None
    try:
        wasm = base64.b64decode(wasm_b64, validate=True)
    except (ValueError, TypeError) as exc:
        _log.warning(
            "policy.rego: rego_wasm_base64 decode failed (%s) — "
            "falling through to legacy allowlist", exc,
        )
        return None

    entrypoint = f"cullis/policy/{surface}"
    policy = CompiledPolicy.from_wasm(wasm)
    try:
        decision = evaluate_decision(
            policy, input_doc, entrypoint=entrypoint,
        )
    except RegoEvalError as exc:
        # Operator's Rego is misshaped — log + fall through to legacy.
        # The dashboard Save flow validates the shape at compile time,
        # but a Rego that compiles can still return an unexpected
        # document at runtime (e.g. a partial rule that didn't cover
        # one of the operator's input shapes).
        _log.warning(
            "policy.rego: %s eval failed (%s) — falling through to "
            "legacy allowlist for this decision", surface, exc,
        )
        return None

    _log.info(
        "policy.rego: %s decision=%s (sha256=%s)",
        surface, decision.get("decision"), policy.sha256[:12],
    )
    return decision
