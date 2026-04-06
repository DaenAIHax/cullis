# Cullis Session Policy — OPA Rego
#
# Evaluates session requests from the Cullis broker.
# Loaded by OPA and queried at: POST /v1/data/atn/session/allow
#
# Input document (from Cullis broker):
#   {
#     "initiator_agent_id": "org-a::buyer-agent",
#     "initiator_org_id":   "org-a",
#     "target_agent_id":    "org-b::supplier-agent",
#     "target_org_id":      "org-b",
#     "capabilities":       ["order.read", "order.write"]
#   }
#
# Output:
#   {"allow": true/false, "reason": "..."}

package atn.session

import rego.v1

default allow := {"allow": false, "reason": "no matching policy rule"}

# ─── Configuration ───────────────────────────────────────────────────────────
# Override these in a separate data file or via OPA bundle.

# Organizations allowed to initiate sessions (empty = allow all)
allowed_initiator_orgs := data.config.allowed_initiator_orgs if {
    data.config.allowed_initiator_orgs
} else := []

# Organizations allowed as targets (empty = allow all)
allowed_target_orgs := data.config.allowed_target_orgs if {
    data.config.allowed_target_orgs
} else := []

# Capabilities allowed in sessions (empty = allow all)
allowed_capabilities := data.config.allowed_capabilities if {
    data.config.allowed_capabilities
} else := []

# Agents explicitly blocked
blocked_agents := data.config.blocked_agents if {
    data.config.blocked_agents
} else := []

# ─── Rules ───────────────────────────────────────────────────────────────────

# Deny if any agent is blocked
allow := {"allow": false, "reason": reason} if {
    some agent in blocked_agents
    agent == input.initiator_agent_id
    reason := sprintf("agent %s is blocked", [agent])
}

allow := {"allow": false, "reason": reason} if {
    some agent in blocked_agents
    agent == input.target_agent_id
    reason := sprintf("agent %s is blocked", [agent])
}

# Deny if initiator org is not in the allowed list (when list is non-empty)
allow := {"allow": false, "reason": reason} if {
    count(allowed_initiator_orgs) > 0
    not input.initiator_org_id in allowed_initiator_orgs
    reason := sprintf("org %s is not in allowed initiator orgs", [input.initiator_org_id])
}

# Deny if target org is not in the allowed list (when list is non-empty)
allow := {"allow": false, "reason": reason} if {
    count(allowed_target_orgs) > 0
    not input.target_org_id in allowed_target_orgs
    reason := sprintf("org %s is not in allowed target orgs", [input.target_org_id])
}

# Deny if any requested capability is not allowed (when list is non-empty)
allow := {"allow": false, "reason": reason} if {
    count(allowed_capabilities) > 0
    some cap in input.capabilities
    not cap in allowed_capabilities
    reason := sprintf("capability %s is not allowed", [cap])
}

# Allow if no deny rule matched
allow := {"allow": true, "reason": "all checks passed"} if {
    not _any_blocked
    not _initiator_org_blocked
    not _target_org_blocked
    not _capability_blocked
}

# ─── Helper rules ────────────────────────────────────────────────────────────

_any_blocked if {
    some agent in blocked_agents
    agent == input.initiator_agent_id
}

_any_blocked if {
    some agent in blocked_agents
    agent == input.target_agent_id
}

_initiator_org_blocked if {
    count(allowed_initiator_orgs) > 0
    not input.initiator_org_id in allowed_initiator_orgs
}

_target_org_blocked if {
    count(allowed_target_orgs) > 0
    not input.target_org_id in allowed_target_orgs
}

_capability_blocked if {
    count(allowed_capabilities) > 0
    some cap in input.capabilities
    not cap in allowed_capabilities
}
