---
title: "Rego policies — beyond allowlists"
description: "Replace the dashboard's allowlist / blocklist with full Rego rules. Cullis compiles the operator's Rego to a WASM bundle at save time and evaluates it in-process on every decision, with the allowlist as a safety fallback."
category: "Operate"
order: 9
updated: "2026-05-23"
---

# Rego policies

The dashboard Policies page accepts two layers, evaluated in order on every PDP decision:

1. **Rego layer** — when the operator has authored a Rego policy, Cullis compiles it to a WASM bundle via the bundled OPA CLI, persists the bundle next to the source, and evaluates it in-process on every call to `/pdp/policy`, `/v1/data/cullis/policy/session`, and `/v1/data/cullis/policy/tool_call`.

2. **Legacy allowlist** — `blocked_agents`, `allowed_orgs`, `capabilities`, `tool_rules`. Backstop for deployments that never authored Rego, also kicks in transparently when the Rego layer fails to evaluate (logged at warning level so the operator catches it; never silently denies).

Cullis ships OPA, so there is **no extra component to install**. Writing Rego adds expressiveness without changing the deployment topology.

## Why Rego over allowlists

Allowlists answer "is this agent / org / tool on the list". Rego answers anything you can describe in a rule:

- "Treasury wire transfers are allowed only when the agent's enrollment is less than 24 hours old"
- "The KYC screener can call sanctions_lookup but never PII export"
- "Cross-org session-open is allowed only when the target org is in the operator's approved partner list AND the initiator has the `kyc.partner-disclose` capability"

The expressiveness comes from the same Rego the OPA community uses, with all of `data` / `input` / `package` / function composition. Operators familiar with OPA write what they already know; operators new to Rego work from the examples below.

## Surfaces

Cullis evaluates two Rego entrypoints:

- `data.cullis.policy.session` — invoked for `/pdp/policy` (legacy broker webhook) and `/v1/data/cullis/policy/session` (external policy bridge). The `input` document mirrors the OPA Data API session shape:

  ```json
  {
    "initiator_agent_id": "orga::a",
    "target_agent_id": "orgb::b",
    "initiator_org_id": "orga",
    "target_org_id": "orgb",
    "session_context": "initiator",
    "capabilities": ["kyc.read", "kyc.submit"]
  }
  ```

- `data.cullis.policy.tool_call` — invoked for `/v1/data/cullis/policy/tool_call`. The `input` mirrors the OPA Data API tool-call shape:

  ```json
  {
    "agent_id": "orga::kyc-screener",
    "tool_name": "sanctions_lookup",
    "arguments": { "...": "..." }
  }
  ```

Both rules must return one of these shapes:

- A boolean — `true` ⇒ allow, `false` ⇒ deny
- An object — `{"decision": "allow"|"deny", "reason"?: "<string>"}` — recommended, because the dashboard surfaces the `reason` to the operator on every deny.

Anything else fails closed (the call is denied, and the failure is logged so the operator catches it on next dashboard load).

## Example 1 — session policy with org allowlist + capability gate

```rego
package cullis.policy

# Session-open default: allow inside the org, otherwise consult the
# operator's approved partners list and the initiator's capabilities.
session := {"decision": "allow"} if {
    same_org
}

session := {"decision": "allow"} if {
    cross_org_allowed
}

session := {"decision": "deny", "reason": msg} if {
    not same_org
    not cross_org_allowed
    msg := sprintf(
        "cross-org session %s -> %s requires partner approval AND kyc.partner-disclose capability",
        [input.initiator_org_id, input.target_org_id],
    )
}

same_org if {
    input.initiator_org_id == input.target_org_id
    input.initiator_org_id != ""
}

approved_partners := {"orga", "orgb", "treasury-partner-eu"}

cross_org_allowed if {
    input.target_org_id == approved_partners[_]
    "kyc.partner-disclose" == input.capabilities[_]
}
```

What this expresses in plain English: same-org sessions always pass; cross-org sessions pass only when the target org is in the operator's approved list AND the initiator brought the `kyc.partner-disclose` capability. Anything else returns deny with a specific reason the operator sees on every blocked attempt.

## Example 2 — tool-call policy with per-agent allowlist

```rego
package cullis.policy

# Default deny — only the explicit allow rules below let calls through.
tool_call := {"decision": "deny", "reason": msg} if {
    not allow_tool_call
    msg := sprintf(
        "agent %s is not authorised to call tool %s",
        [input.agent_id, input.tool_name],
    )
}

tool_call := {"decision": "allow"} if {
    allow_tool_call
}

# KYC screener: read-only KYC tools.
allow_tool_call if {
    input.agent_id == "orga::kyc-screener"
    input.tool_name == "sanctions_lookup"
}

allow_tool_call if {
    input.agent_id == "orga::kyc-screener"
    input.tool_name == "kyc_status_check"
}

# Treasury bot: explicit list of money-moving tools.
allow_tool_call if {
    input.agent_id == "orga::treasury"
    input.tool_name == {"treasury_wire", "sepa_credit_transfer"}[_]
}

# Open KB lookups for any internal agent.
allow_tool_call if {
    startswith(input.agent_id, "orga::")
    input.tool_name == "knowledge_base_query"
}
```

Both examples use the OPA v1 syntax (`if` keyword required on rule bodies). The bundled OPA binary is v1.16.2; the engine surfaces the `opa build` diagnostic verbatim when the operator pastes pre-v1 Rego, so the error message names the exact line + column to fix.

Default-deny is the safer default — but you can flip the polarity by setting `tool_call := {"decision": "allow"}` as the bare default and explicitly denying the dangerous tools. Make the choice that matches your operator's mental model.

## Authoring workflow

1. Open the dashboard at `https://mastio.example.com:9443/proxy/policies`.
2. Paste Rego into the Policies editor. Save.
3. Cullis runs `opa build -t wasm -e cullis.policy` on the source. On success: green checkmark, WASM bundle persisted, next decision evaluates Rego. On failure: red banner with the `opa build` diagnostic (line + column + error reason). The legacy allowlist stays active until the operator fixes the Rego.
4. Watch the audit log. Every Rego-decided call carries the WASM SHA-256 prefix in the log line (`PDP[rego] DENY: ... sha256=ab12cd34...`) so the operator can correlate a runtime decision back to the policy version that produced it.

## Constraints

A few OPA built-ins do not work in the WASM target — primarily anything that requires a host binding (HTTP, time, crypto outside `crypto.hmac.*`). For deployments that need those, run Cullis with an external OPA server fronting the policy-bridge endpoint and keep the in-process Rego limited to pure rules over `input`. Most policy rules describing access control over `agent_id` / `org_id` / `tool_name` / `capabilities` do not hit these constraints.

The compile step bounds Rego at **10 seconds**. Honest policies compile in well under a second; a 10-second compile usually means a runaway loop and the operator hears about it explicitly on Save.

## Performance

The OPA binary bundled in the image is **v1.16.2**, SHA-256-pinned at build time (`scripts/opa-sha256.txt`, verified with `sha256sum -c`). Policies compile to WebAssembly on Save (~25 ms) and evaluate in-process via `opa-wasmtime` — no sidecar, no network hop. After the first evaluate warms the instance cache, a representative 60-line policy runs at **p50 ~0.2 ms / ~4 600 evals/s** single-thread. The benchmark is reproducible: `python scripts/bench-rego-eval.py`.

## Fall-through to the legacy allowlist

When the Rego layer is empty or its evaluation fails (compile-time issues never reach the runtime, but a runtime-only error like an undefined rule for a specific input still drops to legacy), Cullis falls through to the dashboard's allowlist fields (`blocked_agents`, `allowed_orgs`, `capabilities`, `tool_rules`). Operators can adopt Rego incrementally: keep the allowlist populated, author Rego incrementally, and remove the allowlist entries once the Rego rules cover the same surface.

## What stays the same

- The dashboard Policies page is still the authoring surface.
- `policy_rules` is still the source of truth (the Rego source and compiled WASM live in two new fields inside that same JSON document).
- The OPA Data API + CloudEvents bridge introduced in PR #907 keeps working unchanged — external gateways already pointing at `/v1/data/cullis/policy/*` get the new Rego-shaped decision automatically.
- The audit log still records every decision with the originating agent / org / tool. Rego adds a `sha256=<prefix>` in the log line so the operator can trace decisions back to the policy version, but the audit row itself stays the same shape — no schema migration.
