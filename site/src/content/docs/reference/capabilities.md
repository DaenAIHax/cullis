---
title: "Capabilities catalog"
description: "What every capability token does, which endpoint it gates, and how to grant or revoke it."
category: "Reference"
order: 40
updated: "2026-05-28"
---

# Capabilities catalog

**Who this is for**: an operator deciding which capabilities to grant to an agent, a user, or a workload — and the dev curious to know what `mcp.tools.list` actually unlocks before they paste it into the dashboard.

A **capability** is a short lowercase token (e.g. `llm.chat`, `mcp.tools.list`) attached to a principal. The Mastio checks it as the first gate after DPoP+mTLS authentication, before any provider dispatch or tool execution. Missing capability is fail-closed: HTTP `403` on the LLM path, JSON-RPC `-32005` on the MCP path, and a `denied` row on the audit chain.

The principal carries its capability set in one of three places, depending on its type:

| Principal type | Stored in | Granted via |
|---|---|---|
| Agent (`<org>::<name>`) | `internal_agents.capabilities` (JSON array) | `POST /v1/admin/agents` at enrollment; `PATCH /v1/admin/agents/{id}/capabilities` to edit; dashboard *Agent detail → Capabilities* form |
| User (`<org>::user::<name>`) | `local_user_principals.capabilities` | `POST /v1/admin/users`; `PATCH /v1/admin/users/{principal_id}/capabilities`; dashboard *User detail → Capabilities* card |
| Workload (`<org>::workload::<name>`) | `local_workload_principals.capabilities` | `POST /v1/admin/workloads`; `PATCH /v1/admin/workloads/{principal_id}/capabilities` (admin API only in v0.6.4 — dashboard tab planned for v0.7) |

Capability tokens follow the shape `^[a-z_][a-z0-9_.]{0,63}$` (max 64 chars, max 64 entries per principal) — validation is enforced server-side at both the admin API and the dashboard form, so a typo at create time is a 422 not a silent breakage at the gate.

Zero-trust default: a newly enrolled principal with an empty `capabilities` list is denied on every gated endpoint. The admin must grant capabilities explicitly. There is no "default-allow" fallback path.

## Built-in (shipped with the Mastio)

These four are recognised by the Mastio out of the box. They appear in the dashboard datalist as autocomplete suggestions.

### `llm.chat`

**What**: permits the principal to issue chat completions through the Mastio's AI gateway.

**Endpoints gated**:

- `POST /v1/chat/completions` (OpenAI shape)
- `POST /v1/llm/chat` (same handler, legacy alias)
- `POST /v1/messages` (Anthropic shape)

**Without it**: HTTP `403` with `{"reason": "capability_missing", "required_capability": "llm.chat"}` and a denied audit row (`action=egress_llm_chat status=denied`). Streaming path hits the same gate.

**Typical grant**: every agent that talks to an LLM. Workloads usually don't have it (they're infra, not chat clients). Users get it if you let them use the Mastio as a chat backend (LibreChat, Cherry Studio, Cursor).

### `mcp.tools.list`

**What**: permits the principal to enumerate the MCP tools the Mastio aggregates (built-in + registered MCP resources visible to the principal via bindings).

**Endpoint gated**:

- `POST /v1/mcp` with JSON-RPC method `tools/list`

**Without it**: JSON-RPC error `-32005` `"capability_missing: mcp.tools.list"`, with `data.required_capability="mcp.tools.list"`, and a denied local-audit row (`event_type=mcp_tools_list result=denied`).

**Typical grant**: every agent or user that needs discovery before invoking a tool. Not granting it does NOT hide a tool the principal is already bound to — it just refuses the listing method. Per-tool execution remains gated by binding + per-tool `required_capability` regardless.

### `mcp.tools.call`

**What**: permits invocation of MCP tools via JSON-RPC.

**Endpoint gated**:

- `POST /v1/mcp` with JSON-RPC method `tools/call`

**Notes**: in Phase 1 (v0.6.x) the per-tool `required_capability` (declared by the MCP resource at registration) is the load-bearing check on this method, and `mcp.tools.call` is treated as informational unless a tool registers it as its `required_capability`. The method-level gate lands in v0.7 once the dashboard exposes per-tool capability assignment. Granting it today is forward-compatible — no behaviour change in v0.6.x, automatic enforcement in v0.7.

### `http.get`

**What**: permits the principal to use the Mastio's generic HTTP-GET egress for ad-hoc resource fetches.

**Endpoint gated**: `POST /v1/mcp` `tools/call` for the built-in `http.get` tool.

**Notes**: enforced today via the built-in tool's `required_capability`. Useful for sandbox agents that need to read public docs through the Mastio's egress trail (so the call is audited like every other action).

## Custom (registered by MCP tools)

When an MCP resource is registered via `POST /v1/admin/mcp-resources` with a `required_capability` field, that capability becomes a recognised token on this Mastio. The Mastio does NOT mint these centrally — they are defined by the tool author. Examples from the reference integrations:

- `erp.read` — read-only access to an ERP-backed MCP resource
- `salesforce.query` — Salesforce read via the published Salesforce MCP tool
- `kyc.screen` — KYC screening tool (Cullis demo, `cullis-mcp-kyc`)
- `pitchbook.search` — pitch-book search tool (Cullis demo, `cullis-mcp-pitchbook`)

These do not appear in the dashboard datalist by default — they appear once the tool is registered on this Mastio, because the Mastio reads the registry at boot and adds them to the autocomplete list.

## Operator-defined

You can grant a principal an arbitrary token that no built-in path or registered tool requires today. The Mastio stores it verbatim and surfaces it in audit rows but does not enforce anything else. This is intentional: operator-defined capabilities are a forward-compatibility hook for Rego policies that gate on the presence/absence of a string (e.g. `if "compliance.signed_off" in agent.capabilities`).

In v0.7 the dashboard will expose a *Capabilities → Manage vocabulary* page that lets the admin define operator-specific capabilities, attach descriptions, and link them to Rego rules. Today the workflow is: pick a name following the same shape constraint, grant it to a principal, write your Rego rule that consumes it.

## Granting and rotating

### Via the dashboard

Agent: */proxy/agents → click the agent row → Capabilities section* on the detail page → textbox lists current tokens (precompiled, comma-separated), Update button replaces the set. The autocomplete datalist suggests the four built-ins as you type.

User: */proxy/users → click the user row → Capabilities card* (under Authentication on the Overview tab) → same form shape.

Workload: admin API only in v0.6.4 (`PATCH /v1/admin/workloads/{id}/capabilities`). Dashboard *Workloads* tab planned for v0.7.

### Via the admin API

```bash
# Grant a fresh set (replace, not delta)
curl -k -X PATCH https://mastio.example/v1/admin/agents/acme::alice/capabilities \
  -H "X-Admin-Secret: $MCP_PROXY_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"capabilities": ["llm.chat", "mcp.tools.list", "erp.read"]}'
```

The endpoint is **idempotent set-replacement, not delta apply**. Pass the full list each call. The Mastio bumps `federation_revision` for federated agents so the Phase 3 publisher will propagate the change on its next pass.

Same shape for users (`/v1/admin/users/{principal_id}/capabilities`) and workloads (`/v1/admin/workloads/{principal_id}/capabilities`).

### Audit

Every grant emits one row on the Mastio audit chain. Search by action:

- `agent.capabilities_set` / `agent.capabilities_patched` (dashboard / admin API)
- `user.capabilities_set` / `user.capabilities_patched`
- `workload.capabilities_patched`

The detail payload carries the full new list verbatim — replay-friendly. Append-only triggers prevent retro-editing the row.

## Removing a capability

There is no "remove this one token" endpoint. The semantics are: read the current list, drop the entries you want gone, PATCH the rest.

```bash
# Read
curl -k https://mastio.example/v1/admin/agents \
  -H "X-Admin-Secret: $MCP_PROXY_ADMIN_SECRET" | \
  jq '.[] | select(.agent_id == "acme::alice") | .capabilities'
# → ["llm.chat", "mcp.tools.list", "erp.read"]

# Drop erp.read
curl -k -X PATCH https://mastio.example/v1/admin/agents/acme::alice/capabilities \
  -H "X-Admin-Secret: $MCP_PROXY_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"capabilities": ["llm.chat", "mcp.tools.list"]}'
```

The denied audit row at the next attempt confirms the revoke landed.

## Limits

- Max 64 capability tokens per principal (Pydantic constraint, enforced at the admin API and dashboard form).
- Max 64 characters per token.
- Shape `^[a-z_][a-z0-9_.]{0,63}$` — lowercase identifier with optional dotted segments.
- The list field is stored as a JSON string (`TEXT`) on SQLite + Postgres; no indexed search on capability membership in v0.6.x. If you need "list every agent with `erp.read`", pull the full table and filter in the operator script. A reverse index is on the v0.7 backlog if customer usage demands it.

## Migration notes

Pre-v0.6.4 typed principals (users + workloads) had no `capabilities` column. Migration `0045_principal_capabilities` adds the column on both tables with `server_default '[]'`. Existing rows are backfilled to zero-trust default-deny — the admin grants explicitly. There is no automated "open it up to keep things working" path. This is the breaking change called out in the v0.6.4 CHANGELOG.

For agents enrolled with empty `capabilities` before v0.6.4, the same applies: they will start receiving `403`/`-32005` on the gated endpoints. Either re-enroll with the right set, or `PATCH .../capabilities` directly. The audit row at the first denied call is the operational signal.
