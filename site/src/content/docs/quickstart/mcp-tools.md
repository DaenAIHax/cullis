---
title: "MCP tools via Mastio"
description: "Use `list_mcp_tools` and `call_mcp_tool` outside the chat loop — deterministic task runners, ETL jobs, ops scripts. Covers the binding gate, the capability gate, JSON-RPC errors, and audit linkage."
category: "Quickstart"
order: 50
updated: "2026-05-23"
---

# MCP tools via Mastio

**Scope of this page**: how to discover and invoke MCP tools through Mastio **without an LLM in the loop**. The full chat-driven loop (model emits a `tool_call`, agent dispatches, feeds the result back) is covered in [Chat completion via Mastio](chat-completion). This page is for the cases where a model is not the right driver: deterministic task runners, scheduled batch jobs, ops scripts, integration tests, or the inner pipe of a larger workflow.

**Prerequisites**:

- An enrolled agent with the three identity files on disk + a successful `login_via_proxy_with_local_key()`. If you don't have that yet, do [SDK quickstart](sdk) first.
- At least one MCP resource registered on the Mastio side **and** an active binding from your agent to that resource. Operators register resources from the Mastio dashboard (Resources → Add MCP) or via the admin API; bindings live in `local_agent_resource_bindings` and are managed from the agent detail page.

## 1. When you want this instead of the chat loop

The chat loop is right when a model is making decisions: "given these documents and these tools, figure out what to do." It is **wrong** when you already know what to do.

Use the direct surface here for:

| Pattern | Example |
|---|---|
| Scheduled job | Every night, call `kyc.export_pending` and upload the result to S3. |
| ETL inner loop | Iterate over 10k rows and call `enrichment.lookup` on each. A model in the loop would 100x the cost for zero decision quality. |
| Ops script | One-off: call `infra.list_orphan_certificates`, eyeball, decide. |
| Integration test | Assert that `policy.evaluate` returns `allow` for a known input shape. |
| Pipeline step inside a larger workflow | An Airflow / Prefect / Temporal task that needs to invoke an MCP tool with deterministic arguments. |

The reason to still go through Mastio (rather than calling the MCP server directly) is the same in all five cases: the **binding gate** decides whether your agent is allowed to talk to that resource at all, the **capability gate** decides which tools on that resource it can invoke, every call lands in the audit chain with the agent's identity, and the upstream credential (the API token the MCP server itself needs) stays inside Mastio. Your agent never sees it.

## 2. List the tools you can call

```python
tools = client.list_mcp_tools()

for t in tools:
    print(t["name"])
    print("  ", t.get("description", "").splitlines()[0] if t.get("description") else "")
```

The returned list is the JSON-RPC `tools/list` response, already filtered server-side to the tools your agent is allowed to call. Each entry has three fields:

```python
{
    "name": "kyc.lookup_individual",
    "description": "Look up sanctions/PEP hits for an individual by name + DOB.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "full_name": {"type": "string"},
            "date_of_birth": {"type": "string", "format": "date"},
        },
        "required": ["full_name", "date_of_birth"],
    },
}
```

`inputSchema` is a JSON Schema object. If the upstream MCP server didn't declare one, Mastio returns the empty `{"type": "object", "properties": {}}` placeholder — that's the signal that you'll need to read the server's own docs for the argument shape.

> **"Filtered server-side" matters.** The same agent connected to Mastio A and Mastio B will see different tool lists. The list reflects this agent's bindings on this Mastio, not the global set of registered resources. Don't cache it across deploys.

## 3. Call a tool

```python
result = client.call_mcp_tool(
    "kyc.lookup_individual",
    {"full_name": "Mario Rossi", "date_of_birth": "1985-04-12"},
)

if result.get("isError"):
    raise RuntimeError(f"tool reported error: {result['content']}")

# 'content' is the MCP-spec content array — typically a list of
# {"type": "text", "text": "..."} or {"type": "json", "data": {...}} entries.
for chunk in result.get("content", []):
    if chunk.get("type") == "text":
        print(chunk["text"])
    elif chunk.get("type") == "json":
        print(json.dumps(chunk["data"], indent=2))
```

`call_mcp_tool` returns the upstream MCP server's `result` object verbatim. The shape follows the [MCP spec](https://modelcontextprotocol.io/specification): a `content` array of typed chunks, plus an `isError` boolean. A tool that fails *its own* logic (e.g. "no record found") sets `isError = True` with a human-readable explanation in `content`. A tool that fails *Mastio's* logic (no binding, unknown tool, oversized arguments) doesn't return a result at all — see the next section.

## 4. The two gates

Cullis layers two distinct authorization decisions on every `call_mcp_tool`. Knowing which one denied you is the difference between "ask my operator for a binding" and "ask my operator to widen my capabilities."

**Binding gate** (primary, for MCP resources). Does this agent have an active binding to the MCP resource that hosts this tool? Bindings are agent ↔ resource pairs in `local_agent_resource_bindings`. No binding = `ERR_RESOURCE_NOT_AUTHORIZED` ("No active binding for resource '<id>'") and the call never reaches the upstream MCP server. The aggregator audits the denial with `reason: "no_binding"`.

**Capability gate** (for built-in tools registered without a `resource_id`). Does the agent's `capabilities` list contain the tool's `required_capability`? Capabilities are free-form strings agreed between the operator and the MCP server author (e.g. `kyc.read`, `portfolio.place_order`). Mismatch = the tool simply doesn't appear in `list_mcp_tools()` for that agent, and a direct `call_mcp_tool` returns `ERR_TOOL_NOT_FOUND` because the registry filter hid it.

In practice: if `list_mcp_tools()` returns the tool but `call_mcp_tool()` denies it, that's a binding problem. If `list_mcp_tools()` doesn't return it at all, that's a capability problem.

## 5. Errors

Two error layers stack on the SDK call. **HTTP-level** errors (`raise_for_status` fires) bubble up as `httpx.HTTPStatusError`:

| Status | Cause | Fix |
|---|---|---|
| `401` Unauthorized | Cert thumbprint mismatch, DPoP key not loaded, or token expired | See the chat-completion page's auth section; usually re-enroll. |
| `502` Bad Gateway | Upstream MCP server returned a non-2xx or the TCP connection failed | Check Mastio logs (`docker compose -p cullis-mastio logs mcp-proxy`) — the upstream URL + status code is there. |
| `504` Gateway Timeout | Upstream MCP server didn't reply in 30 seconds | Either the tool is genuinely slow (raise the handler timeout in the MCP server) or it's deadlocked. Worth investigating either way. |

**JSON-RPC-level** errors are returned as a body with an `error` object, which the SDK raises as `RuntimeError`:

| Code | Symbol | Cause |
|---|---|---|
| `-32602` | `ERR_INVALID_PARAMS` | Bad `name`, non-dict `arguments`, or arguments payload exceeds 64 KiB. |
| `-32000` | `ERR_TOOL_NOT_FOUND` | Tool name isn't in the registry, **or** it exists but the capability gate filtered it out for this agent. |
| `-32001` | `ERR_RESOURCE_NOT_AUTHORIZED` | Tool exists in the registry but the agent has no active binding to its MCP resource. |

When `RuntimeError` fires, the SDK includes the JSON-RPC `code` + `message` in the string — keep both in your log line, the code is what an operator searches for.

## 6. Size and timeout limits

The aggregator bounds two things before the call reaches the upstream MCP server:

- **Arguments payload**: 64 KiB (UTF-8 bytes of the serialised JSON). Over the limit → `ERR_INVALID_PARAMS` with `reason: "arguments_too_large"` in the audit row. The limit lives in `MAX_TOOL_PARAMETERS_BYTES` (`mcp_proxy/tools/`) if you need to verify the current value.
- **Per-call handler window**: 30 seconds. If the upstream MCP server hasn't responded by then, Mastio cuts the connection and returns `504`.

If you legitimately need to pass more than 64 KiB to a tool (e.g. an OCR'd document), the right pattern is to upload to object storage out-of-band and pass a reference (URL, S3 key, content hash) as the argument.

## 7. What gets audited

Every `call_mcp_tool` writes one row to `local_audit`:

- `event_type = resource_call`
- `result = ok` / `denied` / `error`
- `agent_id`, `org_id`, `principal_type`
- `details.tool` — the tool name
- `details.resource_id` — when the tool is on an MCP resource
- `details.reason` — populated on denials (`no_binding`, `arguments_too_large`, etc.)

Denials (no binding, oversized arguments) audit before returning the JSON-RPC error, so failed attempts are first-class in the chain — useful for spotting an agent that's hammering a tool it isn't allowed to call.

Inspect the rows from the dashboard at `https://mastio.example.com/proxy/audit` (filter `event_type = resource_call`) or export the chain to NDJSON via [Audit export](../operate/audit-export).

## What's next

- [Chat completion via Mastio](chat-completion) — the LLM-driven loop where `call_mcp_tool` runs *inside* a chat completion
- [Audit export](../operate/audit-export) — pull the `resource_call` rows out for offline analysis
- [Configuration reference](../reference/configuration) — every `MCP_PROXY_*` env var that tunes the aggregator
