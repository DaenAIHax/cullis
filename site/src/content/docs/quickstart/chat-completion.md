---
title: "Chat completion via Mastio"
description: "Make an LLM call through the Mastio AI gateway — OpenAI-compatible request shape, tool use, streaming. Covers Anthropic and Ollama upstream providers."
category: "Quickstart"
order: 40
updated: "2026-05-23"
---

# Chat completion via Mastio

**Scope of this page**: how to make an LLM completion through the Mastio AI gateway, with and without tool calls. Streaming is covered at the end.

**Prerequisites**:

- An enrolled agent with the three identity files on disk and a working `from_identity_dir(...)` + `login_via_proxy_with_local_key()`. If you don't have that yet, do [SDK quickstart](sdk) first — this page picks up where that one ends.
- The agent's capabilities must include **`llm.chat`** (a reserved built-in capability). Since Mastio v0.6.4 the chat endpoints are gated on it: an agent enrolled without `llm.chat` gets `403 capability_missing` before any provider dispatch. Add it at enrollment — see the note in [SDK quickstart § capabilities](sdk).
- A provider key configured on the Mastio side: `MCP_PROXY_ANTHROPIC_API_KEY` in `proxy.env` for Anthropic upstream, or a reachable Ollama daemon for local models. Without that, every call returns `503 provider_key_missing`.

## 1. The minimal call

OpenAI ChatCompletion request shape. Mastio dispatches to the configured upstream through a native adapter (official Anthropic / OpenAI SDKs, raw httpx for Ollama):

```python
response = client.chat_completion({
    "model": "anthropic/claude-haiku-4-5-20251001",
    "messages": [
        {"role": "user", "content": "Summarise the EU AI Act Art. 12 in two sentences."},
    ],
    "max_tokens": 200,
})

print(response["choices"][0]["message"]["content"])
print("trace:", response.get("cullis_trace_id"))
```

The response is the upstream provider's OpenAI-compatible reply plus a `cullis_trace_id` injected by Mastio. The trace id matches an entry in the Mastio audit chain — useful when debugging or for compliance lookups.

### Provider matrix

| Model string | Upstream | Status |
|---|---|---|
| `anthropic/claude-opus-4-7` | Anthropic API | live |
| `anthropic/claude-sonnet-4-6` | Anthropic API | live |
| `anthropic/claude-haiku-4-5-20251001` | Anthropic API | live |
| `ollama_chat/<model-name>` | Local Ollama (e.g. `ollama_chat/qwen2.5:7b`) | live |
| `openai/gpt-4-*`, `gemini/*` | OpenAI / Google | returns `501 not_implemented` — roadmap |

Use the literal model string. The provider prefix tells Mastio which upstream to route to.

> **Ollama prefix gotcha**: use `ollama_chat/<name>`, NOT `ollama/<name>`. The latter routes through the legacy `/api/generate` endpoint that silently drops the `messages` array, returning a 200 with empty content. Always `ollama_chat/`.

## 2. With tools (the agent loop)

A real agent doesn't just chat — it loops: chat, model emits a `tool_call`, agent dispatches the tool, feeds the result back, model responds. The pattern:

```python
# List MCP tools the agent is bound to (server-side filtered by capability gate)
raw_tools = client.list_mcp_tools()

# Convert MCP shape to OpenAI tool-use shape
tools = [
    {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t.get("description", ""),
            "parameters": t.get("inputSchema", {"type": "object"}),
        },
    }
    for t in raw_tools
]

messages = [
    {"role": "system", "content": "You are a KYC screener. Use tools to verify documents."},
    {"role": "user", "content": "Process case KYC-2026-001 for document PASSPORT-IT-MR-871234."},
]

for iteration in range(8):  # cap iterations to avoid infinite loops on misbehaving models
    response = client.chat_completion({
        "model": "anthropic/claude-haiku-4-5-20251001",
        "messages": messages,
        "tools": tools,
    })
    msg = response["choices"][0]["message"]
    messages.append(msg)

    tool_calls = msg.get("tool_calls") or []
    if not tool_calls:
        # Model produced final answer
        print("Final:", msg.get("content"))
        break

    # Dispatch each tool call
    for call in tool_calls:
        name = call["function"]["name"]
        args = json.loads(call["function"]["arguments"])
        result = client.call_mcp_tool(name, args)
        messages.append({
            "role": "tool",
            "tool_call_id": call["id"],
            "content": json.dumps(result),
        })
```

Two things Mastio handles for you in this loop:

1. **Authorization**. Every `call_mcp_tool(name, args)` runs against the **capability gate**. If the agent's capabilities don't include the one the tool requires, Mastio returns `403` before the tool's MCP server is ever contacted.
2. **Audit**. Every chat completion + every tool call lands in `local_audit` with the same `cullis_trace_id`, so the entire loop is reconstructable for compliance.

Reference implementation: [`agent_kyc_screener/main_stack.py`](https://github.com/cullis-security/cullis-enterprise/blob/main/legacy/sandbox/agents-demo/agent_kyc_screener/main_stack.py) shows the same loop with system prompt loading, decision parsing, and trace-id capture.

## 3. Streaming

For long completions you want token-by-token output to the user, not a 30-second blocked call. `chat_completion_stream` returns an iterator of SSE frames:

```python
for frame in client.chat_completion_stream({
    "model": "anthropic/claude-haiku-4-5-20251001",
    "messages": [{"role": "user", "content": "Explain DPoP in three paragraphs."}],
}):
    # Each frame is a raw SSE string, e.g. "data: {...}\n\n"
    print(frame, end="", flush=True)
```

SSE frames include:
- `data: {...delta...}\n\n` — incremental content deltas (OpenAI streaming shape)
- `event: tool_call_start\ndata: {...}\n\n` — Mastio-emitted marker when a tool call begins
- `event: cullis_audit\ndata: {...}\n\n` — Mastio-emitted Cullis Audit Envelope sidecar (matches the row written to `local_audit`)
- `data: [DONE]\n\n` — terminal frame

Parse the frames according to the SSE format ([RFC describing SSE](https://html.spec.whatwg.org/multipage/server-sent-events.html)). Most agent frameworks (Anthropic SDK, OpenAI SDK, LangChain) have an SSE parser you can plug in — pass the raw bytes from `chat_completion_stream` to it.

## 4. Common errors

| Status | Cause | Fix |
|---|---|---|
| `401` Unauthorized | Cert mismatch, DPoP key not loaded, or token expired | Verify `from_identity_dir` got a `dpop_key_path`. The SDK auto-relogins once on 401; if you still hit it, the cert's thumbprint isn't pinned in Mastio's `internal_agents.dpop_jkt` — re-enroll. |
| `403` Forbidden — capability denied | Tool call requires a capability the agent doesn't have | Update the agent's capabilities at enrollment, or pick a different tool. |
| `503` `provider_key_missing` | Upstream provider key not set in `proxy.env` | Set `MCP_PROXY_ANTHROPIC_API_KEY` (Anthropic) or ensure Ollama daemon is reachable from the Mastio container. |
| `501` `not_implemented` | Upstream provider not wired (OpenAI, Gemini, etc.) | Roadmap. Use Anthropic or Ollama for now. |
| `502` Bad Gateway | Upstream provider returned an error or timed out | Check Mastio logs (`docker compose -p cullis-mastio logs mcp-proxy`) for the upstream status. Usually transient. |
| `504` Gateway Timeout | Long completion exceeded Mastio's upstream timeout (default 60s) | Bump `MCP_PROXY_AI_GATEWAY_TIMEOUT` in `proxy.env`, or switch to streaming. |

The full HTTP response body is preserved on the exception (`httpx.HTTPStatusError.response`), so you can introspect what Mastio gave you when debugging.

## 5. Observability

Every chat completion writes one row to `local_audit` with:

- `event_type = mcp.llm_completion`
- `agent_id` = your agent
- `details.model`, `details.tokens_in`, `details.tokens_out`, `details.upstream_provider`
- `cullis_trace_id` — the same id you got back in the response, useful for joining client-side logs to the server-side audit chain

To inspect: dashboard `https://mastio.example.com/proxy/audit` or offline export via [Audit export](../operate/audit-export).

## What's next

- [SDK quickstart](sdk) — enrollment + auth, the prerequisites of this page
- [MCP tools via Mastio](mcp-tools) — deeper dive on `list_mcp_tools` + `call_mcp_tool` outside the chat loop (deterministic task runners, ETL, ops scripts)
- [Audit export](../operate/audit-export) — export the chain that records these calls
- [Mastio on Docker](../install/mastio-bundle) — stand up a local Mastio with Ollama wired for development
