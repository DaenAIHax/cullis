---
title: "Drop-in vanilla provider SDKs via Mastio"
description: "Keep the vanilla Anthropic / OpenAI / Gemini SDK in your agent code and route every call through a Mastio with mTLS + DPoP applied automatically. One transport helper, two provider examples, audit chain preserved."
category: "Quickstart"
order: 45
updated: "2026-05-27"
---

# Drop-in vanilla provider SDKs via Mastio

**Scope of this page**: you already have an agent that calls a provider SDK directly (or a framework that wraps it: LangChain, LlamaIndex, DSPy, Letta, ...) and you want it to route through the Mastio without rewriting the call sites. The provider key stays in `proxy.env` on the Mastio side, the agent host never sees it, and the audit chain still records every call with the agent's identity.

Three new lines at construction time. Everything else stays verbatim provider SDK.

The helper is **LLM-agnostic**: it returns a plain `httpx.Client` preconfigured with mTLS client cert + a DPoP request signer. The provider SDK chooses the path (`/v1/messages` vs `/v1/chat/completions`) and parses the response shape; the Mastio handles both on the same identity + audit infrastructure.

For a **greenfield agent** (new code, no provider SDK in flight), the recommended path is still [Chat completion via Mastio](chat-completion) using `CullisClient.chat_completion(...)` — that returns the audit `cullis_trace_id` in the response object and shares one client with the MCP tools surface.

## Prerequisites

- An enrolled agent with the four-file identity layout on disk (`agent.crt`, `agent.key`, `ca-chain.pem`, `dpop.jwk`). If you don't have that yet, do [SDK quickstart](sdk) first.
- The matching provider key configured on the Mastio side: e.g. `MCP_PROXY_ANTHROPIC_API_KEY=sk-ant-...` in `proxy.env` followed by `./deploy.sh --pull`. The agent never holds the key.
- The Mastio reachable on the URL the agent will pass as `base_url` (typically `https://<mastio>:9443/v1`).

## Anthropic SDK (uses Mastio `/v1/messages`)

```python
import anthropic
from cullis_sdk.providers_compat import cullis_httpx_client

http_client = cullis_httpx_client(identity_dir="~/.cullis/scenario-b")

client = anthropic.Anthropic(
    base_url="https://mastio.myorg.example.com:9443/v1",
    api_key="unused",            # Mastio ignores; mTLS + DPoP are the real auth
    http_client=http_client,
)

resp = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "hello"}],
)
print(resp.content[0].text)
```

The Mastio exposes `/v1/messages` natively (Anthropic shape in, Anthropic shape out). Phase 0 supports plain text content. Tool-use response blocks and streaming land in Phase 1 — until then, a tool-use turn coming back from the upstream model raises `501 tool_use_response_not_implemented` rather than silently dropping the call, so the SDK customer fails loud and can switch to the OpenAI path or wait for Phase 1.

## OpenAI SDK (uses Mastio `/v1/chat/completions`)

```python
from openai import OpenAI
from cullis_sdk.providers_compat import cullis_httpx_client

client = OpenAI(
    base_url="https://mastio.myorg.example.com:9443/v1",
    api_key="unused",
    http_client=cullis_httpx_client(identity_dir="~/.cullis/scenario-b"),
)

resp = client.chat.completions.create(
    model="claude-sonnet-4-6",   # or any LiteLLM-supported model
    messages=[{"role": "user", "content": "hello"}],
)
print(resp.choices[0].message.content)
```

The OpenAI SDK targets `/v1/chat/completions`, which is the Mastio's native OpenAI-shape endpoint (LiteLLM under the hood). Streaming, tool use, and prompt caching all work because the Mastio is transparent on the request/response payload — the helper only adds the transport-layer wrapping.

## Framework integration (LangChain, LlamaIndex, DSPy, ...)

Frameworks that wrap the Anthropic or OpenAI SDK typically expose a way to pass a pre-built client (often via a `client=` kwarg or by accepting an `http_client=` directly). The same three-line construction works as the source of truth.

```python
# LangChain — Anthropic
from langchain_anthropic import ChatAnthropic
from cullis_sdk.providers_compat import cullis_httpx_client

llm = ChatAnthropic(
    model="claude-sonnet-4-6",
    base_url="https://mastio.myorg.example.com:9443/v1",
    anthropic_api_key="unused",
    http_client=cullis_httpx_client(identity_dir="~/.cullis/scenario-b"),
)
```

When the framework does not surface `http_client`, two options:

1. **File a request with the framework**: most accept upstream-client injection somewhere — common pattern for testing.
2. **Use the SDK directly**: `CullisClient.chat_completion(...)` covers the message-completion path with no framework dependency.

## What the helper does under the hood

1. Loads the four identity files from `identity_dir` (auto-discovery: `agent.crt`, `agent.key`, `ca-chain.pem` optional, `dpop.jwk`).
2. Builds an `httpx.HTTPTransport` with `cert=(agent.crt, agent.key)` and `verify=ca-chain.pem` (or system trust if the bundle is omitted).
3. Wraps it in a `_DpopTransport` that, on every outbound request:
   - Computes a DPoP JWT for `(method, htu)` signed by the persistent EC P-256 key from `dpop.jwk` and attaches it as the `DPoP:` header.
   - Caches any `DPoP-Nonce` returned by the Mastio so subsequent proofs carry it.
   - On a `401` response containing `use_dpop_nonce`, replays the request once with a fresh proof embedding the nonce. The caller never sees the challenge.

Thread-safe: the cached nonce is guarded so multiple concurrent requests through the same SDK client sign consistently.

## What the helper does NOT do

- **No URL rewriting**. You pass `base_url=https://mastio:9443/v1` explicitly. The helper is the auth shim, not a transparent reverse-proxy that intercepts `api.anthropic.com` / `api.openai.com`. A drop-in transparent sidecar is on the roadmap (ADR-038 Phase 2), with the trade-off of one extra container per agent host.
- **No response shape translation on the client side**. The Mastio handles shape negotiation: `/v1/messages` returns Anthropic-shape, `/v1/chat/completions` returns OpenAI-shape. The provider SDK parses what it expects.
- **No bypass of binding/capability gates**. Every call still flows through the Mastio's PDP, audit chain, and per-agent rate limits. The helper changes the wire transport, not the policy plane.

## Phase 0 limits (today)

- **Anthropic `/v1/messages`**: text content only. Streaming returns `501 streaming_not_implemented`. Tool-use *responses* (when the model emits `tool_use` blocks) return `501 tool_use_response_not_implemented`. Tool *requests* (you sending tools=[...] for the model to optionally call) translate transparently; the limit is only on what comes back in the response.
- **OpenAI `/v1/chat/completions`**: streaming + tool use + prompt caching all work (this endpoint has been on the Mastio since v0.5.x).
- **Google `genai` SDK**: helper transport works, but a Mastio handler for the Gemini-native path is Phase 1.

## When to use this vs `CullisClient.chat_completion`

| | `cullis_httpx_client` + provider SDK | `CullisClient.chat_completion` |
|---|---|---|
| Existing provider SDK codebase | ✓ minimal change | ✗ rewrite call sites |
| Greenfield agent | works | ✓ recommended (richer surface) |
| Need `cullis_trace_id` returned in response object | requires reading response headers | ✓ surfaced in the response dict |
| Need MCP tools on the same client | separate `CullisClient` instance | ✓ same object |
| Framework integration (LangChain etc.) | ✓ drop-in | requires framework support for the Cullis client shape |
| Streaming (Anthropic) | ✗ Phase 1 | ✓ supported |
| Streaming (OpenAI) | ✓ supported | ✓ supported |
| Tool use (Anthropic responses) | ✗ Phase 1 | ✓ supported |
| Future provider portability (Claude → GPT) | rewrite to other provider SDK | ✓ provider switch via `model=` only |

There is no wrong answer. Most projects in the wild use both: existing call sites stay on the vanilla SDK + helper, new components reach for `CullisClient` to get the MCP tools surface on the same object.

## Related

- [SDK quickstart](sdk) — enrol an agent and materialise the identity directory.
- [Chat completion via Mastio](chat-completion) — the `CullisClient.chat_completion(...)` path for greenfield agents.
- [MCP tools via Mastio](mcp-tools) — discovering and invoking MCP tools through the Mastio.
- ADR-038 — design rationale for this helper (internal, not yet ratified).
