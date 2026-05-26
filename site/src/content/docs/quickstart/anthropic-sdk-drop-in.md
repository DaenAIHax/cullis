---
title: "Drop-in vanilla Anthropic SDK via Mastio"
description: "Keep the vanilla anthropic.Anthropic SDK in your agent code and route every call through a Mastio with mTLS + DPoP applied automatically. Three new lines, zero changes to call sites, streaming, tool use, prompt caching."
category: "Quickstart"
order: 45
updated: "2026-05-27"
---

# Drop-in vanilla Anthropic SDK via Mastio

**Scope of this page**: you already have an agent that calls `anthropic.Anthropic()` directly (or a framework that wraps it: LangChain `ChatAnthropic`, LlamaIndex `Anthropic` LLM, DSPy `dspy.LM`, Letta, ...) and you want it to route through the Mastio without rewriting the call sites. The Anthropic key stays in `proxy.env` on the Mastio side, the agent host never sees it, and the audit chain still records every call with the agent's identity.

Three new lines at construction time. Everything else stays verbatim Anthropic SDK.

For a **greenfield agent** (new code, no Anthropic SDK in flight), the recommended path is still [Chat completion via Mastio](chat-completion) using `CullisClient.chat_completion(...)` — that returns the audit `cullis_trace_id` in the response and shares one client object with the MCP tools surface.

## Prerequisites

- An enrolled agent with the four-file identity layout on disk (`agent.crt`, `agent.key`, `ca-chain.pem`, `dpop.jwk`). If you don't have that yet, do [SDK quickstart](sdk) first.
- An Anthropic key configured on the Mastio side: `MCP_PROXY_ANTHROPIC_API_KEY=sk-ant-...` in `proxy.env` followed by `./deploy.sh --pull`. The agent never holds this key.
- The Mastio reachable on the URL the agent will pass as `base_url` (typically `https://<mastio>:9443/v1`).

## The three lines

```python
import anthropic
from cullis_sdk.anthropic_compat import cullis_httpx_client

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

That is the whole helper. Every other call site (`messages.create(...)`, `messages.stream(...)`, tool-use, prompt caching, batch API) is **verbatim** Anthropic SDK because the helper changes only the transport layer: it returns a `httpx.Client` preconfigured with mTLS client cert + a `DPoP` header signed per request.

## Streaming

```python
with client.messages.stream(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "long prose request"}],
) as stream:
    for chunk in stream.text_stream:
        print(chunk, end="", flush=True)
```

Works without any additional wiring. The Anthropic SDK uses the same underlying `httpx.Client` for both unary and streaming requests; the DPoP proof is attached on the initial request before the SSE stream opens, and the Mastio forwards the SSE events from the upstream Anthropic response back to your agent untouched.

If your streaming completion can run longer than the default 60s per-request timeout, pass `timeout=300.0` (or whatever fits) to `cullis_httpx_client(...)`.

## Tool use

The Anthropic Messages API accepts tool definitions inside the request body and surfaces tool-use responses in the standard shape. The helper passes the body through to the Mastio, which forwards it upstream to Anthropic verbatim. No special handling on the helper side.

```python
resp = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    tools=[
        {
            "name": "get_weather",
            "description": "...",
            "input_schema": {"type": "object", "properties": {...}},
        }
    ],
    messages=[{"role": "user", "content": "weather in Roma"}],
)

# Standard Anthropic SDK objects:
if resp.stop_reason == "tool_use":
    tool_use_block = next(b for b in resp.content if b.type == "tool_use")
    print(tool_use_block.name, tool_use_block.input)
```

## Framework integration (LangChain, LlamaIndex, DSPy, ...)

Frameworks that wrap the Anthropic SDK typically expose a way to pass a pre-built `anthropic.Anthropic` client (often via a `client=` kwarg or by accepting an `http_client=` directly). The same three-line construction works as the source of truth.

```python
# LangChain
from langchain_anthropic import ChatAnthropic
from cullis_sdk.anthropic_compat import cullis_httpx_client

llm = ChatAnthropic(
    model="claude-sonnet-4-6",
    base_url="https://mastio.myorg.example.com:9443/v1",
    anthropic_api_key="unused",
    default_request_timeout=60,
    # LangChain creates its own internal anthropic.Anthropic; passing
    # http_client through the langchain layer depends on the version.
    # As of langchain-anthropic 0.3.x, this is:
    http_client=cullis_httpx_client(identity_dir="~/.cullis/scenario-b"),
)
```

When the framework does not surface `http_client`, two options:

1. **File a request with the framework**: most accept upstream-client injection somewhere — it is a common pattern for testing.
2. **Use the SDK directly**: `CullisClient.chat_completion(...)` covers the message-completion path with no framework dependency.

## What the helper does under the hood

1. Loads the four identity files from `identity_dir` (auto-discovery: `agent.crt`, `agent.key`, `ca-chain.pem` optional, `dpop.jwk`).
2. Builds an `httpx.HTTPTransport` with `cert=(agent.crt, agent.key)` and `verify=ca-chain.pem` (or system trust if the bundle is omitted).
3. Wraps it in a `_DpopTransport` that, on every outbound request:
   - Computes a DPoP JWT for `(method, htu)` signed by the persistent EC P-256 key from `dpop.jwk` and attaches it as the `DPoP:` header.
   - Caches any `DPoP-Nonce` returned by the Mastio so subsequent proofs carry it.
   - On a `401` response containing `use_dpop_nonce`, replays the request once with a fresh proof embedding the nonce. The caller never sees the challenge.

Thread-safe: the cached nonce is guarded so multiple concurrent requests through the same Anthropic client (parallel `messages.create` in a thread pool) sign consistently.

## What the helper does NOT do

- **URL rewriting**. You pass `base_url=https://mastio:9443/v1` explicitly. The helper is the auth shim, not a transparent reverse-proxy that intercepts `api.anthropic.com`. A drop-in transparent sidecar that does that is on the roadmap (ADR-038 Phase 2), with the trade-off of one extra container per agent host.
- **Response shape translation**. The Mastio's `/v1/chat/completions` returns Anthropic-Messages-API-shaped JSON. The Anthropic SDK parses it natively. No conversion needed on the helper side.
- **Bypass binding / capability gates**. Every call still flows through the Mastio's PDP, audit chain, and per-agent rate limits. The helper changes the wire transport, not the policy plane.

## When to use this vs `CullisClient.chat_completion`

| | `cullis_httpx_client` + Anthropic SDK | `CullisClient.chat_completion` |
|---|---|---|
| Existing Anthropic SDK codebase | ✓ minimal change | ✗ rewrite call sites |
| Greenfield agent | works | ✓ recommended (richer surface) |
| Need `cullis_trace_id` returned in response object | requires reading response headers | ✓ surfaced in the response dict |
| Need MCP tools on the same client | separate `CullisClient` instance | ✓ same object |
| Framework integration (LangChain etc.) | ✓ drop-in | requires framework support for the Cullis client shape |
| Streaming + tool use + prompt caching | ✓ Anthropic SDK native | ✓ supported, response shape Cullis-specific |
| Future provider portability (Claude → GPT) | rewrite to OpenAI SDK | ✓ provider switch via `model=` only |

There is no wrong answer. Most projects in the wild use both: existing call sites stay on the vanilla SDK + helper, new components reach for `CullisClient` to get the MCP tools surface on the same object.

## Related

- [SDK quickstart](sdk) — enrol an agent and materialise the identity directory.
- [Chat completion via Mastio](chat-completion) — the `CullisClient.chat_completion(...)` path for greenfield agents.
- [MCP tools via Mastio](mcp-tools) — discovering and invoking MCP tools through the Mastio.
- ADR-038 — design rationale for this helper (internal, not yet ratified).
