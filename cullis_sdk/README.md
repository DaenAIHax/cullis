# `cullis-sdk`

**Python SDK for Cullis Mastio. Zero-trust identity, policy, and audit for autonomous AI agents in regulated environments.**

`cullis-sdk` is the Python client an autonomous agent imports to talk to a Cullis Mastio (the org-level gateway). It handles mTLS client cert presentation, DPoP proof signing, token refresh, and request retries, exposing a small surface that maps onto what an agent actually does: ask the LLM something, list the MCP tools it is allowed to call, call one, and let the audit trail accumulate underneath.

The SDK never holds the upstream LLM API key. The Mastio is the only thing that talks to Anthropic, OpenAI, Ollama, or any other provider. The agent only sees its own client certificate and the Mastio URL.

---

## Install

```bash
pip install cullis-sdk
```

Python 3.10+ required.

Optional extras:

```bash
pip install 'cullis-sdk[spiffe]'         # SPIFFE workload-API integration
pip install 'cullis-sdk[litellm-legacy]' # opt-in legacy LiteLLM upstream path
```

---

## Quick start

The standard flow is: an org admin mints your agent's identity in the Mastio dashboard, downloads the resulting `identity-bundle.zip`, and delivers it to your agent host out of band (scp, KMS, Vault, systemd LoadCredential, whatever your runbook says). You unzip it anywhere on the agent host. The SDK reads `agent.crt + agent.key` from disk; `ca-chain.pem` and `dpop.jwk` are auto-discovered as siblings.

```python
from cullis_sdk import CullisClient

# Admin minted this identity in the dashboard and sent you the zip.
# Unzip anywhere on the agent host. The cert IS the credential
# (ADR-014, RFC 8705 mTLS); there is no shared API key.
client = CullisClient.from_identity_dir(
    "https://mastio.acme.local:9443",
    cert_path="/etc/cullis/agent/agent.crt",
    key_path="/etc/cullis/agent/agent.key",
    verify_tls=False,  # self-signed Org CA on a laptop; pin ca_chain_path in prod
)

# Ask the LLM. The Mastio dispatches to whichever provider the org
# admin configured (Anthropic, OpenAI, Ollama). The agent never sees
# the upstream API key.
response = client.chat_completion(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Screen the latest applicant batch."}],
)

# List the MCP tools the policy engine allows this agent to invoke.
for tool in client.list_mcp_tools():
    print(tool["name"], tool.get("description", ""))

# Invoke one. The Mastio enforces the capability gate again on the
# server side, applies the Rego policy, and writes an audit row.
result = client.call_mcp_tool(
    "sanctions_lookup",
    {"full_name": "Acme Holding Ltd"},
)
```

The other entry point is `CullisClient.enroll_via_dashboard_approval(mastio_url, requester_name=..., requester_email=..., save_to=...)` — the scripted bootstrap path for CI/CD onboarding flows where no human is at a terminal to copy files. The SDK submits a CSR, polls until an admin clicks Approve in the dashboard, then writes the identity-dir layout and returns the client.

For Linux production hosts using systemd, `CullisClient.from_systemd_credentials(...)` reads the identity from the `LoadCredential=` tmpfs delivery instead of disk.

---

## Vanilla Anthropic / OpenAI SDK drop-in (ADR-038)

If your agent code already uses `anthropic.Anthropic` or `openai.OpenAI` directly and you do not want to refactor it to `client.chat_completion(...)`, the SDK ships a 3-line drop-in helper that routes the vanilla SDK through Mastio:

```python
import anthropic
from cullis_sdk.providers_compat import cullis_httpx_client

# cullis_httpx_client reads agent.crt + agent.key + ca-chain.pem + dpop.jwk
# from the directory you point at (same layout the admin-minted
# identity-bundle.zip unpacks to). It wires mTLS, DPoP signing, and
# the nonce-retry challenge so the vanilla provider SDK does not need
# to know any of that.
http = cullis_httpx_client(identity_dir="/etc/cullis/agent")

# Hand the httpx client to the vanilla Anthropic SDK. Streaming, tool
# use, prompt caching all work as if you were hitting the Anthropic
# API directly. Every request flows through Mastio and lands in the
# audit chain. The Mastio holds the upstream Anthropic key; the agent
# host never sees it, hence ``api_key="unused"``.
client = anthropic.Anthropic(
    base_url="https://mastio.acme.local:9443/v1",
    api_key="unused",
    http_client=http,
)

msg = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

Same pattern with `openai.OpenAI(base_url="https://mastio.acme.local:9443/v1", api_key="unused", http_client=cullis_httpx_client(identity_dir="..."))`. See `docs/quickstart/provider-sdk-drop-in.md` on the site.

---

## Architecture

```
   ┌──────────┐  mTLS + DPoP   ┌──────────┐    HTTPS     ┌────────────┐
   │  Agent   │───────────────▶│  Mastio  │─────────────▶│ LLM upstr. │
   │ (cullis- │                │  (Cullis │              │ (Anthropic,│
   │   sdk)   │                │  gateway)│              │  OpenAI,   │
   └──────────┘                └────┬─────┘              │  Ollama)   │
                                    │                    └────────────┘
                                    ▼
                              ┌──────────┐
                              │  Audit   │
                              │  chain   │
                              └──────────┘
```

The Mastio is the only component that holds upstream LLM credentials. Per-agent identity flows into every dispatched call as part of the audit trail. The audit chain replays deterministically: an external auditor can verify it offline without holding any Cullis credentials.

The default dispatch path uses Cullis-owned native adapters (official Anthropic and OpenAI SDKs, raw httpx for Ollama). No third-party AI gateway library in the critical path (ADR-039).

---

## Documentation

- Repository: [github.com/cullis-security/cullis](https://github.com/cullis-security/cullis)
- Site: [cullis.io](https://cullis.io)
- Quickstart (SDK): [cullis.io/docs/quickstart/sdk](https://cullis.io/docs/quickstart/sdk)
- Vanilla SDK drop-in: [cullis.io/docs/quickstart/provider-sdk-drop-in](https://cullis.io/docs/quickstart/provider-sdk-drop-in)
- MCP tool calls from the SDK: [cullis.io/docs/quickstart/mcp-tools](https://cullis.io/docs/quickstart/mcp-tools)
- Issues: [github.com/cullis-security/cullis/issues](https://github.com/cullis-security/cullis/issues)

---

## License

Apache 2.0 ([`LICENSE`](https://github.com/cullis-security/cullis/blob/main/cullis_sdk/LICENSE)). Permissive, permanent. The SDK is a permissive component; the Cullis Mastio (`mcp_proxy/`) ships under FSL-1.1-Apache-2.0 (non-competing use, two-year Apache 2.0 future grant) — see [the repo NOTICE file](https://github.com/cullis-security/cullis/blob/main/NOTICE).
