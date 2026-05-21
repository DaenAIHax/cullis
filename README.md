<p align="center">
  <img src="branding/cullis-mark.svg" alt="Cullis" width="120"><br><br>
  <strong>Cullis. Zero-trust governance layer for autonomous AI agents in regulated environments.</strong><br>
  Self-hosted. LLM-agnostic. FSL-1.1+Apache-2.0.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11-blue.svg" alt="Python"></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-alpha-yellow.svg" alt="Status: alpha"></a>
</p>

---

## What Cullis does

Banks, insurers, and other regulated organizations are starting to put AI agents into production paths that touch real customer data and real money. A KYC screener calling a sanctions API. A pitchbook builder pulling MNPI off the deal-room drive. A vendor-risk reporter aggregating evidence for DORA Article 28. The agent code is the easy part. Proving to a regulator, eighteen months later, that the agent acted with the authority it claimed, on the inputs it claimed, and that nothing in the chain has been tampered with, is the hard part.

Cullis sits underneath any agent stack (Claude Agent SDK, OpenAI Agents SDK, custom loops) and provides the three primitives a regulated deployment is missing: per-agent cryptographic identity bound to whoever or whatever authorized the agent, a policy decision point that runs before the LLM call lands, and a hash-chained append-only audit log that an external auditor can verify without trusting Cullis or your IT team.

Cullis is LLM-agnostic by design. The embedded gateway routes to Anthropic, OpenAI, Gemini, or Ollama via LiteLLM, and an alternative AI gateway can be wired in as a sidecar. The identity, policy, and audit primitives stay the same.

---

## Cullis Mastio

Mastio is the gateway. One container, one organization, one source of truth for every agent action that touches the LLM or an MCP tool inside that organization. It runs standalone, air-gapped if you need it to be, with no external service dependency.

**Identity.** Each agent receives an x509 leaf certificate signed by an organization-owned CA, bound to a SPIFFE SAN, pinned by thumbprint. The certificate is the credential. The Mastio rejects any token presented without the matching client certificate (mTLS RFC 8705 §3) and verifies a DPoP proof (RFC 9449) on every authenticated request, refusing plain Bearer tokens outright.

**Policy.** A policy decision point evaluates each request before the LLM or MCP tool is reached. Default-deny for new sessions, default-allow for messages with optional restrictions. An OPA bundle or a webhook backend is supported, both fail safe on timeout. Capability gates apply per agent and per typed principal (user, workload, agent), so a Frontdesk user can never invoke an agent-only tool by accident.

**Audit.** Every accepted action lands as a row in an append-only audit log, hash-chained per organization, optionally anchored to RFC 3161 TSA on a configurable cadence. The chain replays deterministically: an external auditor can verify it offline without holding any Cullis credentials.

**Embedded AI gateway.** LiteLLM is bundled. Anthropic, OpenAI, Gemini, and Ollama work out of the box, and per-agent identity is propagated into every upstream call as part of the audit trail. The provider can be switched by env var without touching agent code.

**MCP reverse proxy.** Mastio terminates MCP traffic from agents, applies the capability gate, propagates the agent identity into the tool call, and logs the result. Both stdio and HTTP transports are supported. Resources are declared per tool with explicit allowed-domain lists.

**Admin API.** A small set of administrative endpoints covers agent enrollment (CSR + BYOCA), cert rotation, policy push, audit export, AI-provider configuration, and user principal management. Everything an org admin needs in production is reachable both from the dashboard and from `curl`.

---

## Cullis SDK (Python, for autonomous agents)

`cullis-sdk` is the Python client an autonomous agent uses to talk to Mastio. It handles mTLS client cert presentation, DPoP signing, token refresh, and request retries, exposing a small surface that maps onto what an agent actually does: ask the LLM something, list the MCP tools it is allowed to call, call one, and let the audit trail accumulate underneath.

The canonical entry point is `CullisClient.from_identity_dir(...)`, which takes the path to the leaf cert, the matching private key, and an optional DPoP private JWK that the SDK uses to sign each egress request. The cert and key are the credential. There is no shared API key to leak.

`chat_completion` and `chat_completion_stream` route through Mastio's `/v1/llm/chat` endpoint. The provider, the model, and the upstream API key are configured org-side, in the Mastio dashboard. The agent never sees the upstream key, and every prompt and response is audit-logged with the agent identity attached.

`list_mcp_tools` returns the tools the agent is allowed to invoke (the capability gate decides). `call_mcp_tool(name, arguments)` invokes one; Mastio enforces the gate again on the server side, applies the policy, and writes an audit row. The same identity that authenticated the SDK call is propagated into the MCP server.

```python
from cullis_sdk import CullisClient

client = CullisClient.from_identity_dir(
    "https://mastio.example.com:9443",
    cert_path="./identity/agent.crt",
    key_path="./identity/agent.key",
    dpop_key_path="./identity/dpop.jwk",
    agent_id="kyc-screener",
    org_id="acme",
)

response = client.chat_completion({
    "model": "claude-sonnet-4-6",
    "messages": [{"role": "user", "content": "Screen the latest applicant batch."}],
})

for tool in client.list_mcp_tools():
    print(tool["name"], tool.get("description", ""))

result = client.call_mcp_tool(
    "sanctions_lookup",
    {"full_name": "Acme Holding Ltd"},
)
```

---

## Quickstart

Pull the Mastio bundle, deploy it, enroll an agent identity, install the SDK, run an agent loop. The Mastio bundle is a self-contained `docker compose` stack with first-boot Org CA minting, an admin account, and a dashboard.

```bash
# 1. Mastio
curl -L https://github.com/cullis-security/cullis/releases/download/mastio-v0.5.1/cullis-mastio-bundle.tar.gz | tar xz
cd cullis-mastio-bundle && ./deploy.sh

# 2. Open https://localhost:9443/proxy/login, accept the self-signed TLS warning,
#    create the admin account, mint an agent identity bundle from the dashboard,
#    download the zip and unpack it into ./identity/.

# 3. SDK
pip install cullis-sdk
```

Then point your agent at the identity dir using the code example above. The first request lands as an audit row visible in the dashboard under `Audit`.

The Mastio bundle README in `packaging/mastio-bundle/` covers custom hostnames, Postgres and Vault production overrides, oauth2-proxy integration, and the upgrade procedure.

---

## Project layout

```
mcp_proxy/         Cullis Mastio (org gateway, FastAPI)
cullis_sdk/        Cullis SDK (Python client + MCP server)
packaging/         Release bundles (Mastio container bundle, SDK PyPI build)
deploy/            Helm chart + Docker Compose for the Mastio
nginx/             TLS sidecar config used by the Mastio bundle
docs/              cullis.io site source, ops runbooks, ratified ADRs
scripts/           Maintainer scripts (env generation, audit verification, Postgres backup)
site/              cullis.io Astro site
```

Runtime: Python 3.11, FastAPI, PostgreSQL 16, Redis, HashiCorp Vault (optional), `cryptography`, PyJWT, OpenTelemetry, Prometheus, OPA (optional), Docker, Helm.

---

## Status

Alpha. The Mastio runs end-to-end on a laptop and ships from a public release train with a multi-track security audit on every release. External certification and pilot validation are in progress, not done.

| Component | Latest | What it is |
|---|---|---|
| **Cullis Mastio** | [`mastio-v0.5.1`](https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.1) | Org gateway, agent CA, policy enforcement, audit chain, MCP reverse proxy, embedded AI gateway |
| **Cullis SDK** | [`cullis-sdk 0.1.3`](https://pypi.org/project/cullis-sdk/) | Python client used by autonomous agents to talk to Mastio |

Use Cullis in evaluation, integration, and internal deploys. Talk to us before putting it in front of regulated production traffic.

---

## License

Split licensing.

- **Cullis Mastio (`mcp_proxy/`)** under [FSL-1.1-Apache-2.0](LICENSE). Non-competing use permitted (internal deployments, services, research, modifications, forks). Each release becomes [Apache 2.0](LICENSE-APACHE-2.0) two years after publication.
- **Cullis SDK (`cullis_sdk/`)** under [Apache 2.0](cullis_sdk/LICENSE). Permissive, permanent.

See [NOTICE](NOTICE) for the component-by-component map.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, PR workflow, and code conventions.

Security vulnerabilities: [SECURITY.md](SECURITY.md) for private reporting.

## Contact

General, partnerships, demos: [hello@cullis.io](mailto:hello@cullis.io)

Security (private): [security@cullis.io](mailto:security@cullis.io) and [SECURITY.md](SECURITY.md)

Bugs, feature requests: [GitHub Issues](https://github.com/cullis-security/cullis/issues)

---

> Architecture deep-dives, deployment patterns, and the project's reason for existing live at **[cullis.io](https://cullis.io)**.
