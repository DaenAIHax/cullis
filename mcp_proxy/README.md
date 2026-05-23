# `mcp_proxy` — Cullis Mastio

**The org-level trust authority for autonomous AI agents.**

This directory implements **Cullis Mastio**, the per-organization gateway that an org admin deploys inside their own infrastructure. The directory is named `mcp_proxy/` for historical reasons; the brand name `Mastio` and the directory name `mcp_proxy/` refer to the same thing. Same for the Python package import path (`from mcp_proxy import ...`) and the published wheel name (`cullis-mastio` on PyPI from v0.3.x onwards).

The Cullis Mastio is one of two public components in this repo. The other is the [Python SDK](../cullis_sdk/) (`cullis-sdk`) used by autonomous agents to talk to the Mastio.

## What the Mastio does

- Issues **agent identity** (x509 leaf certificates with SPIFFE SAN, with BYOCA support).
- Enforces **per-org policy** (default-deny session, default-allow message, PDP webhook with fail-safe deny-on-timeout, per-tool capability gate).
- Records a **local hash-chain audit** that never leaves the org, optionally anchored to an RFC 3161 TSA.
- Acts as the **MCP reverse-proxy** between in-org agents and the MCP servers exposed by the org, propagating agent identity into every tool call.
- Hosts the **embedded AI gateway** (LiteLLM in-process by default), so per-principal egress policy is enforced at the same trust boundary as MCP.

## Code layout

```
main.py            FastAPI app, lifespan, routers
config.py          Settings (env vars, MCP_PROXY_* prefix)
db.py / db_models.py  SQLAlchemy async models
admin/             Org admin API + dashboard backend
agents/            Agent enrollment, cert lifecycle, rotation
auth/              x509 + JWT + DPoP enforcement
audit/             Local hash chain, TSA anchoring
dashboard/         Admin web UI (Jinja2 + HTMX + Tailwind)
egress/            AI gateway dispatcher + LiteLLM embedded backend
enrollment/        Device-code, BYOCA, SPIFFE enrollment flows
ingress/           Inbound A2A receiver, decrypt + verify
middleware/        Auth + DPoP + rate limit + CORS
observability/     OpenTelemetry, custom metrics
pki/               CA chain, cert issuance, revocation
policy/            PDP webhook, default rules
rbac.py            Multi-admin RBAC
redis/             Connection pool
registry/          Local agent registry
reverse_proxy/     MCP reverse-proxy (auto-inject Cullis identity)
spiffe.py          SPIFFE ID translation
tools/             Builtin MCP tools + tool capability gate
```

## MCP builtin: `cullis_send_to_agent`

The Mastio's MCP aggregator (`POST /v1/mcp`) ships with a builtin tool that lets any MCP client ask the model to send a one-shot message to another Cullis agent without writing transport code. Identity propagation + audit chain are handled server-side — the model only supplies recipient and content.

```jsonc
// JSON-RPC tools/call body
{
  "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": {
    "name": "cullis_send_to_agent",
    "arguments": {
      "target_agent_id": "mario",              // bare name, or "orgb::mario", or "spiffe://..."
      "target_org_id": "orgb",                  // optional; defaults to caller's org
      "content": "lavoro finito",               // string -> {"text": ...}, or pass a dict
      "correlation_id": "corr-abc",             // optional; server generates one when omitted
      "reply_to": "msg-prev",                   // optional
      "ttl_seconds": 300                        // optional; default 5 min, max 1 h
    }
  }
}
```

Response shape (success):

```jsonc
{
  "correlation_id": "...", "msg_id": "...",
  "status": "enqueued", "target_agent_id": "...", "target_org_id": "..."
}
```

Errors come back as `{ "error": "reach_denied" | "policy_denied" | "invalid_recipient" | "send_failed" | "invalid_parameters", "reason": "..." }` so the model can branch in-band. The Mastio audit chain still captures the specific detail for ops.

Capability gate: agents need `cullis.a2a.send` in their scope. Typed principals (user / workload) bypass the scope check — their binding table is the authoritative authz — but the same reach + policy + audit gates apply.

## Running

For local dev and demos, use the Mastio bundle:

```bash
cd ../packaging/mastio-bundle
./deploy.sh
# https://localhost:9443/proxy/login
```

For Kubernetes, see the [Helm chart](../deploy/helm/cullis-mastio/) and the install guide at [cullis.io/docs/install/mastio-kubernetes](https://cullis.io/docs/install/mastio-kubernetes/).

The Mastio also ships as a PyPI wheel `cullis-mastio` for embedded deployments.
