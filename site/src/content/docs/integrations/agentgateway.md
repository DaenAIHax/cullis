---
title: "agentgateway integration"
description: "Run agentgateway (agentgateway.dev) as the Rust data plane and Cullis Mastio as the policy + audit control plane. One pilot, two products, no glue code."
category: "Integrations"
order: 10
updated: "2026-05-23"
---

# agentgateway integration

The customer that already runs [agentgateway](https://agentgateway.dev) for the data-plane (Rust unified gateway for HTTP, gRPC, MCP, A2A) doesn't need to swap it out to adopt Cullis. agentgateway handles transport and per-call routing; Cullis handles **identity, policy, and a cryptographically verifiable audit chain that the regulator can replay offline without trusting either vendor**. This page shows the two ways the bridge plugs in.

## What Cullis exposes

The Mastio ships two integration endpoints on the standard `https://mastio.example.com:9443` listener:

- `POST /v1/data/cullis/policy/{path}` — **OPA Data API** compatible. agentgateway is configured with its OPA policy endpoint pointed here; every authorization decision arrives as `{"input": {...}}` and returns `{"result": {"decision": "allow" | "deny", "reason": "..."}}`. Two paths are wired today: `session` (mirror of `/pdp/policy`) and `tool_call` (mirror of `/v1/policy/tool-call`). Any other path returns `{"result": null}`, so agentgateway's own `default` posture takes over for queries Cullis has no opinion on.

- `POST /v1/integrations/cloudevents` — **CloudEvents HTTP binding** sink (binary mode + structured mode). agentgateway already emits OpenTelemetry / CloudEvents for every decision and routed call; point them at this endpoint and each event becomes one append-only row on Cullis' hash-chained `audit_log`. The customer gets one verifiable audit trail covering both planes without writing aggregation code.

Both endpoints share a single HMAC-SHA256 guard: set `MCP_PROXY_INTEGRATIONS_HMAC_SECRET` in `proxy.env`, and every inbound request must carry `X-Cullis-Integration-Signature: <hex(hmac-sha256(body))>`. Without the secret the endpoints accept unsigned calls and the Mastio logs a warning at boot — fine for the rollout window, switch on before the first production traffic.

## Architecture

```
                 ┌────────────────────────┐
   Agent  ──TLS─▶│   agentgateway (Rust)  │──MCP/HTTP─▶  Tools / Models
                 │     - mTLS, TLS-1.3    │
                 │     - LLM routing      │
                 │     - Semantic cache   │
                 └────────────┬───────────┘
                              │
              (a) OPA Data API│        ┌─────────────────────────┐
                              ├───────▶│  /v1/data/cullis/policy │
                              │        │   ↳ policy_rules eval   │
                              │        │   ↳ allow / deny        │
              (b) CloudEvents │        │                         │
                              └───────▶│ /v1/integrations/       │
                                       │      cloudevents        │
                                       │   ↳ audit_log row       │
                                       │   ↳ hash-chained        │
                                       │                         │
                                       │   Cullis Mastio         │
                                       └─────────────────────────┘
                                                  │
                                                  ▼
                                  ┌──────────────────────────────┐
                                  │  cullis-audit-verify.py      │
                                  │  Offline. No Cullis creds.   │
                                  │  Auditor / regulator runs    │
                                  │  it against the NDJSON dump. │
                                  └──────────────────────────────┘
```

The data-plane hot path (agent → tool / model) stays on Rust — full agentgateway throughput, no Python in the way. Cullis is consulted **per decision**, not per byte. The CloudEvents sink is fire-and-forget from agentgateway's perspective; back-pressure on Cullis does not block the data plane.

## Deploy

### 1. Configure Cullis

```bash
# In your Mastio bundle's proxy.env
MCP_PROXY_INTEGRATIONS_HMAC_SECRET=<32+ bytes of random>
```

Then bring up (or restart) the Mastio:

```bash
cd cullis-mastio-bundle && ./deploy.sh
```

Smoke the endpoints from the agentgateway host:

```bash
# OPA Data API — empty policy_rules → default-allow
curl -k -X POST https://mastio.example.com:9443/v1/data/cullis/policy/session \
  -H "Content-Type: application/json" \
  -d '{"input": {"initiator_agent_id": "orga::a", "target_agent_id": "orgb::b", "session_context": "initiator"}}'
# → {"result": {"decision": "allow"}}

# CloudEvents binary mode
curl -k -X POST https://mastio.example.com:9443/v1/integrations/cloudevents \
  -H "ce-id: smoke-1" \
  -H "ce-source: agentgateway://test" \
  -H "ce-type: io.agentgateway.smoke" \
  -H "ce-specversion: 1.0" \
  -H "Content-Type: application/json" \
  -d '{"hello": "world"}'
# → 202 {"status": "recorded", "id": "smoke-1"}
```

### 2. Point agentgateway at Cullis

In your agentgateway config, set the OPA endpoint URL and the CloudEvents exporter target (refer to agentgateway's docs for the exact YAML keys — they evolve faster than this page; the values to plug in are):

- **OPA URL**: `https://mastio.example.com:9443/v1/data/cullis/policy`
- **OPA policy paths** (agentgateway queries these for each decision type):
  - session-open: `session`
  - tool-call: `tool_call`
- **CloudEvents sink URL**: `https://mastio.example.com:9443/v1/integrations/cloudevents`
- **Shared signature secret**: the same value you put in `MCP_PROXY_INTEGRATIONS_HMAC_SECRET`. agentgateway must sign each request body with HMAC-SHA256 keyed on this secret and ship the hex digest in `X-Cullis-Integration-Signature`.
- **CA bundle**: Cullis' self-signed TLS cert is rooted at the Org CA exported under `./certs/org-ca.pem` on the bundle host. Distribute it to the agentgateway host's trust store, or point agentgateway at the file path if it supports a custom CA bundle.

### 3. Verify the bridge end-to-end

Run one agent call through agentgateway and confirm:

```bash
# Cullis dashboard → Audit page shows the agentgateway row(s).
# Filter on `agent_id` starting with ``agentgateway:`` to isolate the
# external-plane history.

# Or via the audit chain CLI:
docker exec cullis-mastio-proxy \
  python /opt/cullis/scripts/cullis-audit-verify.py \
  --tail 10

# The latest rows include ce-source / ce-type from agentgateway,
# hash-chained back to the genesis row — same verifier the regulator
# would run.
```

If you see Cullis' allow / deny decisions reflected in agentgateway's behaviour AND an audit row per call on the dashboard, the bridge is live.

## Mapping reference

### CloudEvent → audit_log

| CloudEvent attribute | audit_log column     | Notes |
|----------------------|----------------------|-------|
| `source`             | `agent_id`           | Prefixed with `agentgateway:` so dashboard queries can isolate external-plane rows from native Cullis ones. |
| `type`               | `action`             | Verbatim. agentgateway's own taxonomy lands here. |
| `subject`            | `tool_name`          | Optional. If absent, the column is `NULL`. |
| `id`                 | `request_id`         | Used by audit chain verification + cross-system tracing. |
| `data`               | `detail` (JSON)      | Embedded under `detail.data` next to the original envelope. |
| `time`               | embedded in `detail` | Cullis stamps its own `timestamp` so the hash chain stays deterministic; the originating `time` is preserved inside `detail.cloudevent.time`. |

### OPA `input` shape

`session` path expects:

```json
{
  "input": {
    "initiator_agent_id": "<org>::<agent>",
    "target_agent_id": "<org>::<agent>",
    "initiator_org_id": "<org>",
    "target_org_id": "<org>",
    "session_context": "initiator | target",
    "capabilities": ["cap.read", "cap.write"]
  }
}
```

`tool_call` path expects:

```json
{
  "input": {
    "agent_id": "<org>::<agent>",
    "tool_name": "kyc_lookup",
    "arguments": { ... }
  }
}
```

The full `arguments` object is passed through but not inspected by today's policy engine — it's there for the operator's own Rego (or the Cullis Policies dashboard) to grow into.

## What stays on each side

| Concern                           | agentgateway | Cullis Mastio |
|-----------------------------------|--------------|---------------|
| TLS termination                   | ✓            |               |
| Per-agent mTLS client cert        | ✓            | ✓ (when calling Mastio directly) |
| LLM routing / token budgeting     | ✓            |               |
| Semantic caching                  | ✓            |               |
| Policy authoring (Rego / YAML)    | ✓ (operator) | ✓ (Cullis Policies dashboard) |
| Policy decision                   |              | ✓             |
| Audit chain (hash-chained, offline-verifiable) |   | ✓             |
| Per-org CA + cert thumbprint pinning |          | ✓             |
| Cloud KMS (Azure / AWS / GCP)     |              | ✓ (enterprise plugins) |
| DPoP RFC 9449 signing             |              | ✓             |
| External regulator-side verifier  |              | ✓ (`cullis-audit-verify.py`) |

The customer keeps both products. Each one does what it's best at. The bridge is two HTTP endpoints, one shared secret, and a CA bundle — no glue code, no schema migrations, no vendor lock-in handshake.
