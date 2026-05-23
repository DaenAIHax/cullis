---
title: "Policy bridge — Cullis as OPA PDP + CloudEvents sink"
description: "Expose Cullis Mastio's policy decisions over the OPA Data API and accept any external CloudEvents emitter as an audit-log source. Plug Cullis into an existing agent infrastructure without rewriting the data plane."
category: "Integrations"
order: 10
updated: "2026-05-23"
---

# Policy bridge

A customer who already runs an agent infrastructure component for the data plane — a gateway, proxy, mesh, or framework adapter — does not need to replace it to adopt Cullis. Cullis exposes its policy + audit surface over two standards-shaped HTTP endpoints. Anything that already speaks the OPA Data API contract and emits CloudEvents can plug in.

## What Cullis exposes

- `POST /v1/data/cullis/policy/{path}` — **OPA Data API** compatible. The external component points its OPA endpoint here; every authorization decision arrives as `{"input": {...}}` and returns `{"result": {"decision": "allow" | "deny", "reason": "..."}}`. Two paths are wired today: `session` (mirror of `/pdp/policy`) and `tool_call` (mirror of `/v1/policy/tool-call`). Unknown paths return `{"result": null}`, OPA's convention for "document undefined", so the caller's own `default` posture takes over for queries Cullis has no opinion on.

- `POST /v1/integrations/cloudevents` — **CloudEvents HTTP binding** sink (binary mode + structured mode). Any component that already emits OpenTelemetry / CloudEvents for its decisions and routed calls can target this endpoint; each event becomes one append-only row on Cullis' hash-chained `audit_log`. The customer gets one verifiable audit trail covering both planes without writing aggregation code.

Both endpoints share a single HMAC-SHA256 guard. Set `MCP_PROXY_INTEGRATIONS_HMAC_SECRET` in `proxy.env` and every inbound request must carry `X-Cullis-Integration-Signature: <hex(hmac-sha256(body))>`. Without the secret the endpoints accept unsigned calls and the Mastio logs a warning at boot — convenient during the rollout window, switch on before the first production traffic.

## Architecture

```
   Agent  ──TLS─▶  External data plane  ──MCP/HTTP─▶  Tools / Models
                   (any gateway / mesh /
                    framework adapter)
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

The data-plane hot path stays on whatever component the customer chose. Cullis is consulted **per decision**, not per byte. The CloudEvents sink is fire-and-forget from the caller's perspective; back-pressure on Cullis does not block the data plane.

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

Smoke the endpoints from the external host:

```bash
# OPA Data API — empty policy_rules → default-allow
curl -k -X POST https://mastio.example.com:9443/v1/data/cullis/policy/session \
  -H "Content-Type: application/json" \
  -d '{"input": {"initiator_agent_id": "orga::a", "target_agent_id": "orgb::b", "session_context": "initiator"}}'
# → {"result": {"decision": "allow"}}

# CloudEvents binary mode
curl -k -X POST https://mastio.example.com:9443/v1/integrations/cloudevents \
  -H "ce-id: smoke-1" \
  -H "ce-source: gateway://test" \
  -H "ce-type: io.gateway.smoke" \
  -H "ce-specversion: 1.0" \
  -H "Content-Type: application/json" \
  -d '{"hello": "world"}'
# → 202 {"status": "recorded", "id": "smoke-1"}
```

### 2. Configure the external component

In the calling component's config, set:

- **OPA endpoint URL**: `https://mastio.example.com:9443/v1/data/cullis/policy`
- **OPA policy paths** (the component queries these for each decision type):
  - session-open: `session`
  - tool-call: `tool_call`
- **CloudEvents sink URL**: `https://mastio.example.com:9443/v1/integrations/cloudevents`
- **Shared signature secret**: the same value you put in `MCP_PROXY_INTEGRATIONS_HMAC_SECRET`. The caller must sign each request body with HMAC-SHA256 keyed on this secret and ship the hex digest in `X-Cullis-Integration-Signature`.
- **CA bundle**: Cullis' self-signed TLS cert is rooted at the Org CA exported under `./certs/org-ca.pem` on the bundle host. Distribute it to the calling host's trust store, or point it at the file path if it supports a custom CA bundle.

The actual YAML / config keys differ by product. Consult the calling component's own documentation for the exact field names; the values above are what you plug in.

### 3. Verify the bridge end-to-end

Run one agent call through the data plane and confirm:

```bash
# Cullis dashboard → Audit page shows the bridged row(s). Filter on
# agent_id starting with ``external:`` to isolate the bridge history
# from native Cullis agents.

# Or via the audit chain CLI:
docker exec cullis-mastio-proxy \
  python /opt/cullis/scripts/cullis-audit-verify.py \
  --tail 10

# The latest rows include ce-source / ce-type from the caller,
# hash-chained back to the genesis row — same verifier the regulator
# would run.
```

If Cullis' allow / deny decisions are reflected in the caller's behaviour AND an audit row per call appears on the dashboard, the bridge is live.

## Mapping reference

### CloudEvent → audit_log

| CloudEvent attribute | audit_log column     | Notes |
|----------------------|----------------------|-------|
| `source`             | `agent_id`           | Prefixed with `external:` so dashboard queries can isolate bridge rows from native Cullis ones. |
| `type`               | `action`             | Verbatim. The caller's own taxonomy lands here. |
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

| Concern                           | External data plane | Cullis Mastio |
|-----------------------------------|---------------------|---------------|
| TLS termination                   | ✓                   |               |
| Per-agent mTLS client cert        | ✓                   | ✓ (when calling Mastio directly) |
| LLM routing / token budgeting     | ✓                   |               |
| Semantic caching                  | ✓                   |               |
| Policy authoring (Rego / YAML)    | ✓ (operator)        | ✓ (Cullis Policies dashboard) |
| Policy decision                   |                     | ✓             |
| Audit chain (hash-chained, offline-verifiable) |        | ✓             |
| Per-org CA + cert thumbprint pinning |                  | ✓             |
| Cloud KMS (Azure / AWS / GCP)     |                     | ✓ (enterprise plugins) |
| DPoP RFC 9449 signing             |                     | ✓             |
| External regulator-side verifier  |                     | ✓ (`cullis-audit-verify.py`) |

The customer keeps both products. Each one does what it's best at. The bridge is two HTTP endpoints, one shared secret, and a CA bundle — no glue code, no schema migrations, no vendor lock-in handshake.
