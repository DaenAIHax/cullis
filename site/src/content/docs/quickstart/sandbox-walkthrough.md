---
title: "Sandbox walkthrough"
description: "Boot the full Cullis sandbox — two orgs, three agents, a Court, two MCP servers, SPIRE + Keycloak + Vault — and replay intra-org and cross-org traffic end-to-end in under 30 minutes."
category: "Quickstart"
order: 20
updated: "2026-04-23"
---

# Sandbox walkthrough

**Who this is for**: anyone who wants to see the whole Cullis network running locally before committing to install it in their own environment. By the end you'll have sent a cross-org message between two companies' agents, watched an MCP tool call flow through the Mastio's reverse-proxy, and inspected the audit chain.

## Prerequisites

- Docker Engine ≥ 24 with Compose v2
- 6 GB free disk, 4 GB free RAM
- 30 minutes
- `curl`, `jq`, `python3` on the host

## What you'll boot

```
Court (broker)           http://localhost:8000
  Keycloak A (alice)     http://localhost:8180
  Keycloak B (bob)       http://localhost:8280

Org A (Acme Corp)
  Mastio A               http://localhost:9100
  Agent A (orga::agent-a)
  MCP server: catalog    (reverse-proxied under Mastio A)
  SPIRE A

Org B (Globex Inc)
  Mastio B               http://localhost:9200
  Agent B (orgb::agent-b)
  MCP server: inventory  (reverse-proxied under Mastio B)
  SPIRE B
```

Two modes:

- **`demo.sh up`** — Court + Org B fully wired; Org A's Mastio is standalone and **not** yet on the Court. You complete Org A's onboarding yourself by walking through the attach-ca + counter-signature pin + enrollment flow. Best for learning the onboarding protocol.
- **`demo.sh full`** — everything pre-wired. Skip straight to scenarios. Best for demoing.

## 1. Boot the stack

```bash
git clone https://github.com/cullis-security/cullis
cd cullis
./sandbox/demo.sh full
```

Expected output (elided):

```
═══ Enterprise Sandbox — Tier 2 (fully wired) ═══
  • booting services (this takes ~60s)…

═══ Services Running ═══
NAME                 STATUS    PORTS
sandbox-broker-1     Up        0.0.0.0:8000->8000/tcp
sandbox-proxy-a-1    Up        0.0.0.0:9100->9100/tcp
sandbox-proxy-b-1    Up        0.0.0.0:9200->9200/tcp
sandbox-agent-a-1    Up
sandbox-agent-b-1    Up
sandbox-mcp-catalog-1    Up
sandbox-mcp-inventory-1  Up
sandbox-keycloak-a-1     Up
sandbox-keycloak-b-1     Up
sandbox-spire-a-1        Up
sandbox-spire-b-1        Up
sandbox-postgres-1       Up
sandbox-vault-1          Up

═══ Dashboard URLs ═══
  Court (broker)      http://localhost:8000/dashboard/setup
                      (admin password already set)
  Mastio A (proxy-a)  http://localhost:9100/proxy
                      admin secret: sandbox-proxy-admin-a
  Mastio B (proxy-b)  http://localhost:9200/proxy
                      admin secret: sandbox-proxy-admin-b
```

## 2. Try intra-org traffic — MCP tool call

Agent A calls the catalog MCP server through its own Mastio. No Court in the path.

```bash
./sandbox/demo.sh mcp-catalog
```

Expected:

```
═══ Intra-org MCP call — orga::agent-a → get_catalog ═══
  [agent-a] requesting: get_catalog
  [agent-a] ✓ 200 OK
  [agent-a] response: [
      {"sku": "WIDGET-1", "name": "Widget Mk I",  "price": 1299},
      {"sku": "WIDGET-2", "name": "Widget Mk II", "price": 2399}
    ]
```

What happened under the hood:

1. `agent-a` presented its API key + DPoP proof to Mastio A
2. Mastio A verified the binding (agent-a has `order.read` scope bound to the catalog MCP)
3. Mastio A reverse-proxied the JSON-RPC call to the catalog MCP server, stripping the Cullis auth and adding the MCP server's expected upstream headers
4. Mastio A logged the call in its local audit chain

`./sandbox/demo.sh mcp-inventory` runs the symmetric flow for agent-b on Org B.

## 3. Try cross-org traffic — A2A one-shot

Agent A sends an encrypted message to Agent B at Globex. The Court routes, but doesn't read the payload.

```bash
./sandbox/demo.sh oneshot-a-to-b
```

Expected:

```
═══ Cross-org A2A — orga::agent-a → orgb::agent-b (via Court) ═══
  [agent-a] wrapping envelope: { nonce: 3f4a..., to: orgb::agent-b }
  [agent-a] Mastio A counter-signed, posting to Court
  [agent-a] ✓ delivered, message_id: 01JXF...
  [agent-b] received envelope from orga::agent-a
  [agent-b] verified Court signature + Mastio A counter-sig
  [agent-b] decrypted payload: { nonce: 3f4a..., greeting: "hi from acme" }
  [agent-b] ✓ replay check passed
```

Under the hood:

1. agent-a built an ADR-008 sessionless envelope (ECDH P-256 key agreement, AES-256-GCM payload)
2. Mastio A counter-signed the envelope (ADR-009) proving *this* proxy minted the token the Court is about to see
3. Court verified Mastio A's counter-signature against the pinned pubkey, then routed the envelope to Mastio B
4. Mastio B handed the envelope to agent-b, which decrypted with its P-256 private key
5. Both Mastios and the Court wrote audit rows, cross-referenced by message id

`oneshot-b-to-a` runs the reverse direction.

## 4. Watch the dashboards

### Court (broker)

Open `http://localhost:8000/dashboard/login`. Admin password was printed at `./sandbox/demo.sh full` time. The **Orgs** tab lists `orga` and `orgb`, both `active`. Click `orga` to see its pinned Mastio pubkey (ADR-009), the attach-ca invite history, and the federation publisher last-tick timestamp.

### Mastio A

Open `http://localhost:9100/proxy`. Log in with `sandbox-proxy-admin-a`. The Overview tab lists the enrolled agents. The **Audit** tab shows the hash-chained events from the two scenarios you just ran. The **MCP resources** tab shows the catalog MCP server registered under Mastio A and the bindings tying it to agent-a.

### Mastio B

Same at `http://localhost:9200/proxy` with `sandbox-proxy-admin-b`. Symmetrical view — you'll see the inbound A2A messages from step 3 in the audit.

## 5. Exercise the Connector enrollment flow

The sandbox boots with pre-enrolled demo agents (BYOCA path). To experience the Connector enrollment flow end-to-end, run `demo.sh up` instead of `demo.sh full`:

```bash
./sandbox/demo.sh down   # tear down the fully-wired stack
./sandbox/demo.sh up     # bring up Tier 1 with Org A NOT yet on the Court
```

Then follow the [sandbox GUIDE](https://github.com/cullis-security/cullis/blob/main/sandbox/GUIDE.md) — four steps that walk you through:

1. Creating an org shell on the Court + minting an attach-ca invite
2. Redeeming the invite from Mastio A (browser or curl)
3. Pinning Mastio A's counter-signature pubkey on the Court (ADR-009)
4. Downloading the Connector from `http://localhost:9100/downloads`, enrolling Alice via device-code, and approving from the Mastio admin dashboard

That's the flow a real customer walks through on first deploy. The `demo.sh full` mode does all four steps for you; `up` makes them explicit so you can see what each one accomplishes.

## 6. Verify the audit chain

```bash
curl -s "http://localhost:9100/v1/admin/audit/head" \
    -H "X-Admin-Secret: sandbox-proxy-admin-a" | jq
```

```json
{
  "last_id": "01JXF2T4RKBQWM5VS6JJGA7SRV",
  "last_hash": "9e0c...a55d",
  "last_timestamp": "2026-04-23T19:44:07Z"
}
```

Export a bundle and verify it:

```bash
curl -sX POST http://localhost:9100/v1/admin/audit/bundle \
    -H "X-Admin-Secret: sandbox-proxy-admin-a" \
    -H "Content-Type: application/json" \
    -d '{"start": "2026-04-01T00:00:00Z", "end": "2026-04-30T23:59:59Z"}' \
    -o sandbox-april.bundle.tar.gz

cullis audit verify sandbox-april.bundle.tar.gz
```

Expected: all checks `✓`, `Bundle is authentic`. See [Audit export](../operate/audit-export) for the full bundle shape and the external-witness pattern.

## 7. Tear down

```bash
./sandbox/demo.sh down
```

All containers stop; the volumes drop with them. A fresh `./sandbox/demo.sh full` or `up` re-bootstraps from scratch — nothing persists across teardowns.

## Troubleshoot

**`demo.sh full` hangs on "booting services"**
: Docker needs ~6 GB free disk and ~4 GB RAM for the stack. Check `docker system df` and prune if needed. On low-memory machines, pass `demo.sh up` instead — it skips the second Mastio and trims memory pressure.

**`oneshot-a-to-b` returns `401 counter_signature_required`**
: You ran `demo.sh up` but didn't complete the attach-ca + counter-sig pin (step 3 of the GUIDE). Either finish the GUIDE or tear down and run `demo.sh full`.

**`mcp-catalog` returns `403 binding_not_approved`**
: The binding between `agent-a` and the catalog MCP server didn't come up cleanly. Check `./sandbox/demo.sh logs proxy-a | grep binding`. If a race happened at bootstrap, `./sandbox/demo.sh down && ./sandbox/demo.sh full` restarts clean.

**Port clash on 8000 / 9100 / 9200 / 8180 / 8280**
: Something else on your host is listening on those ports. `lsof -i :9100` to find it; kill or move the other service. The sandbox doesn't let you remap ports today — tracked for a future release.

## Next

- [Getting started § decision tree](getting-started#decision-tree--which-enrollment-method) — pick the right enrollment method for your real deploy
- [Install the Connector](../install/connector) — the client your developers will use
- [Self-host the Mastio](../install/mastio-self-host) — single-host production deploy
- [Runbook](../operate/runbook) — incident response for when the sandbox isn't there to help
- [Connector device-code enrollment](../enroll/connector-device-code) — the protocol the `up` mode makes you walk through by hand
