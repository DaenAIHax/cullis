---
title: "Getting started"
description: "Pick the right enrollment method, understand how the three Cullis components fit together, and go from zero to running agent in under an hour."
category: "Quickstart"
order: 10
updated: "2026-04-23"
---

# Getting started

**Who this is for**: anyone new to Cullis. You'll end this page knowing which of the three Cullis components you need to install, which enrollment method fits your situation, and what to read next.

Cullis gives each AI agent a cryptographic identity, enforces policy at your organization boundary, and records every action in a tamper-evident audit chain. If you want the product pitch, go to [cullis.io](https://cullis.io). This page assumes you're already sold and want to try it.

## The three components, in one picture

```
    ┌────────────────┐
    │   Connector    │  End-user laptop. Turns any MCP client
    │                │  (Claude Desktop, Cursor, Cline, Code CLI)
    │                │  into a Cullis-aware agent.
    └────────┬───────┘
             │  API key + DPoP proof
             ▼
    ┌────────────────┐
    │     Mastio     │  Your organization. Holds agent certs,
    │                │  enforces policy, writes the local audit
    │                │  chain, reverse-proxies MCP resources.
    └────────┬───────┘
             │  Counter-signed envelope
             ▼
    ┌────────────────┐
    │     Court      │  Cross-org network. Routes between
    │                │  Mastios from different companies.
    │                │  You need this only for federation.
    └────────────────┘
```

**Standalone deploys run without the Court.** One Mastio + agents + MCP servers = a single-org Cullis. Add a Court later without re-enrolling anyone.

## Decision tree — which enrollment method?

You enroll each agent once. The method you pick determines how the Mastio verifies the agent the first time; runtime auth is identical in all three cases (API key + DPoP proof).

```
What kind of agent are you enrolling?

├── A human developer on a laptop
│   └── Connector enrollment — OIDC login + admin approval
│       → Install the Connector
│       → docs/enroll/connector-device-code
│
├── A headless service, your org has a PKI
│   └── BYOCA enrollment — cert signed by your Org CA
│       → docs/enroll/byoca
│
├── A K8s workload, SPIRE already issues SVIDs
│   └── SPIRE enrollment — SVID verified against trust bundle
│       → docs/enroll/spire
│
└── I'm not sure yet
    └── Try the sandbox first — it exercises all three
        → docs/quickstart/sandbox-walkthrough
```

At a glance:

| Method | Pick when | Trust anchor at enrollment |
|---|---|---|
| [Connector](../enroll/connector-device-code) | Dev laptops, interactive onboarding | OIDC login + admin approval in the Mastio dashboard |
| [BYOCA](../enroll/byoca) | Programmatic agents, CI/CD, enterprise PKI in place, air-gapped bootstrap | Admin secret + Org-CA-signed cert |
| [SPIRE](../enroll/spire) | K8s workloads under SPIRE | Admin secret + SVID verified against the SPIRE trust bundle |

The admin secret is the Mastio's own secret — not the Court's, not a per-user password. BYOCA and SPIRE use it because they're called non-interactively; the Connector doesn't need it because the admin approves the enrollment from the dashboard in person.

## Three paths from here

### A. I want to see it work first

You have Docker installed, 6 GB free disk, and half an hour. The sandbox boots a complete two-org Cullis network locally — two Mastios, a Court, three agents, two MCP servers, SPIRE, Keycloak, and Vault. It replays intra-org and cross-org scenarios end-to-end.

```bash
git clone https://github.com/cullis-security/cullis
cd cullis
./sandbox/demo.sh full
```

Go to [Sandbox walkthrough](sandbox-walkthrough) for the step-by-step.

### B. I'm a developer, I want to use Cullis from my IDE

Install the Connector on your laptop and enroll against your org's Mastio. The Connector wraps MCP so Claude Desktop, Cursor, Cline, and Claude Code CLI all speak Cullis.

1. Your admin gives you the Mastio URL (`https://mastio.yourcompany.com`)
2. [Install the Connector](../install/connector)
3. Run `cullis-connector enroll` — the [device-code flow](../enroll/connector-device-code) handles the rest
4. Wire the Connector into your MCP client from the dashboard at `http://127.0.0.1:7777`

### C. I'm an operator, I want to deploy a Mastio

Pick the deploy topology that matches your environment:

- **Docker Compose on a single host** — [Self-host the Mastio](../install/mastio-self-host). Good for evaluation, small orgs, air-gapped environments.
- **Kubernetes** — [Mastio on Kubernetes](../install/mastio-kubernetes). Good for multi-node, multi-region, or if Kubernetes is already your deploy target.

Once the Mastio is up:

1. Walk through the [first-boot wizard](../install/mastio-self-host#4-first-boot-wizard) to set the admin password
2. Onboard your agents using one of the three methods above
3. Bookmark [Runbook](../operate/runbook) — incident response for the failures most likely to wake you up

## Runtime — one path for every method

Regardless of how you enrolled, runtime code is identical:

```python
from cullis_sdk import CullisClient

client = CullisClient.from_api_key_file(
    mastio_url="https://mastio.acme.corp",
    api_key_path="/etc/cullis/agent/api-key",
    dpop_key_path="/etc/cullis/agent/dpop.jwk",
)

# Cross-org message, no session state
client.send_oneshot("globex::fulfillment-bot", {"order_id": "A123"})

# Or open a stateful session
session_id = client.open_session("globex::fulfillment-bot")
client.send(session_id, {"hello": "world"})
client.close_session(session_id)
```

Connector-enrolled identities swap the constructor:

```python
client = CullisClient.from_connector()  # reads ~/.cullis/identity/
```

No cert on the wire at runtime. No direct call to the Court. DPoP proof binds every request to the keypair the Mastio pinned at enrollment time.

## Common first-day questions

**Do I need the Court to run Cullis?**
: No. A single Mastio + agents is a complete standalone deploy. Add the Court later if you want cross-org federation — existing agents don't re-enroll.

**Can I have two enrollment methods in the same org?**
: Yes. A Connector-enrolled dev laptop and a BYOCA-enrolled CI agent coexist under the same `org_id`. The Mastio discriminates per-agent, not per-org.

**What happens if the Mastio is down?**
: Agents can't mint new DPoP-bound tokens — no new sessions or messages. Existing tokens stay valid until their 15-minute TTL expires. See [Runbook § Mastio is down](../operate/runbook#1-mastio-is-down) for recovery.

**Is the audit log admissible as legal evidence?**
: Every Mastio's audit is SHA-256 hash-chained and can be anchored against an RFC 3161 TSA for long-term integrity. See [Audit export](../operate/audit-export) for the flow.

## Next

- [Sandbox walkthrough](sandbox-walkthrough) — 30-minute hands-on tour of every flow
- [Install the Connector](../install/connector) — single-user laptop setup
- [Self-host the Mastio](../install/mastio-self-host) — single-host enterprise deploy
- [Runbook](../operate/runbook) — bookmark before production
