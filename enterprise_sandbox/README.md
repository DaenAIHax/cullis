# Cullis Enterprise Sandbox

Docker compose single-host con 2 org isolate, ognuna con stack enterprise finto (Keycloak IdP, Vault, SPIRE) + Cullis broker/proxy/connector/agent.

**Scopo**: shake-out pre-customer-discovery + asset marketing "prova Cullis da solo".

**Differenza da `demo_network/`**:
- demo_network = 1 broker + 2 proxy (stessa org), pre-merge gate veloce
- enterprise_sandbox = 2 org separate cross-org, Pattern C onboarding, IdP reale

## Status

🚧 **Work in progress** — vedi `imp/enterprise_sandbox_plan.md` per roadmap completa.

Blocco corrente: **1 — Scheletro + 2 broker cross-org** (in progress)

## Quickstart (target)

```bash
./up.sh         # ~90s cold start
./smoke.sh      # ~60s, 10 assertion
./down.sh
```

## Topologia

```
┌──────────────── public-wan ────────────────┐
│    broker-a                  broker-b      │
└────┬────────────────────────────┬──────────┘
     │                            │
┌────┼── orga-internal ──┐   ┌────┼── orgb-internal ──┐
│  proxy-a connector-a   │   │  proxy-b connector-b   │
│  agent-a               │   │  agent-b               │
│  keycloak-a vault-a    │   │  keycloak-b vault-b    │
│  spire-a               │   │  spire-b               │
└────────────────────────┘   └────────────────────────┘
```

Solo i broker attraversano `public-wan`. Tutto il resto è chiuso nella org-internal.

## File di riferimento

- `imp/enterprise_sandbox_plan.md` — piano completo 6 blocchi
- `demo_network/` — pattern base riutilizzato
