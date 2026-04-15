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

Modello federazione Cullis: **1 broker condiviso** + N org che attach-ano la propria CA. Il cross-org avviene via quel broker (zero-knowledge, vede solo ciphertext E2E).

```
┌──────────────── public-wan ────────────────┐
│              broker (shared)               │
└────┬──────────────────────────┬────────────┘
     │                          │
┌────┼── orga-internal ──┐  ┌───┼── orgb-internal ──┐
│  proxy-a  (bridge)     │  │  proxy-b  (bridge)   │
│  connector-a agent-a   │  │  connector-b agent-b │
│  keycloak-a vault-a    │  │  keycloak-b vault-b  │
│  spire-a               │  │  spire-b             │
└────────────────────────┘  └──────────────────────┘
```

Ogni proxy è attached a org-internal + public-wan (fa da bridge). IdP/Vault/SPIRE/agent chiusi dentro org-internal. Le 2 org non si vedono tra loro se non via broker.

## Browser OIDC login (manuale)

Aggiungi al tuo `/etc/hosts`:
```
127.0.0.1 keycloak-a keycloak-b
```

Poi browse:
- Broker dashboard: http://localhost:8000/
- Login via Keycloak-a (Org A): http://localhost:8000/dashboard/oidc/start?role=org&org_id=orga
  - credenziali: `alice` / `alice-sandbox`
- Login via Keycloak-b (Org B): http://localhost:8000/dashboard/oidc/start?role=org&org_id=orgb
  - credenziali: `bob` / `bob-sandbox`
- Keycloak admin-a: http://localhost:8180/ (admin / admin-sandbox)
- Keycloak admin-b: http://localhost:8280/ (admin / admin-sandbox)

## File di riferimento

- `imp/enterprise_sandbox_plan.md` — piano completo 6 blocchi
- `demo_network/` — pattern base riutilizzato
