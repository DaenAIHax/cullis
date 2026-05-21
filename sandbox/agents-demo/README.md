# Cullis reference demo agents

Three reference AI agents that exercise Cullis governance primitives
(per-agent identity, capability gate, hash-chained audit log, cross-org
A2A) under different LLM stacks to prove the governance layer is
LLM-agnostic. They map 1:1 to the regulated-EU agent selection in
`imp/2026-05-21-strategic-decisions.md` (D3) and the frustrated-pilot
dossier `imp/2026-05-21-frustrated-pilots-research.md`.

## The three agents

| Agent | LLM | Loop runtime | Quadrant (ADR-020) | Regulatory hook |
|---|---|---|---|---|
| [KYC Screener](agent_kyc_screener/README.md) | Claude Haiku 4.5 | **Claude Agent SDK** (`main_sdk.py`) + litellm + Mastio variants | U2A | EU AI Act Art. 12 + 14 + Annex III |
| [Pitchbook Builder](agent_pitchbook_builder/README.md) | Claude Haiku 4.5 | litellm chat completions | U2A + A2A intra-org (Chinese Wall) | EU AI Act Art. 13 + MAR / Information Barriers |
| [DORA Vendor/TPA Reporter](agent_dora_reporter/README.md) | **Ollama on-prem** (default `mistral-small`) | litellm chat completions | A2A cross-org | DORA Art. 28 + EU AI Act Art. 12 |

The three agents demonstrate Cullis governance under **three different
loop drivers** on purpose: KYC uses the official Anthropic
`claude-agent-sdk` (proves Cullis composes with native Claude tooling),
Pitchbook uses the LLM-agnostic litellm pattern (proves Cullis is not
locked to one SDK), DORA uses litellm against on-prem Ollama (proves
Cullis governs even SaaS-free deployments — a DORA Art. 28 control by
itself).

The KYC + Pitchbook agents demonstrate that **Cullis governs cloud
LLMs** (Claude via Anthropic) — the audit chain, capability gate and
Chinese Wall enforcement run regardless of which Claude tier the agent
is calling. The DORA Reporter demonstrates that **Cullis governs
on-prem LLMs** — same primitives, no SaaS LLM contacted at all, which
is itself a DORA Art. 28 control (vendor risk data does not leave the
bank perimeter while drafting the register that names LLM providers as
third parties).

## Two modes of operation

The repo ships each agent in **two forms** sharing the same system prompt
+ tools + capability YAML + tests, with different runtime targets:

| File | Runtime target | Audit / gate | When to use |
|---|---|---|---|
| `agent_*/main.py` | Standalone Python process | Local `AuditChain` + `CapabilityGate` from `shared/` | CI tests, offline reading, mock LLM (no API key needed) |
| `agent_*/main_stack.py` | `./stack/demo.sh` running locally | Production Mastio audit chain + PDP + `local_agent_resource_bindings` gate | Live demo, Cullis primitives end-to-end |

The standalone form makes the governance pattern legible without
infrastructure dependency; the stack form proves the same code runs
under the production gate.

## How to run

### Standalone (no infra; runs in CI)

```bash
pytest sandbox/agents-demo/ -v
```

All ten E2E tests use deterministic `MockLLMClient` scripts. No API
keys, no Docker, no network.

### Standalone with a real LLM

```bash
export CULLIS_AGENT_DEMO_MODE=live
export ANTHROPIC_API_KEY=sk-ant-...        # for KYC + Pitchbook
# ollama serve + ollama pull mistral-small for DORA

python -m sandbox.agents-demo.agent_kyc_screener.main         # CLI demo
python -m sandbox.agents-demo.agent_pitchbook_builder.main
python -m sandbox.agents-demo.agent_dora_reporter.main
```

The same `main.py` switches to a real LiteLLM client when
`CULLIS_AGENT_DEMO_MODE=live`.

### Against a running Cullis Mastio deployment

`main_stack.py` is a generic CLI that connects to any Mastio +
Court deployment over mTLS + DPoP via the `cullis_sdk` runtime. The
prerequisites are out-of-band:

1. A Cullis Mastio + Court instance reachable to your machine.
2. Three BYOCA agent identities enrolled on that Mastio with the
   capabilities declared in each agent's `capabilities.yaml`:
   `orga::kyc-screener`, `orga::pitchbook-builder`, `orga::dora-reporter`.
3. Their per-agent identity material (`agent.pem`, `agent-key.pem`,
   `dpop.jwk`) materialised on disk, plus the Org A CA chain for
   verify_tls.
4. The MCP tool servers exposed via the Mastio MCP aggregator with
   active bindings (one resource per tool name, see each agent's
   tool list under `tools.py`). The Mastio embedded LiteLLM gateway
   must have `MCP_PROXY_ANTHROPIC_API_KEY` configured for the two
   Claude-backed agents; the DORA Reporter uses Ollama on-prem via
   `host.docker.internal:11434` and needs no API key.

Once that is in place, invoke any of the three CLIs:

```bash
python sandbox/agents-demo/agent_kyc_screener/main_stack.py \
    --case-id case_demo_001 \
    --document-id doc_low_risk_retail \
    --mastio-url https://localhost:9443 \
    --identity-dir ./.data/agents-demo/kyc-screener \
    --ca-chain ./.data/agents-demo/_ca/ca.pem

python sandbox/agents-demo/agent_pitchbook_builder/main_stack.py \
    --target IndustrialDemoA \
    --desk industrials \
    --mastio-url https://localhost:9443 \
    --identity-dir ./.data/agents-demo/pitchbook-builder \
    --ca-chain ./.data/agents-demo/_ca/ca.pem

python sandbox/agents-demo/agent_dora_reporter/main_stack.py \
    --report-id dora_2026_q2 \
    --target-auditor-org auditor_org_demo \
    --role compliance_officer \
    --mastio-url https://localhost:9443 \
    --identity-dir ./.data/agents-demo/dora-reporter \
    --ca-chain ./.data/agents-demo/_ca/ca.pem
```

The Cullis maintainers run this against a local-only dogfood stack
that bootstraps Court + 2 Mastios + Frontdesk + the 3 MCP tool
servers, mints + enrols all agent identities and seeds the
bindings. That stack is operator-side infra, not part of this repo.

## Directory layout

```
sandbox/agents-demo/
  README.md                     # this file
  conftest.py                   # sys.path bootstrap for the dash-named dir
  shared/
    __init__.py
    audit_hooks.py              # hash-chained RSA-PSS audit chain
    capability_gate.py          # YAML-driven fail-closed evaluator
    llm_client.py               # MockLLMClient + LiteLLMClient + default_client()
    test_fixtures.py            # 100% synthetic mock data
  agent_kyc_screener/
    README.md                   # use case + EU AI Act mapping + evidence quote
    system_prompt.md
    tools.py                    # standalone tool handlers (with local gate + audit)
    capabilities.yaml
    main.py                     # standalone entry (local audit + gate)
    main_stack.py               # stack entry (Mastio audit + gate)
    test_e2e.py                 # 4 scenarios, MockLLMClient, all green in CI
  agent_pitchbook_builder/
    ...                         # same shape, 5 tools, 3 scenarios
  agent_dora_reporter/
    ...                         # same shape, 4 tools, 3 scenarios
```

## What is NOT in the demo

- **Per-tool capability binding within a single MCP server**. The
  production Mastio gates per-resource (an MCP server is one authz
  unit); fine-grained per-tool gating is future ADR work. For the
  Pitchbook Chinese Wall, the desk-scope check therefore lives in the
  agent loop on the standalone form (`CapabilityGate.require` with
  `from_context: memo_desk`) and in the LLM-side discipline on the
  stack form (system prompt + post-hoc audit cross-check). Both
  variants record the read in the audit chain so a supervisor can
  detect a cross-desk leak after the fact.
- **Real cross-organisation A2A via Court federation** for the DORA
  Reporter. The `submit_to_auditor_org` MCP tool returns a synthetic
  `transmission_id` and writes a JSONL evidence trail; a real
  integration would use `cullis_sdk.send_to_agent` with a sealed
  envelope. The MCP server is joined to both `orga-internal` and
  `orgb-internal` docker networks to make the topology explicit.
- **Anthropic API key provisioning for the live KYC + Pitchbook
  path**. The two Claude-backed agents need the Mastio embedded
  LiteLLM gateway to have `MCP_PROXY_ANTHROPIC_API_KEY` configured;
  how to inject it depends on the operator's deployment. The DORA
  Reporter needs no API key (Ollama on-prem).

## Reference

- Strategic context: `imp/2026-05-21-strategic-decisions.md` (D3 — agent selection)
- Evidence dossier: `imp/2026-05-21-frustrated-pilots-research.md`
- Cullis core conventions: `CLAUDE.md`
- ADR-017 (AI gateway), ADR-019 (Frontdesk), ADR-020 (4 quadranti A2A/A2U/U2A/U2U), ADR-021 (multi-user KMS)
