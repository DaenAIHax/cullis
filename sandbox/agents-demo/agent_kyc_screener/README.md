# Agent 1 -- KYC Screener

Reference demo agent that uses Cullis governance primitives (per-agent
identity, capability gate, hash-chained audit log) under a Claude Haiku 4.5
brain.

## Anthropic Finance Agent overlap

Direct overlap with **Anthropic's "KYC screener" Finance Agent template**,
published 5 May 2026.

## Production-stuck-pilot evidence

> Anthropic 'KYC screener' template; NatWest 2026 Fintech Programme cohort
> explicitly includes 'compliance onboarding' and 'real-time business
> onboarding' as Series-A-stage pilots, framed as 'production within 2
> years'. Blocker: AML reproducibility, sanctions FP rate, GDPR biometrics,
> AI Act Annex III high-risk if identification.

Source: `imp/2026-05-21-frustrated-pilots-research.md` (Sezione 1, Banking #5)

## Regulatory articles addressed

| Article | Cullis primitive |
|---|---|
| EU AI Act Art. 12 (logging) | Hash-chained audit log: every document hash, every tool call, every score, every decision is signed and chained. |
| EU AI Act Art. 14 (human oversight) | Agent is structurally incapable of auto-rejecting; high score / sanctions / PEP always routes to `escalate_to_compliance` and the human queue. |
| EU AI Act Annex III (high-risk identification) | Capability gate blocks auto-approve unless the principal additionally holds `kyc.auto_approve` AND score is strictly below threshold. |
| GDPR Art. 22 (automated decisions) | Auto-approve path is opt-in via per-principal capability; default binding for first-line analysts is review-and-escalate only. |

## ADR-020 quadrant

**User-to-Agent (U2A).** A bank compliance analyst invokes the agent with
their own user identity; the agent inherits the user's `org_id`, role and
capability set. There is no agent-to-agent fanout in this scenario.

## Stack — three interchangeable runtimes

The KYC Screener ships in **three forms** that share the same system
prompt, tool schemas, capability YAML and audit semantics. They differ
only in how the agent loop is driven:

| Runtime | LLM transport | Chat passes through Cullis Mastio? | When to use |
|---|---|---|---|
| `main.py` | `litellm` chat completions (LLM-agnostic) | No (or yes when paired with `main_stack.py`) | Offline CI tests + LLM-agnostic positioning |
| `main_sdk.py` | **Official Anthropic `claude-agent-sdk`** | No — direct to api.anthropic.com | **Anthropic Partner Network pitch** + native Claude tooling |
| `main_stack.py` | `cullis_sdk` mTLS+DPoP → Mastio AI gateway | Yes (full Cullis governance on chat too) | Live demo against a running Cullis Mastio |

All three call the same `tools.py` handlers, so the capability gate +
audit chain fire identically across runtimes.

## Files

| File | Purpose |
|---|---|
| `system_prompt.md` | Hard rules + scoring rubric + output format. |
| `tools.py` | 4 MCP-style tool handlers + JSON schemas. |
| `capabilities.yaml` | Capability binding (kyc.read, kyc.submit, kyc.auto_approve, kyc.escalate). |
| `main.py` | litellm variant — hand-written loop, MockLLMClient in CI. |
| `main_sdk.py` | **Claude Agent SDK variant** — official Anthropic agent loop. |
| `main_stack.py` | CullisClient variant — chat through Mastio AI gateway. |
| `test_e2e.py` | 4 scenarios: happy path, sanctions hit, PEP hit, capability bypass. |

## How to run

From the repo root:

```bash
# Deterministic mock LLM (no API key needed). CI path.
pytest sandbox/agents-demo/agent_kyc_screener/ -v
```

**litellm variant** (LLM-agnostic, default `main.py`):

```bash
pip install -e sandbox/agents-demo/[live]
export CULLIS_AGENT_DEMO_MODE=live
export ANTHROPIC_API_KEY=sk-ant-...
python -m agent_kyc_screener.main
```

**Claude Agent SDK variant** (recommended for Anthropic Partner pitch):

```bash
pip install -e sandbox/agents-demo/[sdk]
export ANTHROPIC_API_KEY=sk-ant-...
python -m agent_kyc_screener.main_sdk \
    --case-id case_demo_001 \
    --document-id doc_low_risk_retail
```

The SDK variant uses the bundled `claude` CLI as the agent loop driver
and exposes the 4 KYC tools as an in-process MCP server via the
`@tool` decorator. The Cullis capability gate fires inside each tool
wrapper before the mock provider runs — same governance contract as
the other two variants, just hosted by the SDK's loop instead of a
home-grown `while`.

The demo entry point processes the synthetic `doc_low_risk_retail` case and
prints the decision JSON + the audit chain length.

## Test scenarios mapped to articles

| # | Scenario | Article tested |
|---|---|---|
| 1 | Low-risk retail customer | Art. 12 (full audit chain on the auto-approve path) |
| 2 | Sanctions hit | Art. 14 (forced escalation to human, agent cannot auto-clear) |
| 3 | PEP hit, score >= 30 | Annex III (score threshold gating) |
| 4 | Capability gate bypass | EU AI Act Art. 14 + 26 (principal without `kyc.auto_approve` cannot finalize an auto-approve, even if the LLM tries) |

## Caveats

This is a **reference demo**, not a production KYC system. Specifically:

- All identity, sanctions, PEP and beneficial-owner data is **synthetic**.
  See `shared/test_fixtures.py`. Names like `Synthetic-Sanctions-Test
  Petrov` are intentionally signaled so they cannot be confused with real
  individuals.
- The scoring rubric in `system_prompt.md` is a deliberately simple
  pedagogical example. A production rubric would include FATF country
  ratings, document forgery indicators, transaction-pattern adjustments,
  and would be validated against an institution-specific risk appetite.
- The audit chain is local to a single agent run. In production the chain
  is hosted by Mastio and anchored cross-org by Court (ADR-033 TSA timestamp).
