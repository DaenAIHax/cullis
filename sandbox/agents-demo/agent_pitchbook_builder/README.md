# Agent 2 -- Pitchbook Builder

Reference demo agent that uses Cullis governance primitives (per-user
desk scope, Chinese Wall capability gate, MNPI-aware audit log) under a
Claude Haiku 4.5 brain.

## Anthropic Finance Agent overlap

Direct overlap with **Anthropic's "Pitchbook Builder" Finance Agent
template**, published 5 May 2026.

## Production-stuck-pilot evidence

> Anthropic financial services agents launched 5 May 2026, sold as 'pitch
> builder' reference architecture; named adopters include Goldman Sachs,
> Citi, AIG; Rogo (Series D $160M Kleiner Perkins) deployed at Rothschild
> & Co, Jefferies, Lazard, Moelis, Nomura. EU tier-1 CIB desks (BNP, SG,
> Deutsche, UBS, Barclays) implied buyers. Blocker: MAR /
> inside-information segregation; Chinese Wall.

Source: `imp/2026-05-21-frustrated-pilots-research.md` (Sezione 1, Banking #7)

## Regulatory articles addressed

| Article | Cullis primitive |
|---|---|
| EU AI Act Art. 13 (transparency) | Every source the deck cites maps to a successful tool call in the audit chain. The agent loop refuses to finalize if `sources_cited` references a memo it did not actually read. |
| EU MAR (Market Abuse Regulation) | Chinese Wall: the capability gate refuses to read internal memos tagged with a desk different from the invoking user's desk. Denial is recorded as `capability_denied` audit event with both desks named for supervisor review. |
| Information Barriers (industry practice) | MNPI-tagged memos are flagged in the final `sources_cited` list and in the audit chain so the desk supervisor can identify confidential material that informed the draft. |

## ADR-020 quadrant

**U2A + A2A intra-org (cross-desk segregation).** A banker invokes the
agent under their own identity; the agent inherits the user's desk scope.
Two banker-invocations from different desks are, from Cullis's point of
view, two distinct principals -- the second cannot read the first's
research even though the underlying agent class is identical. This is
how Mastio implements desk separation without per-desk replicated agents.

## Stack

- **LLM**: Claude Haiku 4.5 via the Mastio embedded LiteLLM gateway
  (ADR-017). The demo defaults to Haiku for cost; a production deployment
  would route high-stakes pitch drafting to Sonnet or Opus tier instead.
  The governance layer (audit + capability gate + Chinese Wall) is
  identical across tiers.
- **Audit chain**: append-only RSA-PSS-SHA256 hash chain.

## Files

| File | Purpose |
|---|---|
| `system_prompt.md` | Chinese Wall rules + citation requirements + output format. |
| `tools.py` | 5 tools, including the `read_internal_research` Chinese Wall enforcement point. |
| `capabilities.yaml` | Capability binding, including the `pitchbook.read_research` desk-scope gate. |
| `main.py` | Agent loop + output parser + cross-check against the audit chain (hallucination guard). |
| `test_e2e.py` | 3 scenarios: same-desk happy, cross-desk denied, MNPI same-desk. |

## How to run the E2E

```bash
pytest sandbox/agents-demo/agent_pitchbook_builder/ -v
```

To run with a real Claude Haiku 4.5 brain:

```bash
export CULLIS_AGENT_DEMO_MODE=live
export ANTHROPIC_API_KEY=sk-ant-...
python -m agent_pitchbook_builder.main
```

## Test scenarios mapped to controls

| # | Scenario | Control tested |
|---|---|---|
| 1 | Same-desk happy path | Citation integrity: every cited memo has a successful audit read. |
| 2 | Cross-desk read denied | Chinese Wall: gate denies, agent cannot leak blocked content. |
| 3 | Same-desk MNPI memo | MNPI tagging propagated to citations + audit chain. |

## Caveats

- All comps, memos and news headlines are **synthetic**. See
  `shared/test_fixtures.py`. Names like `DemoCorpA`, `IndustrialDemoB`
  are intentionally signaled.
- The "Information Barrier" model here uses a single `desk` scope. Real
  banks layer multiple barriers (research/IBD, public/private side,
  jurisdiction, market-maker/agency). The capability gate generalizes
  trivially to multi-scope; the demo keeps a single dimension for clarity.
- The agent has no `pitchbook.share_to_desk` tool. A2A cross-desk
  forwarding (where a draft moves between desks under a controlled
  declassification process) is a follow-up the production Mastio
  exposes via `mcp_proxy/tools/cullis_send_to_agent`; integrating that
  requires a running Cullis stack and is deferred.
