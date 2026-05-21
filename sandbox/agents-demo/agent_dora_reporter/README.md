# Agent 3 -- DORA Vendor/TPA Compliance Reporter

Reference demo agent that uses Cullis governance primitives (per-action
cryptographic identity, role-gated cross-org A2A, dual-write evidence chain
across federated Mastios) under an **Ollama on-prem** LLM brain.

This is the **sovereignty showcase** of the trio: the bank's vendor risk
data never leaves the bank's perimeter while the very same data is used to
draft the third-party register that names the LLM provider. No SaaS LLM is
contacted. This is itself an Art. 28 control.

## Anthropic Finance Agent overlap

**None -- Cullis-unique.** Anthropic's 5 May 2026 Finance Agents catalogue
does not include a DORA Art. 28 reporter. The gap is industry-wide.

## Production-stuck-pilot evidence

> DORA expectation: 'every action by a human or agent must be linked to a
> unique, immutable identity (such as a cryptographic identity)'. EU
> industry-wide gap, no named insurer in production. 'Fragmented logs
> cannot reconstruct cross-system incident chains; no visibility into
> third-party vendor access paths'.

Source: Teleport DORA evidence guide, cited in
`imp/2026-05-21-frustrated-pilots-research.md` §6.1.

> 9 | DORA vendor/TPA compliance agent (cross-third-party identity +
> audit chain) | EU industry-wide, **no named insurer in production** |
> Pre-production at infrastructure level | "Fragmented logs cannot
> reconstruct cross-system incident chains; need for cryptographic
> identity per action".

Source: `imp/2026-05-21-frustrated-pilots-research.md` Sezione 2,
Insurance #9.

## Regulatory articles addressed

| Article | Cullis primitive |
|---|---|
| DORA Art. 28 (third-party ICT risk) | Per-vendor `entry_hash` (SHA-256 of canonical draft) bound to the drafting principal's identity; the audit chain links every read/draft/submit to the principal cert. |
| DORA Art. 28(3) (cryptographic identity per action) | Every audit entry is RSA-PSS signed by the agent key; the chain is hash-linked, append-only, tamper-evident. |
| EU AI Act Art. 12 (cross-org audit chain anchor) | `submit_to_auditor_org` mocks the dual-write pattern: outbound entry on the caller's chain + inbound ack on the auditor's chain, sharing a `transmission_id`. |
| EU AI Act Art. 14 (human oversight) | Cross-org submission requires the `compliance_officer` role at the gate, mirroring the human-in-the-loop authorisation point. |
| EU GDPR Art. 32 / DORA Art. 28(7) (LLM provider concentration risk) | On-prem Ollama means the bank's vendor risk data never crosses the bank perimeter while drafting the very register that lists LLM providers as third parties. |

## ADR-020 quadrant

**A2A cross-organisation.** The `submit_to_auditor_org` tool is a sealed
A2A envelope routed via the Cullis Court federation. The caller Mastio
(bank) and the auditor Mastio (external auditor org) both append a
cross-org evidence record bound to the same `transmission_id`. This is
the cross-org pattern Cullis is structurally designed for and that no
single-org governance vendor exposes.

## Stack

- **LLM**: Ollama on-prem via the Mastio embedded LiteLLM gateway (ADR-017).
- **Default model**: `ollama/mistral-small` (Mistral AI, EU sovereignty narrative). Override with `CULLIS_DORA_REPORTER_MODEL`.
- **Common alternatives**:
  - `ollama/qwen2.5` -- lighter (~4.5GB), strong tool calling
  - `ollama/llama3.1` -- broad availability (~5GB)
- **Setup for live mode**:
  ```bash
  curl https://ollama.ai/install.sh | sh
  ollama pull mistral-small      # ~14GB; or 'ollama pull qwen2.5' for ~4.5GB
  export CULLIS_AGENT_DEMO_MODE=live
  ```
  No API key. No network egress.

## Files

| File | Purpose |
|---|---|
| `system_prompt.md` | Hard rules + output format. |
| `tools.py` | 4 tools, including the `submit_to_auditor_org` cross-org A2A handler. |
| `capabilities.yaml` | Capability binding, including the role-gated `dora.cross_org_submit`. |
| `main.py` | Agent loop + decision parser. |
| `test_e2e.py` | 3 scenarios: single-org draft-only, cross-org happy path, capability gate denial on missing role. |

## How to run the E2E

```bash
pytest sandbox/agents-demo/agent_dora_reporter/ -v
```

To run with a live Ollama model:

```bash
ollama serve &
ollama pull mistral-small
export CULLIS_AGENT_DEMO_MODE=live
python -m agent_dora_reporter.main
```

## Test scenarios mapped to controls

| # | Scenario | Control tested |
|---|---|---|
| 1 | Single-org draft only | Principal without `cross_org_submit` capability completes draft cycle; no cross-org evidence written. |
| 2 | Cross-org submission happy path | Compliance officer + enrolled auditor: dual-write (outbound + inbound_ack) appears in audit chain, shared transmission_id. |
| 3 | Capability gate denial -- missing role | Principal with `cross_org_submit` capability but no `compliance_officer` role: gate denies inline with `reason: missing_role:compliance_officer`, agent emits `skipped:not_authorized`. |

## Deferred work (real `./stack/demo.sh` integration)

The cross-org A2A path is **mocked** in `tools.py:submit_to_auditor_org`.
A real integration would:

1. Bring up `./stack/demo.sh` from the repo root (Court + 2 Mastios + 2
   agents). Healthcheck `./stack/smoke.sh`.
2. Enrol the auditor org in the Cullis Court federation via
   `app/registry/store.py` enrolment endpoint.
3. Replace the mock dual-write with a real `cullis_sdk.AgentClient.send`
   to the auditor's Mastio public URL, with a sealed A2A envelope (E2E
   AES-256-GCM + RSA-OAEP + RSA-PSS double-signature).
4. Verify the auditor's Mastio audit chain shows the inbound entry with
   matching `entry_hash` and `transmission_id`.

The reason this is deferred: it requires a running Cullis stack and is
out of scope for the demo trio's "self-contained, reproducible in CI"
property. The mock proves the pattern at the agent + tool + audit layer;
the real integration proves the network + federation layer.

## Caveats

- All vendor, assessment and auditor-org data is **synthetic**. See
  `shared/test_fixtures.py`.
- The `entry_hash` is a SHA-256 over a canonical JSON projection of the
  draft. A production register would additionally bind the hash to a
  TSA timestamp (ADR-033) and to the Mastio audit chain tip.
- The federation enrolment check in `submit_to_auditor_org` reads a
  dict (`FEDERATED_AUDITOR_ORGS`). The production Mastio consults Court
  in real time and refreshes a cached snapshot on a TTL.
