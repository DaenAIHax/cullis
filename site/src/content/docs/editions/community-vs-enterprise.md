---
title: "Community vs Enterprise"
description: "What the open-source Cullis bundle ships out of the box, and what the Enterprise license adds for regulated production deployments."
category: "Editions"
order: 10
updated: "2026-05-24"
---

# Community vs Enterprise

Cullis ships as an **open-core** product. The Community edition is the public repo at [`github.com/cullis-security/cullis`](https://github.com/cullis-security/cullis) — full source, FSL-1.1-Apache-2.0 (Mastio) and Apache-2.0 (SDK). It runs every workload a single-org regulated deployment needs to pass a DORA Art. 12 or AI Act Art. 12 audit. The Enterprise edition layers in the pieces a banking-grade rollout typically asks for as a separate procurement track: WORM-sealed forensic archive, federated cross-org audit, advanced SSO, multi-admin RBAC, deployment automation against managed cloud KMS.

This page is the source of truth for what is in which edition. Both editions consume the same Mastio gateway and the same SDK — the Enterprise feature surface is delivered as plugins and additional binaries, not a fork.

## Quick look

| Capability | Community | Enterprise |
|---|---|---|
| Mastio gateway (FastAPI, Postgres, single-org) | ✓ | ✓ |
| Python SDK (`cullis-sdk`) | ✓ | ✓ |
| PKI 3-tier (Org Root → Mastio Intermediate → Agent Leaf) | ✓ | ✓ |
| DPoP RFC 9449 + mTLS RFC 8705 §3 | ✓ | ✓ |
| Embedded AI gateway (LiteLLM, Anthropic + OpenAI + Gemini + Ollama) | ✓ | ✓ |
| MCP reverse proxy + capability gate | ✓ | ✓ |
| Rego policy engine (in-process WASM, ~0.2 ms p50) | ✓ | ✓ |
| OPA Data API + CloudEvents bridge (HMAC-signed) | ✓ | ✓ |
| Append-only hash-chained audit log (Mastio v2 schema) | ✓ | ✓ |
| RFC 3161 TSA anchoring of the chain head | ✓ | ✓ |
| Merkle batch anchors + O(log n) inclusion proofs | ✓ | ✓ |
| Offline `cullis-audit-verify` CLI (chain + TSA + Merkle proofs) | ✓ | ✓ |
| Dashboard (admin + Audit + Policies + Settings) | ✓ | ✓ |
| Docker Compose bundle + Helm chart + Postgres pilot | ✓ | ✓ |
| **WORM-sealed forensic archive** (S3 Object Lock + STH per epoch) | — | ✓ |
| **Signed Tree Head daily seal** signed by the Mastio key | — | ✓ |
| **Court cross-org federation** (audit dual-write between Mastios) | — | ✓ |
| **SAML 2.0 IdP integration** (Okta, Azure AD, etc.) | — | ✓ |
| **SCIM 2.0 user provisioning** | — | ✓ |
| **RBAC multi-admin** with per-action quorum approval | — | ✓ |
| **Cloud KMS plugins** (AWS KMS, Azure Key Vault, GCP KMS) | — | ✓ |
| **LLM guardian** advanced (PII detection, content moderation policy chain) | — | ✓ |
| Vendor-backed SLA (48h acknowledgement, 7-day triage) | — | ✓ |
| Production support contract | — | ✓ |

## Three primitives, side by side

### Identity

Both editions ship the same per-agent x509 certificate machinery — Org Root CA owned by you, Mastio Intermediate minted at first boot, agent leaf certs bound to a SPIFFE SAN, mTLS RFC 8705 §3, DPoP RFC 9449 with ES256 ephemeral keys, JTI replay protection via Redis, thumbprint pinning. The Community edition uses local-file KMS by default and HashiCorp Vault as a production option.

The Enterprise edition adds **managed cloud KMS plugins** (AWS KMS, Azure Key Vault, GCP KMS) so the Org CA private key never sits on the Mastio disk in regulated cloud rollouts. Enterprise also ships the **SCIM 2.0 provisioning endpoint** and **SAML 2.0 IdP integration** for organisations whose user lifecycle is owned by Okta, Azure AD, Ping, or similar.

### Policy

Both editions run the same Rego engine — operator authors policies in the dashboard, the Mastio compiles them via the bundled `opa build` (OPA v1.16.2, SHA-pinned in the image), and `opa-wasmtime` evaluates the WebAssembly bundle in-process on every decision at ~0.2 ms p50. Both editions expose the same **OPA Data API** (`/v1/data/cullis/policy/{session, tool_call}`) and **CloudEvents HTTP binding** (`/v1/integrations/cloudevents`), HMAC-signed, so any external data plane already speaking those two protocols can plug into Cullis as its control plane.

The Enterprise edition adds **RBAC multi-admin with per-action quorum approval** — sensitive admin actions (agent enrollment, federation peer add, license import, capability grants) require N-of-M approvers logged independently. Useful when the operator is one team but the auditors require segregation of duties.

### Audit

Both editions ship the **same forensic core**: append-only hash-chained audit log per organisation, RFC 3161 TSA anchoring of the chain head on a configurable cadence, Merkle batch anchors with O(log n) inclusion proofs, and the `cullis-audit-verify` standalone CLI that an auditor runs offline against the NDJSON export bundle plus inclusion proof JSONs (no Mastio access required, no Cullis vendor trust required). The Community audit chain is **tamper-evident even against the operator and the Cullis vendor** out of the box.

The Enterprise edition adds the **WORM-sealed forensic archive**:

- **Sink plugins** (`file://`, `s3://` with Object Lock COMPLIANCE mode, with Azure Blob immutable storage and GCS bucket lock on the roadmap) export the per-epoch audit bundle to immutable storage. Deleting an exported bundle, even with full IAM access, returns `InvalidRequest: Object is WORM protected and cannot be overwritten` until the retention period expires.
- **Signed Tree Head (STH) per epoch**: every 24 hours (configurable), the Mastio computes a fresh Merkle tree over the day's audit rows, signs the root with the Mastio's ES256 identity key, and persists the STH in `audit_sth_log`. An auditor verifies an inclusion proof against a known STH without needing the live Mastio.
- **STH replication to a federated Court** for cross-org audit reconciliation (Enterprise + Court module): bancassurance partners or supply chain peers can compare their independent Mastios' STH and reconcile cross-org agent calls without trusting either organisation.

The Enterprise audit archive is the piece a regulator typically asks for in a Tier 1 banking pilot: not because the chain itself isn't sound, but because the **WORM property gives them a defensible chain of custody story** that doesn't depend on the bank's internal IAM. The Community chain is dispute-grade by math; the Enterprise archive is dispute-grade *and* regulator-friendly by default.

## Why this split

We made the open-core line where we did for two reasons:

1. **The math is yours.** Every cryptographic primitive that makes the Cullis audit defensible — hash chain, TSA anchoring, Merkle inclusion — is in the Community edition. An auditor who reads the source can replay the verification end-to-end with the standalone CLI. That has to be open, or the threat model collapses to "trust the vendor", which is the opposite of what we sell.

2. **The integration is ours.** The pieces that move from "math is sound" to "regulator-ready in production" — managed cloud KMS, SAML/SCIM, WORM sink wiring, RBAC quorum approval, Court federation — are the integration surface where Cullis Security s.r.l. delivers ongoing value via SLA, security advisories, and the Enterprise plugin roadmap. That is where Enterprise pays for itself.

A regulated organisation that runs the Community edition and wants the Enterprise add-ons later does not need to re-architect anything: the plugin loader is on by default in the Community Mastio (you see `plugin skipped: feature ... not in license` warnings in the bootlog today), and the Enterprise license unlocks the same plugins running against the same gateway.

## How to procure

- **Community**: clone the repo, run `./deploy.sh`, done. No license file required. FSL-1.1-Apache-2.0 source code, converts to Apache-2.0 automatically two years after each release.
- **Enterprise**: contact [hello@cullis.io](mailto:hello@cullis.io) with the deployment context (org size, regulated jurisdiction, target go-live). We typically run a one-week PoC against your Mastio with the Enterprise plugin set unlocked, scoped to the specific feature surface you need.

We do not publish a price list because the Enterprise license is sized per deployment (number of Mastios + Court federation peers + plugin set). The PoC week clarifies which features actually matter for your audit, so the quote is based on what you will use, not on a feature checklist.
