---
title: "Compliance mapping"
description: "How Cullis Mastio primitives map to specific clauses in EU AI Act, DORA, EIOPA, IDD, NIST AI RMF, Colorado AI Act, ISO 42001, HIPAA, and other frameworks regulated deployments encounter."
category: "Reference"
order: 40
updated: "2026-05-21"
---

# Compliance mapping

Compliance teams need to map Cullis capabilities to specific clauses in
their framework. The table below is the working map for the current
Mastio release. It is a reference, not a certification: a specific
compliance assessment for any regulated deployment remains the
responsibility of the deploying organization.

| Framework | Article / clause | Cullis capability |
|---|---|---|
| **EU AI Act** | Art. 12 (logging), 13 (transparency), 14 (human oversight) | Tamper-evident audit chain, per-decision reasoning capture, ADR-020 4-quadrant identity |
| **EU AI Act Annex III** | High-risk classification (credit, insurance pricing, recruitment) | Per-agent identity + per-decision audit + 4-eye approval capability |
| **DORA** | Art. 28 (third-party ICT) | mTLS + DPoP cryptographic identity per action, self-hosted deployer model |
| **EIOPA** | Aug 2025 Opinion 8-axis governance | Mastio dashboard + audit export + policy decision logging across fairness, data, record, transparency, oversight, accuracy, robustness, cyber |
| **IDD** | Art. 17 (fair treatment), Art. 20, 30 | Per-claim audit chain, exportable signed bundle for customer complaint reconstruction |
| **EU GMP Annex 22** | AI/ML in pharma manufacturing | Per-agent identity + immutable change log + signed releases for validated lifecycle |
| **NIST AI RMF** | MEASURE 2.7, GOVERN 1.7 | Standardized audit log export, per-agent identity, role separation |
| **Colorado AI Act** | Consumer disclosure for high-risk AI (June 2026) | Decision logging with reason, per-decision provenance |
| **ISO 42001** | AI Management System controls | Operational governance, lifecycle controls, audit evidence |
| **HIPAA** | 164.312(b) audit controls | Append-only audit chain, integrity controls, external verification |

## How to read this table

Each row pairs a regulator's requirement with the Cullis Mastio
primitive that addresses it. Most rows reduce to one of three Mastio
building blocks: per-agent x509 + SPIFFE identity, the policy decision
point that runs before every LLM or MCP call, and the hash-chained
append-only audit log.

The mapping is conservative. Where a clause requires evidence Cullis
cannot itself produce (e.g. data-quality management for the training
set under EU AI Act Art. 10), the row is omitted rather than stretched.

## Further reading

The research that backs this mapping (long-form articles on EU AI Act
Annex III, DORA, EIOPA, and the broader regulated-AI landscape) is
published at [mazzolad.com/writing](https://mazzolad.com/writing).
