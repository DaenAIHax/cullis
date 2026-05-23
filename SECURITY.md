# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Cullis, please report it responsibly.

**Do not open a public GitHub issue.**

### How to Report

**Email: [security@cullis.io](mailto:security@cullis.io)** — preferred channel.

This mailbox is monitored continuously by the maintainers. Please include
"SECURITY" or a CVE-style identifier in the subject line to make sure your
report is triaged quickly.

Alternative channel: [GitHub's private vulnerability reporting](https://github.com/cullis-security/cullis/security/advisories/new) if you cannot send email.

Both channels keep the report confidential until a fix is available. We do
**not** want public GitHub issues, X/Twitter posts, or blog posts about
vulnerabilities before a coordinated disclosure window has passed.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

Cullis is currently maintained by a small team. The targets below are
aspirational and best-effort, not contractual. We will communicate a
concrete timeline in the acknowledgment of each report.

| Phase | Target (best effort) |
|---|---|
| Acknowledgment of receipt | within 7 days |
| Initial triage + severity assignment | within 14 days |
| Fix for CRITICAL severity | top priority — typically weeks, not months |
| Fix for HIGH severity | next planned release window |
| Fix for MEDIUM / LOW severity | as scope and capacity permit |
| Coordinated public disclosure | 90 days from acknowledgment, or upon a coordinated release, whichever comes first |

Severity follows [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)
base score:

- **CRITICAL** — CVSS 9.0 - 10.0
- **HIGH** — CVSS 7.0 - 8.9
- **MEDIUM** — CVSS 4.0 - 6.9
- **LOW** — CVSS 0.1 - 3.9

If a fix will take longer than the targets above (breaking change,
coordinated upstream release, capacity), we will say so explicitly in
the acknowledgment and agree a revised timeline with the reporter.

## Supported Versions

We patch security issues on the **latest stable release of each
release track**. Older tags are end-of-life unless explicitly listed
below.

| Component | Release tag prefix | Supported window |
|---|---|---|
| Cullis Mastio (open-core image) | `mastio-v*` | latest stable |
| Cullis Mastio bundle | distributed via the `mastio-v*` release | latest stable |
| Python SDK (`cullis-sdk`) | PyPI semver | latest minor |

While Cullis is pre-1.0 the support window is intentionally narrow —
operators should expect to track the latest release. Once a component
reaches 1.0 the support window will widen and this policy will be
updated in this file before the change takes effect.

## Scope

In scope for this policy:

- This repository (`cullis-security/cullis`) — Cullis Mastio source,
  Python SDK source, Mastio bundle, site sources.
- The published container images on `ghcr.io/cullis-security/*` for
  the Mastio.
- The published PyPI package `cullis-sdk`.
- The Mastio bundle archive attached to GitHub Releases
  (`cullis-mastio-bundle-*.tar.gz`).

Out of scope:

- Customer-operated deployments (we ship images and bundles; operators
  are responsible for runtime configuration). We are still happy to
  receive reports about hardening defaults that make customer
  misconfiguration easy.
- Third-party AI providers reachable through the embedded AI gateway
  (Anthropic, OpenAI, etc.). Report those upstream.
- The `cullis.io` marketing site for non-security cosmetic issues —
  open a regular GitHub issue instead.

## Safe Harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to follow this policy.
- Avoid privacy violations, destruction of data, and disruption of our
  services or others' services.
- Only interact with accounts and infrastructure that they own, or for
  which they have explicit permission from the owner.
- Give us a reasonable time to respond before any public disclosure.

If you are unsure whether your testing falls within these boundaries,
contact us first at security@cullis.io and we will discuss before you
start.

## Acknowledgements

We will credit reporters in the release notes of the fix unless they
ask to remain anonymous. We currently do not run a paid bounty
programme; this section will be updated here when that changes.

## Security Design

Cullis is built with security as a core design principle:

- x509 PKI with 3-tier certificate chain (Org Root → Mastio Intermediate → agent leaf)
- DPoP token binding (RFC 9449) — no plain Bearer tokens accepted
- mTLS RFC 8705 §3 — client cert is the credential, no shared API key
- Default-deny session policy with PDP webhook + capability gate per agent
- Append-only cryptographic audit log (per-org hash chain, RFC 3161 TSA optional)
- Certificate thumbprint pinning
- Rate limiting on all public endpoints

For a full security architecture overview see the [README](README.md) and the threat model at [cullis.io/docs/security/threat-model](https://cullis.io/docs/security/threat-model/).
