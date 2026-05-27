# Changelog

PyPI release history for `cullis-sdk`. The monorepo's top-level
`CHANGELOG.md` covers all components (Mastio, Connector, Court, SDK)
on their respective release cadences; this file is the SDK-only
slice, kept next to the PyPI `pyproject.toml` so distributors who
only see the published wheel have a self-contained history.

Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-27

First release on PyPI since 2026-05-01 (0.1.3). Closes a ~4-week drift
between the published wheel and the repo HEAD that left the public
README quickstart examples broken on a fresh `pip install cullis-sdk`.

### Added

- `CullisClient.chat_completion(...)` and `.chat_completion_stream(...)` -
  route LLM completions through Mastio's embedded AI gateway (LiteLLM,
  ADR-017). Accepts either an OpenAI-shape request dict or kwargs.
  mTLS client cert + DPoP signing applied automatically; the audit
  trail carries a per-call `cullis_trace_id`.
- `CullisClient.list_mcp_tools()` / `.call_mcp_tool(name, arguments)` -
  MCP reverse-proxy surface. Capability gate enforced server-side.
- `CullisClient.from_enrollment(enroll_url, verify_tls=False)` quickstart
  constructor: paste a one-shot enrollment URL from the dashboard,
  get a ready-to-use client. No file paths to wire up.
- `CullisClient.enroll_via_dashboard_approval(mastio_url, requester_name=,
  requester_email=, save_to=)` scripted bootstrap path for CI/CD
  onboarding: SDK submits a CSR, polls until admin clicks Approve,
  persists identity-dir.

### Changed

- `CullisClient.from_identity_dir(...)` auto-discovers `ca-chain.pem`
  sibling and `dpop.jwk` sibling, so an admin-minted
  identity-bundle.zip just works after `unzip` (no manual wiring of
  `dpop_key_path` / `ca_chain_path`).
- All authenticated egress now flows through the cert-pinned DPoP path
  (no plain Bearer accepted).

### Compatibility

- Python >= 3.10 (unchanged).
- Wire-compatible with Mastio >= 0.5.0. Older Mastios may 404 on
  `/v1/llm/chat` and the MCP endpoints - these landed server-side
  in 0.5.x.

## [0.1.3] - 2026-05-01

Last release before the ~4-week drift window. ADR-008 one-shot
messaging + ADR-014 mTLS-cert-as-credential surface, plus legacy
session API kept around as deprecated.
