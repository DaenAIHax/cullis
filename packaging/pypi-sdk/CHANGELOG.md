# Changelog

PyPI release history for `cullis-sdk`. The monorepo's top-level
`CHANGELOG.md` covers all components (Mastio, Connector, Court, SDK)
on their respective release cadences; this file is the SDK-only
slice, kept next to the PyPI `pyproject.toml` so distributors who
only see the published wheel have a self-contained history.

Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-05-27

Patch release on top of 0.2.0 to ship the ADR-038 Phase 0 provider
SDK drop-in helper. The 0.2.0 wheel was built before the ADR-038 PR
landed on `main`, so `cullis_sdk.providers_compat` was missing from
the published package even though `chat_completion` and the MCP
surface had already shipped. Same-day catch-up.

### Added

- `cullis_sdk.providers_compat.cullis_httpx_client(identity_dir=...)` —
  LLM-agnostic helper returning an `httpx.Client` with mTLS client
  cert + DPoP signing transport. Plug into the vanilla Anthropic SDK
  (`Anthropic(base_url="https://mastio:9443", api_key="cullis",
  http_client=cullis_httpx_client(identity_dir="..."))`) or the
  vanilla OpenAI SDK (`OpenAI(base_url="https://mastio:9443/v1", ...,
  http_client=cullis_httpx_client(...))`) so agent code uses the
  upstream SDK directly while Cullis stays in the transport path
  for identity, audit, and policy. Three-line constructor; no
  Cullis SDK on the agent business-logic path.

### Compatibility

- Wire-compatible with Mastio >= 0.6.0 for the Anthropic SDK path
  (the `POST /v1/messages` endpoint that translates Anthropic
  Messages requests to the LiteLLM dispatch landed server-side in
  v0.6.0). OpenAI SDK path works against any Mastio with
  `/v1/chat/completions` (>= v0.5.0).

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

### Deprecated

- `CullisClient.from_enrollment(enroll_url)` now emits a
  `DeprecationWarning` and will be removed in 0.3.0. The ADR-011
  one-shot URL flow was an API-key bearer design predating ADR-014
  (mTLS RFC 8705); the server-side `GET /v1/enroll/<token>` endpoint
  did not survive the 2026-05 pivot to Mastio standalone. The
  admin-minted `identity-bundle.zip` workflow (download from the
  Mastio dashboard, unzip wherever the agent host stores credentials,
  load via `from_identity_dir`) covers the same operator use case
  without a shared API key. CI/CD bootstrap paths that need to
  generate identity dynamically should use
  `enroll_via_dashboard_approval(...)` instead.

### Compatibility

- Python >= 3.10 (unchanged).
- Wire-compatible with Mastio >= 0.5.0. Older Mastios may 404 on
  `/v1/llm/chat` and the MCP endpoints - these landed server-side
  in 0.5.x.

## [0.1.3] - 2026-05-01

Last release before the ~4-week drift window. ADR-008 one-shot
messaging + ADR-014 mTLS-cert-as-credential surface, plus legacy
session API kept around as deprecated.
