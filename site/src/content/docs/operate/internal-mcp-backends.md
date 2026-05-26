---
title: "Internal MCP backends (SSRF guard escape)"
description: "Allow the Mastio to register MCP backends on a private network (Docker bridge, on-prem) without disabling the SSRF defence. FQDN-scoped allowlist preferred; global private-range escape as a dev/sandbox fallback."
category: "Operate"
order: 6
updated: "2026-05-26"
---

# Internal MCP backends (SSRF guard escape)

**Who this is for**: an operator registering an MCP backend whose endpoint URL points at a private (RFC 1918), loopback, or Docker-bridge address — for example, a sibling `mcp-pitchbook` container on the same compose network, or an on-prem `internal-mcp.corp.example` that resolves to `10.20.30.40`.

**Default by bundle**:

- **Community bundle** ships `MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=1` in `proxy.env.example`. RFC 1918 + loopback addresses are accepted out-of-the-box — the docker-compose-with-sibling-MCP-container scenario is the primary use case, so the first-run experience is smooth. Cloud-metadata (`169.254/16`) and CGNAT (`100.64/10`) stay blocked regardless.
- **Enterprise bundle** ships the same knob set to `0`. The primary scenario there is cloud-hosted with externally-routable backends, so a private-range URL is almost always a misconfiguration or an IMDS attempt. You will see the HTTP 400 below the first time you register an internal backend, and you opt in explicitly via Option A or B.

If you are on the community bundle and want to tighten posture (e.g. running on a cloud VPS with externally-routable MCP backends only), flip `MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=0` in `proxy.env` and adopt Option A.

## The error you hit

When the SSRF guard is in default-deny mode (enterprise bundle, or community bundle with the knob explicitly flipped to `0`), in the dashboard **Backends → Save**, you see HTTP 400 with a message like:

```
endpoint_url is blocked by the SSRF guard: hostname 'mcp-pitchbook' resolves to
172.18.0.3 which is blocked: private (RFC 1918, RFC 4193).

If this backend is an internal MCP server you trust, allow it explicitly:
  - Recommended (FQDN-scoped): add 'mcp-pitchbook' to MCP_PROXY_INTERNAL_HOST_ALLOWLIST
    (comma-separated FQDNs), then restart the Mastio.
  - Or (dev/sandbox, opens all RFC 1918): set MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=1,
    then restart the Mastio.

Docs: https://cullis.io/docs/operate/internal-mcp-backends
```

This is not a bug. It is the F-A-301 SSRF defence (audit 2026-05-20): without it, an admin (or a compromised admin role) could register an MCP resource pointing at `169.254.169.254` and have the Mastio fire a POST against the cloud IMDS endpoint on every tool invocation. The default-deny posture is non-negotiable.

What you choose next depends on the trust posture you can defend to your CISO.

## Option A — FQDN-scoped allowlist (recommended)

`MCP_PROXY_INTERNAL_HOST_ALLOWLIST` is a comma-separated list of hostnames that bypass the IP-block check. The Mastio matches the URL hostname against this list **before** DNS resolution, so the entry is independent of which internal IP the name happens to resolve to today.

Trade-offs:

- **Pros**: only the hostnames you name are trusted; everything else (including future internal containers an operator forgets to audit) remains blocked. Cloud-metadata (`169.254/16`) and CGNAT (`100.64/10`) stay blocked even for allowlisted FQDNs.
- **Cons**: every new internal backend needs an env edit + Mastio restart.

Compose snippet (community bundle, `proxy.env`):

```bash
# Trust two sibling MCP containers on the same docker network.
MCP_PROXY_INTERNAL_HOST_ALLOWLIST=mcp-pitchbook,mcp-pricing
```

Then:

```bash
./deploy.sh --upgrade   # or: docker compose -p cullis-mastio up -d --force-recreate --wait
```

Re-open the dashboard, **Backends → Save** the same `http://mcp-pitchbook:8080` URL — green.

## Option B — Global private-range escape (community bundle default)

`MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=1` opens up the entire RFC 1918 + loopback range. Any URL the admin types is accepted as long as it is not in the cloud-metadata or CGNAT family. This is the **community bundle default**, on the assumption that the primary scenario is a single docker-compose stack the operator controls end-to-end.

Trade-offs:

- **Pros**: zero per-backend config; a single-tenant dev or on-prem-LAN stack where you control every container on the bridge just works.
- **Cons**: an admin (or a leaked admin session) can register **any** internal address as an MCP backend. Not defensible in a regulated production deploy — the enterprise bundle therefore ships with this knob off.

Compose snippet:

```bash
MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=1
```

Restart the same way (`./deploy.sh --upgrade`).

## Which one to pick

| Deployment | Recommendation |
|---|---|
| Single-tenant dev / hack day / laptop demo (community bundle) | **B**, which is the community bundle default. No action needed. |
| On-prem LAN, one operator, MCP backends are sibling containers (community bundle) | **B** is fine. The community bundle default already covers you. |
| Pilot with a CISO in the room (community bundle, hardened) | Flip `MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=0` and adopt **A**. Name every backend you trust; let the dashboard reject the rest. |
| Production on-prem / cloud (enterprise bundle) | **A**, full stop. The enterprise bundle already ships default-deny; you add hostnames you trust. The audit trail of which hostnames were added (and when) lives in your config management; `B` leaves no per-backend record. |
| Mixed (dev compose + real internal backend) | **A** for the real backend; spin a separate dev compose stack with `B` for sandbox experimentation. |

## What stays blocked either way

Both escapes leave the following families **always refused**, by design:

- Cloud metadata: `169.254.0.0/16` (AWS IMDS, GCP metadata), `fe80::/10` (IPv6 link-local).
- CGNAT: `100.64.0.0/10` (AWS internal NAT range; used by IMDSv2 in some configs).
- Non-HTTP schemes: `file://`, `gopher://`, etc. — only `http://` and `https://` are accepted at the dashboard boundary.

If your legitimate backend uses one of these ranges, the answer is **not** to bypass the guard. Put it behind a hostname that resolves to a routable address, or front it with a reverse proxy you trust.

## Where the knobs are read

Both env vars are read at Mastio startup. Editing `proxy.env` without restarting the container has no effect. The `proxy.env.example` template ships with both knobs documented and commented out at sensible defaults; copy it to `proxy.env` and edit there.

## Related

- Threat model: SSRF section (`docs/security/threat-model.md`, F-A-301).
- ADR-030: Mastio bundle upgrade + data layout — explains why `proxy.env` is the single source of truth for the bundled deploy.
