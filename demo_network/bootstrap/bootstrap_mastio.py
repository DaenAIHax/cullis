"""Post-proxy-boot wiring for demo_network.

Runs after ``bootstrap`` has onboarded both orgs (``/state/bootstrap.done``
present) and after the proxies have booted and generated their Mastio CA +
leaf identity. Drives four steps in order:

1. **ADR-009 mastio_pubkey pin** — fetch each proxy's leaf pubkey and PATCH
   it onto the Court so counter-signed federation pushes are accepted.

2. **ADR-010 Phase 6a-4-I — Mastio agent seed** — for every agent the outer
   bootstrap minted a cert/key pair for, POST the material to the owning
   Mastio's ``/v1/admin/agents`` with ``federated=true``. The Phase 3
   publisher loop carries the row to the Court; we no longer hit the
   legacy ``POST /v1/registry/agents``.

3. **Binding create + approve** — once the publisher has propagated the
   agent, create and approve a binding on the Court using ``x-org-secret``.
   Retried until the agent shows up (publisher interval is a handful of
   seconds in the demo via ``MCP_PROXY_FEDERATION_POLL_INTERVAL_S``).

4. **Test-only revocations** — for agents flagged ``revoke_cert`` /
   ``revoke_binding`` in ``/state/agents.json`` (A5/A6 smoke assertions),
   call the corresponding broker admin/registry endpoint.

Idempotent: the Mastio returns 409 on duplicate seed; binding create
tolerates 409; revoke is only invoked for agents explicitly flagged.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
from datetime import timezone

import httpx
from cryptography import x509


BROKER_URL   = os.environ.get("BROKER_URL", "http://broker:8000")
ADMIN_SECRET = os.environ["ADMIN_SECRET"]
STATE        = pathlib.Path(os.environ.get("STATE_DIR", "/state"))

_PROXIES = [
    {
        "org_id":       os.environ.get("PROXY_A_ORG", "demo-org-a"),
        "proxy_url":    os.environ.get("PROXY_A_URL", "http://proxy-a:9100"),
        "admin_secret": os.environ.get("PROXY_A_ADMIN_SECRET", "demo-proxy-admin-a"),
    },
    {
        "org_id":       os.environ.get("PROXY_B_ORG", "demo-org-b"),
        "proxy_url":    os.environ.get("PROXY_B_URL", "http://proxy-b:9100"),
        "admin_secret": os.environ.get("PROXY_B_ADMIN_SECRET", "demo-proxy-admin-b"),
    },
]
PROXY_BY_ORG = {p["org_id"]: p for p in _PROXIES}

# Maximum time we're willing to wait for the federation publisher to push
# a seeded agent to the Court before each binding create. Publisher ticks
# every MCP_PROXY_FEDERATION_POLL_INTERVAL_S seconds (2s in demo); 60s
# covers a cold-cache Postgres matrix leg while still surfacing a genuine
# publisher hang quickly.
BINDING_CREATE_TIMEOUT_S = 60.0
BINDING_CREATE_RETRY_S = 2.0


def _log(msg: str) -> None:
    print(f"bootstrap_mastio: {msg}", flush=True)


def _fetch_mastio_pubkey(
    client: httpx.Client, proxy_url: str, admin_secret: str,
    timeout_s: float = 120.0,
) -> str:
    deadline = time.monotonic() + timeout_s
    last = "(pending)"
    while time.monotonic() < deadline:
        try:
            r = client.get(
                f"{proxy_url}/v1/admin/mastio-pubkey",
                headers={"X-Admin-Secret": admin_secret}, timeout=5.0,
            )
            if r.status_code == 200 and r.json().get("mastio_pubkey"):
                return r.json()["mastio_pubkey"]
            last = f"HTTP {r.status_code} mastio_pubkey={r.json().get('mastio_pubkey')}"
        except httpx.TransportError as exc:
            last = f"transport: {exc}"
        time.sleep(1.0)
    _log(f"timeout fetching mastio_pubkey from {proxy_url} — last={last}")
    raise SystemExit(1)


def _pin(client: httpx.Client, org_id: str, pem: str) -> None:
    r = client.patch(
        f"{BROKER_URL}/v1/admin/orgs/{org_id}/mastio-pubkey",
        headers={"X-Admin-Secret": ADMIN_SECRET},
        json={"mastio_pubkey": pem}, timeout=10.0,
    )
    if r.status_code != 200:
        _log(f"PATCH mastio-pubkey failed for {org_id}: {r.status_code} {r.text[:200]}")
        raise SystemExit(1)


def _seed_agent_on_mastio(
    client: httpx.Client, proxy: dict, agent: dict,
) -> None:
    """POST /v1/admin/agents with pre-generated cert/key + federated=true."""
    role = agent["role"]
    org_dir = STATE / agent["org_id"]
    cert_pem = (org_dir / f"{role}.pem").read_text()
    key_pem  = (org_dir / f"{role}-key.pem").read_text()

    r = client.post(
        f"{proxy['proxy_url']}/v1/admin/agents",
        headers={"X-Admin-Secret": proxy["admin_secret"]},
        json={
            "agent_name":      role,
            "display_name":    agent["display_name"],
            "capabilities":    agent["capabilities"],
            "federated":       True,
            "cert_pem":        cert_pem,
            "private_key_pem": key_pem,
        },
        timeout=10.0,
    )
    if r.status_code == 201:
        _log(f"{agent['agent_id']}: seeded on Mastio (federated=true)")
    elif r.status_code == 409:
        _log(f"{agent['agent_id']}: already on Mastio — skipping seed")
    else:
        _log(
            f"{agent['agent_id']}: seed failed "
            f"HTTP {r.status_code} {r.text[:200]}",
        )
        raise SystemExit(1)


def _read_org_secret(org_id: str) -> str:
    return (STATE / org_id / "org_secret").read_text().strip()


def _create_and_approve_binding(
    client: httpx.Client, agent: dict, org_secret: str,
) -> str:
    """Create + approve a binding for this agent, polling until the
    federation publisher has propagated the agent to the Court.

    Returns the binding id so downstream steps (revoke-binding) can act
    on it without re-listing.
    """
    org_id   = agent["org_id"]
    agent_id = agent["agent_id"]
    headers  = {"x-org-id": org_id, "x-org-secret": org_secret}
    body     = {"org_id": org_id, "agent_id": agent_id, "scope": agent["capabilities"]}

    deadline = time.monotonic() + BINDING_CREATE_TIMEOUT_S
    last = "(no attempt)"
    while time.monotonic() < deadline:
        r = client.post(
            f"{BROKER_URL}/v1/registry/bindings", json=body,
            headers=headers, timeout=10.0,
        )
        if r.status_code == 201:
            binding_id = r.json()["id"]
            _log(f"{agent_id}: binding {binding_id} created")
            break
        if r.status_code == 409:
            # Binding already exists — grab its id.
            r = client.get(
                f"{BROKER_URL}/v1/registry/bindings",
                params={"org_id": org_id}, headers=headers, timeout=10.0,
            )
            r.raise_for_status()
            binding_id = next(
                b["id"] for b in r.json() if b.get("agent_id") == agent_id
            )
            _log(f"{agent_id}: binding {binding_id} already existed")
            break
        # Agent not yet on the Court (publisher hasn't ticked) — retry.
        last = f"HTTP {r.status_code} {r.text[:200]}"
        time.sleep(BINDING_CREATE_RETRY_S)
    else:
        _log(
            f"{agent_id}: binding create timed out after "
            f"{BINDING_CREATE_TIMEOUT_S:.0f}s (last={last}). "
            "Federation publisher may be stuck — check proxy logs.",
        )
        raise SystemExit(1)

    r = client.post(
        f"{BROKER_URL}/v1/registry/bindings/{binding_id}/approve",
        headers=headers, timeout=10.0,
    )
    if r.status_code != 200:
        _log(
            f"{agent_id}: binding {binding_id} approve failed "
            f"HTTP {r.status_code} {r.text[:200]}",
        )
        raise SystemExit(1)
    _log(f"{agent_id}: binding {binding_id} approved")
    return binding_id


def _revoke_agent_cert(client: httpx.Client, agent: dict) -> None:
    """Admin-revoke the agent's current cert (A5 assertion path)."""
    org_id   = agent["org_id"]
    role     = agent["role"]
    agent_id = agent["agent_id"]
    cert_pem = (STATE / org_id / f"{role}.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial_hex = format(cert.serial_number, "x")
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    r = client.post(
        f"{BROKER_URL}/v1/admin/certs/revoke",
        json={
            "serial_hex":     serial_hex,
            "org_id":         org_id,
            "agent_id":       agent_id,
            "reason":         "smoke-A5-test",
            "revoked_by":     "smoke-bootstrap-mastio",
            "cert_not_after": not_after.isoformat(),
        },
        headers={"x-admin-secret": ADMIN_SECRET},
        timeout=10.0,
    )
    if r.status_code != 200:
        _log(f"{agent_id}: cert revoke failed {r.status_code} {r.text[:200]}")
        raise SystemExit(1)
    _log(f"{agent_id}: cert {serial_hex} revoked")


def _revoke_agent_binding(
    client: httpx.Client, agent: dict, binding_id: str, org_secret: str,
) -> None:
    """Admin-revoke the agent's binding (A6 assertion path)."""
    org_id = agent["org_id"]
    r = client.post(
        f"{BROKER_URL}/v1/registry/bindings/{binding_id}/revoke",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
        timeout=10.0,
    )
    if r.status_code != 200:
        _log(
            f"{agent['agent_id']}: binding {binding_id} revoke failed "
            f"{r.status_code} {r.text[:200]}",
        )
        raise SystemExit(1)
    _log(f"{agent['agent_id']}: binding {binding_id} revoked")


def main() -> int:
    _log("starting")

    agents_path = STATE / "agents.json"
    if not agents_path.exists():
        _log(f"missing {agents_path} — bootstrap did not run or did not mint certs")
        raise SystemExit(1)
    agents: list[dict] = json.loads(agents_path.read_text())

    with httpx.Client() as client:
        # Step 1 — pin mastio_pubkey per org.
        for proxy in _PROXIES:
            _log(f"fetching mastio_pubkey from {proxy['proxy_url']}")
            pem = _fetch_mastio_pubkey(
                client, proxy["proxy_url"], proxy["admin_secret"],
            )
            _log(f"pinning on Court for {proxy['org_id']}")
            _pin(client, proxy["org_id"], pem)

        # Step 2 — seed every agent on its Mastio (federated=true).
        for agent in agents:
            proxy = PROXY_BY_ORG.get(agent["org_id"])
            if proxy is None:
                _log(f"{agent['agent_id']}: no proxy configured for org — skipping")
                continue
            _seed_agent_on_mastio(client, proxy, agent)

        # Step 3 — bindings (with publisher-propagation retry) + test revocations.
        secrets_by_org = {
            org_id: _read_org_secret(org_id)
            for org_id in {a["org_id"] for a in agents}
        }
        for agent in agents:
            secret = secrets_by_org[agent["org_id"]]
            binding_id = _create_and_approve_binding(client, agent, secret)
            if agent.get("revoke_cert"):
                _revoke_agent_cert(client, agent)
            if agent.get("revoke_binding"):
                _revoke_agent_binding(client, agent, binding_id, secret)

    _log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
