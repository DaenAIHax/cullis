"""demo_network — ADR-009 Phase 2/4 mastio_pubkey pinning.

Runs after the proxies boot (docker depends_on service_healthy). Fetches
each proxy's mastio leaf pubkey via ``GET /v1/admin/mastio-pubkey`` and
pins it on the Court via ``PATCH /v1/admin/orgs/{id}/mastio-pubkey``.
Without this, /v1/auth/token refuses every login in the demo (Phase 4
removed the legacy NULL-pubkey soft path).
"""
from __future__ import annotations

import os
import sys
import time

import httpx


BROKER_URL   = os.environ.get("BROKER_URL", "http://broker:8000")
ADMIN_SECRET = os.environ["ADMIN_SECRET"]

PROXIES = [
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


def _fetch(client: httpx.Client, proxy_url: str, admin_secret: str,
           timeout_s: float = 120.0) -> str:
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
    print(f"pin_mastio: timeout for {proxy_url} — last={last}", flush=True)
    raise SystemExit(1)


def _pin(client: httpx.Client, org_id: str, pem: str) -> None:
    r = client.patch(
        f"{BROKER_URL}/v1/admin/orgs/{org_id}/mastio-pubkey",
        headers={"X-Admin-Secret": ADMIN_SECRET},
        json={"mastio_pubkey": pem}, timeout=10.0,
    )
    if r.status_code != 200:
        print(f"pin_mastio: PATCH failed for {org_id}: {r.status_code} {r.text[:200]}",
              flush=True)
        raise SystemExit(1)


def main() -> int:
    print("pin_mastio: starting", flush=True)
    with httpx.Client() as client:
        for cfg in PROXIES:
            print(f"pin_mastio: fetching from {cfg['proxy_url']}", flush=True)
            pem = _fetch(client, cfg["proxy_url"], cfg["admin_secret"])
            print(f"pin_mastio: pinning on Court for {cfg['org_id']}", flush=True)
            _pin(client, cfg["org_id"], pem)
            print(f"pin_mastio: ✓ {cfg['org_id']}", flush=True)
    print("pin_mastio: done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
