"""Demo-network bootstrap: register 2 organizations on the broker, one via the
generic /onboarding/join flow and one via admin-registration + attach-ca,
so the smoke exercises both onboarding paths.

Also mints per-agent certs/keys signed by the Org CA, but stops there — the
Mastio-authoritative registration (ADR-010) happens later in
``bootstrap_mastio.py`` via ``POST /v1/admin/agents`` once the proxies are
healthy. Binding create/approve and any test-only revocations live there
too, since they require the agent to already exist on the Court via the
federation publisher.

Outputs (into /state, a shared Docker volume):
  /state/{org_id}/ca.pem           — org CA certificate
  /state/{org_id}/ca-key.pem       — org CA private key
  /state/{org_id}/org_secret       — opaque secret used by the proxy to auth
  /state/{org_id}/display_name     — human-readable label
  /state/{org_id}/{role}.pem       — agent leaf cert (org-CA signed)
  /state/{org_id}/{role}-key.pem   — agent leaf key
  /state/orgs.json                 — list of orgs for downstream services
  /state/agents.json               — list of agents for bootstrap_mastio
  /state/bootstrap.done            — flag file; dependents gate on this

Idempotent: re-runs skip work if /state/bootstrap.done exists.
"""
from __future__ import annotations

import datetime
import json
import os
import pathlib
import secrets
import sys
import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

PKI_KEY_TYPE = os.environ.get("PKI_KEY_TYPE", "rsa").strip().lower()


def _gen_key(bits: int):
    """Generate a private key of the configured type (PKI_KEY_TYPE)."""
    if PKI_KEY_TYPE == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if PKI_KEY_TYPE == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    raise SystemExit(f"bootstrap: unsupported PKI_KEY_TYPE={PKI_KEY_TYPE!r}")

BROKER_URL   = os.environ["BROKER_URL"]
ADMIN_SECRET = os.environ["ADMIN_SECRET"]
CA_BUNDLE    = os.environ.get("CA_BUNDLE", "/certs/ca.crt")
STATE        = pathlib.Path(os.environ.get("STATE_DIR", "/state"))
DONE_FLAG    = STATE / "bootstrap.done"

TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "cullis.test")

ORGS = [
    # Onboarding via POST /onboarding/join (one-shot, org created from scratch)
    {
        "org_id": "demo-org-a", "display_name": "Demo Org A", "flow": "join",
        "agent_role": "sender",
        "capabilities": ["message.exchange"],
        # Extra agent to exercise the DENY branch of the PDP: proxy-b's
        # policy_rules list this agent as blocked, so any session it opens
        # with the checker must be refused.
        "extra_agents": [
            {"role": "banned-sender", "capabilities": ["message.exchange"]},
            # Agent whose x509 cert will be admin-revoked after creation; the
            # smoke then proves login fails with 401 (A5).
            {"role": "revoked-agent", "capabilities": ["message.exchange"],
             "revoke_after_creation": True},
            # Agent whose cert is valid but whose binding is revoked — smoke
            # proves session open fails with 403 even though login succeeds (A6).
            {"role": "unbound-agent", "capabilities": ["message.exchange"],
             "revoke_binding_after_creation": True},
        ],
        "webhook_url": "https://proxy-a.cullis.test:8443/pdp/policy",
    },
    # Onboarding via admin-register + POST /onboarding/attach (simulates the
    # realistic enterprise path where the broker admin creates the org before
    # the customer org installs their MCP proxy).
    {
        "org_id": "demo-org-b", "display_name": "Demo Org B", "flow": "attach",
        "agent_role": "checker",
        "capabilities": ["message.exchange"],
        "webhook_url": "https://proxy-b.cullis.test:8443/pdp/policy",
    },
]


def _gen_org_ca(org_id: str) -> tuple[bytes, bytes]:
    key = _gen_key(bits=4096)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _wait_broker(client: httpx.Client, timeout_s: float = 60.0) -> None:
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        try:
            r = client.get(f"{BROKER_URL}/health")
            if r.status_code == 200:
                print(f"bootstrap: broker healthy after {time.monotonic() - start:.1f}s")
                return
        except Exception:
            pass
        time.sleep(1)
    raise SystemExit(f"bootstrap: broker never became healthy within {timeout_s}s")


def _admin_headers() -> dict[str, str]:
    return {"x-admin-secret": ADMIN_SECRET}


def _persist_org(org_id: str, display_name: str, cert_pem: bytes,
                 key_pem: bytes, org_secret: str) -> None:
    d = STATE / org_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "ca.pem").write_bytes(cert_pem)
    (d / "ca-key.pem").write_bytes(key_pem)
    (d / "org_secret").write_text(org_secret)
    (d / "display_name").write_text(display_name)
    # Broad perms so downstream containers (different UIDs) can read.
    for p in d.iterdir():
        p.chmod(0o644)


def _onboard_via_join(client: httpx.Client, org: dict, cert_pem: bytes,
                      key_pem: bytes, org_secret: str) -> None:
    org_id = org["org_id"]

    r = client.post(
        f"{BROKER_URL}/v1/admin/invites",
        json={"label": f"smoke-{org_id}", "ttl_hours": 1},
        headers=_admin_headers(),
    )
    r.raise_for_status()
    token = r.json()["token"]

    r = client.post(f"{BROKER_URL}/v1/onboarding/join", json={
        "org_id": org_id,
        "display_name": org["display_name"],
        "secret": org_secret,
        "ca_certificate": cert_pem.decode(),
        "contact_email": f"admin@{org_id}.test",
        "invite_token": token,
        "webhook_url": org.get("webhook_url"),
    })
    if r.status_code != 202:
        raise SystemExit(f"join failed for {org_id}: HTTP {r.status_code} {r.text}")

    r = client.post(
        f"{BROKER_URL}/v1/admin/orgs/{org_id}/approve",
        headers=_admin_headers(),
    )
    r.raise_for_status()
    print(f"bootstrap: {org_id} active via /onboarding/join")


def _gen_agent_cert(agent_id: str, org_id: str, ca_cert_pem: bytes,
                    ca_key_pem: bytes) -> tuple[bytes, bytes]:
    """Issue an agent cert signed by the org CA with a SPIFFE SAN."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key  = load_pem_private_key(ca_key_pem, password=None)

    key = _gen_key(bits=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    _, agent_name = agent_id.split("::", 1)
    spiffe_id = f"spiffe://{TRUST_DOMAIN}/{org_id}/{agent_name}"
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _mint_agent_cert(
    org: dict, role: str, capabilities: list[str],
    revoke_after_creation: bool = False,
    revoke_binding_after_creation: bool = False,
) -> dict:
    """Generate the agent's cert/key pair and persist it under /state.

    ADR-010 Phase 6a-4-I: bootstrap no longer registers the agent on the
    Court. The returned dict is serialized into /state/agents.json so
    that bootstrap_mastio can seed the Mastio via /v1/admin/agents once
    the proxies are healthy; the federation publisher then propagates
    the row to the Court.
    """
    org_id = org["org_id"]
    agent_id = f"{org_id}::{role}"

    org_dir = STATE / org_id
    ca_cert_pem = (org_dir / "ca.pem").read_bytes()
    ca_key_pem  = (org_dir / "ca-key.pem").read_bytes()

    cert_pem, key_pem = _gen_agent_cert(agent_id, org_id, ca_cert_pem, ca_key_pem)
    (org_dir / f"{role}.pem").write_bytes(cert_pem)
    (org_dir / f"{role}-key.pem").write_bytes(key_pem)
    (org_dir / f"{role}.pem").chmod(0o644)
    (org_dir / f"{role}-key.pem").chmod(0o644)

    print(f"bootstrap: minted cert for {agent_id}")
    return {
        "org_id":       org_id,
        "display_name": f"{org['display_name']} {role}",
        "agent_id":     agent_id,
        "role":         role,
        "capabilities": capabilities,
        "revoke_cert":  revoke_after_creation,
        "revoke_binding": revoke_binding_after_creation,
    }


def _onboard_via_attach(client: httpx.Client, org: dict, cert_pem: bytes,
                        key_pem: bytes, org_secret: str) -> None:
    org_id = org["org_id"]

    # 1. Admin creates the org with a placeholder secret (no CA yet).
    r = client.post(f"{BROKER_URL}/v1/registry/orgs", json={
        "org_id": org_id,
        "display_name": org["display_name"],
        "secret": "placeholder-will-be-rotated",
    }, headers=_admin_headers())
    r.raise_for_status()

    # 2. Admin generates an attach-ca invite bound to this org_id.
    r = client.post(
        f"{BROKER_URL}/v1/admin/orgs/{org_id}/attach-invite",
        json={"label": f"smoke-attach-{org_id}", "ttl_hours": 1},
        headers=_admin_headers(),
    )
    r.raise_for_status()
    token = r.json()["token"]

    # 3. Proxy side calls /onboarding/attach with its chosen secret + PDP URL.
    r = client.post(f"{BROKER_URL}/v1/onboarding/attach", json={
        "ca_certificate": cert_pem.decode(),
        "invite_token": token,
        "secret": org_secret,
        "webhook_url": org.get("webhook_url"),
    })
    if r.status_code != 200:
        raise SystemExit(f"attach failed for {org_id}: HTTP {r.status_code} {r.text}")
    print(f"bootstrap: {org_id} active via /onboarding/attach (CA + secret rotated)")


def main() -> int:
    # Always run. The broker keeps its DB on tmpfs so it forgets orgs on every
    # restart; skipping bootstrap would leave the broker empty while the
    # state volume (holding agent certs) looks stale-valid. smoke.sh does
    # `down -v` on every fresh run anyway, so idempotency here is best-effort.
    STATE.mkdir(parents=True, exist_ok=True)
    # If we were interrupted mid-run, any leftover marker is meaningless.
    if DONE_FLAG.exists():
        DONE_FLAG.unlink()

    with httpx.Client(verify=CA_BUNDLE, timeout=30.0) as client:
        _wait_broker(client)

        for org in ORGS:
            org_id = org["org_id"]
            print(f"bootstrap: provisioning {org_id} via {org['flow']}")
            cert_pem, key_pem = _gen_org_ca(org_id)
            org_secret = secrets.token_urlsafe(32)
            _persist_org(org_id, org["display_name"], cert_pem, key_pem, org_secret)

            if org["flow"] == "join":
                _onboard_via_join(client, org, cert_pem, key_pem, org_secret)
            elif org["flow"] == "attach":
                _onboard_via_attach(client, org, cert_pem, key_pem, org_secret)
            else:
                raise SystemExit(f"unknown flow: {org['flow']}")

        # Verification: both orgs must be active from the admin API view.
        r = client.get(f"{BROKER_URL}/v1/registry/orgs", headers=_admin_headers())
        r.raise_for_status()
        active_ids = {o["org_id"] for o in r.json() if o.get("status") == "active"}
        expected = {o["org_id"] for o in ORGS}
        missing = expected - active_ids
        if missing:
            raise SystemExit(f"bootstrap: orgs not active on broker: {missing}")

        # Sanity-check that both orgs can self-auth with their chosen secret.
        for org in ORGS:
            org_id = org["org_id"]
            org_secret = (STATE / org_id / "org_secret").read_text().strip()
            r = client.get(
                f"{BROKER_URL}/v1/registry/orgs/me",
                headers={"x-org-id": org_id, "x-org-secret": org_secret},
            )
            if r.status_code != 200:
                raise SystemExit(
                    f"bootstrap: {org_id} self-auth failed ({r.status_code} {r.text}). "
                    "Secret rotation or registration broken."
                )

    # Mint per-agent certs and persist the spec list. No broker calls here —
    # bootstrap_mastio picks up /state/agents.json and calls the Mastio's
    # /v1/admin/agents once proxies are healthy (ADR-010 Phase 6a-4-I).
    agents: list[dict] = []
    for org in ORGS:
        agents.append(_mint_agent_cert(org, org["agent_role"], org["capabilities"]))
        for extra in org.get("extra_agents") or []:
            agents.append(_mint_agent_cert(
                org, extra["role"], extra["capabilities"],
                revoke_after_creation=bool(extra.get("revoke_after_creation")),
                revoke_binding_after_creation=bool(
                    extra.get("revoke_binding_after_creation")
                ),
            ))

    (STATE / "orgs.json").write_text(json.dumps([
        {"org_id": o["org_id"], "display_name": o["display_name"], "flow": o["flow"]}
        for o in ORGS
    ], indent=2))
    (STATE / "agents.json").write_text(json.dumps(agents, indent=2))
    DONE_FLAG.touch()
    print(f"bootstrap: {len(ORGS)} orgs active, {len(agents)} agent certs minted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
