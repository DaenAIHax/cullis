"""Tests for the mastio-nginx leaf cert SAN encoding.

Closes the bug a non-tech operator hits the moment they deploy
``cullis-mastio-bundle`` to a VM with an IP-literal hostname:

  - ``./deploy.sh`` prompts for the public URL → operator types
    ``https://192.168.122.154:9443``.
  - ``deploy.sh`` extracts the host and writes
    ``MCP_PROXY_NGINX_SAN=192.168.122.154,mastio.local,localhost``.
  - The Mastio container boots, generates an Org CA, then asks
    ``InternalAgentManager.emit_nginx_server_cert(sans=[...])`` to
    mint a leaf for nginx.
  - Pre-fix: every SAN entry went into ``x509.DNSName(s)``. RFC 6125
    + Python's ``ssl`` reject IP literals matched against ``DNSName``
    SANs → every Connector dialing the IP failed
    ``[SSL: CERTIFICATE_VERIFY_FAILED] IP address mismatch`` despite
    a "valid" cert with ``DNS:192.168.122.154`` printed in it.

The fix splits ``sans`` into two buckets: real hostnames →
``x509.DNSName``, IP literals → ``x509.IPAddress``. These tests pin
that behaviour so a regression silently bringing the old shape back
shows up at unit-test time, not at the next dogfood.
"""
from __future__ import annotations

import asyncio
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_proxy.egress.agent_manager import AgentManager


def _make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Standalone Org CA — mirrors the fast-boot path in main.py
    without touching Vault or DB."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "test-org CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_manager_with_ca() -> AgentManager:
    """An AgentManager wired with an Org CA + Mastio Intermediate but
    skipping the Vault / DB bootstrap — the SAN logic only touches
    in-memory CA material + a path on disk.

    Three-tier PKI hardening (audit 2026-05-18) — ensure_nginx_server_cert
    now signs the leaf with the Intermediate, so the test fixture has
    to populate ``_mastio_ca_*`` too. We use the same self-signed cert
    as both Root and Intermediate for the SAN tests, which only
    inspect SAN extension shape on the leaf.
    """
    mgr = AgentManager.__new__(AgentManager)
    key, cert = _make_ca()
    mgr._org_ca_key = key
    mgr._org_ca_cert = cert
    mgr._mastio_ca_key = key
    mgr._mastio_ca_cert = cert
    mgr._org_id = "test-org"
    return mgr


def _emit(mgr: AgentManager, out: Path, sans: list[str]) -> Path:
    """Run the emit method synchronously, return the leaf cert path."""
    asyncio.run(
        mgr.ensure_nginx_server_cert(
            out_dir=out,
            sans=sans,
            validity_days=30,
            renew_within_days=7,
        )
    )
    return out / "mastio-server.crt"


def _read_sans(crt_path: Path) -> tuple[set[str], set[str]]:
    """Return (DNS names, IP literals as strings) from the cert SAN."""
    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName,
    ).value
    dns = set(san.get_values_for_type(x509.DNSName))
    ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    return dns, ips


# ── Mint path ──────────────────────────────────────────────────────


def test_mint_ipv4_literal_lands_in_ip_address_san(tmp_path):
    """The IP-literal-on-VM bug — pin it to the iPAddress slot."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["192.168.122.154", "mastio.local", "localhost"])
    dns, ips = _read_sans(crt)
    assert dns == {"mastio.local", "localhost"}
    assert ips == {"192.168.122.154"}


def test_mint_ipv6_literal_lands_in_ip_address_san(tmp_path):
    """IPv6 deploys deserve the same treatment — same bug, different
    address family. Operator using ``[::1]`` or a ULA hits this on
    home-lab setups."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["::1", "mastio.local"])
    dns, ips = _read_sans(crt)
    assert dns == {"mastio.local"}
    # cryptography normalises IPv6 to canonical form on read.
    assert ips == {str(ipaddress.ip_address("::1"))}


def test_mint_pure_hostnames_unchanged(tmp_path):
    """No IPs in the list → IPAddress SAN must be empty (regression
    guard for environments that still use only DNS-style SANs)."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["mastio.acme.local", "localhost"])
    dns, ips = _read_sans(crt)
    assert dns == {"mastio.acme.local", "localhost"}
    assert ips == set()


# ── Reuse path ──────────────────────────────────────────────────────


def test_reuse_path_accepts_existing_cert_with_correct_split(tmp_path):
    """A second boot with the same SAN list must NOT regenerate the
    cert. This was already the contract pre-fix, just on DNSName-only
    inputs — pin it for the new mixed-type case."""
    mgr = _make_manager_with_ca()
    sans = ["192.168.122.154", "mastio.local"]
    crt1 = _emit(mgr, tmp_path, sans)
    serial1 = x509.load_pem_x509_certificate(crt1.read_bytes()).serial_number

    # Second emit with the same input — must reuse, not regenerate.
    _emit(mgr, tmp_path, sans)
    serial2 = x509.load_pem_x509_certificate(crt1.read_bytes()).serial_number
    assert serial1 == serial2, (
        "second emit regenerated the leaf — reuse path didn't recognise "
        "the existing cert with mixed DNS+IP SANs"
    )


def test_reuse_path_regenerates_when_san_list_changes(tmp_path):
    """Changing IPs/hosts must trigger a fresh mint — otherwise an
    operator who edits MCP_PROXY_NGINX_SAN would silently keep the old
    cert and the new hostname would still fail validation."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["192.168.122.154", "mastio.local"])
    serial1 = x509.load_pem_x509_certificate(crt.read_bytes()).serial_number

    _emit(mgr, tmp_path, ["10.0.0.5", "mastio.local"])
    serial2 = x509.load_pem_x509_certificate(crt.read_bytes()).serial_number
    assert serial1 != serial2, (
        "SAN list changed (192.168.122.154 → 10.0.0.5) but the leaf "
        "wasn't regenerated"
    )
    dns, ips = _read_sans(crt)
    assert ips == {"10.0.0.5"}


def test_reuse_path_regenerates_when_legacy_cert_has_ip_in_dns_san(tmp_path):
    """A pre-fix cert (IP shoved into DNSName) MUST be regenerated on
    next boot — otherwise the operator never sees the bug fix even
    after upgrading. Simulate the legacy state by emitting the cert
    with the buggy code path, then re-emit with the same input and
    assert the new cert has the right shape."""
    # Build a legacy-shape cert by hand (IP in DNSName SAN) so we
    # don't depend on the buggy code path still existing.
    out = tmp_path
    out.mkdir(parents=True, exist_ok=True)
    ca_path = out / "org-ca.crt"
    crt_path = out / "mastio-server.crt"
    key_path = out / "mastio-server.key"

    mgr = _make_manager_with_ca()
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    legacy = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "192.168.122.154"),
        ]))
        .issuer_name(mgr._org_ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=180))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("192.168.122.154"),  # ← the legacy bug
                x509.DNSName("mastio.local"),
            ]),
            critical=False,
        )
        .sign(mgr._org_ca_key, hashes.SHA256())
    )
    crt_path.write_bytes(legacy.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    ca_path.write_bytes(
        mgr._org_ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    _emit(mgr, out, ["192.168.122.154", "mastio.local"])
    dns, ips = _read_sans(crt_path)
    assert dns == {"mastio.local"}
    assert ips == {"192.168.122.154"}, (
        "legacy cert with IP-as-DNSName was reused instead of being "
        "replaced — operator stays stuck with CERTIFICATE_VERIFY_FAILED"
    )


# ── Multi-worker boot race: torn cert/key pair ──────────────────────
#
# Cold first boot with N uvicorn workers and an empty cert dir: every
# worker fails the reuse check, enters the mint path, generates its OWN
# leaf keypair and writes the three shared output files. The per-file
# tmp+rename is atomic but the three-file set is not, so the writes
# interleave across workers and leave ``mastio-server.crt`` carrying
# worker B's leaf pubkey next to ``mastio-server.key`` holding worker
# A's private key — a torn pair nginx rejects with "key values
# mismatch" on the 9443 mTLS port. The fix: (1) fence reuse-recheck +
# mint + write under a cross-worker boot lock so exactly one worker
# mints, and (2) make the reuse check validate that the on-disk private
# key actually owns the leaf's public key, so a torn pair from a
# pre-fix boot is regenerated instead of reused forever.


def _pair_consistent(crt_path: Path, key_path: Path) -> bool:
    """True when the on-disk private key owns the leaf cert's pubkey."""
    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    priv = serialization.load_pem_private_key(
        key_path.read_bytes(), password=None,
    )
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    return (
        priv.public_key().public_bytes(serialization.Encoding.DER, spki)
        == cert.public_key().public_bytes(serialization.Encoding.DER, spki)
    )


def _write_valid_leaf_for_key(
    mgr: AgentManager, out: Path, leaf_key, sans: list[str],
) -> int:
    """Write a full, valid nginx triple on disk for ``leaf_key`` and
    return the leaf serial. Mirrors the mint output shape (crt = leaf ||
    Intermediate bundle, ca = Org || Intermediate) so it passes every
    reuse check EXCEPT whatever the caller deliberately breaks."""
    out.mkdir(parents=True, exist_ok=True)
    san_hosts, san_ips = [], []
    for entry in sans:
        try:
            ipaddress.ip_address(entry)
            san_ips.append(entry)
        except ValueError:
            san_hosts.append(entry)
    now = datetime.now(timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, sans[0]),
        ]))
        .issuer_name(mgr._mastio_ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(h) for h in san_hosts]
                + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips],
            ),
            critical=False,
        )
        .sign(mgr._mastio_ca_key, hashes.SHA256())
    )
    bundle = (
        leaf.public_bytes(serialization.Encoding.PEM)
        + mgr._mastio_ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    (out / "mastio-server.crt").write_bytes(bundle)
    (out / "org-ca.crt").write_bytes(
        mgr._org_ca_cert.public_bytes(serialization.Encoding.PEM)
        + mgr._mastio_ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    return leaf.serial_number


def test_minted_pair_is_internally_consistent(tmp_path):
    """Sanity: a freshly minted triple has a key that owns the cert."""
    mgr = _make_manager_with_ca()
    _emit(mgr, tmp_path, ["mastio.local", "192.168.122.154"])
    assert _pair_consistent(
        tmp_path / "mastio-server.crt", tmp_path / "mastio-server.key",
    )


def test_reuse_rejects_torn_keypair_and_regenerates(tmp_path):
    """The core multi-worker race fix: a torn cert/key pair on disk
    (valid cert, but the private key belongs to a DIFFERENT keypair)
    must NOT be reused — it must be regenerated into a consistent pair.
    Without the key↔cert match in the reuse check, the torn pair passes
    issuer/expiry/CA/SAN/bundle validation and nginx stays broken
    across every restart."""
    mgr = _make_manager_with_ca()
    sans = ["mastio.local", "192.168.122.154"]

    # Lay down a torn pair: a valid leaf cert for key A, but the .key
    # file holds an unrelated key B.
    key_a = ec.generate_private_key(ec.SECP256R1())
    key_b = ec.generate_private_key(ec.SECP256R1())
    torn_serial = _write_valid_leaf_for_key(mgr, tmp_path, key_a, sans)
    (tmp_path / "mastio-server.key").write_bytes(key_b.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    crt_path = tmp_path / "mastio-server.crt"
    key_path = tmp_path / "mastio-server.key"
    assert not _pair_consistent(crt_path, key_path), "fixture not torn"

    _emit(mgr, tmp_path, sans)

    # Regenerated: new serial AND a consistent pair.
    new_serial = x509.load_pem_x509_certificate(
        crt_path.read_bytes(),
    ).serial_number
    assert new_serial != torn_serial, (
        "torn cert/key pair was reused instead of regenerated — nginx "
        "would stay broken with key/cert mismatch across restarts"
    )
    assert _pair_consistent(crt_path, key_path), (
        "regenerated pair is still torn"
    )


def test_reuse_accepts_consistent_pair_no_regen(tmp_path):
    """A matching (non-torn) pair with the right SANs is reused — the
    key match must not cause spurious regeneration on every boot."""
    mgr = _make_manager_with_ca()
    sans = ["mastio.local", "192.168.122.154"]
    _emit(mgr, tmp_path, sans)
    crt_path = tmp_path / "mastio-server.crt"
    serial1 = x509.load_pem_x509_certificate(
        crt_path.read_bytes(),
    ).serial_number
    _emit(mgr, tmp_path, sans)
    serial2 = x509.load_pem_x509_certificate(
        crt_path.read_bytes(),
    ).serial_number
    assert serial1 == serial2, "consistent pair was needlessly regenerated"


def test_concurrent_emits_converge_to_consistent_pair(tmp_path):
    """N workers provisioning into the same dir concurrently must leave
    a single consistent pair (the double-checked-lock + adopt contract).
    In-process asyncio can't reproduce the cross-process interleave the
    flock/advisory lock guards against, but it pins the convergence
    contract and the recheck-adopt path."""
    mgr = _make_manager_with_ca()
    sans = ["mastio.local", "10.1.2.3"]

    async def _run():
        await asyncio.gather(*[
            mgr.ensure_nginx_server_cert(
                out_dir=tmp_path, sans=sans,
                validity_days=30, renew_within_days=7,
            )
            for _ in range(4)
        ])

    asyncio.run(_run())
    crt_path = tmp_path / "mastio-server.crt"
    key_path = tmp_path / "mastio-server.key"
    assert _pair_consistent(crt_path, key_path), (
        "concurrent provisioning left a torn pair"
    )
    dns, ips = _read_sans(crt_path)
    assert dns == {"mastio.local"} and ips == {"10.1.2.3"}
