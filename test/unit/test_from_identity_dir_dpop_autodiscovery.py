"""Tests for ``CullisClient.from_identity_dir`` ``dpop.jwk`` sibling
auto-discovery (D-11 cold-reader 401 fix, 2026-05-26).

Mirrors the ca-chain.pem sibling auto-discovery pattern at
``cullis_sdk/_client/_enrollment.py:284-315``. ``enroll_via_dashboard_approval``
(PR #934) writes the four-file identity layout
(``cert.pem``, ``key.pem``, ``ca-chain.pem``, ``dpop.jwk``, ``meta.json``) but
prior to this fix ``from_identity_dir`` only auto-discovered ``ca-chain.pem``;
customers who replayed the dashboard quickstart with just ``cert_path`` and
``key_path`` got a silent 401 from the Mastio DPoP gate on the first
``chat_completion`` call because ``_egress_dpop_key`` stayed ``None`` and
the request went out without a ``DPoP:`` header.

Three invariants pinned:

1. ``dpop.jwk`` sibling next to ``cert_path`` is auto-discovered when no
   explicit ``dpop_key_path`` is passed (the D-11 customer path).
2. An explicit ``dpop_key_path=`` argument always wins over the sibling
   (covers the case where the customer keeps the per-agent DPoP key in
   a separate KMS-released directory).
3. No sibling + no explicit path leaves ``_egress_dpop_key`` as ``None``
   (legacy callers who deliberately opt out of DPoP keep working while
   the server's ``egress_dpop_mode`` is ``off`` or ``optional``).

No real Mastio, no httpx mock: the tests only inspect the post-construction
state of the returned client instance. ``verify_tls=False`` skips the
ca_bundle validation path so the SDK doesn't reach for the system trust
store during fixture setup.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cullis_sdk.client import CullisClient
from cullis_sdk.dpop import DpopKey


def _write_test_identity(tmp_path: Path) -> tuple[Path, Path]:
    """Write a minimal self-signed EC P-256 cert + matching key.

    The cert+key pair has to validate ``_cert_key_pair_matches`` (the
    pre-flight inside ``_build_proxy_http_client``) and carry a SPIFFE
    SAN so the ``from_identity_dir`` SAN-derived ``_proxy_agent_id``
    population branch does not log a warning during the test.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")],
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        "spiffe://test.local/test-org/test-agent",
                    ),
                ],
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    return cert_path, key_path


def test_dpop_jwk_sibling_auto_discovered(tmp_path: Path) -> None:
    """``dpop.jwk`` sibling next to ``cert_path`` is picked up when no
    explicit ``dpop_key_path`` is passed — the D-11 customer path."""
    cert_path, key_path = _write_test_identity(tmp_path)
    # Sibling lives next to cert_path, matching the layout written by
    # enroll_via_dashboard_approval (PR #934).
    dpop_key = DpopKey.generate(path=tmp_path / "dpop.jwk")
    expected_jkt = dpop_key.thumbprint()

    client = CullisClient.from_identity_dir(
        "https://localhost:9443",
        cert_path=cert_path,
        key_path=key_path,
        # dpop_key_path INTENTIONALLY OMITTED — this is the cold-reader
        # path that the D-11 fix is closing.
        verify_tls=False,
    )

    assert client._egress_dpop_key is not None, (
        "dpop.jwk sibling was not auto-discovered — D-11 regression. "
        "from_identity_dir should have loaded the dpop.jwk sitting next "
        "to cert_path the same way it loads ca-chain.pem."
    )
    assert client._egress_dpop_key.thumbprint() == expected_jkt


def test_explicit_dpop_key_path_overrides_sibling(tmp_path: Path) -> None:
    """An explicit ``dpop_key_path`` always wins over a sibling.

    Models the operator who keeps the per-agent DPoP key in a separate
    KMS-released directory but still uses ``enroll_via_dashboard_approval``
    for the cert+key layout — the explicit path must not be overridden by
    the sibling auto-discovery.
    """
    cert_path, key_path = _write_test_identity(tmp_path)
    # Sibling = key A
    sibling_key = DpopKey.generate(path=tmp_path / "dpop.jwk")
    sibling_jkt = sibling_key.thumbprint()
    # Explicit (different dir) = key B
    other_dir = tmp_path / "kms-released"
    other_dir.mkdir()
    explicit_key = DpopKey.generate(path=other_dir / "different_dpop.jwk")
    explicit_jkt = explicit_key.thumbprint()
    assert sibling_jkt != explicit_jkt, (
        "fixture bug — sibling and explicit keys collide; the test cannot "
        "distinguish which one was loaded"
    )

    client = CullisClient.from_identity_dir(
        "https://localhost:9443",
        cert_path=cert_path,
        key_path=key_path,
        dpop_key_path=other_dir / "different_dpop.jwk",
        verify_tls=False,
    )

    assert client._egress_dpop_key is not None
    assert client._egress_dpop_key.thumbprint() == explicit_jkt, (
        "explicit dpop_key_path was overridden by the sibling — the "
        "auto-discovery should defer to the explicit argument."
    )
    assert client._egress_dpop_key.thumbprint() != sibling_jkt


def test_no_dpop_jwk_sibling_no_explicit_path_no_dpop_key(
    tmp_path: Path,
) -> None:
    """No sibling + no explicit path leaves ``_egress_dpop_key`` as ``None``.

    Legacy opt-in DPoP path: customers who don't write a ``dpop.jwk``
    next to their cert and don't pass ``dpop_key_path`` keep running
    without DPoP binding. The server's ``egress_dpop_mode=off|optional``
    accepts that; ``required`` will 401 — which is correct behaviour, not
    a regression caused by this fix.
    """
    cert_path, key_path = _write_test_identity(tmp_path)
    # No dpop.jwk written. Verify the precondition.
    assert not (tmp_path / "dpop.jwk").exists()

    client = CullisClient.from_identity_dir(
        "https://localhost:9443",
        cert_path=cert_path,
        key_path=key_path,
        verify_tls=False,
    )

    assert client._egress_dpop_key is None, (
        "_egress_dpop_key should remain None when no sibling exists and "
        "no explicit dpop_key_path was passed — legacy opt-in path."
    )


def test_malformed_dpop_jwk_sibling_does_not_crash_client(
    tmp_path: Path,
) -> None:
    """A malformed ``dpop.jwk`` sibling (missing required JWK fields
    like ``kty`` / ``crv``) must not crash ``from_identity_dir`` — the
    client falls back to ``_egress_dpop_key=None`` and emits a warning
    so the customer sees a hint before the eventual 401.

    Pre-fix the catch only covered ``(OSError, ValueError, JSONDecodeError)``
    so a JWK that parses as JSON but is structurally invalid (e.g. an
    empty object, or one missing ``crv``) propagated ``AttributeError``
    or ``KeyError`` out of ``DpopKey.load`` / cryptography and crashed
    ``from_identity_dir`` mid-construction. The customer would then see
    a Python traceback instead of a usable mTLS-only client.
    """
    import json as _json
    cert_path, key_path = _write_test_identity(tmp_path)
    # Valid JSON, but structurally invalid as a JWK (no kty, no crv,
    # no x/y/d). DpopKey.load checks 'd' first → raises ValueError,
    # which the original catch already covered. So we go one step
    # further: a JWK that has 'd' but is otherwise malformed (no kty)
    # — this is the case AttributeError/KeyError were leaking from.
    malformed_jwk = {"d": "AAAA"}  # 'd' present so we pass the ValueError gate
    (tmp_path / "dpop.jwk").write_text(_json.dumps(malformed_jwk))

    # Must not raise. _egress_dpop_key must end up None. The warning
    # log is emitted but pytest captures it; we don't assert on its
    # content because the log() helper is stdout-bound.
    client = CullisClient.from_identity_dir(
        "https://localhost:9443",
        cert_path=cert_path,
        key_path=key_path,
        verify_tls=False,
    )

    assert client._egress_dpop_key is None, (
        "A malformed dpop.jwk sibling must downgrade to _egress_dpop_key="
        "None rather than crash from_identity_dir mid-construction."
    )
