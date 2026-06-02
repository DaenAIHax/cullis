"""H4 (audit 2026-06-02) — key-strength floor on the Connector
agent-enrollment signing path.

sign_external_pubkey accepted any loadable key, so an RSA-512 or
non-NIST-curve key could obtain a legitimate Org-Intermediate-signed mTLS
leaf (a cert on a factorable key, invisible to the approving admin). The
user-CSR path already enforced RSA>=2048 + NIST curves (F-A-102); these
tests lock in parity via assert_strong_public_key.
"""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from mcp_proxy.egress.agent_manager import assert_strong_public_key


def _rsa_pub(bits: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()


def _ec_pub(curve):
    return ec.generate_private_key(curve).public_key()


def test_rsa_1024_rejected():
    # cryptography refuses to *generate* RSA < 1024, so 1024 is the
    # smallest constructible weak key; it is still below the 2048 floor and
    # must be rejected. A factorable RSA-512 submitted as PEM from an
    # external tool would hit the same key_size < 2048 branch.
    with pytest.raises(ValueError, match="too small"):
        assert_strong_public_key(_rsa_pub(1024))


def test_rsa_2048_accepted():
    assert_strong_public_key(_rsa_pub(2048))  # no raise


def test_ec_p256_accepted():
    assert_strong_public_key(_ec_pub(ec.SECP256R1()))  # no raise


def test_ec_p384_accepted():
    assert_strong_public_key(_ec_pub(ec.SECP384R1()))  # no raise


def test_ec_non_nist_curve_rejected():
    # secp256k1 (Bitcoin curve) is a strong-ish curve but outside the
    # NIST allowlist the rest of the PKI uses — must be refused.
    with pytest.raises(ValueError, match="not allowed"):
        assert_strong_public_key(_ec_pub(ec.SECP256K1()))


def test_ed25519_rejected_as_unsupported():
    pub = ed25519.Ed25519PrivateKey.generate().public_key()
    with pytest.raises(ValueError, match="Unsupported"):
        assert_strong_public_key(pub)
