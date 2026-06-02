"""Audit H1 (2026-06-02) — /v1/auth/token x509 chain forgery.

``_verify_chain`` previously verified only the signature links of the
``x5c`` chain, never the issuing CA constraints. That let any enrolled
agent forge a leaf carrying a *victim's* identity, sign it with its own
(non-CA) leaf key, and present ``[forged, attacker_leaf]``: the chain
walked to the pinned Org CA and validated, so ``issue_local_token`` minted
a LOCAL_TOKEN as the victim (full impersonation — the victim's
capabilities and bindings). The mTLS path was immune (it pins the leaf
DER against ``internal_agents.cert_pem``); ``/v1/auth/token`` is reachable
without mTLS and had no such pin.

These tests exercise ``_verify_chain`` directly: the forgery must be
rejected because a non-CA leaf can no longer act as an issuer, while
legitimate 2- and 3-level chains still verify. The forgery test fails
pre-fix (no raise).
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mcp_proxy.auth.local_token import _verify_chain


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _name(cn: str, org: str = "acme") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])


def _ca(cn, *, issuer_key=None, issuer_cert=None, path_length=0):
    """Mint a CA cert (BasicConstraints ca=True + keyCertSign). Self-signed
    when no issuer is given, otherwise signed by the provided issuer."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(cn)
    issuer_name = issuer_cert.subject if issuer_cert is not None else subject
    signing_key = issuer_key if issuer_key is not None else key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(signing_key, hashes.SHA256())
    )
    return key, cert


def _leaf(cn, issuer_key, issuer_cert, *, public_key=None):
    """Mint an end-entity leaf (BasicConstraints ca=False) signed by the
    given issuer. ``public_key`` lets a caller forge a leaf for an arbitrary
    key (the H1 attack)."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub = public_key if public_key is not None else key.public_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return key, cert


def test_forged_leaf_signed_by_non_ca_leaf_is_rejected():
    """The H1 attack: an enrolled agent's own (non-CA) leaf signs a forged
    victim leaf; [forged, attacker_leaf] must be rejected because the
    attacker leaf is not a CA and cannot act as an issuer."""
    ca_key, ca_cert = _ca("acme Org CA")
    # The attacker's own legitimately-enrolled leaf: ca=False, Org-CA-signed.
    attacker_key, attacker_cert = _leaf("acme::attacker", ca_key, ca_cert)
    # Forge a leaf carrying the victim's identity, signed with the attacker
    # leaf key, over a key the attacker controls.
    victim_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    _, forged = _leaf(
        "acme::victim", attacker_key, attacker_cert, public_key=victim_pub,
    )
    with pytest.raises(ValueError):
        _verify_chain([forged, attacker_cert], ca_cert)


def test_direct_leaf_chain_accepted():
    """Legitimate single-leaf chain (leaf signed directly by the Org CA)
    still verifies."""
    ca_key, ca_cert = _ca("acme Org CA")
    _, leaf_cert = _leaf("acme::alice", ca_key, ca_cert)
    _verify_chain([leaf_cert], ca_cert)  # no raise


def test_three_level_chain_accepted():
    """Legitimate 3-level chain (leaf ← intermediate CA ← Org root) still
    verifies — the intermediate is a real CA, so the CA-constraint check
    passes."""
    root_key, root_cert = _ca("acme Org Root", path_length=1)
    int_key, int_cert = _ca(
        "acme Intermediate", issuer_key=root_key, issuer_cert=root_cert,
        path_length=0,
    )
    _, leaf_cert = _leaf("acme::bob", int_key, int_cert)
    _verify_chain([leaf_cert, int_cert], root_cert)  # no raise
