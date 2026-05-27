"""Tests for the RFC 3161 TSA signature verification in
``scripts/cullis-audit-verify.py`` (F-A-405).

Before this fix the standalone verifier only matched the
``messageImprint`` field of the stored ``TimeStampToken`` against
``sha256(row_hash)`` — never the CMS signature, never the chain to a
TSA root. An attacker with row_hash could fabricate a TST that passed.

These tests build a self-signed ``test CA`` + a ``test TSA`` leaf
(with the ``id-kp-timeStamping`` ExtKeyUsage RFC 3161 §2.3 requires),
hand-craft a valid CMS-signed TimeStampToken, then run the verifier
against:

  * a valid token + matching trust store → must verify
  * a tampered token (signature byte flipped) → must reject
  * a valid token but no trust store and no opt-in → must refuse
  * a valid token, no trust store, ``allow_unverified_signature=True``
    → downgraded path returns True with a warning label
  * a token whose ``genTime`` is in the future → must reject
  * a token whose ``messageImprint`` does not match the claimed digest
    → must reject
  * a token signed by a cert WITHOUT the timestamping EKU → must reject
  * a token verified against the wrong trust root → must reject

The verifier script is imported via ``importlib.util`` because it
lives under ``scripts/`` with a hyphen in the filename (not a valid
Python module name).
"""
from __future__ import annotations

import hashlib
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asn1crypto import algos, cms, core
from asn1crypto import tsp as asn1_tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


_REPO_ROOT = Path(__file__).resolve().parents[2]
_VERIFIER_PATH = _REPO_ROOT / "scripts" / "cullis-audit-verify.py"


@pytest.fixture(scope="module")
def verifier_mod():
    """Load the standalone verifier script as a module.

    The script lives outside the package import path (``scripts/`` is
    intentionally not a Python package — it ships maintainer tooling
    operators run with ``python scripts/cullis-audit-verify.py``).
    """
    spec = importlib.util.spec_from_file_location(
        "cullis_audit_verify", str(_VERIFIER_PATH),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# ── PKI scaffolding ────────────────────────────────────────────────────


def _build_ca(*, common_name: str = "test CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
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
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_tsa_leaf(
    ca_key,
    ca_cert,
    *,
    with_timestamping_eku: bool = True,
    eku_critical: bool = True,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test TSA")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    if with_timestamping_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=eku_critical,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _build_tst(
    *,
    tsa_key,
    tsa_cert,
    ca_cert,
    message: bytes,
    gen_time: datetime | None = None,
) -> tuple[bytes, bytes]:
    """Build a CMS-signed TimeStampToken matching the wire format the
    Mastio TSA client persists. Returns (tst_der, message_digest)."""
    if gen_time is None:
        gen_time = datetime.now(timezone.utc)
    digest = hashlib.sha256(message).digest()

    tst_info = asn1_tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.5",
        "message_imprint": asn1_tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "hashed_message": digest,
        }),
        "serial_number": 1,
        "gen_time": gen_time,
    })
    tst_info_der = tst_info.dump()
    tst_info_hash = hashlib.sha256(tst_info_der).digest()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [tst_info_hash]}),
    ])
    signed_attrs_der = signed_attrs.dump()

    signature = tsa_key.sign(
        signed_attrs_der, padding.PKCS1v15(), hashes.SHA256(),
    )

    tsa_asn1 = asn1_x509.Certificate.load(
        tsa_cert.public_bytes(serialization.Encoding.DER),
    )
    ca_asn1 = asn1_x509.Certificate.load(
        ca_cert.public_bytes(serialization.Encoding.DER),
    )

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier(
            name="issuer_and_serial_number",
            value=cms.IssuerAndSerialNumber({
                "issuer": tsa_asn1.issuer,
                "serial_number": tsa_asn1.serial_number,
            }),
        ),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({
            "algorithm": "rsassa_pkcs1v15",
        }),
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": cms.DigestAlgorithms([
            algos.DigestAlgorithm({"algorithm": "sha256"}),
        ]),
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst_info_der),
        }),
        "certificates": cms.CertificateSet([
            cms.CertificateChoices(name="certificate", value=tsa_asn1),
            cms.CertificateChoices(name="certificate", value=ca_asn1),
        ]),
        "signer_infos": cms.SignerInfos([signer_info]),
    })

    tst_token = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })
    return tst_token.dump(), digest


@pytest.fixture
def trust_store(tmp_path):
    """Write a CA + TSA + corresponding PEM bundle to ``tmp_path``.

    Returns a dict with keys ``ca_key``, ``ca_cert``, ``tsa_key``,
    ``tsa_cert``, ``pem_path`` (str path to the trust-store bundle the
    verifier will load with ``--tsa-trust-store``).
    """
    ca_key, ca_cert = _build_ca()
    tsa_key, tsa_cert = _build_tsa_leaf(ca_key, ca_cert)
    pem_path = tmp_path / "tsa-roots.pem"
    pem_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "tsa_key": tsa_key,
        "tsa_cert": tsa_cert,
        "pem_path": str(pem_path),
    }


# ── Verifier behaviour tests ───────────────────────────────────────────


def test_valid_token_with_matching_trust_store_verifies(
    verifier_mod, trust_store,
):
    """The happy path: valid TST signed by the trust store's CA verifies
    end-to-end (signature + chain + EKU + imprint + genTime)."""
    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=message,
    )

    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
    )
    assert ok, f"expected verify success, got label={label}"
    assert label == "rfc3161-verified"


def test_tampered_signature_is_rejected(verifier_mod, trust_store):
    """F-A-405 core fix: flipping a byte in the CMS signature region
    must cause the verifier to reject the token. Before the fix, the
    verifier only matched messageImprint and would let this through."""
    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=message,
    )
    bad = bytearray(raw_tst)
    # Flip a byte deep in the body — last 50 bytes lie inside the
    # signed_data / SignerInfo region for tokens of this size, so the
    # CMS signature verify fails on the modified bytes regardless of
    # which exact field they belong to.
    bad[-50] ^= 0xFF
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + bytes(bad),
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
    )
    assert not ok, "tampered token must not verify"
    # Either a clean signature-invalid (most common — flipped byte
    # landed in the signature) or a parse error (flipped byte broke
    # the DER structure). Both are rejection paths the operator wants.
    assert label in {
        "rfc3161-signature-invalid",
        "rfc3161-parse-error",
        "rfc3161-decode-error",
    }, f"unexpected rejection label: {label}"


def test_no_trust_store_default_refuses(verifier_mod, trust_store):
    """Without ``--tsa-trust-store`` and without the explicit downgrade
    opt-in, the verifier fails closed on RFC 3161 anchors. This is the
    dispute-grade default."""
    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=message,
    )
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=None,
        allow_unverified_signature=False,
    )
    assert not ok
    assert label == "rfc3161-no-trust-store"


def test_no_trust_store_with_allow_downgrade_returns_warning_label(
    verifier_mod, trust_store,
):
    """Operators without a trust store on hand can opt into the
    pre-fix behaviour. The verifier returns True but flags the path
    with a distinct backend label so the caller knows the anchor is
    not dispute-grade."""
    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=message,
    )
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=None,
        allow_unverified_signature=True,
    )
    assert ok
    assert label == "rfc3161-imprint-eku-only"


def test_future_gentime_is_rejected(verifier_mod, trust_store):
    """genTime more than ``skew_seconds`` in the future fails. Catches
    a forged token whose GenTime was set to 9999-01-01 to side-step a
    future trust-store rotation."""
    message = b"row_hash_hex_aabbccddeeff"
    far_future = datetime.now(timezone.utc) + timedelta(days=2)
    raw_tst, digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=message,
        gen_time=far_future,
    )
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
    )
    assert not ok
    assert label == "rfc3161-gentime-future"


def test_stale_gentime_is_rejected(verifier_mod, trust_store):
    """genTime older than ``max_age_days`` fails."""
    message = b"row_hash_hex_aabbccddeeff"
    old = datetime.now(timezone.utc) - timedelta(days=4000)
    raw_tst, digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=message,
        gen_time=old,
    )
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
        max_age_days=3650,
    )
    assert not ok
    assert label == "rfc3161-gentime-stale"


def test_message_imprint_mismatch_is_rejected(verifier_mod, trust_store):
    """If the caller claims digest_hex=X but the TST's messageImprint
    is digest of Y, the imprint check fires before the signature path
    even runs. Catches an attacker who tries to bind a stolen token to
    a different audit chain head."""
    real_message = b"row_hash_hex_aabbccddeeff"
    other_message = b"different_message_entirely"
    raw_tst, _real_digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=other_message,
    )
    # Caller claims this TST is for ``real_message`` — the imprint
    # inside it is for ``other_message``, so it must fail.
    claimed_digest = hashlib.sha256(real_message).hexdigest()
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        claimed_digest,
        row_hash=real_message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
    )
    assert not ok
    assert label == "rfc3161-imprint-mismatch"


def test_signer_cert_without_timestamping_eku_is_rejected(
    verifier_mod, trust_store,
):
    """RFC 3161 §2.3: the signing cert MUST carry
    ``id-kp-timeStamping`` in ExtKeyUsage. A token signed by a CA cert
    (or any leaf cert lacking the EKU) must be rejected."""
    bad_tsa_key, bad_tsa_cert = _build_tsa_leaf(
        trust_store["ca_key"], trust_store["ca_cert"],
        with_timestamping_eku=False,
    )
    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=bad_tsa_key,
        tsa_cert=bad_tsa_cert,
        ca_cert=trust_store["ca_cert"],
        message=message,
    )
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
    )
    assert not ok
    assert label == "rfc3161-no-timestamping-eku"


def test_signer_cert_with_non_critical_timestamping_eku(
    verifier_mod, trust_store,
):
    """Pin the EKU-criticality discrepancy between Cullis pre-check and
    ``rfc3161-client``.

    The Cullis pre-check in ``_verify_rfc3161_full`` accepts the EKU
    ``id-kp-timeStamping`` regardless of its ``critical`` flag — it
    only inspects ``ExtendedKeyUsage.value`` for the OID. ``rfc3161-
    client._Verifier._verify_leaf_certs`` (`:289-291`), however,
    requires the extension to be marked critical and rejects the
    token otherwise. The net effect is: a TST whose leaf has
    ``EKU(critical=False)`` passes the pre-check, then fails at the
    library's ``verify_message`` step and surfaces as
    ``rfc3161-signature-invalid``.

    This test pins the current behaviour so a future refactor that
    pulls the pre-check stricter (or that swaps the library) does not
    silently change the failure label observed by ops.
    """
    tsa_key, tsa_cert = _build_tsa_leaf(
        trust_store["ca_key"], trust_store["ca_cert"],
        eku_critical=False,
    )
    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=tsa_key,
        tsa_cert=tsa_cert,
        ca_cert=trust_store["ca_cert"],
        message=message,
    )
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
    )
    # Today: Cullis pre-check passes (EKU present, criticality not
    # enforced) but the library's _verify_leaf_certs raises and we
    # return rfc3161-signature-invalid. If a future change pulls the
    # pre-check stricter to match the library, the expected label
    # becomes rfc3161-no-timestamping-eku — update this assert
    # consciously when that happens.
    assert not ok
    assert label == "rfc3161-signature-invalid"


def test_wrong_trust_root_is_rejected(verifier_mod, trust_store, tmp_path):
    """Building the verifier with a DIFFERENT CA than the one that
    signed the TSA leaf must fail — the cert chain walk has no path
    to the operator's trust root."""
    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=trust_store["tsa_key"],
        tsa_cert=trust_store["tsa_cert"],
        ca_cert=trust_store["ca_cert"],
        message=message,
    )
    # Generate a completely unrelated CA and use it as the trust root.
    _other_key, other_cert = _build_ca(common_name="unrelated CA")
    other_pem = tmp_path / "other-roots.pem"
    other_pem.write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))

    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=str(other_pem),
    )
    assert not ok
    # The strict chain walk rejects before the rfc3161-client
    # signature verify even runs — the operator's trust pin is
    # enforced before the library can spuriously accept a chain that
    # only resolves through the token's own embedded certs.
    assert label == "rfc3161-untrusted-chain"


def test_attacker_embedded_rogue_ca_is_rejected(
    verifier_mod, trust_store, tmp_path,
):
    """F-A-405 attack scenario: a forger embeds their OWN self-signed
    CA + leaf in the TST so the CMS signature verifies under their own
    PKI. The strict chain walk must reject because no path leads to the
    operator's pinned trust root, even though the rfc3161-client
    library on its own would accept the chain (it folds embedded certs
    into its trust set)."""
    # Attacker PKI — completely unrelated to operator's trust store.
    atk_ca_key, atk_ca_cert = _build_ca(common_name="attacker CA")
    atk_tsa_key, atk_tsa_cert = _build_tsa_leaf(atk_ca_key, atk_ca_cert)

    message = b"row_hash_hex_aabbccddeeff"
    raw_tst, digest = _build_tst(
        tsa_key=atk_tsa_key,
        tsa_cert=atk_tsa_cert,
        ca_cert=atk_ca_cert,
        message=message,
    )
    # Operator's trust store contains the LEGITIMATE CA, not the
    # attacker's. The chain walk must fail to reach it.
    ok, label = verifier_mod.verify_token_against_digest(
        b"T1|" + raw_tst,
        digest.hex(),
        row_hash=message.decode("ascii"),
        trust_store_path=trust_store["pem_path"],
    )
    assert not ok
    assert label == "rfc3161-untrusted-chain"


def test_mock_token_path_unchanged(verifier_mod):
    """The legacy ``MK|<digest>|<anything>`` mock token path stays
    behaviourally unchanged — F-A-405 fix only touches RFC 3161."""
    digest_hex = hashlib.sha256(b"hello").hexdigest()
    token = b"MK|" + digest_hex.encode("ascii") + b"|whatever"
    ok, label = verifier_mod.verify_token_against_digest(token, digest_hex)
    assert ok
    assert label == "mock"


def test_unrecognized_token_returns_false(verifier_mod):
    """Unknown magic prefix → (False, "unrecognized") so the caller
    can route to exit 5."""
    ok, label = verifier_mod.verify_token_against_digest(
        b"ZZ|garbage", "00" * 32,
    )
    assert not ok
    assert label == "unrecognized"
