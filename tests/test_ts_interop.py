"""
Cross-language E2E interop between the TypeScript SDK and the Python SDK.

Verifies that blobs produced by one SDK can be decrypted by the other, for
both RSA-OAEP and ECDH+HKDF key wrapping. Also guards against regressions of
the base64url no-pad bug (TS emits no-pad, Python must tolerate).

Skipped automatically if Node.js or the built TS SDK (sdk-ts/dist) are absent.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cullis_sdk.crypto.e2e import decrypt_from_agent, encrypt_for_agent

REPO_ROOT = Path(__file__).resolve().parent.parent
TS_DIST = REPO_ROOT / "sdk-ts" / "dist" / "crypto.js"
HARNESS = REPO_ROOT / "tests" / "interop" / "ts_roundtrip.mjs"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not TS_DIST.exists(),
    reason="node or built sdk-ts/dist missing — run `cd sdk-ts && npm run build`",
)


def _pem_keypair(kind: str) -> tuple[str, str]:
    if kind == "ec":
        priv = ec.generate_private_key(ec.SECP256R1())
    elif kind == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        raise ValueError(kind)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _run_node(mode: str, payload: dict) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        fpath = f.name
    result = subprocess.run(
        ["node", str(HARNESS), mode, f"--input={fpath}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"node harness failed: {result.stderr}")
    return json.loads(result.stdout)


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_python_encrypt_to_ts_decrypt(kind: str) -> None:
    priv_pem, pub_pem = _pem_keypair(kind)
    payload = {"kind": kind, "direction": "py->ts", "n": 7}
    blob = encrypt_for_agent(
        pub_pem,
        payload,
        "inner-sig-from-python",
        "sess-py2ts",
        "orgA::python-sender",
        client_seq=11,
    )
    out = _run_node(
        "decrypt",
        {
            "recipient_priv_pem": priv_pem,
            "blob": blob,
            "session_id": "sess-py2ts",
            "sender_agent_id": "orgA::python-sender",
            "client_seq": 11,
        },
    )
    assert out["payload"] == payload
    assert out["inner_signature"] == "inner-sig-from-python"


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_ts_encrypt_to_python_decrypt(kind: str) -> None:
    priv_pem, pub_pem = _pem_keypair(kind)
    payload = {"kind": kind, "direction": "ts->py", "n": 13}
    out = _run_node(
        "encrypt",
        {
            "recipient_pub_pem": pub_pem,
            "payload": payload,
            "inner_signature": "inner-sig-from-ts",
            "session_id": "sess-ts2py",
            "sender_agent_id": "orgB::ts-sender",
            "client_seq": 3,
        },
    )
    blob = out["blob"]
    decoded_payload, inner_sig = decrypt_from_agent(
        priv_pem,
        blob,
        "sess-ts2py",
        "orgB::ts-sender",
        client_seq=3,
    )
    assert decoded_payload == payload
    assert inner_sig == "inner-sig-from-ts"


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_python_sign_ts_verify(kind: str) -> None:
    """Python signs a canonical message; TS verifies. Proves signature-alg
    auto-dispatch matches Python's RSA-PSS / ECDSA selection."""
    from app.auth.message_signer import sign_message

    priv_pem, pub_pem = _pem_keypair(kind)
    payload = {"kind": kind, "k": "py-sign"}
    nonce = "n-py-ts"
    ts = 1700000000
    signature = sign_message(priv_pem, "s1", "orgA::alice", nonce, ts, payload, 5)
    out = _run_node(
        "verify",
        {
            "sender_pub_pem": pub_pem,
            "signature": signature,
            "session_id": "s1",
            "sender_agent_id": "orgA::alice",
            "nonce": nonce,
            "timestamp": ts,
            "payload": payload,
            "client_seq": 5,
        },
    )
    assert out.get("valid") is True, out


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_ts_sign_python_verify(kind: str) -> None:
    """TS signs; Python verifies against the raw pubkey (matches broker logic)."""
    import base64 as _b64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    priv_pem, pub_pem = _pem_keypair(kind)
    payload = {"kind": kind, "k": "ts-sign"}
    nonce = "n-ts-py"
    ts = 1700000001
    out = _run_node(
        "sign",
        {
            "sender_priv_pem": priv_pem,
            "session_id": "s2",
            "sender_agent_id": "orgB::bob",
            "nonce": nonce,
            "timestamp": ts,
            "payload": payload,
            "client_seq": 9,
        },
    )
    signature = out["signature"]
    import json as _json
    payload_str = _json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    canonical = f"s2|orgB::bob|{nonce}|{ts}|9|{payload_str}".encode()
    sig_bytes = _b64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    pub_key = serialization.load_pem_public_key(pub_pem.encode())
    if isinstance(pub_key, _rsa.RSAPublicKey):
        pub_key.verify(
            sig_bytes, canonical,
            _padding.PSS(
                mgf=_padding.MGF1(hashes.SHA256()),
                salt_length=_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        assert isinstance(pub_key, _ec.EllipticCurvePublicKey)
        pub_key.verify(sig_bytes, canonical, _ec.ECDSA(hashes.SHA256()))


def test_ts_blob_has_no_base64_padding() -> None:
    """
    Guards against regressions of the TS→Python base64 padding bug.
    All base64url fields emitted by the TS SDK must not end with '='.
    """
    _, pub_pem = _pem_keypair("ec")
    out = _run_node(
        "encrypt",
        {
            "recipient_pub_pem": pub_pem,
            "payload": {"x": 1},
            "inner_signature": "sig",
            "session_id": "s",
            "sender_agent_id": "a",
        },
    )
    blob = out["blob"]
    for field in ("ciphertext", "iv", "encrypted_key", "ephemeral_pubkey"):
        if field in blob:
            assert not blob[field].endswith("="), (
                f"TS SDK emitted padded base64url for {field}; "
                f"server decoders rely on no-pad convention"
            )
