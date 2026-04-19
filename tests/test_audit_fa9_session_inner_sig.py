"""Regression tests for audit F-A-9 — session ``decrypt_payload`` must
verify the inner (plaintext) signature.

Threat model: without inner-signature verification a compromised broker
could craft a ciphertext it already knows the AES key for (picked up
when the recipient enrolled a pubkey it controls) and forge plaintext
attributed to any sender. The outer ciphertext integrity alone does
not bind the plaintext to the sender's long-term key.

Mirrors the pattern already used by :meth:`CullisClient.decrypt_oneshot`.
"""
from __future__ import annotations

import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cullis_sdk.client import CullisClient
from cullis_sdk.crypto.e2e import encrypt_for_agent
from cullis_sdk.crypto.message_signer import sign_message


# ── Key helpers ──────────────────────────────────────────────────────

def _gen_ec_keypair() -> tuple[str, str]:
    """Generate an EC P-256 keypair, return (priv_pem, pub_pem) strings."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _make_session_msg(
    recipient_pub_pem: str,
    sender_priv_pem: str,
    sender_pub_pem_for_lookup: str,
    *,
    session_id: str,
    sender_agent_id: str,
    payload: dict,
    tamper_signature: bool = False,
    empty_signature: bool = False,
) -> dict:
    """Build a session-path message dict as the recipient would see it.

    Shape matches what broker returns via ``/v1/broker/sessions/{sid}/messages``:
    ``{session_id, sender_agent_id, payload (cipher blob), nonce, timestamp, client_seq}``.
    """
    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    client_seq = 0

    # Sign the plaintext with sender's real key (honest path) ...
    inner_sig = sign_message(
        sender_priv_pem, session_id, sender_agent_id,
        nonce, timestamp, payload, client_seq=client_seq,
    )
    if empty_signature:
        inner_sig = ""
    elif tamper_signature:
        # Flip a few characters — still valid base64url length, wrong sig.
        # Replace first char with another legal b64url char so decoding
        # passes but the verify check fails.
        inner_sig = ("A" if inner_sig[0] != "A" else "B") + inner_sig[1:]

    cipher_blob = encrypt_for_agent(
        recipient_pub_pem, payload, inner_sig,
        session_id, sender_agent_id, client_seq=client_seq,
    )

    return {
        "session_id": session_id,
        "sender_agent_id": sender_agent_id,
        "payload": cipher_blob,
        "nonce": nonce,
        "timestamp": timestamp,
        "client_seq": client_seq,
        "msg_id": str(uuid.uuid4()),
    }


def _make_client_with_stubbed_pubkey(
    recipient_priv_pem: str,
    sender_agent_id: str,
    sender_pub_pem: str,
) -> CullisClient:
    """Construct a CullisClient preloaded with the recipient's priv key
    and a cached sender pubkey — no broker HTTP required."""
    client = CullisClient("https://broker.test")
    client._signing_key_pem = recipient_priv_pem
    # Seed pubkey cache so get_agent_public_key() never hits the network.
    client._pubkey_cache[sender_agent_id] = (sender_pub_pem, time.time())
    return client


# ── Positive path ────────────────────────────────────────────────────

def test_decrypt_payload_valid_inner_sig_succeeds():
    """Honest sender + valid inner sig → plaintext returned as-is."""
    recipient_priv, recipient_pub = _gen_ec_keypair()
    sender_priv, sender_pub = _gen_ec_keypair()

    session_id = "sess-" + uuid.uuid4().hex
    sender_agent_id = "orgA::alice"
    payload = {"text": "hello", "n": 42}

    msg = _make_session_msg(
        recipient_pub, sender_priv, sender_pub,
        session_id=session_id, sender_agent_id=sender_agent_id,
        payload=payload,
    )
    client = _make_client_with_stubbed_pubkey(
        recipient_priv, sender_agent_id, sender_pub,
    )

    decrypted = client.decrypt_payload(msg, session_id=session_id)

    assert decrypted["payload"] == payload
    assert decrypted["sender_agent_id"] == sender_agent_id
    # Original cipher-containing dict must not be mutated in place.
    assert "ciphertext" in msg["payload"]


# ── Forgery: tampered inner signature ────────────────────────────────

def test_decrypt_payload_tampered_inner_sig_rejected():
    """A valid outer ciphertext with a forged inner signature (as a
    compromised broker could produce if it knew an AES key) MUST be
    rejected. This is the core F-A-9 zero-trust guarantee."""
    recipient_priv, recipient_pub = _gen_ec_keypair()
    sender_priv, sender_pub = _gen_ec_keypair()

    session_id = "sess-" + uuid.uuid4().hex
    sender_agent_id = "orgA::bob"
    payload = {"text": "legit", "amount": 100}

    msg = _make_session_msg(
        recipient_pub, sender_priv, sender_pub,
        session_id=session_id, sender_agent_id=sender_agent_id,
        payload=payload,
        tamper_signature=True,
    )
    client = _make_client_with_stubbed_pubkey(
        recipient_priv, sender_agent_id, sender_pub,
    )

    with pytest.raises(ValueError, match="integrity"):
        client.decrypt_payload(msg, session_id=session_id)


def test_decrypt_payload_wrong_signer_rejected():
    """Inner sig produced by a DIFFERENT key than the one the registry
    returns for ``sender_agent_id`` must not be accepted. Models the
    case where the broker attributes a message to Alice but whoever
    actually signed had their own key."""
    recipient_priv, recipient_pub = _gen_ec_keypair()
    # sender_agent_id is alice, but msg is signed by mallory_priv while
    # the registry still returns alice_pub → verify must fail.
    alice_priv, alice_pub = _gen_ec_keypair()
    mallory_priv, _ = _gen_ec_keypair()

    session_id = "sess-" + uuid.uuid4().hex
    sender_agent_id = "orgA::alice"
    payload = {"transfer": "to-mallory"}

    msg = _make_session_msg(
        recipient_pub, mallory_priv, alice_pub,
        session_id=session_id, sender_agent_id=sender_agent_id,
        payload=payload,
    )
    client = _make_client_with_stubbed_pubkey(
        recipient_priv, sender_agent_id, alice_pub,
    )

    with pytest.raises(ValueError, match="integrity"):
        client.decrypt_payload(msg, session_id=session_id)


def test_decrypt_payload_empty_inner_sig_rejected():
    """Inner signature field present but empty → reject. Prevents a
    'just leave it blank' downgrade path."""
    recipient_priv, recipient_pub = _gen_ec_keypair()
    sender_priv, sender_pub = _gen_ec_keypair()

    session_id = "sess-" + uuid.uuid4().hex
    sender_agent_id = "orgA::eve"
    payload = {"noop": True}

    msg = _make_session_msg(
        recipient_pub, sender_priv, sender_pub,
        session_id=session_id, sender_agent_id=sender_agent_id,
        payload=payload,
        empty_signature=True,
    )
    client = _make_client_with_stubbed_pubkey(
        recipient_priv, sender_agent_id, sender_pub,
    )

    with pytest.raises(ValueError, match="integrity"):
        client.decrypt_payload(msg, session_id=session_id)


# ── No-op paths still work (regressions) ────────────────────────────

def test_decrypt_payload_returns_msg_when_no_ciphertext():
    """Non-E2E messages (already plaintext) must pass through unchanged."""
    recipient_priv, _ = _gen_ec_keypair()
    client = CullisClient("https://broker.test")
    client._signing_key_pem = recipient_priv

    msg = {
        "session_id": "s1",
        "sender_agent_id": "orgA::alice",
        "payload": {"already": "plaintext"},
    }
    assert client.decrypt_payload(msg, session_id="s1") == msg


def test_decrypt_payload_returns_msg_when_no_signing_key():
    """Without a signing key the SDK cannot decrypt — return msg unchanged
    (caller is expected to have called ``login()``)."""
    client = CullisClient("https://broker.test")
    assert client._signing_key_pem is None

    msg = {"session_id": "s1", "payload": {"ciphertext": "xxx"}}
    # No exception — caller responsibility.
    assert client.decrypt_payload(msg) is msg
