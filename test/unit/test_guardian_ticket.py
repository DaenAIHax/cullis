"""ADR-016 Phase 1 — guardian ticket sign + verify.

The ticket is a JWT HS256 carrying the inspection decision so the
agent runtime can verify Mastio actually saw the message before
delivering it. The tests below cover the round trip plus the failure
modes the runtime must recognize and refuse delivery on.
"""
from __future__ import annotations

import time

import pytest

from mcp_proxy.guardian.ticket import (
    GuardianTicketError,
    sign_ticket,
    verify_ticket,
)


_KEY_HEX = "00112233445566778899aabbccddeeff" * 2  # 32 bytes
_KEY_B64URL = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"  # 32 bytes


def _common_args():
    return dict(
        agent_id="orga::alice",
        peer_agent_id="orgb::bob",
        msg_id="msg-001",
        direction="out",
        decision="pass",
        audit_id="aud-001",
    )


def test_sign_verify_roundtrip_hex_key():
    token, exp = sign_ticket(key=_KEY_HEX, **_common_args())
    claims = verify_ticket(key=_KEY_HEX, token=token)
    assert claims["agent_id"] == "orga::alice"
    assert claims["peer_agent_id"] == "orgb::bob"
    assert claims["msg_id"] == "msg-001"
    assert claims["direction"] == "out"
    assert claims["decision"] == "pass"
    assert claims["audit_id"] == "aud-001"
    assert claims["exp"] == exp
    assert exp > int(time.time())


def test_sign_verify_roundtrip_b64url_key():
    """Operators who paste base64url-encoded entropy must also work."""
    token, _ = sign_ticket(key=_KEY_B64URL, **_common_args())
    claims = verify_ticket(key=_KEY_B64URL, token=token)
    assert claims["agent_id"] == "orga::alice"


def test_expired_ticket_rejected():
    token, _ = sign_ticket(key=_KEY_HEX, ttl_s=1, **_common_args())
    time.sleep(1.5)
    with pytest.raises(GuardianTicketError) as exc:
        verify_ticket(key=_KEY_HEX, token=token)
    assert exc.value.reason == "expired"


def test_bad_signature_rejected():
    token, _ = sign_ticket(key=_KEY_HEX, **_common_args())
    other_key = "ff" * 32
    with pytest.raises(GuardianTicketError) as exc:
        verify_ticket(key=other_key, token=token)
    assert exc.value.reason == "bad_signature"


def test_msg_id_mismatch_rejected():
    """Replay protection: a captured ticket from msg-001 must not
    validate when the runtime is about to deliver msg-002."""
    token, _ = sign_ticket(key=_KEY_HEX, **_common_args())
    with pytest.raises(GuardianTicketError) as exc:
        verify_ticket(key=_KEY_HEX, token=token, expected_msg_id="msg-002")
    assert exc.value.reason == "msg_id_mismatch"


def test_agent_id_mismatch_rejected():
    token, _ = sign_ticket(key=_KEY_HEX, **_common_args())
    with pytest.raises(GuardianTicketError) as exc:
        verify_ticket(
            key=_KEY_HEX, token=token, expected_agent_id="orga::evil",
        )
    assert exc.value.reason == "agent_id_mismatch"


def test_missing_key_raises_meaningfully():
    with pytest.raises(GuardianTicketError) as exc:
        sign_ticket(key="", **_common_args())
    assert exc.value.reason == "missing_key"


def test_malformed_key_raises_meaningfully():
    with pytest.raises(GuardianTicketError) as exc:
        sign_ticket(key="not-hex-not-b64!!!@@@", **_common_args())
    assert exc.value.reason == "malformed_key"
