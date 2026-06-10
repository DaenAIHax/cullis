"""D-6: dashboard session cookie must round-trip through Python ``requests``.

Cold-reader Python users who script against Mastio dashboard with the
stdlib-shaped ``requests.Session()`` (instead of the official
``cullis-sdk`` httpx-based client) used to land in a silent
session-invalid loop: every state-changing POST + every protected GET
re-redirected to ``/proxy/login`` even after a successful login. The
root cause was the cookie wire format: the payload was raw JSON, which
contains characters outside the RFC 6265 cookie-octet set (``{``, ``}``,
``"``, ``,``, ``:``, space), so Starlette emitted the cookie as a
quoted-string and escaped commas as ``\\054``. The Python ``requests``
library re-quoted the already-quoted value on the next request,
producing a doubly-wrapped cookie the server middleware refused to parse.

The fix encodes the payload as base64url before HMAC-signing it, so the
cookie value contains only ``[A-Za-z0-9_.-]``, which is cookie-octet
safe. Starlette emits it bare; ``requests``, ``httpx`` and ``curl`` all
round-trip it unchanged.

Test coverage:
  * end-to-end ``requests.Session()`` round-trip against a live HTTP
    server emitting the new cookie format (no manual ``Cookie`` header
    bypass),
  * payload preservation through the new sign/verify path so role +
    csrf_token + roles + user_id all survive,
  * backward-compat: legacy raw-JSON cookies still verify so a worker
    upgrade does not log every admin out,
  * tamper rejection: flipping a byte in the signature half (or in the
    payload half) returns ``None``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import re
import threading
import time

import pytest


# ---------------------------------------------------------------------------
# Test scaffolding: pin the signing key so HMAC outputs are deterministic and
# load ``mcp_proxy.dashboard.session`` after the env is primed.
# ---------------------------------------------------------------------------

_SECRET = "d6-test-signing-key-" + "x" * 32


@pytest.fixture
def session_module(monkeypatch):
    """Import ``mcp_proxy.dashboard.session`` with a pinned signing key."""
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", _SECRET)
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv(
        "MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default",
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    import mcp_proxy.dashboard.session as session
    yield session
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Test 1: vanilla ``requests.Session()`` round-trip through a live HTTP server.
#
# The whole point of D-6 is that a cold reader who reaches for the stdlib-shaped
# ``requests`` library does NOT have to set the Cookie header by hand. So the
# test drives a real socket, lets ``requests`` parse Set-Cookie via its own
# cookielib, and asserts the server receives the cookie value byte-identical
# on the next GET. No TestClient / no httpx, those use a different cookie
# parser and would mask the regression.
# ---------------------------------------------------------------------------


def test_login_cookie_compatible_with_python_requests(session_module):
    """Real ``requests.Session()`` round-trips the new cookie unchanged."""
    requests = pytest.importorskip("requests")

    payload = json.dumps({
        "role": "admin",
        "roles": ["admin"],
        "csrf_token": "test-csrf-token",
        "exp": int(time.time()) + 3600,
    })
    cookie_value = session_module._sign(payload)

    captured: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                f"mcp_proxy_session={cookie_value}; HttpOnly; Path=/; "
                f"SameSite=Strict",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            captured["cookie"] = self.headers.get("Cookie", "")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_a, **_kw):  # silence the stderr noise
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        s = requests.Session()
        s.post(f"http://127.0.0.1:{port}/proxy/login", timeout=5)
        s.get(f"http://127.0.0.1:{port}/proxy/overview", timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=2)

    expected = f"mcp_proxy_session={cookie_value}"
    assert captured.get("cookie") == expected, (
        "requests mangled the cookie value across the round-trip. "
        f"sent {expected!r}, server received {captured.get('cookie')!r}."
    )
    # Defensive: the cookie value itself must not contain any character
    # that would force Starlette / requests into the quoted-string path
    # (this is the structural guarantee that prevents the D-6 regression
    # from coming back if a future refactor changes the encoding).
    assert re.search(r'[\s",;\\]', cookie_value) is None, (
        f"cookie value {cookie_value!r} contains a non-cookie-octet "
        "character; the wire format will be quoted + escape-sequenced "
        "and the requests cookielib will mangle it."
    )


# ---------------------------------------------------------------------------
# Test 2: payload preservation. Encoding switch must not drop fields.
# ---------------------------------------------------------------------------


def test_login_cookie_preserves_role_and_csrf(session_module):
    """Every field set at login round-trips through sign + verify."""
    payload = {
        "role": "admin",
        "roles": ["admin", "auditor"],
        "csrf_token": "csrf-" + "f" * 16,
        "user_id": 42,
        "exp": int(time.time()) + 3600,
    }
    signed = session_module._sign(json.dumps(payload))
    verified = session_module._verify(signed)
    assert verified is not None, "sign + verify round-trip failed"
    got = json.loads(verified)
    assert got == payload, (
        "payload was not preserved across the new cookie format. "
        f"sent {payload!r}, got {got!r}."
    )


# ---------------------------------------------------------------------------
# Test 3: backward-compat. Cookies signed in the legacy raw-JSON format must
# still verify so a worker upgrade does not invalidate live admin sessions.
# ---------------------------------------------------------------------------


def test_old_cookie_format_still_parseable(session_module):
    """Legacy ``json_payload.hex_sig`` cookies still verify post-upgrade."""
    payload = json.dumps({
        "role": "admin",
        "roles": ["admin"],
        "csrf_token": "legacy-csrf",
        "exp": int(time.time()) + 3600,
    })
    # Hand-craft the legacy cookie: HMAC was computed over the raw JSON
    # before the D-6 base64url switch.
    legacy_sig = hmac.new(
        _SECRET.encode(), payload.encode(), hashlib.sha256,
    ).hexdigest()
    legacy_cookie = f"{payload}.{legacy_sig}"
    verified = session_module._verify(legacy_cookie)
    assert verified == payload, (
        "Legacy raw-JSON cookie format must remain verifiable so live "
        "sessions survive the worker upgrade."
    )


# ---------------------------------------------------------------------------
# Test 4: tamper detection. The signature gate must still slam shut on any
# bit-flip in either half of the cookie.
# ---------------------------------------------------------------------------


def test_cookie_signed_or_hmac_verifies_tamper_rejected(session_module):
    """Tampered cookies (payload or sig) are rejected by ``_verify``."""
    payload = json.dumps({
        "role": "admin",
        "roles": ["admin"],
        "csrf_token": "abc",
        "exp": int(time.time()) + 3600,
    })
    signed = session_module._sign(payload)
    head, sig = signed.rsplit(".", 1)

    # Flip a byte in the signature.
    flipped_sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    assert session_module._verify(f"{head}.{flipped_sig}") is None, (
        "Signature tampering must invalidate the cookie."
    )

    # Flip a byte in the payload (the HMAC will no longer match).
    flipped_head = head[:-1] + ("A" if head[-1] != "A" else "B")
    assert session_module._verify(f"{flipped_head}.{sig}") is None, (
        "Payload tampering must invalidate the cookie."
    )

    # Substitute a payload that decodes to attacker-chosen JSON, signed
    # under a key the attacker controls. The server's secret must reject
    # it. (This is the classic JWT-style ``alg=none`` shape attack
    # rephrased for the base64url cookie.)
    attacker_payload = json.dumps({"role": "admin", "exp": 9999999999})
    attacker_b64 = base64.urlsafe_b64encode(
        attacker_payload.encode(),
    ).rstrip(b"=").decode("ascii")
    attacker_sig = hmac.new(
        b"attacker-key-not-the-server-secret",
        attacker_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert session_module._verify(f"{attacker_b64}.{attacker_sig}") is None, (
        "Cookie signed under a foreign key must be rejected."
    )

    # Garbage payload that is not base64url at all.
    assert session_module._verify("!!!notbase64!!!.deadbeef") is None
    # Missing separator.
    assert session_module._verify("nodot") is None
    # Empty halves.
    assert session_module._verify(".sig") is None
    assert session_module._verify("head.") is None
