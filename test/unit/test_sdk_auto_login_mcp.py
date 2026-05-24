"""Tests for the lazy first-call auto-login (Bug #1 fix).

The proxy-bound factories ``from_identity_dir`` / ``from_enrollment``
build a client with ``self.token = None`` because the broker token is
minted by a separate explicit step (``login_via_proxy`` /
``login_via_proxy_with_local_key``). Before this fix the first authed
call (``list_mcp_tools`` / ``call_mcp_tool`` / ``send_oneshot`` /
``chat_completion``) raised ``RuntimeError("Not authenticated — call
login() first")`` from ``_AuthMixin._headers``, forcing every customer
to chain a login call.

The fix sets ``instance._auto_login_pending = True`` in both factories
and adds a guarded branch at the top of ``_authed_request`` that faults
in the right login method (local-key when ``_signing_key_pem`` is set,
proxy-mediated otherwise). The branch clears the flag BEFORE the login
call so a recursive authed sub-request from inside the login cannot
loop.

The tests run against a real ``CullisClient`` constructed via the
factories. ``_build_proxy_http_client`` is patched out so no TLS
context is built (the factories try to load real cert/key files);
``self._http`` is replaced with a stub that records calls. The login
methods are also patched so the tests don't try to mint real DPoP
proofs against a fake httpx; they just observe whether the lazy branch
called them and how many times.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


class _FakeHttp:
    """Minimal httpx.Client replacement.

    Returns a 200 JSON-RPC ``tools/list`` envelope so the SDK's
    ``list_mcp_tools`` / ``call_mcp_tool`` flow can complete without
    talking to a real Mastio. ``raise_for_status`` is a no-op.
    """

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict]] = []

    def request(self, method: str, url: str, **kwargs: Any):
        self.requests.append((method, url, kwargs))
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = ""
        resp.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []},
        }
        resp.raise_for_status = MagicMock()
        return resp

    def close(self) -> None:
        pass


@pytest.fixture
def fake_http_factory(monkeypatch):
    """Stub ``_build_proxy_http_client`` so factories don't touch the disk
    for cert/key. Returns the same ``_FakeHttp`` instance on each call.
    """
    http = _FakeHttp()

    def _stub(**_kwargs: Any) -> _FakeHttp:  # noqa: ARG001
        return http

    monkeypatch.setattr(
        "cullis_sdk.client._build_proxy_http_client", _stub,
    )
    return http


@pytest.fixture
def patched_logins(monkeypatch):
    """Patch both proxy login methods so the lazy branch is observable
    without minting real tokens. Each patched method sets ``self.token``
    to a sentinel so subsequent ``_headers`` calls succeed.
    """
    from cullis_sdk._client._auth import _AuthMixin

    proxy_calls: list[str] = []
    local_calls: list[str] = []

    def _fake_proxy(self) -> None:
        proxy_calls.append(getattr(self, "_proxy_agent_id", "?"))
        self.token = "fake-proxy-token"
        # Set DPoP material so _headers doesn't crash on the proof call.
        from cullis_sdk.auth import generate_dpop_keypair
        self._dpop_privkey, self._dpop_pubkey_jwk = generate_dpop_keypair()
        self._relogin_callable = self.login_via_proxy

    def _fake_local(self) -> None:
        local_calls.append(getattr(self, "_proxy_agent_id", "?"))
        self.token = "fake-local-token"
        from cullis_sdk.auth import generate_dpop_keypair
        self._dpop_privkey, self._dpop_pubkey_jwk = generate_dpop_keypair()
        self._relogin_callable = self.login_via_proxy_with_local_key

    monkeypatch.setattr(_AuthMixin, "login_via_proxy", _fake_proxy)
    monkeypatch.setattr(
        _AuthMixin, "login_via_proxy_with_local_key", _fake_local,
    )
    return proxy_calls, local_calls


# ── from_identity_dir ────────────────────────────────────────────────────


def test_from_identity_dir_sets_auto_login_pending(
    tmp_path, fake_http_factory,
):
    """The factory sets the flag so the first call faults login in."""
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    client = CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=cert,
        key_path=key,
    )
    assert client._auto_login_pending is True
    assert client.token is None


def test_from_identity_dir_first_call_triggers_proxy_login(
    tmp_path, fake_http_factory, patched_logins,
):
    """First ``list_mcp_tools`` after ``from_identity_dir`` calls
    ``login_via_proxy`` exactly once (no local signing key on disk so
    the lazy branch picks the proxy-mediated path)."""
    proxy_calls, local_calls = patched_logins
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    client = CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=cert,
        key_path=key,
        agent_id="acme::agent-1",
    )
    # Replace _http after construction so we don't depend on the
    # internal SSLContext.
    client._http = fake_http_factory

    tools = client.list_mcp_tools()
    assert tools == []
    assert len(proxy_calls) == 1, (
        f"expected exactly one login_via_proxy call, got {proxy_calls}"
    )
    assert len(local_calls) == 0
    assert client._auto_login_pending is False
    assert client.token == "fake-proxy-token"


def test_explicit_login_before_first_call_does_not_double_login(
    tmp_path, fake_http_factory, patched_logins,
):
    """Customer that explicitly calls ``login_via_proxy_with_local_key``
    before the first MCP call gets ONE login, not two — the lazy branch
    is gated by ``self.token is None`` and short-circuits."""
    proxy_calls, local_calls = patched_logins
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    client = CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=cert,
        key_path=key,
    )
    client._http = fake_http_factory
    # Customer's explicit login call.
    client.login_via_proxy_with_local_key()
    assert len(local_calls) == 1

    # First authed call after explicit login.
    client.list_mcp_tools()
    assert len(local_calls) == 1, (
        "explicit login + first call must not trigger a second login"
    )
    assert len(proxy_calls) == 0


def test_local_signing_key_routes_to_local_login(
    tmp_path, fake_http_factory, patched_logins,
):
    """When ``_signing_key_pem`` is set the lazy branch picks the
    on-device-key login flow, matching what ``from_connector`` /
    ambassadors expect."""
    proxy_calls, local_calls = patched_logins
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    client = CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=cert,
        key_path=key,
    )
    client._http = fake_http_factory
    # Simulate a downstream consumer that set _signing_key_pem after
    # construction (the canonical from_connector path; from_identity_dir
    # itself leaves it None).
    client._signing_key_pem = "FAKE-KEY-PEM"
    client._cert_pem = "FAKE-CERT-PEM"

    client.list_mcp_tools()
    assert len(local_calls) == 1
    assert len(proxy_calls) == 0


# ── from_enrollment ───────────────────────────────────────────────────────


def test_from_enrollment_first_call_triggers_proxy_login(
    fake_http_factory, patched_logins, monkeypatch,
):
    """``from_enrollment`` builds a client without a local signing key,
    so the first authed call routes to ``login_via_proxy``."""
    proxy_calls, local_calls = patched_logins

    # Stub the enrollment GET so the factory returns a client without
    # talking to a real Mastio.
    def _fake_get(self, url, **kwargs):  # noqa: ARG001
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "agent_id": "acme::agent-1",
            "org_id": "acme",
            "proxy_url": "https://mastio.local:9443",
        }
        resp.raise_for_status = MagicMock()
        return resp

    monkeypatch.setattr(_FakeHttp, "get", _fake_get, raising=False)
    from cullis_sdk import CullisClient

    client = CullisClient.from_enrollment(
        "https://mastio.local:9443/v1/enroll/enroll_abc",
    )
    assert client._auto_login_pending is True
    client._http = fake_http_factory  # ensure no SSL handshake

    client.list_mcp_tools()
    assert len(proxy_calls) == 1
    assert len(local_calls) == 0


# ── failure path ──────────────────────────────────────────────────────────


def test_auto_login_failure_surfaces_login_exception(
    tmp_path, fake_http_factory, monkeypatch,
):
    """When the lazy login itself fails, the caller sees the login's
    exception (informative) rather than the cryptic ``RuntimeError``
    that ``_headers`` would have raised."""
    from cullis_sdk._client._auth import _AuthMixin

    def _failing_login(self) -> None:
        raise PermissionError("login_via_proxy failed (HTTP 401): nope")

    monkeypatch.setattr(_AuthMixin, "login_via_proxy", _failing_login)

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    client = CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=cert,
        key_path=key,
    )
    client._http = fake_http_factory

    with pytest.raises(PermissionError, match="login_via_proxy failed"):
        client.list_mcp_tools()
    # Flag must be cleared even when login failed so a retry does not
    # re-enter the lazy branch with a now-broken inner state.
    assert client._auto_login_pending is False


# ── back-compat: existing direct callers ──────────────────────────────────


def test_direct_instantiation_still_fails_fast(monkeypatch):
    """A caller that bypasses the factories (``cls.__new__(cls)`` then
    manually wiring ``self.token = None``) MUST still hit the original
    ``RuntimeError`` so legacy contract is preserved. The lazy branch is
    gated by the ``_auto_login_pending`` flag which only the proxy
    factories set."""
    from cullis_sdk import CullisClient

    instance = CullisClient.__new__(CullisClient)
    instance.token = None
    # Deliberately do NOT set _auto_login_pending — direct callers that
    # built the client outside the factories keep the original fail-fast.
    with pytest.raises(RuntimeError, match="Not authenticated"):
        instance._headers("GET", "/v1/mcp")


# ── token-expiry path is untouched ────────────────────────────────────────


def test_token_expiry_relogin_path_still_works(
    tmp_path, fake_http_factory, patched_logins,
):
    """Existing token-expiry 401 → ``_relogin_callable`` → retry path
    must not regress. After the first lazy login wires the callable, a
    subsequent 401 from the server triggers exactly one re-login + one
    retry."""
    proxy_calls, _local_calls = patched_logins
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    client = CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=cert,
        key_path=key,
    )
    # Custom _http that returns 401 on the first call (post-lazy-login),
    # then 200 on the retry. The token-expiry branch in _authed_request
    # invokes _relogin_callable once and replays.
    call_count = {"n": 0}

    def _request(method, url, **kwargs):  # noqa: ARG001
        call_count["n"] += 1
        resp = MagicMock()
        if call_count["n"] == 1:
            resp.status_code = 401
            resp.text = "token expired"
        else:
            resp.status_code = 200
            resp.text = ""
            resp.json.return_value = {
                "jsonrpc": "2.0", "id": 1, "result": {"tools": []},
            }
        resp.headers = {}
        resp.raise_for_status = MagicMock()
        return resp

    client._http = MagicMock()
    client._http.request = _request

    client.list_mcp_tools()
    # 1 lazy login + 1 re-login on the 401 = 2 total login_via_proxy
    # invocations. The fake _relogin_callable is the same patched
    # method, so the count rolls into proxy_calls.
    assert len(proxy_calls) == 2
    # 2 _http.request calls: first 401, retry 200.
    assert call_count["n"] == 2
