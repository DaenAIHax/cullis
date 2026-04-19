"""Tests for ``cullis_connector.tools._identity``.

Focused on the security-audit contract for ``prime_sender_pubkey_cache``
(NEW #4): the function MUST raise ``PubkeyPrimeError`` on any failure
to seed the SDK pubkey cache — including an empty ``target_cert_pem``
in the ``/v1/egress/resolve`` response — instead of silently returning
and letting the caller fall through to the broker JWT path with no
audit trail.
"""
from __future__ import annotations

import time

import pytest

from cullis_connector.tools._identity import (
    PubkeyPrimeError,
    prime_sender_pubkey_cache,
)


class _Resp:
    def __init__(self, status_code: int = 200, body: dict | None = None) -> None:
        self.status_code = status_code
        self._body = body or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return dict(self._body)


class _Client:
    def __init__(self, resp: _Resp | Exception) -> None:
        self._resp = resp
        self._pubkey_cache: dict = {}
        self.calls: list[dict] = []

    def _egress_http(self, method, path, *, json=None, **kw):
        self.calls.append({"method": method, "path": path, "json": json})
        if isinstance(self._resp, Exception):
            raise self._resp
        return self._resp


def test_raises_when_client_missing_pubkey_cache():
    class _BadClient:
        # no _pubkey_cache attribute
        pass

    with pytest.raises(PubkeyPrimeError, match="_pubkey_cache"):
        prime_sender_pubkey_cache(_BadClient(), "acme::mario")


def test_raises_when_resolve_returns_no_target_cert_pem():
    """Empty / missing target_cert_pem → PubkeyPrimeError, NOT silent
    return. Previously this path logged a WARNING and returned, which
    dropped the security-relevant skip out of the audit trail."""
    client = _Client(_Resp(200, {"target_cert_pem": ""}))
    with pytest.raises(PubkeyPrimeError, match="no target_cert_pem"):
        prime_sender_pubkey_cache(client, "acme::mario")
    # Cache stays empty — we did not seed anything.
    assert client._pubkey_cache == {}


def test_raises_when_resolve_http_call_fails():
    """Network / proxy errors propagate as PubkeyPrimeError so the
    caller can log at ERROR and skip the message."""
    client = _Client(RuntimeError("connection refused"))
    with pytest.raises(PubkeyPrimeError, match="connection refused"):
        prime_sender_pubkey_cache(client, "acme::mario")


def test_raises_when_resolve_returns_4xx():
    client = _Client(_Resp(404, {}))
    with pytest.raises(PubkeyPrimeError, match="404"):
        prime_sender_pubkey_cache(client, "acme::mario")


def test_cache_hit_is_noop_and_does_not_call_resolve():
    """TTL-fresh cache entry → no-op, no HTTP call. Regression guard
    for the 67e3b95 fix (prime helper must honour SDK pubkey cache TTL)."""
    client = _Client(_Resp(200, {"target_cert_pem": "PEM"}))
    client._pubkey_cache["acme::mario"] = ("cached-PEM", time.time())
    prime_sender_pubkey_cache(client, "acme::mario")
    assert client.calls == [], "cache hit should not hit the resolve endpoint"


def test_cache_stale_triggers_refetch_and_populates():
    """When the cached entry is older than the SDK TTL, we refetch —
    otherwise stale pubkeys would leak into decrypt_oneshot."""
    client = _Client(_Resp(200, {"target_cert_pem": "FRESH-PEM"}))
    # Entry is way past the 300s TTL.
    client._pubkey_cache["acme::mario"] = ("stale-PEM", time.time() - 3600)
    prime_sender_pubkey_cache(client, "acme::mario")
    assert client._pubkey_cache["acme::mario"][0] == "FRESH-PEM"
    assert len(client.calls) == 1


def test_bare_sender_mirrors_into_cache():
    """Canonicalised ``<org>::<agent>`` is the primary key, the bare
    handle is mirrored so ``decrypt_oneshot`` (which reads whatever
    form the inbox row carried) still finds the entry."""
    # No identity loaded → canonical_recipient falls back to input
    # unchanged, so the mirror branch only fires when caller already
    # passed the canonical form. Exercise that here.
    client = _Client(_Resp(200, {"target_cert_pem": "PEM"}))
    # Pretend the test bench has an identity loaded so bare → canonical.
    from unittest.mock import MagicMock

    from cullis_connector.state import get_state, reset_state

    reset_state()
    fake_attr = MagicMock()
    fake_attr.value = "acme"
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = [fake_attr]
    fake_identity = MagicMock()
    fake_identity.cert = fake_cert
    get_state().extra["identity"] = fake_identity

    try:
        prime_sender_pubkey_cache(client, "mario")
        assert "acme::mario" in client._pubkey_cache
        assert "mario" in client._pubkey_cache
    finally:
        reset_state()
