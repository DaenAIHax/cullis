"""Tests for the shared ``_init_common()`` factory surface (2026-06-10 P0).

The ``cls.__new__(cls)`` factories used to replicate the ``__init__``
attribute surface by hand; every attribute added to ``__init__`` but
missed in a factory was a latent ``AttributeError`` on that
construction path. Last hit: ``_user_session_lock`` (used by
``attach_user_session``) was missing from ALL factories, so the
ADR-032 user-session binding crashed on any client built via the
canonical ``from_identity_dir`` route.

The fix routes ``__init__`` and every factory through a single
``CullisClient._init_common()``. Two layers of coverage here:

1. Regression tests for the concrete crash (``attach_user_session`` /
   ``detach_user_session`` / ``attach_device_attestation`` on
   factory-built clients).
2. A structural parity test: the attribute surface of every
   factory-built instance must be a superset of the surface a plain
   ``CullisClient(...)`` gets from ``__init__``. This is the
   anti-drift net — a NEW attribute added to ``__init__`` (i.e. to
   ``_init_common``) can never be missing from a factory-built client
   again, no matter which factory.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


class _FakeHttp:
    """Minimal httpx.Client replacement recording verb calls + kwargs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    def _respond(self) -> Any:
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = ""
        resp.json.return_value = {"id": "chatcmpl-1", "choices": []}
        resp.raise_for_status = MagicMock()
        return resp

    def post(self, url: str, **kwargs: Any) -> Any:
        self.calls.append(("post", url, kwargs))
        return self._respond()

    def get(self, url: str, **kwargs: Any) -> Any:
        self.calls.append(("get", url, kwargs))
        return self._respond()

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append((method, url, kwargs))
        return self._respond()

    def close(self) -> None:
        pass


@pytest.fixture
def fake_http_factory(monkeypatch):
    """Stub ``_build_proxy_http_client`` so factories don't build a real
    TLS context from the fake cert/key fixtures on disk.
    """
    http = _FakeHttp()

    def _stub(**_kwargs: Any) -> _FakeHttp:  # noqa: ARG001
        return http

    monkeypatch.setattr(
        "cullis_sdk.client._build_proxy_http_client", _stub,
    )
    return http


@pytest.fixture
def identity_dir(tmp_path):
    """Minimal on-disk identity for ``from_identity_dir``."""
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("FAKE-CERT")
    key.write_text("FAKE-KEY")
    return tmp_path


def _identity_client(identity_dir, **kwargs):
    from cullis_sdk import CullisClient

    return CullisClient.from_identity_dir(
        "https://mastio.local:9443",
        cert_path=identity_dir / "cert.pem",
        key_path=identity_dir / "key.pem",
        **kwargs,
    )


def _connector_client(tmp_path):
    import json

    from cullis_sdk import CullisClient

    identity = tmp_path / "connector" / "identity"
    identity.mkdir(parents=True)
    (identity / "metadata.json").write_text(json.dumps({
        "agent_id": "orga::desk-agent",
        "site_url": "https://mastio.local:9443",
    }))
    return CullisClient.from_connector(
        tmp_path / "connector", enable_dpop=False,
    )


def _user_principal_client():
    from cullis_sdk import CullisClient

    return CullisClient.from_user_principal_pem(
        "https://mastio.local:9443",
        principal_id="td/orga/user/alice",
        cert_pem="FAKE-CERT",
        key_pem="FAKE-KEY",
        enable_dpop=False,
    )


# ── 1. Concrete regression: ADR-032 session binding on factory clients ──


def test_attach_user_session_on_identity_dir_client(
    identity_dir, fake_http_factory,
):
    """Pre-fix: AttributeError on ``self._user_session_lock`` because no
    factory initialised it — on the CANONICAL construction path.
    """
    client = _identity_client(identity_dir)
    client.attach_user_session("sess-token", "td/orga/user/alice")
    assert client.get_user_session() == ("sess-token", "td/orga/user/alice")
    client.detach_user_session()
    assert client.get_user_session() is None


def test_attach_device_attestation_on_identity_dir_client(
    identity_dir, fake_http_factory,
):
    client = _identity_client(identity_dir)
    client.attach_device_attestation({"tier": "managed"})
    assert client.get_device_attestation() == {"tier": "managed"}


def test_user_session_headers_ride_on_egress(
    identity_dir, fake_http_factory,
):
    """End-to-end through ``proxy_headers``: the bound session must show
    up on the egress wire call, not just in the getter.
    """
    client = _identity_client(identity_dir)
    client.attach_user_session("sess-token", "td/orga/user/alice")
    client.chat_completion(model="m", messages=[])
    _, _, kwargs = fake_http_factory.calls[-1]
    assert kwargs["headers"]["X-Cullis-Session-Token"] == "sess-token"
    assert (
        kwargs["headers"]["X-Cullis-On-Behalf-Of-User"]
        == "td/orga/user/alice"
    )


# ── 2. Structural parity: factory surface ⊇ __init__ surface ────────────


def _factory_clients(identity_dir, tmp_path):
    return {
        "from_identity_dir": _identity_client(identity_dir),
        "from_connector": _connector_client(tmp_path),
        "from_user_principal_pem": _user_principal_client(),
    }


def test_factory_attribute_surface_matches_init(
    identity_dir, tmp_path, fake_http_factory,
):
    """Every attribute ``__init__`` sets must exist on every
    factory-built instance. Catches the whole class of drift bugs, not
    just the ``_user_session_lock`` instance of it.
    """
    from cullis_sdk import CullisClient

    baseline = set(vars(CullisClient("https://broker.example")))
    for name, client in _factory_clients(identity_dir, tmp_path).items():
        missing = baseline - set(vars(client))
        assert not missing, (
            f"{name} is missing attributes __init__ sets: {sorted(missing)}. "
            "Add defaults to CullisClient._init_common, never inline in a "
            "factory."
        )


def test_factories_share_init_common_defaults(
    identity_dir, tmp_path, fake_http_factory,
):
    """Spot-check the defaults that bit production code paths before."""
    for client in _factory_clients(identity_dir, tmp_path).values():
        assert client.server_role is None  # _update_nonce reads it
        assert client._relogin_callable is None
        assert client._user_session is None
        assert client._device_attestation is None
