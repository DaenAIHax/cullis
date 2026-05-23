"""Tests for ``CullisClient.from_systemd_credentials`` — the Tier 2
agent key storage path that replaces the plain-file 0600 layout with
systemd's ``LoadCredential=`` mechanism.

The factory itself is a thin wrapper around ``from_identity_dir`` —
the only logic worth exercising is the resolution of the credentials
directory, the optional metadata read, and the eager existence /
config errors. The tests monkey-patch ``from_identity_dir`` so they
don't depend on a real cert pair or an httpx client construction.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def fake_creds(tmp_path) -> Path:
    """Materialise the credential layout systemd would create.

    Files are zero-byte placeholders; ``from_identity_dir`` is patched
    out, so no real cert / key parsing happens. Tests that care about
    metadata write a non-empty ``agent.json``.
    """
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    (creds / "key.pem").write_text("FAKE-KEY")
    (creds / "dpop.jwk").write_text("{\"kty\": \"FAKE\"}")
    return creds


@pytest.fixture
def patched_from_identity_dir(monkeypatch):
    """Capture the kwargs ``from_systemd_credentials`` forwards.

    Returns a list that each test inspects after the factory call. The
    patched method returns a sentinel ``object()`` so callers can still
    assert "got a client back".
    """
    calls: list[dict] = []

    def _fake(cls, mastio_url: str, **kwargs):  # noqa: ARG001 — mimic classmethod signature
        calls.append({"mastio_url": mastio_url, **kwargs})
        return object()  # opaque sentinel — represents the client

    from cullis_sdk._client._enrollment import _EnrollmentMixin
    monkeypatch.setattr(
        _EnrollmentMixin, "from_identity_dir", classmethod(_fake),
    )
    return calls


# ── credentials directory resolution ──────────────────────────────────────


def test_explicit_credentials_dir_wins(
    monkeypatch, fake_creds, patched_from_identity_dir,
):
    """Passing credentials_dir= overrides $CREDENTIALS_DIRECTORY."""
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/UNRELATED")
    from cullis_sdk import CullisClient

    CullisClient.from_systemd_credentials(
        "https://mastio.local:9443",
        credentials_dir=fake_creds,
    )
    call = patched_from_identity_dir[0]
    assert Path(call["cert_path"]).parent == fake_creds


def test_falls_back_to_env(monkeypatch, fake_creds, patched_from_identity_dir):
    """No explicit arg → read $CREDENTIALS_DIRECTORY."""
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(fake_creds))
    from cullis_sdk import CullisClient

    CullisClient.from_systemd_credentials("https://mastio.local:9443")
    call = patched_from_identity_dir[0]
    assert Path(call["cert_path"]).parent == fake_creds


def test_raises_when_neither_arg_nor_env_set(monkeypatch):
    """No way to find the credentials → explicit RuntimeError."""
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    from cullis_sdk import CullisClient

    with pytest.raises(RuntimeError, match="CREDENTIALS_DIRECTORY"):
        CullisClient.from_systemd_credentials("https://mastio.local:9443")


# ── file existence pre-flight ─────────────────────────────────────────────


def test_missing_cert_raises_named_error(tmp_path):
    """Operator forgot a ``LoadCredential=cert.pem`` line."""
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "key.pem").write_text("FAKE-KEY")  # cert.pem absent
    from cullis_sdk import CullisClient

    with pytest.raises(FileNotFoundError, match="cert.pem"):
        CullisClient.from_systemd_credentials(
            "https://mastio.local:9443", credentials_dir=creds,
        )


def test_missing_key_raises_named_error(tmp_path):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    from cullis_sdk import CullisClient

    with pytest.raises(FileNotFoundError, match="key.pem"):
        CullisClient.from_systemd_credentials(
            "https://mastio.local:9443", credentials_dir=creds,
        )


def test_missing_dpop_is_tolerated(
    tmp_path, patched_from_identity_dir,
):
    """DPoP key absent → ``dpop_key_path=None`` to from_identity_dir.

    Matches the ``egress_dpop_mode=off|optional`` server posture. The
    factory must not refuse to construct just because the operator
    chose not to ship a DPoP key.
    """
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    (creds / "key.pem").write_text("FAKE-KEY")
    # dpop.jwk absent on purpose.
    from cullis_sdk import CullisClient

    CullisClient.from_systemd_credentials(
        "https://mastio.local:9443", credentials_dir=creds,
    )
    call = patched_from_identity_dir[0]
    assert call["dpop_key_path"] is None


def test_dpop_disabled_explicitly(
    fake_creds, patched_from_identity_dir,
):
    """dpop_key_name=None skips DPoP loading even when the file exists."""
    from cullis_sdk import CullisClient

    CullisClient.from_systemd_credentials(
        "https://mastio.local:9443",
        credentials_dir=fake_creds,
        dpop_key_name=None,
    )
    call = patched_from_identity_dir[0]
    assert call["dpop_key_path"] is None


# ── metadata (agent.json) auto-population ─────────────────────────────────


def test_metadata_populates_mastio_url(
    tmp_path, patched_from_identity_dir,
):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    (creds / "key.pem").write_text("FAKE-KEY")
    (creds / "agent.json").write_text(json.dumps({
        "agent_id": "kyc-screener",
        "org_id": "acme",
        "mastio_url": "https://mastio.acme.local:9443",
    }))
    from cullis_sdk import CullisClient

    # mastio_url= NOT passed → resolved from agent.json
    CullisClient.from_systemd_credentials(credentials_dir=creds)
    call = patched_from_identity_dir[0]
    assert call["mastio_url"] == "https://mastio.acme.local:9443"
    assert call["agent_id"] == "kyc-screener"
    assert call["org_id"] == "acme"


def test_explicit_args_win_over_metadata(
    tmp_path, patched_from_identity_dir,
):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    (creds / "key.pem").write_text("FAKE-KEY")
    (creds / "agent.json").write_text(json.dumps({
        "agent_id": "metadata-agent",
        "org_id": "metadata-org",
        "mastio_url": "https://metadata.local:9443",
    }))
    from cullis_sdk import CullisClient

    CullisClient.from_systemd_credentials(
        "https://explicit.local:9443",
        credentials_dir=creds,
        agent_id="explicit-agent",
        org_id="explicit-org",
    )
    call = patched_from_identity_dir[0]
    assert call["mastio_url"] == "https://explicit.local:9443"
    assert call["agent_id"] == "explicit-agent"
    assert call["org_id"] == "explicit-org"


def test_metadata_absent_requires_explicit_mastio_url(tmp_path):
    """No agent.json + no mastio_url= → RuntimeError with a clear hint."""
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    (creds / "key.pem").write_text("FAKE-KEY")
    from cullis_sdk import CullisClient

    with pytest.raises(RuntimeError, match="mastio_url"):
        CullisClient.from_systemd_credentials(credentials_dir=creds)


def test_metadata_disabled_via_metadata_name_none(
    tmp_path, patched_from_identity_dir,
):
    """metadata_name=None skips the agent.json read even when present."""
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    (creds / "key.pem").write_text("FAKE-KEY")
    (creds / "agent.json").write_text(json.dumps({
        "mastio_url": "https://from-metadata.local:9443",
    }))
    from cullis_sdk import CullisClient

    CullisClient.from_systemd_credentials(
        "https://explicit.local:9443",
        credentials_dir=creds,
        metadata_name=None,
    )
    call = patched_from_identity_dir[0]
    # metadata file was NOT consulted even though present on disk.
    assert call["mastio_url"] == "https://explicit.local:9443"


def test_malformed_metadata_surfaces_runtime_error(tmp_path):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "cert.pem").write_text("FAKE-CERT")
    (creds / "key.pem").write_text("FAKE-KEY")
    (creds / "agent.json").write_text("not-json{")
    from cullis_sdk import CullisClient

    with pytest.raises(RuntimeError, match="metadata"):
        CullisClient.from_systemd_credentials(
            "https://mastio.local:9443", credentials_dir=creds,
        )


# ── custom file names (operator deviated from the SDK layout) ─────────────


def test_custom_credential_names(tmp_path, patched_from_identity_dir):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "client.crt").write_text("FAKE-CERT")
    (creds / "client.key").write_text("FAKE-KEY")
    (creds / "dpop.json").write_text("{\"kty\": \"FAKE\"}")
    from cullis_sdk import CullisClient

    CullisClient.from_systemd_credentials(
        "https://mastio.local:9443",
        credentials_dir=creds,
        cert_name="client.crt",
        key_name="client.key",
        dpop_key_name="dpop.json",
        metadata_name=None,
    )
    call = patched_from_identity_dir[0]
    assert Path(call["cert_path"]).name == "client.crt"
    assert Path(call["key_path"]).name == "client.key"
    assert Path(call["dpop_key_path"]).name == "dpop.json"
