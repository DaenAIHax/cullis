"""Tests for the GCP Cloud KMS plugin (Secret Manager-backed Org CA)."""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run cloud_kms_gcp tests",
        allow_module_level=True,
    )

from google.api_core.exceptions import AlreadyExists, NotFound

from cullis_enterprise.mastio.cloud_kms_gcp.config import (
    GcpKmsConfig, load_config,
)
from cullis_enterprise.mastio.cloud_kms_gcp.provider import (
    GcpSecretManagerKMSProvider,
)


PROJECT_ID = "cullis-test-project"
SECRET_ID = "cullis-org-ca-test"
INTERMEDIATE_SECRET_ID = "cullis-intermediate-ca-test"
SECRET_PATH = f"projects/{PROJECT_ID}/secrets/{SECRET_ID}"
INTERMEDIATE_SECRET_PATH = f"projects/{PROJECT_ID}/secrets/{INTERMEDIATE_SECRET_ID}"


# ── fake SDK ───────────────────────────────────────────────────────────────


@dataclass
class _FakePayload:
    data: bytes


@dataclass
class _FakeVersionResponse:
    payload: _FakePayload


class FakeSecretManagerClient:
    """Stand-in for ``SecretManagerServiceClient``.

    Tracks secret existence + the latest version's payload, plus call
    counters per method so tests can assert workflow.
    """

    def __init__(self):
        self.secrets: dict[str, list[bytes]] = {}  # secret_path → versions
        self.create_calls = 0
        self.access_calls = 0
        self.add_version_calls = 0

    def access_secret_version(self, *, name: str) -> _FakeVersionResponse:
        self.access_calls += 1
        secret_path, _, version = name.rsplit("/", 2)[-3], None, None
        # Parse "projects/.../secrets/.../versions/<v>"
        prefix, _, vlabel = name.rpartition("/versions/")
        if prefix not in self.secrets or not self.secrets[prefix]:
            raise NotFound(f"secret {prefix!r} not found")
        # We always serve the most recent version regardless of label.
        return _FakeVersionResponse(_FakePayload(self.secrets[prefix][-1]))

    def add_secret_version(self, *, parent: str, payload: dict):
        self.add_version_calls += 1
        if parent not in self.secrets:
            raise NotFound(f"secret {parent!r} not found")
        self.secrets[parent].append(payload["data"])
        return None

    def create_secret(self, *, parent: str, secret_id: str, secret: dict):
        self.create_calls += 1
        path = f"{parent}/secrets/{secret_id}"
        if path in self.secrets:
            raise AlreadyExists(f"{path} already exists")
        self.secrets[path] = []
        return None


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def client() -> FakeSecretManagerClient:
    return FakeSecretManagerClient()


@pytest.fixture
def provider(client) -> GcpSecretManagerKMSProvider:
    return GcpSecretManagerKMSProvider(
        client,
        project_id=PROJECT_ID,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=True,
    )


# ── load when missing ──────────────────────────────────────────────────────


async def test_load_returns_none_when_secret_missing(provider):
    assert await provider.load_org_ca() is None


# ── store creates secret + first version ───────────────────────────────────


async def test_store_creates_secret_and_first_version(provider, client):
    await provider.store_org_ca("KEY-PEM", "CERT-PEM")
    assert client.create_calls == 1
    # add_secret_version is called twice on first store: once before
    # create_secret (raises NotFound, expected), once after (succeeds).
    assert client.add_version_calls == 2
    assert SECRET_PATH in client.secrets
    body = client.secrets[SECRET_PATH][0]
    assert b"KEY-PEM" in body and b"CERT-PEM" in body


async def test_round_trip(provider):
    await provider.store_org_ca("KEY-A", "CERT-A")
    loaded = await provider.load_org_ca()
    assert loaded == ("KEY-A", "CERT-A")


# ── store appends new version when secret exists ──────────────────────────


async def test_store_appends_new_version_when_secret_exists(
    provider, client,
):
    await provider.store_org_ca("KEY-1", "CERT-1")
    await provider.store_org_ca("KEY-2", "CERT-2")
    # ``create_secret`` only on the first store. add_secret_version
    # ran 2 times for the first store (NotFound + retry) plus 1 for
    # the second (secret exists → succeeds first try) = 3.
    assert client.create_calls == 1
    assert client.add_version_calls == 3
    # Latest version wins on read.
    assert await provider.load_org_ca() == ("KEY-2", "CERT-2")


# ── intermediate CA (ADR-033 three-tier hardening) ────────────────────────


async def test_intermediate_load_returns_none_when_missing(provider):
    assert await provider.load_intermediate_ca() is None


async def test_intermediate_round_trip(provider):
    await provider.store_intermediate_ca("INT-KEY", "INT-CERT")
    assert await provider.load_intermediate_ca() == ("INT-KEY", "INT-CERT")


async def test_org_and_intermediate_isolated(provider, client):
    """Storing one CA must not touch the other secret."""
    await provider.store_org_ca("ORG-KEY", "ORG-CERT")
    await provider.store_intermediate_ca("INT-KEY", "INT-CERT")
    assert await provider.load_org_ca() == ("ORG-KEY", "ORG-CERT")
    assert await provider.load_intermediate_ca() == ("INT-KEY", "INT-CERT")
    # Two distinct GCP secret paths so IAM bindings can grant separate
    # access (cold-storage Org CA vs hot Intermediate).
    assert SECRET_PATH in client.secrets
    assert INTERMEDIATE_SECRET_PATH in client.secrets


async def test_already_exists_during_create_is_swallowed(provider, client):
    """Race: another worker created the secret between our NotFound and create."""
    # Pre-create the secret.
    client.create_secret(parent=f"projects/{PROJECT_ID}", secret_id=SECRET_ID, secret={})
    # Now store: NotFound on first add → falls through to create_secret
    # (raises AlreadyExists because the worker pre-created it) → still
    # adds the version successfully.
    await provider.store_org_ca("KEY-RACE", "CERT-RACE")
    assert await provider.load_org_ca() == ("KEY-RACE", "CERT-RACE")


# ── safety on malformed payloads ───────────────────────────────────────────


async def test_load_returns_none_for_malformed_json(client):
    client.create_secret(parent=f"projects/{PROJECT_ID}", secret_id=SECRET_ID, secret={})
    client.add_secret_version(
        parent=SECRET_PATH, payload={"data": b"not-json{"},
    )
    p = GcpSecretManagerKMSProvider(
        client,
        project_id=PROJECT_ID,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
    )
    assert await p.load_org_ca() is None


async def test_load_returns_none_when_payload_missing_fields(client):
    client.create_secret(parent=f"projects/{PROJECT_ID}", secret_id=SECRET_ID, secret={})
    client.add_secret_version(
        parent=SECRET_PATH, payload={"data": b'{"key_pem": "ONLY-KEY"}'},
    )
    p = GcpSecretManagerKMSProvider(
        client,
        project_id=PROJECT_ID,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
    )
    assert await p.load_org_ca() is None


# ── create_if_missing=False ────────────────────────────────────────────────


async def test_store_raises_when_create_disabled_and_secret_missing(client):
    p = GcpSecretManagerKMSProvider(
        client,
        project_id=PROJECT_ID,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=False,
    )
    with pytest.raises(NotFound):
        await p.store_org_ca("KEY", "CERT")


async def test_store_with_create_disabled_succeeds_when_secret_exists(client):
    client.create_secret(parent=f"projects/{PROJECT_ID}", secret_id=SECRET_ID, secret={})
    p = GcpSecretManagerKMSProvider(
        client,
        project_id=PROJECT_ID,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=False,
    )
    await p.store_org_ca("NEW-KEY", "NEW-CERT")
    assert await p.load_org_ca() == ("NEW-KEY", "NEW-CERT")


# ── config + plugin wiring ─────────────────────────────────────────────────


def test_config_unset_yields_unconfigured(monkeypatch):
    monkeypatch.delenv("CULLIS_CLOUD_KMS_GCP_PROJECT_ID", raising=False)
    cfg = load_config()
    assert cfg.configured is False


def test_config_default_secret_id(monkeypatch):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_GCP_PROJECT_ID", PROJECT_ID)
    monkeypatch.delenv("CULLIS_CLOUD_KMS_GCP_SECRET_ID", raising=False)
    cfg = load_config()
    assert cfg.secret_id == "cullis-org-ca"


def test_config_paths_built_from_project_and_secret(monkeypatch):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_GCP_PROJECT_ID", PROJECT_ID)
    monkeypatch.setenv("CULLIS_CLOUD_KMS_GCP_SECRET_ID", "custom")
    cfg = load_config()
    assert cfg.parent == f"projects/{PROJECT_ID}"
    assert cfg.secret_path == f"projects/{PROJECT_ID}/secrets/custom"
    assert cfg.latest_version_path == f"projects/{PROJECT_ID}/secrets/custom/versions/latest"


def test_config_default_intermediate_secret_id(monkeypatch):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_GCP_PROJECT_ID", PROJECT_ID)
    monkeypatch.delenv(
        "CULLIS_CLOUD_KMS_GCP_INTERMEDIATE_SECRET_ID", raising=False,
    )
    cfg = load_config()
    assert cfg.intermediate_secret_id == "cullis-intermediate-ca"


def test_config_custom_intermediate_secret_id(monkeypatch):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_GCP_PROJECT_ID", PROJECT_ID)
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_GCP_INTERMEDIATE_SECRET_ID", "my-int",
    )
    cfg = load_config()
    assert cfg.intermediate_secret_id == "my-int"


def test_plugin_kms_factory_returns_None_for_other_backends():
    from cullis_enterprise.mastio.cloud_kms_gcp.plugin import (
        CloudKmsGcpPlugin,
    )
    p = CloudKmsGcpPlugin()
    assert p.kms_factory("aws") is None
    assert p.kms_factory("azure") is None
    assert p.kms_factory("local") is None


def test_plugin_kms_factory_returns_callable_for_gcp():
    from cullis_enterprise.mastio.cloud_kms_gcp.plugin import (
        CloudKmsGcpPlugin,
    )
    p = CloudKmsGcpPlugin()
    factory = p.kms_factory("gcp")
    assert factory is not None
    assert callable(factory)


def test_plugin_factory_raises_when_project_id_unset(monkeypatch):
    monkeypatch.delenv("CULLIS_CLOUD_KMS_GCP_PROJECT_ID", raising=False)
    from cullis_enterprise.mastio.cloud_kms_gcp.plugin import _build_provider
    with pytest.raises(RuntimeError, match="CULLIS_CLOUD_KMS_GCP_PROJECT_ID"):
        _build_provider(settings=None)


# ── integration with mcp_proxy.kms factory ────────────────────────────────


async def test_mcp_proxy_kms_factory_dispatches_to_gcp_plugin(
    monkeypatch, client,
):
    """End-to-end: MCP_PROXY_KMS_BACKEND=gcp → GcpSecretManagerKMSProvider."""
    from mcp_proxy import plugins as core_plugins
    from mcp_proxy.kms.factory import get_kms_provider, reset_kms_provider
    from mcp_proxy.config import get_settings
    from cullis_enterprise.mastio.cloud_kms_gcp.plugin import CloudKmsGcpPlugin

    monkeypatch.setenv("CULLIS_CLOUD_KMS_GCP_PROJECT_ID", PROJECT_ID)
    monkeypatch.setenv("CULLIS_CLOUD_KMS_GCP_SECRET_ID", SECRET_ID)
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "gcp")
    get_settings.cache_clear()

    # Patch SecretManagerServiceClient so the builder uses our fake.
    import google.cloud.secretmanager_v1 as smv1
    monkeypatch.setattr(
        smv1, "SecretManagerServiceClient", lambda *a, **k: client,
    )

    fake_registry = core_plugins.PluginRegistry(plugins=[CloudKmsGcpPlugin()])
    monkeypatch.setattr(core_plugins, "_registry", fake_registry)

    reset_kms_provider()
    try:
        provider = get_kms_provider()
        assert isinstance(provider, GcpSecretManagerKMSProvider)
        # F-A-PKI-033 — round-trip both CAs through the factory-built
        # provider so isinstance is backed by behaviour on both surfaces.
        await provider.store_org_ca("E2E-KEY", "E2E-CERT")
        assert await provider.load_org_ca() == ("E2E-KEY", "E2E-CERT")
        await provider.store_intermediate_ca("E2E-INT-KEY", "E2E-INT-CERT")
        assert await provider.load_intermediate_ca() == (
            "E2E-INT-KEY", "E2E-INT-CERT",
        )
    finally:
        reset_kms_provider()
        get_settings.cache_clear()
