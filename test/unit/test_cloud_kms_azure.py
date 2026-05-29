"""Tests for the Azure Cloud KMS plugin (Key Vault Secrets-backed Org CA).

Azure Key Vault has no moto-equivalent, so we exercise the provider
against a hand-rolled ``FakeSecretClient`` that mimics the SDK shape
(``get_secret`` / ``set_secret`` + ``ResourceNotFoundError``).
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run cloud_kms_azure tests",
        allow_module_level=True,
    )

from azure.core.exceptions import ResourceNotFoundError

from cullis_enterprise.mastio.cloud_kms_azure.config import (
    AzureKmsConfig, load_config,
)
from cullis_enterprise.mastio.cloud_kms_azure.provider import (
    AzureKeyVaultKMSProvider,
)


SECRET_NAME = "cullis-org-ca-test"
INTERMEDIATE_SECRET_NAME = "cullis-intermediate-ca-test"


# ── fake SDK ───────────────────────────────────────────────────────────────


@dataclass
class _FakeSecret:
    value: str


class FakeSecretClient:
    """Minimal SecretClient stand-in for the two methods we exercise."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self.get_calls = 0
        self.set_calls = 0

    def get_secret(self, name: str) -> _FakeSecret:
        self.get_calls += 1
        if name not in self._store:
            raise ResourceNotFoundError(f"secret {name!r} not found")
        return _FakeSecret(value=self._store[name])

    def set_secret(self, name: str, value: str) -> _FakeSecret:
        self.set_calls += 1
        self._store[name] = value
        return _FakeSecret(value=value)


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def client() -> FakeSecretClient:
    return FakeSecretClient()


@pytest.fixture
def provider(client) -> AzureKeyVaultKMSProvider:
    return AzureKeyVaultKMSProvider(
        client,
        secret_name=SECRET_NAME,
        intermediate_secret_name=INTERMEDIATE_SECRET_NAME,
        create_if_missing=True,
    )


# ── load when missing ──────────────────────────────────────────────────────


async def test_load_returns_none_when_secret_missing(provider):
    assert await provider.load_org_ca() is None


# ── store creates / overwrites ─────────────────────────────────────────────


async def test_store_creates_secret_when_missing(provider, client):
    await provider.store_org_ca("KEY-PEM", "CERT-PEM")
    assert client.set_calls == 1
    val = client._store[SECRET_NAME]
    assert "KEY-PEM" in val and "CERT-PEM" in val


async def test_round_trip(provider):
    await provider.store_org_ca("KEY-A", "CERT-A")
    loaded = await provider.load_org_ca()
    assert loaded == ("KEY-A", "CERT-A")


async def test_store_overwrites_existing_secret(provider):
    await provider.store_org_ca("KEY-1", "CERT-1")
    await provider.store_org_ca("KEY-2", "CERT-2")
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
    # Different vault secrets — distinct Key Vault names so RBAC can be
    # bound separately to the cold-storage Org CA vs the hot Intermediate.
    assert SECRET_NAME in client._store
    assert INTERMEDIATE_SECRET_NAME in client._store


# ── safety on malformed payloads ───────────────────────────────────────────


async def test_load_returns_none_for_malformed_json(client):
    client.set_secret(SECRET_NAME, "not-json{")
    p = AzureKeyVaultKMSProvider(
        client,
        secret_name=SECRET_NAME,
        intermediate_secret_name=INTERMEDIATE_SECRET_NAME,
    )
    assert await p.load_org_ca() is None


async def test_load_returns_none_when_payload_missing_fields(client):
    client.set_secret(SECRET_NAME, '{"key_pem": "ONLY-KEY"}')
    p = AzureKeyVaultKMSProvider(
        client,
        secret_name=SECRET_NAME,
        intermediate_secret_name=INTERMEDIATE_SECRET_NAME,
    )
    assert await p.load_org_ca() is None


# ── create_if_missing=False ────────────────────────────────────────────────


async def test_store_raises_when_create_disabled_and_secret_missing(client):
    p = AzureKeyVaultKMSProvider(
        client,
        secret_name=SECRET_NAME,
        intermediate_secret_name=INTERMEDIATE_SECRET_NAME,
        create_if_missing=False,
    )
    with pytest.raises(ResourceNotFoundError):
        await p.store_org_ca("KEY", "CERT")


async def test_store_with_create_disabled_succeeds_when_secret_exists(client):
    client.set_secret(SECRET_NAME, '{"key_pem": "old", "cert_pem": "old"}')
    p = AzureKeyVaultKMSProvider(
        client,
        secret_name=SECRET_NAME,
        intermediate_secret_name=INTERMEDIATE_SECRET_NAME,
        create_if_missing=False,
    )
    await p.store_org_ca("NEW-KEY", "NEW-CERT")
    assert await p.load_org_ca() == ("NEW-KEY", "NEW-CERT")


# ── config + plugin wiring ─────────────────────────────────────────────────


def test_config_unset_yields_unconfigured(monkeypatch):
    monkeypatch.delenv("CULLIS_CLOUD_KMS_AZURE_VAULT_URL", raising=False)
    cfg = load_config()
    assert cfg.configured is False


def test_config_default_secret_name(monkeypatch):
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AZURE_VAULT_URL", "https://x.vault.azure.net/",
    )
    monkeypatch.delenv("CULLIS_CLOUD_KMS_AZURE_SECRET_NAME", raising=False)
    cfg = load_config()
    assert cfg.secret_name == "cullis-org-ca"


def test_config_custom_secret_name(monkeypatch):
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AZURE_VAULT_URL", "https://x.vault.azure.net/",
    )
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AZURE_SECRET_NAME", "my-custom-name",
    )
    cfg = load_config()
    assert cfg.secret_name == "my-custom-name"


def test_config_default_intermediate_secret_name(monkeypatch):
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AZURE_VAULT_URL", "https://x.vault.azure.net/",
    )
    monkeypatch.delenv(
        "CULLIS_CLOUD_KMS_AZURE_INTERMEDIATE_SECRET_NAME", raising=False,
    )
    cfg = load_config()
    assert cfg.intermediate_secret_name == "cullis-intermediate-ca"


def test_config_custom_intermediate_secret_name(monkeypatch):
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AZURE_VAULT_URL", "https://x.vault.azure.net/",
    )
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AZURE_INTERMEDIATE_SECRET_NAME", "my-int",
    )
    cfg = load_config()
    assert cfg.intermediate_secret_name == "my-int"


def test_plugin_kms_factory_returns_None_for_other_backends():
    from cullis_enterprise.mastio.cloud_kms_azure.plugin import (
        CloudKmsAzurePlugin,
    )
    p = CloudKmsAzurePlugin()
    assert p.kms_factory("aws") is None
    assert p.kms_factory("gcp") is None
    assert p.kms_factory("local") is None


def test_plugin_kms_factory_returns_callable_for_azure():
    from cullis_enterprise.mastio.cloud_kms_azure.plugin import (
        CloudKmsAzurePlugin,
    )
    p = CloudKmsAzurePlugin()
    factory = p.kms_factory("azure")
    assert factory is not None
    assert callable(factory)


def test_plugin_factory_raises_when_vault_url_unset(monkeypatch):
    monkeypatch.delenv("CULLIS_CLOUD_KMS_AZURE_VAULT_URL", raising=False)
    from cullis_enterprise.mastio.cloud_kms_azure.plugin import _build_provider
    with pytest.raises(RuntimeError, match="CULLIS_CLOUD_KMS_AZURE_VAULT_URL"):
        _build_provider(settings=None)


# ── integration with mcp_proxy.kms factory ────────────────────────────────


async def test_mcp_proxy_kms_factory_dispatches_to_azure_plugin(
    monkeypatch, client,
):
    """End-to-end: MCP_PROXY_KMS_BACKEND=azure → AzureKeyVaultKMSProvider via plugin."""
    from mcp_proxy import plugins as core_plugins
    from mcp_proxy.kms.factory import get_kms_provider, reset_kms_provider
    from mcp_proxy.config import get_settings
    from cullis_enterprise.mastio.cloud_kms_azure.plugin import (
        CloudKmsAzurePlugin,
    )

    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AZURE_VAULT_URL", "https://test.vault.azure.net/",
    )
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AZURE_SECRET_NAME", SECRET_NAME)
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "azure")
    get_settings.cache_clear()

    # Patch the Azure SDK at the import target so the plugin builder
    # picks up our FakeSecretClient instead of opening real credentials.
    # The plugin imports DefaultAzureCredential + SecretClient inside
    # ``_build_provider`` so module-level monkeypatch is enough.
    import azure.identity
    import azure.keyvault.secrets

    class _FakeCredential:
        pass

    def _fake_secret_client(*, vault_url, credential, **kwargs):
        return client

    monkeypatch.setattr(azure.identity, "DefaultAzureCredential", _FakeCredential)
    monkeypatch.setattr(azure.keyvault.secrets, "SecretClient", _fake_secret_client)

    fake_registry = core_plugins.PluginRegistry(plugins=[CloudKmsAzurePlugin()])
    monkeypatch.setattr(core_plugins, "_registry", fake_registry)

    reset_kms_provider()
    try:
        provider = get_kms_provider()
        assert isinstance(provider, AzureKeyVaultKMSProvider)
        # F-A-PKI-033 — the protocol now covers both CAs; round-trip
        # each side end-to-end through the factory-built provider so
        # the isinstance check above is backed by behaviour.
        await provider.store_org_ca("E2E-KEY", "E2E-CERT")
        assert await provider.load_org_ca() == ("E2E-KEY", "E2E-CERT")
        await provider.store_intermediate_ca("E2E-INT-KEY", "E2E-INT-CERT")
        assert await provider.load_intermediate_ca() == (
            "E2E-INT-KEY", "E2E-INT-CERT",
        )
    finally:
        reset_kms_provider()
        get_settings.cache_clear()
