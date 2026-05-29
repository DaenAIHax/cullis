"""Tests for the AWS Cloud KMS plugin (Secrets Manager-backed Org CA).

Mocks Secrets Manager via moto. The Mastio core runs alongside (so
``mcp_proxy.kms`` is reachable for the factory dispatch test).
"""
from __future__ import annotations

import importlib.util

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run cloud_kms_aws tests",
        allow_module_level=True,
    )

import boto3
from moto import mock_aws

from cullis_enterprise.mastio.cloud_kms_aws.config import AwsKmsConfig, load_config
from cullis_enterprise.mastio.cloud_kms_aws.provider import (
    AwsSecretsManagerKMSProvider,
)


SECRET_ID = "cullis/test/org-ca"
INTERMEDIATE_SECRET_ID = "cullis/test/intermediate-ca"


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def secrets_client():
    """moto-mocked Secrets Manager client. The bucket of secrets is empty."""
    with mock_aws():
        yield boto3.client("secretsmanager", region_name="us-east-1")


@pytest.fixture
def provider(secrets_client) -> AwsSecretsManagerKMSProvider:
    return AwsSecretsManagerKMSProvider(
        secrets_client,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=True,
    )


# ── load when missing ──────────────────────────────────────────────────────


async def test_load_returns_none_when_secret_missing(provider):
    assert await provider.load_org_ca() is None


# ── store creates the secret ───────────────────────────────────────────────


async def test_store_creates_secret_when_missing(provider, secrets_client):
    await provider.store_org_ca("KEY-PEM", "CERT-PEM")
    # The secret now exists.
    resp = secrets_client.describe_secret(SecretId=SECRET_ID)
    assert resp["Name"] == SECRET_ID
    # And contains our payload.
    val = secrets_client.get_secret_value(SecretId=SECRET_ID)["SecretString"]
    assert "KEY-PEM" in val and "CERT-PEM" in val


async def test_round_trip(provider):
    await provider.store_org_ca("KEY-A", "CERT-A")
    loaded = await provider.load_org_ca()
    assert loaded == ("KEY-A", "CERT-A")


# ── store overwrites ───────────────────────────────────────────────────────


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


async def test_org_and_intermediate_isolated(provider, secrets_client):
    """Storing one CA must not touch the other secret."""
    await provider.store_org_ca("ORG-KEY", "ORG-CERT")
    await provider.store_intermediate_ca("INT-KEY", "INT-CERT")
    assert await provider.load_org_ca() == ("ORG-KEY", "ORG-CERT")
    assert await provider.load_intermediate_ca() == ("INT-KEY", "INT-CERT")
    # Two distinct Secrets Manager entries so operator IAM can bind
    # tighter policies to the cold Org CA than to the hot Intermediate.
    assert secrets_client.describe_secret(SecretId=SECRET_ID)["Name"] == SECRET_ID
    assert (
        secrets_client.describe_secret(SecretId=INTERMEDIATE_SECRET_ID)["Name"]
        == INTERMEDIATE_SECRET_ID
    )


# ── safety on malformed payloads ───────────────────────────────────────────


async def test_load_returns_none_for_malformed_json(secrets_client):
    secrets_client.create_secret(Name=SECRET_ID, SecretString="not-json{")
    p = AwsSecretsManagerKMSProvider(
        secrets_client,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=True,
    )
    assert await p.load_org_ca() is None


async def test_load_returns_none_when_payload_missing_fields(secrets_client):
    secrets_client.create_secret(
        Name=SECRET_ID,
        SecretString='{"key_pem": "ONLY-KEY"}',  # no cert_pem
    )
    p = AwsSecretsManagerKMSProvider(
        secrets_client,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=True,
    )
    assert await p.load_org_ca() is None


# ── create_if_missing=False ────────────────────────────────────────────────


async def test_store_raises_when_create_disabled_and_secret_missing(
    secrets_client,
):
    p = AwsSecretsManagerKMSProvider(
        secrets_client,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=False,
    )
    from botocore.exceptions import ClientError
    with pytest.raises(ClientError):
        await p.store_org_ca("KEY", "CERT")


async def test_store_with_create_disabled_succeeds_when_secret_exists(
    secrets_client,
):
    secrets_client.create_secret(
        Name=SECRET_ID, SecretString='{"key_pem": "old", "cert_pem": "old"}',
    )
    p = AwsSecretsManagerKMSProvider(
        secrets_client,
        secret_id=SECRET_ID,
        intermediate_secret_id=INTERMEDIATE_SECRET_ID,
        create_if_missing=False,
    )
    await p.store_org_ca("NEW-KEY", "NEW-CERT")
    assert await p.load_org_ca() == ("NEW-KEY", "NEW-CERT")


# ── config + plugin wiring ─────────────────────────────────────────────────


def test_config_unset_yields_unconfigured(monkeypatch):
    monkeypatch.delenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", raising=False)
    cfg = load_config()
    assert cfg.configured is False


def test_config_resolves_region_from_aws_default(monkeypatch):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", "x")
    monkeypatch.delenv("CULLIS_CLOUD_KMS_AWS_REGION", raising=False)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    cfg = load_config()
    assert cfg.region == "eu-west-1"


def test_config_explicit_region_wins(monkeypatch):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", "x")
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_REGION", "us-east-2")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    cfg = load_config()
    assert cfg.region == "us-east-2"


def test_config_intermediate_defaults_to_sibling_suffix(monkeypatch):
    """When the operator doesn't pin an Intermediate ARN, derive one."""
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", "cullis/prod/org-ca")
    monkeypatch.delenv(
        "CULLIS_CLOUD_KMS_AWS_INTERMEDIATE_SECRET_ID", raising=False,
    )
    cfg = load_config()
    assert cfg.intermediate_secret_id == "cullis/prod/org-ca-intermediate"


def test_config_intermediate_explicit_wins(monkeypatch):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", "cullis/prod/org-ca")
    monkeypatch.setenv(
        "CULLIS_CLOUD_KMS_AWS_INTERMEDIATE_SECRET_ID",
        "cullis/prod/intermediate-explicit",
    )
    cfg = load_config()
    assert cfg.intermediate_secret_id == "cullis/prod/intermediate-explicit"


def test_plugin_kms_factory_returns_None_for_other_backends():
    from cullis_enterprise.mastio.cloud_kms_aws.plugin import CloudKmsAwsPlugin
    p = CloudKmsAwsPlugin()
    assert p.kms_factory("azure") is None
    assert p.kms_factory("gcp") is None
    assert p.kms_factory("local") is None


def test_plugin_kms_factory_returns_callable_for_aws():
    from cullis_enterprise.mastio.cloud_kms_aws.plugin import CloudKmsAwsPlugin
    p = CloudKmsAwsPlugin()
    factory = p.kms_factory("aws")
    assert factory is not None
    assert callable(factory)


def test_plugin_factory_raises_when_secret_id_unset(monkeypatch):
    monkeypatch.delenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", raising=False)
    from cullis_enterprise.mastio.cloud_kms_aws.plugin import _build_provider
    with pytest.raises(RuntimeError, match="CULLIS_CLOUD_KMS_AWS_SECRET_ID"):
        _build_provider(settings=None)


def test_plugin_factory_builds_provider(monkeypatch, secrets_client):
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", SECRET_ID)
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_REGION", "us-east-1")
    from cullis_enterprise.mastio.cloud_kms_aws.plugin import _build_provider
    provider = _build_provider(settings=None)
    assert isinstance(provider, AwsSecretsManagerKMSProvider)


# ── integration with mcp_proxy.kms factory ────────────────────────────────


async def test_mcp_proxy_kms_factory_dispatches_to_aws_plugin(
    monkeypatch, secrets_client,
):
    """End-to-end: when the operator sets MCP_PROXY_KMS_BACKEND=aws and the
    plugin is installed + licensed, ``mcp_proxy.kms.get_kms_provider()``
    returns the Secrets Manager-backed provider.
    """
    from mcp_proxy import plugins as core_plugins
    from mcp_proxy.kms.factory import (
        get_kms_provider, reset_kms_provider,
    )
    from mcp_proxy.config import get_settings
    from cullis_enterprise.mastio.cloud_kms_aws.plugin import CloudKmsAwsPlugin

    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_SECRET_ID", SECRET_ID)
    monkeypatch.setenv("CULLIS_CLOUD_KMS_AWS_REGION", "us-east-1")
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "aws")
    get_settings.cache_clear()

    # Inject the plugin into the registry directly (bypasses the license
    # gate; the gate is tested separately in the core suite).
    fake_registry = core_plugins.PluginRegistry(plugins=[CloudKmsAwsPlugin()])
    monkeypatch.setattr(core_plugins, "_registry", fake_registry)

    reset_kms_provider()
    try:
        provider = get_kms_provider()
        assert isinstance(provider, AwsSecretsManagerKMSProvider)
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
