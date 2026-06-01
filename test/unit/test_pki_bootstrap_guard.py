"""DR-1 hardening — boot-time PKI safety nets.

A disaster-recovery drill on a faithful prod-shape stack (Vault + Postgres
+ production + multi-worker) showed that a PARTIAL restore — Postgres data
restored, Vault CA material not — made the boot path mint fresh CA
material and silently orphan every enrolled agent's mTLS identity (the
agent leaf certs chained to a CA that no longer existed). Two guards close
that:

  * ``AgentManager.ensure_ca_bootstrap_safe`` — refuses (in production) to
    generate/mint fresh CA material when enrolled agents already exist,
    unless ``MCP_PROXY_ALLOW_PKI_REKEY`` opts into an intentional re-key.
  * ``ProxySettings.ca_bootstrap_enabled`` — per-environment default for
    first-time CA provisioning: explicit in production, auto in dev.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import mcp_proxy.config as config_mod
import mcp_proxy.db as db_mod
from mcp_proxy.config import ProxySettings
from mcp_proxy.egress.agent_manager import AgentManager

_ROOT = "the Org Root CA"
_HINT = "restore the org-ca secret"


def _patch_count(monkeypatch, n: int) -> None:
    async def _fake_count() -> int:
        return n
    monkeypatch.setattr(db_mod, "count_enrolled_agents", _fake_count)


def _patch_environment(monkeypatch, environment: str) -> None:
    monkeypatch.setattr(
        config_mod, "get_settings",
        lambda: SimpleNamespace(environment=environment),
    )


# ── ensure_ca_bootstrap_safe (the orphan guard) ─────────────────────────

@pytest.mark.asyncio
async def test_guard_first_boot_no_agents_proceeds(monkeypatch):
    """0 enrolled agents == genuine first boot -> never blocks."""
    _patch_count(monkeypatch, 0)
    _patch_environment(monkeypatch, "production")
    monkeypatch.delenv("MCP_PROXY_ALLOW_PKI_REKEY", raising=False)
    await AgentManager("testorg").ensure_ca_bootstrap_safe(_ROOT, _HINT)


@pytest.mark.asyncio
async def test_guard_agents_in_production_refuses_boot(monkeypatch):
    """Agents enrolled + CA material gone + production -> SystemExit.

    This is the DR-1 partial-restore signature: minting fresh material
    would orphan the fleet, so the deploy must stop loudly.
    """
    _patch_count(monkeypatch, 3)
    _patch_environment(monkeypatch, "production")
    monkeypatch.delenv("MCP_PROXY_ALLOW_PKI_REKEY", raising=False)
    with pytest.raises(SystemExit):
        await AgentManager("testorg").ensure_ca_bootstrap_safe(_ROOT, _HINT)


@pytest.mark.asyncio
async def test_guard_agents_in_dev_warns_but_proceeds(monkeypatch):
    """Non-production: loud warning but boots (dev/test/sandbox stay up)."""
    _patch_count(monkeypatch, 3)
    _patch_environment(monkeypatch, "development")
    monkeypatch.delenv("MCP_PROXY_ALLOW_PKI_REKEY", raising=False)
    await AgentManager("testorg").ensure_ca_bootstrap_safe(_ROOT, _HINT)


@pytest.mark.asyncio
async def test_guard_rekey_override_proceeds_in_production(monkeypatch):
    """An explicit MCP_PROXY_ALLOW_PKI_REKEY re-key proceeds even in prod."""
    _patch_count(monkeypatch, 3)
    _patch_environment(monkeypatch, "production")
    monkeypatch.setenv("MCP_PROXY_ALLOW_PKI_REKEY", "1")
    await AgentManager("testorg").ensure_ca_bootstrap_safe(_ROOT, _HINT)


@pytest.mark.asyncio
async def test_guard_count_failure_does_not_block_boot(monkeypatch):
    """If the agent count can't be read (DB not ready), don't block boot."""
    async def _boom() -> int:
        raise RuntimeError("db not ready")
    monkeypatch.setattr(db_mod, "count_enrolled_agents", _boom)
    _patch_environment(monkeypatch, "production")
    await AgentManager("testorg").ensure_ca_bootstrap_safe(_ROOT, _HINT)


# ── ProxySettings.ca_bootstrap_enabled (the provisioning gate) ──────────

def _settings(monkeypatch, environment: str) -> ProxySettings:
    # Build cleanly in development (production triggers the admin-secret
    # validator), then flip environment post-init — model validators only
    # fire at construction, so ca_bootstrap_enabled reads the flipped value.
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-guard-secret")
    s = ProxySettings()
    s.environment = environment
    return s


def test_ca_bootstrap_default_dev_true(monkeypatch):
    monkeypatch.delenv("MCP_PROXY_ALLOW_CA_BOOTSTRAP", raising=False)
    assert _settings(monkeypatch, "development").ca_bootstrap_enabled() is True


def test_ca_bootstrap_default_production_false(monkeypatch):
    monkeypatch.delenv("MCP_PROXY_ALLOW_CA_BOOTSTRAP", raising=False)
    assert _settings(monkeypatch, "production").ca_bootstrap_enabled() is False


def test_ca_bootstrap_explicit_opt_in_wins_in_production(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_ALLOW_CA_BOOTSTRAP", "1")
    assert _settings(monkeypatch, "production").ca_bootstrap_enabled() is True


def test_ca_bootstrap_explicit_opt_out_wins_in_dev(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_ALLOW_CA_BOOTSTRAP", "false")
    assert _settings(monkeypatch, "development").ca_bootstrap_enabled() is False


def test_ca_bootstrap_empty_env_falls_back_to_per_environment(monkeypatch):
    # docker-compose ${FOO:-} passthrough yields "", which is NOT an opt-in.
    monkeypatch.setenv("MCP_PROXY_ALLOW_CA_BOOTSTRAP", "")
    assert _settings(monkeypatch, "production").ca_bootstrap_enabled() is False
