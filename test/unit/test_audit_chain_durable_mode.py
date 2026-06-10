"""MCP_PROXY_AUDIT_CHAIN_DURABLE — per-row compliance mode (review 2026-06-10).

The batched chain's crash-loss window (queued rows lost on SIGKILL/OOM,
invisible to chain verification because hashes are computed at flush
time) needed an auditor-facing answer. ``audit_chain_durable`` is a
named alias for the legacy per-row path: same routing as
``audit_chain_disabled`` but named for what a compliance reviewer asks
for, not for what it switches off.

Covered here:

* ``build_and_start_from_settings`` registers NO batched singleton under
  durable mode and declares the posture on stderr (AUDIT_DURABILITY line)
  in both modes.
* ``log_audit`` bypasses even a stale registered batched chain when
  durable is set, writing per-row through the legacy path.
* The F-A-404 background-failure-mode gate is moot under durable mode
  (no background flush exists), exactly like under ``disabled``.
"""
from __future__ import annotations

import pytest

from mcp_proxy import audit_chain as _ac
from mcp_proxy.audit_chain import (
    BatchedAuditChain,
    build_and_start_from_settings,
    get_batched_chain,
    set_batched_chain,
    shutdown_singleton,
)


def _fresh_settings():
    from mcp_proxy.config import ProxySettings, get_settings

    get_settings.cache_clear()
    return ProxySettings()


@pytest.fixture(autouse=True)
def _clean_singleton_and_settings():
    """Each test starts and ends with no registered singleton and a
    cold settings cache, so env monkeypatches actually take effect."""
    from mcp_proxy.config import get_settings

    set_batched_chain(None)
    get_settings.cache_clear()
    yield
    set_batched_chain(None)
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_durable_mode_registers_no_batched_singleton(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
):
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DURABLE", "true")
    _fresh_settings()

    chain = await build_and_start_from_settings()
    assert chain is None
    assert get_batched_chain() is None

    err = capsys.readouterr().err
    assert "AUDIT_DURABILITY" in err
    assert "per-row" in err
    assert "MCP_PROXY_AUDIT_CHAIN_DURABLE" in err


@pytest.mark.asyncio
async def test_batched_default_declares_crash_loss_window(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
):
    """The default posture must be on the record in the boot log: an
    auditor reads the window (batch size / interval) without source
    access, and the line says the lost tail is invisible to the
    verifier."""
    monkeypatch.delenv("MCP_PROXY_AUDIT_CHAIN_DURABLE", raising=False)
    monkeypatch.delenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", raising=False)
    _fresh_settings()

    chain = await build_and_start_from_settings()
    try:
        assert chain is not None
        assert get_batched_chain() is chain

        err = capsys.readouterr().err
        assert "AUDIT_DURABILITY" in err
        assert "batched" in err
        assert "crash-loss window" in err
        assert "NOT detectable" in err
    finally:
        await shutdown_singleton()


@pytest.mark.asyncio
async def test_log_audit_bypasses_stale_batched_chain_when_durable(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
):
    """Defence in depth: even if a batched singleton is (wrongly) still
    registered, durable deploys must not re-batch — the row lands on
    disk per-row through the legacy path and the chain verifies."""
    from mcp_proxy.db import dispose_db, get_db, init_db, log_audit, verify_audit_chain
    from sqlalchemy import text

    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DURABLE", "true")
    _fresh_settings()

    url = f"sqlite+aiosqlite:///{tmp_path / 'durable.sqlite'}"
    await init_db(url)
    try:
        # Stale instance with a size threshold that would never fire —
        # if log_audit routed through it the row would sit in memory.
        stale = BatchedAuditChain(batch_size=1000, flush_interval_s=3600.0)
        set_batched_chain(stale)

        await log_audit(
            agent_id="acme::dora",
            action="egress_llm_chat",
            status="ok",
        )

        assert stale.pending_count == 0
        async with get_db() as conn:
            row = (await conn.execute(text(
                "SELECT agent_id, chain_seq, row_hash FROM audit_log"
            ))).first()
        assert row is not None
        assert row[0] == "acme::dora"
        ok, broken_seq, reason = await verify_audit_chain()
        assert ok, (broken_seq, reason)
    finally:
        await dispose_db()


def test_f_a_404_gate_is_moot_under_durable(monkeypatch: pytest.MonkeyPatch):
    """``audit_fail_deny=true`` + batched chain requires an explicit
    background-failure decision (F-A-404). Durable mode has no
    background flush, so the gate must not demand one — symmetric with
    ``audit_chain_disabled``."""
    pytest.importorskip("webauthn")
    from mcp_proxy.config import validate_config

    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-default")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "1" * 64)
    monkeypatch.setenv("MCP_PROXY_SECRET_BACKEND", "vault")
    monkeypatch.setenv("MCP_PROXY_VAULT_ADDR", "https://vault.test.example:8200")
    monkeypatch.setenv("MCP_PROXY_VAULT_TOKEN", "s.test-token")
    monkeypatch.setenv("MCP_PROXY_VAULT_VERIFY_TLS", "true")
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "vault")
    monkeypatch.setenv("MCP_PROXY_DB_ENCRYPTION_KEY", "0" * 64)
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_ENFORCEMENT", "required")
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_RP_ID", "mastio.example")
    monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", "required")
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "2" * 64)
    monkeypatch.setenv("MCP_PROXY_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "true")
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", "false")
    monkeypatch.setenv("MCP_PROXY_AUDIT_FAIL_DENY", "true")
    # The F-A-404 trigger condition: neither background mode declared.
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_BACKGROUND_FAIL_DENY", "false")
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_BACKGROUND_FAIL_OPEN", "false")

    # Without durable: the gate fires.
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DURABLE", "false")
    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1

    # With durable: same env boots past the F-A-404 gate.
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DURABLE", "true")
    settings = _fresh_settings()
    validate_config(settings)


def test_module_default_is_batched(monkeypatch: pytest.MonkeyPatch):
    """The default posture stays batched (the Tier-2 unlock): durable is
    strictly opt-in."""
    monkeypatch.delenv("MCP_PROXY_AUDIT_CHAIN_DURABLE", raising=False)
    settings = _fresh_settings()
    assert settings.audit_chain_durable is False
    assert settings.audit_chain_batch_size == 100
    assert settings.audit_chain_flush_interval_s == 1.0
    assert _ac is not None
