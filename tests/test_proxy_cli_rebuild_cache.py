"""ADR-001 Phase 4c — `cullis-proxy rebuild-cache` CLI tests."""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.cli import main as cli_main
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.sync.cache_admin import drop_federation_cache
from mcp_proxy.sync.handlers import (
    EVENT_AGENT_REGISTERED,
    EVENT_BINDING_GRANTED,
    EVENT_POLICY_UPDATED,
    apply_event,
)


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    # Settings is lru_cache'd — flush so the rebuild-cache command
    # reads the test database URL, not the dev default.
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    yield url
    await dispose_db()
    get_settings.cache_clear()


# ── drop_federation_cache helper ───────────────────────────────────


@pytest.mark.asyncio
async def test_drop_federation_cache_returns_counts(proxy_db):
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=1,
            event_type=EVENT_AGENT_REGISTERED,
            payload={"agent_id": "acme::a", "capabilities": []},
        )
        await apply_event(
            conn, org_id="acme", seq=2,
            event_type=EVENT_AGENT_REGISTERED,
            payload={"agent_id": "acme::b", "capabilities": []},
        )
        await apply_event(
            conn, org_id="acme", seq=3,
            event_type=EVENT_POLICY_UPDATED,
            payload={"policy_id": "p1", "policy_type": "session"},
        )
        await apply_event(
            conn, org_id="acme", seq=4,
            event_type=EVENT_BINDING_GRANTED,
            payload={"binding_id": 9, "agent_id": "acme::a", "scope": []},
        )

    counts = await drop_federation_cache()
    assert counts == {"agents": 2, "policies": 1, "bindings": 1, "cursor": 1}

    async with get_db() as conn:
        for table in (
            "cached_federated_agents", "cached_policies",
            "cached_bindings", "federation_cursor",
        ):
            n = (await conn.execute(text(f"SELECT COUNT(*) FROM {table}"))).scalar_one()
            assert n == 0, f"{table} not empty after drop"


@pytest.mark.asyncio
async def test_drop_federation_cache_on_empty_db_is_noop(proxy_db):
    counts = await drop_federation_cache()
    assert counts == {"agents": 0, "policies": 0, "bindings": 0, "cursor": 0}


# ── CLI integration ────────────────────────────────────────────────


def test_cli_rebuild_cache_with_yes_flag(proxy_db, capsys):
    """Invoke `cullis-proxy rebuild-cache --yes` end-to-end and assert
    the human-readable summary line lands on stdout."""
    # Pre-seed via async helper so the CLI has rows to drop.
    async def _seed():
        async with get_db() as conn:
            await apply_event(
                conn, org_id="acme", seq=1,
                event_type=EVENT_AGENT_REGISTERED,
                payload={"agent_id": "acme::seed", "capabilities": []},
            )
    asyncio.run(_seed())

    rc = cli_main(["rebuild-cache", "--yes"])
    assert rc == 0

    captured = capsys.readouterr()
    assert "federation cache dropped" in captured.out
    assert "agents=1" in captured.out


def test_cli_rebuild_cache_aborts_without_yes(proxy_db, monkeypatch, capsys):
    """Without `--yes`, the CLI prompts on stderr and aborts on a `n`
    answer. We pipe `n\\n` into stdin to confirm the abort path."""
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    rc = cli_main(["rebuild-cache"])
    assert rc == 1

    err = capsys.readouterr().err
    assert "Continue?" in err
    assert "aborted" in err


def test_cli_no_subcommand_prints_help(capsys):
    """Bare `cullis-proxy` invocation must show help, not crash."""
    with pytest.raises(SystemExit) as exc:
        cli_main([])
    # argparse exits with 2 when required subcommand is missing.
    assert exc.value.code == 2
