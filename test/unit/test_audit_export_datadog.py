"""Tests for the Mastio audit-log → Datadog Logs API exporter plugin.

Datadog intake is mocked via ``httpx.MockTransport``. The audit DB is
an in-memory SQLite, identical to ``test_audit_export_s3``.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
from typing import AsyncIterator

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run audit_export_datadog tests",
        allow_module_level=True,
    )

import httpx
from sqlalchemy import text

from mcp_proxy import db as core_db

from cullis_enterprise.mastio.audit_export_datadog import exporter as exporter_mod
from cullis_enterprise.mastio.audit_export_datadog.config import (
    DatadogExportConfig,
)
from cullis_enterprise.mastio.audit_export_datadog.exporter import (
    WATERMARK_KEY, export_once,
)


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
async def fresh_db(tmp_path) -> AsyncIterator[None]:
    # File-backed, not :memory: — the exporter opens its own connection and
    # in-memory SQLite is per-connection (no shared audit_log table). The
    # enterprise conftest hid this with a StaticPool; the public surface
    # has no such shared pool, so use a real file.
    await core_db.init_db(f"sqlite+aiosqlite:///{tmp_path}/datadog.db")
    exporter_mod.stats.update(
        watermark=0, last_export_at=None, last_export_count=0,
        last_status_code=None, last_error=None,
        exports_total=0, rows_total=0,
    )
    try:
        yield
    finally:
        await core_db.dispose_db()


class _IntakeRecorder:
    """Captures every request the exporter makes to the mock transport."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.bodies: list[list[dict]] = []
        self.next_status: int = 202
        self.next_body: bytes = b'{"errors":[]}'

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        try:
            self.bodies.append(json.loads(request.content))
        except (ValueError, TypeError):
            self.bodies.append([])
        return httpx.Response(
            status_code=self.next_status,
            content=self.next_body,
            headers={"Content-Type": "application/json"},
        )


@pytest.fixture
def recorder() -> _IntakeRecorder:
    return _IntakeRecorder()


@pytest.fixture
async def client(recorder) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.MockTransport(recorder.handler)
    async with httpx.AsyncClient(transport=transport) as c:
        yield c


@pytest.fixture
def config() -> DatadogExportConfig:
    return DatadogExportConfig(
        api_key="dd-test-key",
        site="datadoghq.com",
        service="cullis-mastio-test",
        source="cullis",
        hostname="mastio-host",
        tags=("env:test", "service:cullis"),
        interval_seconds=60.0,
        batch_size=1000,
        enabled=True,
    )


# ── helpers ────────────────────────────────────────────────────────────────


async def _insert_audit_rows(count: int, *, agent_prefix: str = "agent") -> None:
    async with core_db.get_db() as conn:
        for i in range(count):
            await conn.execute(
                text(
                    "INSERT INTO audit_log "
                    "(timestamp, agent_id, action, tool_name, status, detail, "
                    " request_id, duration_ms) "
                    "VALUES (:ts, :aid, :act, :tool, :status, :detail, "
                    "        :rid, :dur)"
                ),
                {
                    "ts": f"2026-04-30T11:00:{i:02d}Z",
                    "aid": f"{agent_prefix}-{i}",
                    "act": "session_send",
                    "tool": "echo",
                    "status": "ok",
                    "detail": None,
                    "rid": f"req-{i}",
                    "dur": "9.4",
                },
            )


# ── tests ──────────────────────────────────────────────────────────────────


async def test_export_once_ships_new_rows(fresh_db, client, recorder, config):
    await _insert_audit_rows(3)

    uploaded = await export_once(config, client)
    assert uploaded == 3

    assert len(recorder.requests) == 1
    req = recorder.requests[0]
    assert req.url == "https://http-intake.logs.datadoghq.com/api/v2/logs"
    assert req.headers["DD-API-KEY"] == "dd-test-key"
    assert req.headers["Content-Type"] == "application/json"

    body = recorder.bodies[0]
    assert len(body) == 3
    assert all(entry["service"] == "cullis-mastio-test" for entry in body)
    assert all(entry["ddsource"] == "cullis" for entry in body)
    assert all(entry["hostname"] == "mastio-host" for entry in body)
    assert all(entry["ddtags"] == "env:test,service:cullis" for entry in body)
    assert [entry["audit_id"] for entry in body] == [1, 2, 3]
    assert [entry["agent_id"] for entry in body] == ["agent-0", "agent-1", "agent-2"]

    assert await core_db.get_config(WATERMARK_KEY) == "3"


async def test_export_once_no_new_rows_is_noop(fresh_db, client, recorder, config):
    uploaded = await export_once(config, client)
    assert uploaded == 0
    assert recorder.requests == []
    assert await core_db.get_config(WATERMARK_KEY) is None


async def test_export_resumes_from_watermark(fresh_db, client, recorder, config):
    await _insert_audit_rows(8)
    await core_db.set_config(WATERMARK_KEY, "3")

    uploaded = await export_once(config, client)
    assert uploaded == 5

    body = recorder.bodies[0]
    assert [entry["audit_id"] for entry in body] == [4, 5, 6, 7, 8]
    assert await core_db.get_config(WATERMARK_KEY) == "8"


async def test_consecutive_ticks_do_not_reship(fresh_db, client, recorder, config):
    await _insert_audit_rows(2)
    assert await export_once(config, client) == 2
    assert await export_once(config, client) == 0
    await _insert_audit_rows(1, agent_prefix="later")
    assert await export_once(config, client) == 1

    assert len(recorder.requests) == 2
    all_ids = [
        entry["audit_id"]
        for body in recorder.bodies
        for entry in body
    ]
    assert sorted(all_ids) == [1, 2, 3]


async def test_export_respects_batch_size(fresh_db, client, recorder):
    await _insert_audit_rows(5)
    cfg = DatadogExportConfig(
        api_key="x", site="datadoghq.com", service="s", source="cullis",
        hostname="h", tags=(),
        interval_seconds=60.0, batch_size=2, enabled=True,
    )
    assert await export_once(cfg, client) == 2
    assert await export_once(cfg, client) == 2
    assert await export_once(cfg, client) == 1
    assert await export_once(cfg, client) == 0
    assert len(recorder.requests) == 3


async def test_malformed_watermark_recovers(fresh_db, client, recorder, config):
    await _insert_audit_rows(2)
    await core_db.set_config(WATERMARK_KEY, "garbage")
    assert await export_once(config, client) == 2
    assert await core_db.get_config(WATERMARK_KEY) == "2"


async def test_intake_5xx_does_not_advance_watermark(
    fresh_db, client, recorder, config,
):
    """A failed POST keeps the watermark; the next tick retries the same window."""
    await _insert_audit_rows(2)
    recorder.next_status = 503
    recorder.next_body = b'{"error":"upstream"}'

    with pytest.raises(httpx.HTTPStatusError):
        await export_once(config, client)
    assert await core_db.get_config(WATERMARK_KEY) is None

    # Next tick with intake healthy → ships everything.
    recorder.next_status = 202
    recorder.next_body = b'{"errors":[]}'
    assert await export_once(config, client) == 2
    assert await core_db.get_config(WATERMARK_KEY) == "2"


async def test_stats_reflect_last_export(fresh_db, client, recorder, config):
    await _insert_audit_rows(4)
    await export_once(config, client)

    assert exporter_mod.stats["watermark"] == 4
    assert exporter_mod.stats["last_export_count"] == 4
    assert exporter_mod.stats["exports_total"] == 1
    assert exporter_mod.stats["rows_total"] == 4
    assert exporter_mod.stats["last_status_code"] == 202
    assert exporter_mod.stats["last_error"] is None


async def test_run_exporter_stops_on_event(fresh_db, client, recorder, config):
    cfg = DatadogExportConfig(
        api_key="x", site="datadoghq.com", service="s", source="cullis",
        hostname="h", tags=(),
        interval_seconds=10.0, batch_size=1000, enabled=True,
    )
    await _insert_audit_rows(2)
    stop = asyncio.Event()
    task = asyncio.create_task(exporter_mod.run_exporter(cfg, client, stop))
    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)
    assert exporter_mod.stats["rows_total"] >= 2


# ── plugin lifecycle ───────────────────────────────────────────────────────


async def test_plugin_skips_when_no_api_key(monkeypatch, fresh_db):
    monkeypatch.delenv("CULLIS_AUDIT_EXPORT_DATADOG_API_KEY", raising=False)

    from cullis_enterprise.mastio.audit_export_datadog.plugin import (
        DatadogAuditExportPlugin,
    )
    from fastapi import FastAPI

    plugin = DatadogAuditExportPlugin()
    app = FastAPI()
    await plugin.startup(app)
    assert plugin._task is None
    await plugin.shutdown(app)


async def test_plugin_skips_when_disabled(monkeypatch, fresh_db):
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_API_KEY", "x")
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_ENABLED", "false")

    from cullis_enterprise.mastio.audit_export_datadog.plugin import (
        DatadogAuditExportPlugin,
    )
    from fastapi import FastAPI

    plugin = DatadogAuditExportPlugin()
    app = FastAPI()
    await plugin.startup(app)
    assert plugin._task is None
    await plugin.shutdown(app)


# ── config ─────────────────────────────────────────────────────────────────


def test_intake_url_for_eu_site(monkeypatch):
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_SITE", "datadoghq.eu")
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_API_KEY", "x")
    from cullis_enterprise.mastio.audit_export_datadog.config import load_config

    cfg = load_config()
    assert cfg.intake_url == "https://http-intake.logs.datadoghq.eu/api/v2/logs"


def test_batch_size_capped_at_dd_max(monkeypatch):
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_API_KEY", "x")
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_BATCH_SIZE", "9999")
    from cullis_enterprise.mastio.audit_export_datadog.config import load_config

    cfg = load_config()
    assert cfg.batch_size == 1000


def test_tags_are_split_and_trimmed(monkeypatch):
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_API_KEY", "x")
    monkeypatch.setenv("CULLIS_AUDIT_EXPORT_DATADOG_TAGS", " env:prod , team:secops ,, ")
    from cullis_enterprise.mastio.audit_export_datadog.config import load_config

    cfg = load_config()
    assert cfg.tags == ("env:prod", "team:secops")
    assert cfg.tags_csv == "env:prod,team:secops"
