"""Server-side pagination for the dashboard audit log.

Before this fix ``audit_page`` loaded a fixed ``LIMIT 500`` from each of
``audit_log`` and ``local_audit`` (the admin + traffic streams), merged
the ≤1000 rows in memory, and paginated *that window*. So with 24k rows
in the DB the dashboard could only ever reach the newest ~1000 — every
page/filter combination was still capped, and the sidebar count (real
COUNT) disagreed with the view.

The fix projects both tables onto one positional column set and runs a
single time-ordered ``UNION ALL`` sliced with ``LIMIT/OFFSET`` at the SQL
layer, with the totals coming from ``COUNT(*)``. These tests pin:

1. ``total`` equals the real row count across both tables and exceeds the
   old 1000 cap; ``total_pages`` walks the whole archive.
2. The page slice respects ``LIMIT/OFFSET``: page 1 and page 2 are
   disjoint and ``per_page`` rows each.
3. The OLDEST row is reachable on the last page (the regression — it was
   unreachable under the fixed cap).
4. Rows come back interleaved across streams in timestamp-DESC order.
5. The ``source`` filter scopes the count + rows to one stream.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text
from starlette.datastructures import QueryParams

from mcp_proxy.db import dispose_db, get_db, init_db

PER_PAGE = 50
N_ADMIN = 600
N_TRAFFIC = 600
TOTAL = N_ADMIN + N_TRAFFIC  # 1200 — deliberately past the old 1000 cap


@pytest.fixture
async def seeded_audit_db(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    url = f"sqlite+aiosqlite:///{tmp_path / 'audit_paging.db'}"
    await init_db(url)

    # One global, strictly increasing timestamp per row, alternating
    # streams (even index → admin, odd → traffic). The timestamp-DESC
    # merge is then exactly the reverse of the global index, interleaved.
    admin_rows = []
    traffic_rows = []
    for k in range(TOTAL):
        ts = f"2026-06-03T00:00:00.{k:06d}+00:00"
        if k % 2 == 0:
            # ``dur`` populated so the paginated UNION's CAST(duration_ms AS
            # TEXT) is exercised end-to-end (regression for the template's
            # ``'%.1f'`` filter, which needs a real number not a TEXT cell).
            admin_rows.append({"ts": ts, "aid": f"acme::a{k}", "act": "auth.login", "st": "success", "dur": 12.5})
        else:
            traffic_rows.append({"ts": ts, "aid": f"acme::t{k}", "evt": "tool_execute"})

    async with get_db() as db:
        await db.execute(
            text("INSERT INTO audit_log (timestamp, agent_id, action, status, duration_ms) "
                 "VALUES (:ts, :aid, :act, :st, :dur)"),
            admin_rows,
        )
        await db.execute(
            text("INSERT INTO local_audit (timestamp, agent_id, event_type, result) "
                 "VALUES (:ts, :aid, :evt, 'ok')"),
            traffic_rows,
        )
        await db.commit()
    yield url
    await dispose_db()
    get_settings.cache_clear()


async def _render(qs: str) -> dict:
    """Invoke the real ``audit_page`` and capture the template context.

    ``require_login`` and ``_ctx``/``TemplateResponse`` are stubbed so the
    test exercises the query + pagination logic without an HTTP session or
    Jinja render — the returned dict is the context the template sees.
    """
    import mcp_proxy.dashboard.audit_routes as ar

    class _Req:
        query_params = QueryParams(qs)

    orig_login = ar.require_login
    orig_ctx = ar._ctx
    orig_tr = ar.templates.TemplateResponse
    ar.require_login = lambda request: {"username": "admin"}
    ar._ctx = lambda request, session, **kw: kw
    ar.templates.TemplateResponse = lambda name, ctx: ctx
    try:
        return await ar.audit_page(_Req())
    finally:
        ar.require_login = orig_login
        ar._ctx = orig_ctx
        ar.templates.TemplateResponse = orig_tr


@pytest.mark.asyncio
async def test_total_spans_whole_archive_past_old_cap(seeded_audit_db):
    ctx = await _render("view=raw&page=1")
    assert ctx["total"] == TOTAL
    assert ctx["total"] > 1000  # the old fixed-cap ceiling
    assert ctx["admin_total"] == N_ADMIN
    assert ctx["traffic_total"] == N_TRAFFIC
    assert ctx["total_pages"] == (TOTAL + PER_PAGE - 1) // PER_PAGE  # 24


@pytest.mark.asyncio
async def test_pages_are_disjoint_and_full(seeded_audit_db):
    p1 = await _render("view=raw&page=1")
    p2 = await _render("view=raw&page=2")
    assert len(p1["entries"]) == PER_PAGE
    assert len(p2["entries"]) == PER_PAGE
    ts1 = [e["timestamp"] for e in p1["entries"]]
    ts2 = [e["timestamp"] for e in p2["entries"]]
    assert set(ts1).isdisjoint(ts2)
    # DESC order within and across the page boundary.
    assert ts1 == sorted(ts1, reverse=True)
    assert min(ts1) > max(ts2)


@pytest.mark.asyncio
async def test_oldest_row_reachable_on_last_page(seeded_audit_db):
    last = await _render(f"view=raw&page={(TOTAL + PER_PAGE - 1) // PER_PAGE}")
    oldest_ts = "2026-06-03T00:00:00.000000+00:00"
    assert any(e["timestamp"] == oldest_ts for e in last["entries"]), \
        "oldest row must be reachable — it was beyond the old 1000-row cap"


@pytest.mark.asyncio
async def test_page_one_interleaves_both_streams(seeded_audit_db):
    p1 = await _render("view=raw&page=1")
    sources = {e["source"] for e in p1["entries"]}
    assert sources == {"admin", "traffic"}, "merge must interleave both streams"


def test_audit_route_maps_to_audit_page():
    """The @router.get('/audit') decorator must decorate audit_page, not
    a helper defined nearby — a misplaced decorator turned GET /audit into
    a 422 ('value' field required, the _coerce_ms helper's param leaking
    as a required query param). Direct-call tests can't catch this; assert
    the route wiring."""
    import mcp_proxy.dashboard.audit_routes as ar
    routes = [r for r in ar.router.routes
              if getattr(r, "path", None) == "/audit"
              and "GET" in getattr(r, "methods", set())]
    assert routes, "GET /audit route not registered"
    assert routes[0].endpoint is ar.audit_page, \
        "GET /audit must map to audit_page, not a helper"


@pytest.mark.asyncio
async def test_duration_ms_is_float_for_template(seeded_audit_db):
    """The UNION casts duration_ms to TEXT (Postgres type-alignment); the
    audit template renders it with ``'%.1f' | format(...)`` which raises
    TypeError on a str. Regression for the live 500 — duration_ms must
    reach the context as float (or None), never str."""
    ctx = await _render("view=raw&page=1")
    admin = [e for e in ctx["entries"] if e["source"] == "admin"]
    assert admin, "expected admin rows on page 1"
    for e in admin:
        assert e["duration_ms"] is None or isinstance(e["duration_ms"], float), (
            f"duration_ms must be float for the '%.1f' template filter, "
            f"got {type(e['duration_ms']).__name__}={e['duration_ms']!r}"
        )
    assert any(e["duration_ms"] == 12.5 for e in admin), "seeded duration_ms not coerced"


@pytest.mark.asyncio
async def test_source_filter_scopes_count_and_rows(seeded_audit_db):
    ctx = await _render("view=raw&page=1&source=admin")
    assert ctx["total"] == N_ADMIN
    assert ctx["traffic_total"] == 0
    assert all(e["source"] == "admin" for e in ctx["entries"])
