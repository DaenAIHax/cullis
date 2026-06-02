"""H9 (audit 2026-06-02) — the DB connection URL is logged at INFO on every
boot (db.py init_db). In prod the URL carries the Postgres password inline,
so logging it verbatim leaks the credential. ``_redact_db_url`` masks the
password before it reaches the log.
"""
from mcp_proxy.db import _redact_db_url


def test_postgres_password_is_masked():
    url = "postgresql+asyncpg://cullis:s3cr3t-prod-pw@db.internal:5432/mastio"
    out = _redact_db_url(url)
    assert "s3cr3t-prod-pw" not in out, out
    # user, host, db remain (only the password is hidden) — useful for ops.
    assert "cullis" in out
    assert "db.internal" in out
    assert "mastio" in out


def test_sqlite_url_unchanged_in_substance():
    url = "sqlite+aiosqlite:///var/lib/mastio/proxy.sqlite"
    out = _redact_db_url(url)
    # No credential to hide; the path must survive.
    assert "proxy.sqlite" in out


def test_unparseable_url_falls_back_without_leaking_password():
    # A string make_url can't parse: redaction must still not emit the
    # password (which always precedes the '@').
    url = "not a valid url://user:topsecret@host/db extra"
    out = _redact_db_url(url)
    assert "topsecret" not in out, out
