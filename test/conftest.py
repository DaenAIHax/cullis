"""Root conftest for the Mastio public test surface.

Registers the ``postgres`` marker and exposes the ``pg_url`` fixture so
the asyncpg-binding subset (F0.2 pre-pilot gate) can be opted into with
an env var without forcing every developer to run Docker.

Default behaviour: ``CULLIS_TEST_PG_URL`` unset → every
``@pytest.mark.postgres`` test is skipped. SQLite-backed tests stay
green on a plain developer laptop.

Opt-in behaviour:

    docker compose -f test/compose-pg.yml up -d --wait
    export CULLIS_TEST_PG_URL=postgresql+asyncpg://cullis:cullis@127.0.0.1:5544/cullis_test
    pytest test/ -m postgres -n auto
    docker compose -f test/compose-pg.yml down -v

See ``test/compose-pg.yml`` for the service definition and
``test/integration/test_alembic_full_chain_postgres.py`` (added under
Step 2) for the full 0001→head migration walk against asyncpg.
"""
from __future__ import annotations

import os

import pytest


_PG_URL_ENV = "CULLIS_TEST_PG_URL"


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``postgres`` marker.

    Without this every ``@pytest.mark.postgres`` emits a
    PytestUnknownMarkWarning that becomes an error under strict mode.
    """
    config.addinivalue_line(
        "markers",
        "postgres: opt-in test that requires CULLIS_TEST_PG_URL pointing "
        "to a running Postgres 16 (see test/compose-pg.yml). Skipped when "
        "the env var is absent.",
    )


@pytest.fixture
def pg_url() -> str:
    """Yield the configured Postgres URL or skip the test.

    Tests that cannot fall back to SQLite (Alembic asyncpg integration,
    advisory-lock contention, pg_locks observability) consume this
    fixture so the skip reason is consistent across the suite.
    """
    url = os.environ.get(_PG_URL_ENV)
    if not url:
        pytest.skip(
            f"{_PG_URL_ENV} not set — start test/compose-pg.yml and "
            "export the URL to enable the Postgres-marked subset."
        )
    return url
