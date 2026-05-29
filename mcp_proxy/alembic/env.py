"""Alembic env for the MCP Proxy schema.

Reads PROXY_DB_URL from the environment when set (overrides sqlalchemy.url
in alembic.ini). Falls back to the .ini value (SQLite dev DB) otherwise.
"""
import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

config = context.config

if config.config_file_name is not None:
    # ``disable_existing_loggers=False`` is load-bearing: init_db() runs the
    # alembic upgrade in-process during the app lifespan (mcp_proxy/db.py,
    # main.py: configure_json_logging -> ... -> init_db). The fileConfig
    # default (True) would disable every already-created ``mcp_proxy.*``
    # logger that is not named in alembic.ini, silently suppressing all
    # application logs (denied reasons, decode failures, rate-limit warnings)
    # for the lifetime of the worker. The audit chain (DB-backed) is
    # unaffected; only the operator/SIEM log stream was being muted.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# DSN override: PROXY_DB_URL wins over alembic.ini value.
database_url = os.environ.get("PROXY_DB_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url)

# Import the proxy metadata. db_models registers every Table against
# mcp_proxy.db_models.metadata on import.
from mcp_proxy.db_models import metadata as target_metadata  # noqa: E402


def run_migrations_offline() -> None:
    """Render SQL without connecting to a DB (alembic upgrade --sql)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
