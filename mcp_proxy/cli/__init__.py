"""cullis-proxy CLI — operational commands for the proxy.

Entry point: `python -m mcp_proxy.cli <subcommand>`.

Subcommands:
  rebuild-cache    Drop and re-fetch the federation cache from the broker.

Each subcommand is a thin async wrapper around helpers that live next
to the runtime code (e.g. mcp_proxy.sync.cache_admin) so the CLI itself
stays trivial and the operational logic stays unit-testable.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.sync.cache_admin import drop_federation_cache

_log = logging.getLogger("mcp_proxy.cli")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cullis-proxy",
        description="Operational CLI for the Cullis MCP Proxy.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rebuild = sub.add_parser(
        "rebuild-cache",
        help="Drop the federation cache so the subscriber re-fetches "
        "every event on next start. Safe to run on a live proxy: the "
        "subscriber will replay from seq=0 and converge in seconds.",
    )
    rebuild.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive confirmation prompt.",
    )

    return parser


async def _cmd_rebuild_cache(args: argparse.Namespace) -> int:
    if not args.yes:
        # Reading from stdin keeps the prompt out of the test path —
        # tests always pass --yes. Operators see a clear warning.
        sys.stderr.write(
            "This will DROP all rows in cached_federated_agents, "
            "cached_policies, cached_bindings, and reset the federation "
            "cursor for this proxy. The subscriber will refetch from "
            "the broker on next connection.\n"
            "Continue? [y/N]: "
        )
        sys.stderr.flush()
        ans = sys.stdin.readline().strip().lower()
        if ans not in ("y", "yes"):
            sys.stderr.write("aborted\n")
            return 1

    settings = get_settings()
    await init_db(settings.database_url)
    try:
        counts = await drop_federation_cache()
    finally:
        await dispose_db()

    sys.stdout.write(
        f"federation cache dropped: "
        f"agents={counts['agents']}, "
        f"policies={counts['policies']}, "
        f"bindings={counts['bindings']}, "
        f"cursor_rows={counts['cursor']}\n"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "rebuild-cache":
        return asyncio.run(_cmd_rebuild_cache(args))

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
