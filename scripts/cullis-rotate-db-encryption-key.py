#!/usr/bin/env python3
"""Rotate ``MCP_PROXY_DB_ENCRYPTION_KEY`` — rewrap at-rest stores old → new.

``MCP_PROXY_DB_ENCRYPTION_KEY`` derives the Fernet master that encrypts the
Mastio's at-rest secrets: the signing key (``mastio_keys``) and the Org +
Intermediate CA (``pki_key_store``). Changing it without re-encrypting makes
every row undecryptable — the LocalIssuer and the verifier fail closed and
signing halts. This tool decrypts every row under the OLD passphrase and
re-encrypts under the NEW one in a single transaction.

Run with the **Mastio stopped** and after a backup (``pg-backup.sh`` +
``vault-ca-backup.sh``). The OLD passphrase is the current
``MCP_PROXY_DB_ENCRYPTION_KEY`` in the environment; pass the NEW one via
``--new-key`` or ``MCP_PROXY_DB_ENCRYPTION_KEY_NEW``. When it finishes, set
``MCP_PROXY_DB_ENCRYPTION_KEY`` to the new value in ``proxy.env`` and start
the Mastio.

NOTE: ``ai_provider_credentials`` is encrypted under a SEPARATE key
(``MCP_PROXY_SECRET_ENCRYPTION_KEY_B64``) and is NOT rotated here.

Usage:
  MCP_PROXY_DATABASE_URL=postgresql+asyncpg://... \
  MCP_PROXY_DB_ENCRYPTION_KEY=<OLD> \
    python scripts/cullis-rotate-db-encryption-key.py --new-key <NEW>
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys


async def _run(new_key: str) -> int:
    old_key = os.environ.get("MCP_PROXY_DB_ENCRYPTION_KEY", "").strip()
    if not old_key:
        print("MCP_PROXY_DB_ENCRYPTION_KEY (the OLD key) must be set in the "
              "environment — it is the passphrase the existing rows were "
              "encrypted with.", file=sys.stderr)
        return 2
    if old_key == new_key:
        print("--new-key is identical to the current MCP_PROXY_DB_ENCRYPTION_KEY; "
              "nothing to rotate.", file=sys.stderr)
        return 2
    db_url = os.environ.get("MCP_PROXY_DATABASE_URL", "").strip()
    if not db_url:
        print("MCP_PROXY_DATABASE_URL must be set.", file=sys.stderr)
        return 2

    from mcp_proxy.db import dispose_db, init_db, rewrap_at_rest_master_key

    await init_db(db_url)
    try:
        counts = await rewrap_at_rest_master_key(old_key, new_key)
    except Exception as exc:  # noqa: BLE001 — surface the cause, write nothing
        print(f"REWRAP FAILED ({exc}). No rows were written if the OLD "
              "passphrase was wrong (decrypt is validated before any write). "
              "The store is unchanged; fix the OLD/NEW values and retry.",
              file=sys.stderr)
        return 1
    finally:
        await dispose_db()

    print("✓ MASTER KEY REWRAPPED")
    print(f"  mastio_keys:   {counts['mastio_keys']} row(s)")
    print(f"  pki_key_store: {counts['pki_key_store']} row(s)")
    print("")
    print("  Next: set MCP_PROXY_DB_ENCRYPTION_KEY to the NEW value in "
          "proxy.env, then start the Mastio. ai_provider_credentials uses a "
          "separate key and is not affected.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--new-key",
        default=os.environ.get("MCP_PROXY_DB_ENCRYPTION_KEY_NEW"),
        help="the NEW passphrase (or set MCP_PROXY_DB_ENCRYPTION_KEY_NEW)",
    )
    args = ap.parse_args()
    if not (args.new_key or "").strip():
        print("provide the new passphrase via --new-key or "
              "MCP_PROXY_DB_ENCRYPTION_KEY_NEW.", file=sys.stderr)
        return 2
    return asyncio.run(_run(args.new_key.strip()))


if __name__ == "__main__":
    raise SystemExit(main())
