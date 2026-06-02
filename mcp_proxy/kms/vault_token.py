"""Vault token lifecycle classification + boot-time policy decision.

Pure helpers (no I/O) so the boot guard and the renewal watcher share
one interpretation of an ``auth/token/lookup-self`` response, and the
unit tests can pin the decision matrix without a live Vault.

Context (validated 2026-06-02): :class:`mcp_proxy.kms.vault.VaultKMSProvider`
authenticates with a single static token and has no renewal. A non-root
token therefore lapses after its TTL, and every CA load/store then
returns HTTP 403 — breaking cert rotation and any restart. The boot
guard turns that silent landmine into an explicit, operator-visible
decision; the renewal watcher keeps a renewable/periodic token alive.
"""
from __future__ import annotations

from typing import Any


def classify_token(lookup_data: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Vault ``lookup-self`` ``data`` block to what renewal needs.

    Returns ``{ttl, period, renewable, expires}``:

    * ``ttl`` — seconds of life remaining (0 for a non-expiring token).
    * ``period`` — token period in seconds (0 when not periodic). A
      periodic token renews to this value indefinitely.
    * ``renewable`` — Vault's ``renewable`` flag.
    * ``expires`` — True when the token has a finite life. False for a
      root/unlimited token, which Vault reports as ``ttl == 0`` with a
      null ``expire_time``.
    """
    ttl = int(lookup_data.get("ttl") or 0)
    period = int(lookup_data.get("period") or 0)
    renewable = bool(lookup_data.get("renewable", False))
    expire_time = lookup_data.get("expire_time")
    # A positive ttl OR a non-null expire_time means the token will
    # eventually die. ttl==0 + expire_time null == non-expiring (root).
    expires = ttl > 0 or bool(expire_time)
    return {
        "ttl": ttl,
        "period": period,
        "renewable": renewable,
        "expires": expires,
    }


def boot_decision(
    classified: dict[str, Any], *, is_production: bool,
) -> tuple[str, str]:
    """Decide what the boot guard does about the token's renewability.

    Returns ``(level, message)`` where ``level`` is:

    * ``"ok"``     — non-expiring, or renewable/periodic (the watcher
      keeps it alive). Boot proceeds.
    * ``"warn"``   — a finite, non-renewable token in development. Boot
      proceeds with a loud log.
    * ``"refuse"`` — a finite, non-renewable token in production: it
      WILL expire and Mastio cannot renew it, breaking cert rotation and
      restart. Boot is refused unless the operator overrides.
    """
    if not classified["expires"]:
        return (
            "ok",
            "Vault token does not expire (root/unlimited) — no renewal needed.",
        )
    if classified["renewable"] or classified["period"] > 0:
        kind = "periodic" if classified["period"] > 0 else "renewable"
        return (
            "ok",
            f"Vault token is {kind} (ttl={classified['ttl']}s, "
            f"period={classified['period']}s) — renewal watcher will keep "
            "it alive.",
        )
    # Finite + non-renewable: the landmine.
    msg = (
        f"Vault token is non-renewable with a finite TTL ({classified['ttl']}s). "
        "Mastio cannot renew it; when it expires, cert rotation and any "
        "restart will fail with Vault HTTP 403. Issue a periodic token "
        "(vault token create -period=...) or a renewable token."
    )
    return ("refuse" if is_production else "warn"), msg


__all__ = ["classify_token", "boot_decision"]
