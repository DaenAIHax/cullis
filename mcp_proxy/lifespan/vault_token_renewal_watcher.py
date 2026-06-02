"""Boot guard + background watcher that keep the Vault KMS token alive.

When ``kms_backend=vault`` the Mastio authenticates to Vault with a
single static token. A non-root token has a finite TTL and, without
renewal, lapses mid-deployment — after which every CA load/store
returns HTTP 403 and the next cert rotation or restart fails (validated
2026-06-02: :class:`mcp_proxy.kms.vault.VaultKMSProvider` had no
renewal, and the 60-min soak used an infinite root token so never
exercised expiry).

Two parts:

* :func:`evaluate_vault_token_at_boot` — looks up the token once at
  boot, logs/guards on renewability, and returns the classified token
  for the loop. In production a non-renewable finite token refuses boot
  (override ``MCP_PROXY_VAULT_TOKEN_ALLOW_NONRENEWABLE=true``).
* :func:`vault_token_renewal_watcher_loop` — renews a renewable/periodic
  token at ~half its lease so it never lapses.

Leader-elected like the other lifespan watchers so only one worker
renews in a multi-worker deployment.
"""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger("mcp_proxy.lifespan.vault_token_renewal_watcher")

# Never sleep longer than this between renews even when the lease is
# large — bounds how long a token revoked out-of-band stays trusted and
# keeps the half-life assumption conservative.
_MAX_INTERVAL_SECONDS = 12 * 60 * 60
# After a renew failure, retry on this floor rather than the full
# half-life so a transient Vault blip recovers well before expiry.
_RETRY_FLOOR_SECONDS = 30


def _next_interval(ttl: int, period: int, min_interval: int) -> float:
    """Seconds to sleep before the next renew: ~half the live lease,
    clamped to ``[min_interval, _MAX_INTERVAL_SECONDS]``.

    Renewing at the half-life leaves a full half-life of retry budget
    before the token would actually expire.
    """
    lease = period if period > 0 else ttl
    half = max(int(lease // 2), min_interval)
    return float(min(half, _MAX_INTERVAL_SECONDS))


async def evaluate_vault_token_at_boot(settings) -> dict | None:
    """Introspect the Vault token at boot; guard, log, and return it.

    Returns the classified token dict (``{ttl, period, renewable,
    expires}``) when a renewal loop should run, else ``None`` (backend
    not vault, provider has no token lifecycle, lookup failed, or the
    token never expires / cannot be renewed).

    Raises ``SystemExit`` in production when the token is non-renewable
    with a finite TTL, unless ``vault_token_allow_nonrenewable`` is set —
    such a token will expire and Mastio cannot renew it.
    """
    if getattr(settings, "kms_backend", "local") != "vault":
        return None

    from mcp_proxy.kms import get_kms_provider
    from mcp_proxy.kms.vault_token import boot_decision, classify_token

    provider = get_kms_provider()
    if not hasattr(provider, "lookup_token"):
        return None

    try:
        data = await provider.lookup_token()
    except Exception as exc:  # noqa: BLE001 — never hard-fail boot on lookup alone
        # The CA load right after this will surface a genuinely dead
        # token; a lookup-self blip should not by itself stop boot.
        logger.warning(
            "Vault token lookup-self failed at boot: %s — renewal watcher "
            "disabled for this boot", exc,
        )
        return None

    classified = classify_token(data)
    is_prod = getattr(settings, "environment", "") == "production"
    level, message = boot_decision(classified, is_production=is_prod)
    allow_override = bool(getattr(settings, "vault_token_allow_nonrenewable", False))

    if level == "refuse":
        if not allow_override:
            logger.critical(
                "Vault token policy refusing boot: %s "
                "Set MCP_PROXY_VAULT_TOKEN_ALLOW_NONRENEWABLE=true to "
                "override (accepting that rotation/restart will fail once "
                "the token expires).", message,
            )
            raise SystemExit(1)
        logger.warning(
            "Vault token non-renewable but override active "
            "(MCP_PROXY_VAULT_TOKEN_ALLOW_NONRENEWABLE=true): %s", message,
        )
    elif level == "warn":
        logger.warning("Vault token: %s", message)
    else:
        logger.info("Vault token: %s", message)

    # Only run the renewal loop for a token that can actually be renewed.
    if classified["expires"] and (
        classified["renewable"] or classified["period"] > 0
    ):
        return classified
    return None


async def vault_token_renewal_watcher_loop(
    provider,
    *,
    initial_ttl: int,
    period: int,
    min_interval_seconds: int = 60,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Renew the Vault token at ~half its lease until ``stop_event``.

    The first renew happens after the initial half-life (the token was
    just looked up at boot, so it is fresh). On each success the next
    interval is recomputed from the renewed lease; on failure the loop
    retries on a short floor and keeps going so a transient Vault outage
    recovers without operator action.
    """
    stop_event = stop_event or asyncio.Event()
    interval = _next_interval(initial_ttl, period, min_interval_seconds)
    logger.info(
        "vault_token_renewal_watcher starting (initial_ttl=%ds period=%ds "
        "first_renew_in=%.0fs)", initial_ttl, period, interval,
    )

    while not stop_event.is_set():
        # Sleep with early-exit on shutdown so SIGTERM teardown doesn't
        # wait out the full interval.
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break  # stop_event fired during the sleep
        except asyncio.TimeoutError:
            pass
        if stop_event.is_set():
            break

        try:
            auth = await provider.renew_token()
            new_ttl = int(auth.get("lease_duration") or 0)
            renewable = bool(auth.get("renewable", True))
            if new_ttl <= 0 or not renewable:
                logger.warning(
                    "vault_token_renewal: renew-self returned "
                    "lease_duration=%ss renewable=%s — token may no longer "
                    "be renewable; retrying on floor. Cert rotation/restart "
                    "will fail once it expires.", new_ttl, renewable,
                )
                interval = float(max(min_interval_seconds, _RETRY_FLOOR_SECONDS))
                await _audit(status="error", detail=f"lease_duration={new_ttl}")
                continue
            interval = _next_interval(new_ttl, period, min_interval_seconds)
            logger.info(
                "vault_token_renewal: renewed (new_ttl=%ds next_renew_in=%.0fs)",
                new_ttl, interval,
            )
            await _audit(status="success", detail=f"new_ttl={new_ttl}")
        except Exception as exc:  # noqa: BLE001 — long-running loop must not die
            logger.error(
                "vault_token_renewal: renew-self failed: %s — retrying in "
                "%ds. If this persists the token will expire and cert "
                "rotation / restart will fail with Vault HTTP 403.",
                exc, _RETRY_FLOOR_SECONDS,
            )
            interval = float(max(min_interval_seconds, _RETRY_FLOOR_SECONDS))
            await _audit(status="error", detail=f"error={type(exc).__name__}")

    logger.info("vault_token_renewal_watcher stopped")


async def _audit(*, status: str, detail: str) -> None:
    """Best-effort audit row for a renewal tick. Never raises."""
    try:
        from mcp_proxy.db import log_audit
        await log_audit(
            agent_id="system",
            action="kms.vault_token_renewed",
            status=status,
            detail=detail,
        )
    except Exception:  # noqa: BLE001 — audit is best-effort here
        pass


__all__ = [
    "evaluate_vault_token_at_boot",
    "vault_token_renewal_watcher_loop",
]
