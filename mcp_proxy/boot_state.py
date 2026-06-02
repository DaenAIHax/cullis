"""Process-wide boot-refusal flag.

A fail-closed boot guard (PKI orphan / partial-restore, the explicit
CA-provisioning gate, the Vault token policy) sets this when it refuses
to bring the Mastio up. Two readers:

* the **lifespan** reads it to enter *degraded not-ready mode* instead
  of letting a ``SystemExit`` in the async lifespan task leave the
  container ``Up (unhealthy)`` respawning under ``uvicorn --workers``;
* ``/readyz`` and ``/health`` read it to return 503 with the reason,
  while ``/healthz`` (liveness) stays 200 so the orchestrator marks the
  replica NotReady **without** a restart loop.

The refusal is deterministic — it is caused by config or PKI material,
not a transient fault, so it will not self-heal on restart. A stable
NotReady state is therefore the right signal (the operator fixes the
cause and redeploys), not a crash loop that buries the root cause in
churn.

Module-level state (one interpreter == one Mastio worker process),
mirroring the ``audit_chain`` unhealthy-flag pattern ``/readyz`` already
reads.
"""
from __future__ import annotations

_boot_refusal_reason: str | None = None


def refuse_boot(reason: str) -> None:
    """Mark this worker as having refused to boot.

    ``reason`` is a short, greppable string (it lands in the 503 body
    and the CRITICAL log). Idempotent and first-writer-wins so the
    original cause is preserved if a later guard also trips.
    """
    global _boot_refusal_reason
    if _boot_refusal_reason is None:
        _boot_refusal_reason = reason


def boot_refusal_reason() -> str | None:
    """Return the refusal reason, or ``None`` when the boot is healthy."""
    return _boot_refusal_reason


def is_boot_refused() -> bool:
    """True when a guard has refused this worker's boot."""
    return _boot_refusal_reason is not None


def reset_boot_refusal() -> None:
    """Clear the flag.

    Called at the top of the lifespan so a fresh boot starts clean, and
    exposed for tests.
    """
    global _boot_refusal_reason
    _boot_refusal_reason = None


__all__ = [
    "refuse_boot",
    "boot_refusal_reason",
    "is_boot_refused",
    "reset_boot_refusal",
]
