"""Admin observability endpoints — ADR-013 circuit breaker surface.

Operators need a single place to answer "is the breaker shedding
right now, and what is it seeing?" without grepping logs or
instrumenting anything custom. This endpoint exposes the minimum
state that matters during an incident.

Auth uses the shared ``admin_secret`` — same pattern as
``mcp_proxy/admin/info.py``.
"""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel

from mcp_proxy.config import get_settings

router = APIRouter(prefix="/v1/admin/observability", tags=["admin", "observability"])


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


class CircuitBreakerResponse(BaseModel):
    """Snapshot of the DB latency circuit breaker (ADR-013 layer 6).

    All latency fields are rounded milliseconds. ``None`` on a
    p99 field means the corresponding source hasn't collected
    enough samples yet (``probe_ready = false`` covers the
    composite: at least one source must be ready for the breaker
    to ever shed). Shed counters are absolute: the breaker never
    resets them at runtime, so a monitoring scrape can
    ``rate(shed_total)`` if it wants.
    """
    probe_ready: bool
    p99_ms_probe: float | None
    p99_ms_passive: float | None
    p99_ms_effective: float | None
    probe_samples_in_window: int
    passive_samples_in_window: int
    is_shedding: bool
    shed_fraction: float
    shed_count_last_60s: int
    shed_count_total: int
    activation_threshold_ms: float
    deactivation_threshold_ms: float
    max_shed_fraction: float


@router.get(
    "/circuit-breaker",
    response_model=CircuitBreakerResponse,
    dependencies=[Depends(_require_admin_secret)],
    summary="DB latency circuit breaker runtime snapshot",
)
async def get_circuit_breaker(request: Request) -> CircuitBreakerResponse:
    tracker = getattr(request.app.state, "db_latency_tracker", None)
    state = getattr(request.app.state, "db_latency_cb_state", None)

    if tracker is None or state is None:
        # The middleware/tracker haven't been wired in yet. Return a
        # deterministic "nothing configured" payload rather than 500.
        return CircuitBreakerResponse(
            probe_ready=False,
            p99_ms_probe=None,
            p99_ms_passive=None,
            p99_ms_effective=None,
            probe_samples_in_window=0,
            passive_samples_in_window=0,
            is_shedding=False,
            shed_fraction=0.0,
            shed_count_last_60s=0,
            shed_count_total=0,
            activation_threshold_ms=0.0,
            deactivation_threshold_ms=0.0,
            max_shed_fraction=0.0,
        )

    probe_p99, passive_p99, effective_p99 = tracker.p99_ms()
    probe_samples, passive_samples = tracker.sample_counts()
    probe_ready = effective_p99 is not None

    # The shed fraction the breaker would apply *right now* for a
    # request that arrived this instant. When not in the shedding
    # state the fraction is 0 regardless of p99.
    current_fraction = (
        state.shed_fraction(effective_p99)
        if state.is_shedding and effective_p99 is not None
        else 0.0
    )

    return CircuitBreakerResponse(
        probe_ready=probe_ready,
        p99_ms_probe=round(probe_p99, 1) if probe_p99 is not None else None,
        p99_ms_passive=round(passive_p99, 1) if passive_p99 is not None else None,
        p99_ms_effective=round(effective_p99, 1) if effective_p99 is not None else None,
        probe_samples_in_window=probe_samples,
        passive_samples_in_window=passive_samples,
        is_shedding=state.is_shedding,
        shed_fraction=round(current_fraction, 3),
        shed_count_last_60s=state.shed_count_last_60s(),
        shed_count_total=state.shed_total,
        activation_threshold_ms=state.activation_ms,
        deactivation_threshold_ms=state.deactivation_ms,
        max_shed_fraction=state.max_shed_fraction,
    )
