"""Refuse-to-boot via readiness gate (2026-06-02).

A fail-closed boot guard (PKI orphan / partial-restore, the explicit
CA-provisioning gate, the Vault token policy) raises SystemExit. Under
``uvicorn --workers`` that left the container ``Up (unhealthy)``
respawning instead of a clean refuse. The fix: the guard records a
reason in ``mcp_proxy.boot_state``, the lifespan catches the SystemExit
and serves a degraded not-ready worker, and the probes surface it:

  * ``/readyz`` → 503 (not ready, kept out of rotation / rollout)
  * ``/health`` → 503 (compose healthcheck fails, ``--wait`` fails)
  * ``/healthz`` → 200 (liveness; no restart loop for a deterministic,
    won't-self-heal refusal)

These tests pin the flag semantics and each endpoint's behaviour, and
that ``ensure_ca_bootstrap_safe`` records a reason before refusing.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcp_proxy import boot_state


# ── boot_state flag ────────────────────────────────────────────────────
def test_clean_by_default():
    assert boot_state.boot_refusal_reason() is None
    assert boot_state.is_boot_refused() is False


def test_refuse_sets_reason():
    boot_state.refuse_boot("pki_incoherence: x")
    assert boot_state.is_boot_refused() is True
    assert boot_state.boot_refusal_reason() == "pki_incoherence: x"


def test_first_writer_wins():
    boot_state.refuse_boot("first")
    boot_state.refuse_boot("second")
    assert boot_state.boot_refusal_reason() == "first"


def test_reset_clears():
    boot_state.refuse_boot("x")
    boot_state.reset_boot_refusal()
    assert boot_state.boot_refusal_reason() is None


# ── /readyz ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_readyz_503_when_boot_refused():
    from mcp_proxy.main import readyz

    boot_state.refuse_boot("ca_bootstrap_disabled: restore the CA")
    resp = await readyz()
    assert resp.status_code == 503
    import json
    body = json.loads(bytes(resp.body))
    assert body["status"] == "refused"
    assert "ca_bootstrap_disabled" in body["checks"]["boot"]


# ── /health ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_health_503_when_boot_refused():
    from mcp_proxy.main import health

    boot_state.refuse_boot("pki_incoherence: org-ca absent")
    # request is not touched on the refused path; pass a placeholder.
    resp = await health(request=SimpleNamespace())
    assert resp.status_code == 503
    import json
    body = json.loads(bytes(resp.body))
    assert body["status"] == "refused"
    assert body["reason"] == "pki_incoherence: org-ca absent"


@pytest.mark.asyncio
async def test_health_200_when_clean():
    from mcp_proxy.main import health

    # Clean boot — no refusal flag. The handler reads
    # request.app.state.agent_manager, so provide a minimal stand-in.
    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    result = await health(request=req)
    # Clean path returns a plain dict (FastAPI → 200), not a 503 response.
    assert isinstance(result, dict)
    assert result["status"] == "ok"


# ── /healthz stays 200 (liveness must not flap on a refusal) ───────────
@pytest.mark.asyncio
async def test_healthz_200_even_when_boot_refused():
    from mcp_proxy.main import healthz

    boot_state.refuse_boot("anything")
    result = await healthz()
    # Liveness is shallow and unconditional — a deterministic boot
    # refusal must NOT fail liveness (that would restart-loop the pod).
    assert result == {"status": "ok"}


# ── guard records a reason before refusing ─────────────────────────────
@pytest.mark.asyncio
async def test_ensure_ca_bootstrap_safe_records_reason(monkeypatch):
    """In production with enrolled agents and missing CA, the guard sets
    a boot-refusal reason (not just raising SystemExit) so the degraded
    probes can name the cause."""
    from mcp_proxy.egress.agent_manager import AgentManager

    mgr = AgentManager(org_id="acme", trust_domain="acme.example")

    async def _fake_count():
        return 3

    monkeypatch.setattr(
        "mcp_proxy.db.count_enrolled_agents", _fake_count,
    )
    # Force the production branch + no rekey override.
    monkeypatch.setattr(
        "mcp_proxy.egress.agent_manager._pki_rekey_allowed", lambda: False,
    )
    monkeypatch.setattr(
        "mcp_proxy.config.get_settings",
        lambda: SimpleNamespace(environment="production"),
    )

    with pytest.raises(SystemExit):
        await mgr.ensure_ca_bootstrap_safe("the Org Root CA", "restore org-ca")

    reason = boot_state.boot_refusal_reason()
    assert reason is not None
    assert "pki_incoherence" in reason
