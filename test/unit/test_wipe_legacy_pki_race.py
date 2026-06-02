"""Multi-worker boot race in the Phase 0 legacy-PKI migration.

``AgentManager.wipe_legacy_pki_if_present`` runs at boot in EVERY uvicorn
worker (``main.py`` lifespan). Before the fix it migrated the legacy
plaintext Org CA / Intermediate rows into the KMS via the non-atomic
``store_org_ca`` / ``store_intermediate_ca`` (Vault read-modify-write
whose first-write branch carries no ``cas`` constraint). With N workers
migrating concurrently the interleaved read-modify-write hits a Vault
cas version mismatch → ``RuntimeError`` → the wipe is aborted on a subset
of workers and completed on others, leaving inconsistent at-rest
hardening state across the fleet.

The fix routes the migration through the atomic create-only variants
(``store_org_ca_if_absent`` / ``store_intermediate_ca_if_absent``,
Vault KV v2 ``cas:0``) when the provider exposes them — the same D-9
treatment already applied to the mint path in ``_persist_*`` (#1022).
Providers without the create-only variant (the local dev backend) keep
the legacy path, which is race-safe incidentally via the
``pki_key_store`` primary-key collision on the identical derived key id.

These tests pin that the create-only path is preferred when available
and that the legacy path is the fallback otherwise.
"""
from __future__ import annotations

import asyncio

import mcp_proxy.egress.agent_manager as am
import mcp_proxy.kms as kms
import mcp_proxy.kms.pki_at_rest as pki_at_rest
from mcp_proxy.egress.agent_manager import AgentManager


class _FakeProvider:
    """Records which store-path each migration call took."""

    def __init__(self, name: str, *, with_if_absent: bool) -> None:
        self.name = name
        self.calls: list[str] = []
        if with_if_absent:
            self.store_org_ca_if_absent = self._record(
                "store_org_ca_if_absent", ret=True,
            )
            self.store_intermediate_ca_if_absent = self._record(
                "store_intermediate_ca_if_absent", ret=True,
            )

    def _record(self, label: str, *, ret):
        async def _call(*_a, **_k):
            self.calls.append(label)
            return ret
        return _call

    async def store_org_ca(self, *_a, **_k) -> None:
        self.calls.append("store_org_ca")

    async def store_intermediate_ca(self, *_a, **_k) -> None:
        self.calls.append("store_intermediate_ca")


def _wire(monkeypatch, provider: _FakeProvider) -> None:
    legacy = {
        "org_ca_key": "ORG-KEY-PEM",
        "org_ca_cert": "ORG-CERT-PEM",
        "mastio_ca_key": "INT-KEY-PEM",
        "mastio_ca_cert": "INT-CERT-PEM",
    }

    async def _get_config(key):
        return legacy.get(key)

    async def _noop(*_a, **_k):
        return None

    monkeypatch.setattr(am, "get_config", _get_config)
    monkeypatch.setattr(am, "archive_legacy_pki", _noop)
    monkeypatch.setattr(am, "delete_proxy_config", _noop)
    monkeypatch.setattr(am, "log_audit", _noop)
    monkeypatch.setattr(
        pki_at_rest, "pki_master_key_configured", lambda: True,
    )
    monkeypatch.setattr(kms, "get_kms_provider", lambda: provider)


def test_wipe_prefers_cas_create_only_when_available(monkeypatch):
    """Vault-class provider (exposes ``*_if_absent``): the migration must
    take the atomic create-only path, never the racy read-modify-write."""
    provider = _FakeProvider("vault", with_if_absent=True)
    _wire(monkeypatch, provider)

    mgr = AgentManager.__new__(AgentManager)
    wiped = asyncio.run(mgr.wipe_legacy_pki_if_present())

    assert wiped is True
    assert "store_org_ca_if_absent" in provider.calls
    assert "store_intermediate_ca_if_absent" in provider.calls
    assert "store_org_ca" not in provider.calls, (
        "racy non-cas read-modify-write was used despite a create-only "
        "variant being available"
    )
    assert "store_intermediate_ca" not in provider.calls


def test_wipe_falls_back_to_legacy_store_without_cas(monkeypatch):
    """Local-class provider (no ``*_if_absent``): the migration keeps the
    legacy store path (race-safe via the pki_key_store PK collision)."""
    provider = _FakeProvider("local", with_if_absent=False)
    _wire(monkeypatch, provider)

    mgr = AgentManager.__new__(AgentManager)
    wiped = asyncio.run(mgr.wipe_legacy_pki_if_present())

    assert wiped is True
    assert "store_org_ca" in provider.calls
    assert "store_intermediate_ca" in provider.calls
