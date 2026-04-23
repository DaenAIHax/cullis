"""First concrete federation update — fix the pathLen=0 bug retroactively.

Context: PR #284 (``2cba826``) repaired the Org CA generation code that
emitted ``BasicConstraints(ca=True, path_length=0)`` despite the proxy
minting a Mastio intermediate CA underneath it at runtime. Proxies
already deployed with that CA stay broken after a ``git pull``, because
their Org CA cert sits in ``proxy_config.org_ca_cert`` and is never
regenerated on its own. Issue #285 surfaces the broken state (warn at
boot + Prometheus gauge) but does not repair it.

This migration repairs it — idempotently, preserving every agent's
public key so no re-enrollment is required. It applies only to
Mastio-managed Org CAs (Connector enrollment), not BYOCA: when the
Org CA private key lives outside ``proxy_config.org_ca_key`` (held by
the org's secret manager), :meth:`check` returns False and the
migration stays dormant. A BYOCA-variant operator-driven flow is
tracked as a follow-up issue.

Rollback: restores the pre-rotation cert state (both the old Org CA
and every agent's old leaf) from ``migration_state_backups``. The old
CA private key is restored too, so the old chain validates again.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_proxy.db import (
    delete_migration_backup,
    get_config,
    get_db,
    get_migration_backup,
    insert_migration_backup,
    set_config,
)
from mcp_proxy.updates.base import Migration

from sqlalchemy import text

logger = logging.getLogger("mcp_proxy.updates.migrations.org_ca_pathlen_1")


_CA_NEW_SKEW_MINUTES = 5  # matches ``AgentManager.generate_org_ca`` convention


class OrgCAPathLenFix(Migration):
    """Rotate Org CA to ``pathLen=1`` preserving agent pubkeys.

    Concrete migration for ``2026-04-23-org-ca-pathlen-1``. See module
    docstring for context.
    """

    migration_id = "2026-04-23-org-ca-pathlen-1"
    migration_type = "cert-schema"
    criticality = "critical"
    description = (
        "Rotate the Org CA to BasicConstraints(pathLen=1) preserving every "
        "agent's public key — repairs proxies whose Org CA was generated "
        "before PR #284 fixed the pathLen=0 bug (#280). Without this, "
        "the full chain (Org CA → Mastio intermediate → agent leaf) is "
        "rejected by every stdlib x509 verifier."
    )
    preserves_enrollments = True
    # Connector-only: BYOCA rotation would require operator-driven upload
    # of a new CA (the private key lives outside proxy_config); tracked
    # as a separate follow-up issue.
    affects_enrollments = ("connector",)

    # ── Detection ─────────────────────────────────────────────────────

    async def check(self) -> bool:
        """True iff this proxy has the pathLen=0 bug AND we can fix it.

        Returns False (migration not applicable) when:
          - No Org CA cert loaded (fresh / attached-CA-pre-consume).
          - Org CA already has pathLen >= 1 or None (post-#284 install).
          - No intermediate CA minted below it (no chain violation — a
            2-tier deploy with pathLen=0 is technically valid).
          - Org CA private key absent from ``proxy_config.org_ca_key``
            (BYOCA with secret-manager-held key — operator-driven only).

        Any unexpected read / parse error propagates as an exception —
        the boot detector catches it, logs WARNING, and retries next
        boot (contract from PR 1).
        """
        ca_cert_pem = await get_config("org_ca_cert")
        if not ca_cert_pem:
            return False

        ca_key_pem = await get_config("org_ca_key")
        if not ca_key_pem:
            # BYOCA with secret-manager-held privkey — not auto-migrable.
            return False

        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        try:
            bc = ca_cert.extensions.get_extension_for_class(
                x509.BasicConstraints,
            ).value
        except x509.ExtensionNotFound:
            return False

        # pathLen is an int (constrained) or None (unbounded). Only the
        # explicit 0 triggers the bug.
        if bc.path_length != 0:
            return False

        # Intermediate presence — the #280 failure mode is pathLen=0 +
        # a mastio intermediate CA underneath (violates RFC 5280 §4.2.1.9).
        mastio_cert_pem = await get_config("mastio_ca_cert")
        if not mastio_cert_pem:
            return False

        return True

    # ── Apply ─────────────────────────────────────────────────────────

    async def up(self) -> None:
        """Rotate Org CA, re-sign every agent leaf, snapshot for rollback.

        Idempotent: if :meth:`check` would currently return False (state
        already fixed or not applicable), returns without touching the
        DB and without writing a backup. Expiry guard raises
        ``RuntimeError`` rather than silently rotating a dead CA.
        """
        if not await self.check():
            logger.info(
                "org_ca_pathlen_1: up() called but check() returns False — "
                "state already fixed or not applicable; no-op."
            )
            return

        old_cert_pem = await get_config("org_ca_cert")
        old_key_pem = await get_config("org_ca_key")
        assert old_cert_pem is not None  # check() gated us
        assert old_key_pem is not None

        old_cert = x509.load_pem_x509_certificate(old_cert_pem.encode())
        old_key = serialization.load_pem_private_key(
            old_key_pem.encode(), password=None,
        )

        now = datetime.now(timezone.utc)
        # Explicit expiry guard — a CA that's already dead has bigger
        # problems than pathLen, and the rotate-ca flow (full re-enroll)
        # is the correct recovery path.
        try:
            old_not_after = old_cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42 fallback
            old_not_after = old_cert.not_valid_after.replace(
                tzinfo=timezone.utc,
            )
        if old_not_after <= now:
            raise RuntimeError(
                f"org_ca_pathlen_1: cannot auto-rotate an expired Org CA "
                f"(notAfter={old_not_after.isoformat()}). Use POST "
                f"/pki/rotate-ca for full re-enrollment."
            )

        # Snapshot BEFORE writing anything — if anything fails after the
        # snapshot write, rollback is still possible.
        agents_rows = await _load_internal_agent_certs()
        snapshot = {
            "org_ca_cert_pem": old_cert_pem,
            "org_ca_key_pem": old_key_pem,
            "internal_agents": {
                row["agent_id"]: row["cert_pem"] for row in agents_rows
                if row["cert_pem"]
            },
        }
        await insert_migration_backup(
            migration_id=self.migration_id,
            created_at=now.isoformat(),
            snapshot_json=json.dumps(snapshot),
        )

        # Generate the new CA inline (not via the shared helper — we
        # need a custom notAfter that mirrors the old CA's end-of-life,
        # which the shared helper doesn't expose).
        new_ca_key, new_ca_cert = _build_new_org_ca(
            old_cert=old_cert,
            now=now,
        )

        # Re-sign every leaf preserving pubkey / subject / extensions /
        # validity. Serial is regenerated (stale-serial caches in
        # verifier implementations would otherwise conflict).
        new_leaves: dict[str, str] = {}
        for row in agents_rows:
            if not row["cert_pem"]:
                continue
            old_leaf = x509.load_pem_x509_certificate(
                row["cert_pem"].encode(),
            )
            new_leaf = _resign_leaf(
                old_leaf=old_leaf,
                new_ca_cert=new_ca_cert,
                new_ca_key=new_ca_key,
            )
            new_leaves[row["agent_id"]] = (
                new_leaf.public_bytes(serialization.Encoding.PEM).decode()
            )

        new_ca_cert_pem = new_ca_cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode()
        new_ca_key_pem = new_ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        # Commit. Two-phase wrt Vault is out of scope — a crash between
        # writing proxy_config and writing internal_agents means the
        # operator sees a mismatch at next boot and replays up(); the
        # snapshot backup row from this run lets rollback() unwind if
        # needed.
        await set_config("org_ca_cert", new_ca_cert_pem)
        await set_config("org_ca_key", new_ca_key_pem)
        for agent_id, new_cert_pem in new_leaves.items():
            await _update_internal_agent_cert(agent_id, new_cert_pem)

        logger.info(
            "org_ca_pathlen_1: rotated Org CA (new_serial=%s), re-signed "
            "%d agent leaves; backup row stored.",
            new_ca_cert.serial_number, len(new_leaves),
        )

    # ── Rollback ──────────────────────────────────────────────────────

    async def rollback(self) -> None:
        """Restore the pre-rotation CA + agent leaves from the backup.

        Raises ``RuntimeError`` when no backup exists — the operator
        needs to know that rollback is impossible without prior
        :meth:`up`.
        """
        backup = await get_migration_backup(self.migration_id)
        if backup is None:
            raise RuntimeError(
                f"org_ca_pathlen_1: no backup exists for "
                f"{self.migration_id!r} — cannot rollback. A rotation "
                f"must have run successfully before rollback is usable."
            )

        snapshot = json.loads(backup["snapshot_json"])

        await set_config("org_ca_cert", snapshot["org_ca_cert_pem"])
        await set_config("org_ca_key", snapshot["org_ca_key_pem"])
        for agent_id, old_cert_pem in snapshot["internal_agents"].items():
            await _update_internal_agent_cert(agent_id, old_cert_pem)

        # Clear the backup row so a second rollback fails loudly (the
        # state has already been restored, a second restore would be a
        # no-op over data that may have moved on in the meantime).
        await delete_migration_backup(self.migration_id)

        logger.info(
            "org_ca_pathlen_1: rolled back Org CA + %d agent leaves from "
            "backup taken at %s.",
            len(snapshot["internal_agents"]), backup["created_at"],
        )


# ── Module-level helpers ──────────────────────────────────────────────


def _generate_serial() -> int:
    """Positive 128-bit integer per RFC 5280 §4.1.2.2 guidance."""
    return int.from_bytes(os.urandom(16), "big")


def _build_new_org_ca(
    *,
    old_cert: x509.Certificate,
    now: datetime,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Build the replacement Org CA with pathLen=1, inheriting end-of-life.

    Matches the conventions of ``generate_org_ca`` in
    ``mcp_proxy/dashboard/router.py`` (RSA-4096, SHA-256,
    subject=issuer=old subject, same KeyUsage) except for:
      - ``notAfter`` inherited from the old CA (preserve renewal cadence).
      - explicit pathLen=1.
      - new keypair.
    """
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = old_cert.subject
    try:
        old_not_after = old_cert.not_valid_after_utc
    except AttributeError:
        old_not_after = old_cert.not_valid_after.replace(tzinfo=timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed root
        .public_key(new_key.public_key())
        .serial_number(_generate_serial())
        .not_valid_before(now - timedelta(minutes=_CA_NEW_SKEW_MINUTES))
        .not_valid_after(old_not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(new_key.public_key()),
            critical=False,
        )
    )
    new_cert = builder.sign(new_key, hashes.SHA256())
    return new_key, new_cert


def _resign_leaf(
    *,
    old_leaf: x509.Certificate,
    new_ca_cert: x509.Certificate,
    new_ca_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    """Re-issue a leaf preserving every operator-visible field.

    Changed: issuer (= new CA subject), AuthorityKeyIdentifier (points
    to new CA), serial (new 128-bit), signature. Preserved: subject,
    pubkey, notBefore / notAfter, all other extensions including SAN,
    KeyUsage, EKU, SubjectKeyIdentifier, anything custom.
    """
    try:
        old_not_before = old_leaf.not_valid_before_utc
        old_not_after = old_leaf.not_valid_after_utc
    except AttributeError:
        old_not_before = old_leaf.not_valid_before.replace(tzinfo=timezone.utc)
        old_not_after = old_leaf.not_valid_after.replace(tzinfo=timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(old_leaf.subject)
        .issuer_name(new_ca_cert.subject)
        .public_key(old_leaf.public_key())
        .serial_number(_generate_serial())
        .not_valid_before(old_not_before)
        .not_valid_after(old_not_after)
    )

    for ext in old_leaf.extensions:
        if isinstance(ext.value, x509.AuthorityKeyIdentifier):
            # Will be re-added below pointing at the new CA.
            continue
        builder = builder.add_extension(ext.value, critical=ext.critical)

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            new_ca_cert.public_key(),
        ),
        critical=False,
    )

    return builder.sign(new_ca_key, hashes.SHA256())


async def _load_internal_agent_certs() -> list[dict]:
    """Return every active agent's (agent_id, cert_pem) tuple."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT agent_id, cert_pem FROM internal_agents "
                "WHERE is_active = 1 AND cert_pem IS NOT NULL "
                "ORDER BY agent_id ASC"
            )
        )
        return [dict(row) for row in result.mappings().all()]


async def _update_internal_agent_cert(
    agent_id: str, cert_pem: str,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                "UPDATE internal_agents SET cert_pem = :cert "
                "WHERE agent_id = :aid"
            ),
            {"cert": cert_pem, "aid": agent_id},
        )
