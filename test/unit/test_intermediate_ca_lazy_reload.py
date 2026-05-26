"""D-13 cold-reader dogfood (2026-05-26) tests — lazy Intermediate CA
reload guarantee.

Pre-fix ``mcp_proxy/main.py:332-336`` wraps ``ensure_mastio_identity()``
in a try/except Exception that swallows any transient bootstrap failure
silently (DB lock race, KMS provider initial probe timeout, etc).
Under ``MASTIO_WORKERS=4`` (Mastio bundle default) every uvicorn worker
runs the lifespan independently; if one worker loses the race or hits a
transient error its ``_mastio_ca_key`` stays ``None`` while the other
three workers complete bootstrap and persist the Intermediate pair to
the source-of-truth (KMS or legacy ``proxy_config.mastio_ca_{key,cert}``
rows). The dashboard load-balances admin requests across all workers,
so roughly one in four ``POST /v1/admin/agents`` clicks hits the broken
worker and 500s with::

    Mastio Intermediate CA not loaded, cannot sign agent cert.
    Call ensure_mastio_identity() first.

The fix mirrors the D-9 ``_mint_mastio_ca`` winner-adopt pattern but at
runtime instead of boot: when a signer hits ``_mastio_ca_key=None``,
lazily re-read the persisted pair via
``_reload_intermediate_ca_from_persistence`` before raising. The pair
IS on disk — some other worker won the persist race in
``_persist_intermediate_ca`` — so just re-read it.

Sister race-bootstrap tests live in
``test_pki_bootstrap_concurrent.py`` (D-9). Keep the fixture shape
aligned so both files exercise the same KMS+proxy_config source-of-truth
primitive.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, init_db, set_config
from mcp_proxy.egress.agent_manager import AgentManager


_ADMIN_SECRET = "test-intermediate-ca-lazy-reload-secret"


# ── Helpers to mint a plausible Intermediate CA pair ──────────────────


def _mint_intermediate_pair(org_id: str) -> tuple[str, str]:
    """Mint a self-signed Intermediate CA pair (EC P-256, valid 30 days).

    Self-signed is fine for the lazy-reload tests — we are only
    exercising the "re-read PEMs from persistence and parse them into
    in-memory state" code path, not the full three-tier chain. The
    PEM bytes are what the helper round-trips through
    ``load_pem_private_key`` / ``load_pem_x509_certificate``.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} Mastio CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """File-backed SQLite + dev-fallback persistence path.

    Matches the ``test_pki_bootstrap_concurrent.py`` fixture: skips
    migrations (the lazy-reload helper only touches ``proxy_config``
    rows the metadata-defined schema already covers), disables the
    audit chain, and forces the local-KMS dev fallback by clearing
    ``MCP_PROXY_DB_ENCRYPTION_KEY``. The encrypted ``pki_key_store``
    path is provider-level and tested separately when the provider
    plugin is exercised.
    """
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.delenv("MCP_PROXY_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "intermediate_ca_lazy_reload.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


# ── Tests ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sign_agent_cert_lazy_reload_succeeds_when_pair_in_db(proxy_db):
    """Manager with ``_mastio_ca_key=None`` and the persisted pair
    populated in ``proxy_config`` succeeds at ``_generate_agent_cert``:
    the lazy reload kicks in, parses the pair, and the cert is signed
    against the persisted Intermediate. This is the exact cold-reader
    repro — one worker's bootstrap silently failed but the
    source-of-truth has the pair another worker minted."""
    org_id = "cold-reader-org"
    key_pem, cert_pem = _mint_intermediate_pair(org_id)

    # Populate the source-of-truth as if another worker had won the
    # mint race and persisted the Intermediate via _persist_intermediate_ca.
    await set_config("mastio_ca_key", key_pem)
    await set_config("mastio_ca_cert", cert_pem)

    # The "broken" worker — bootstrap silently failed, _mastio_ca_key
    # stays None. _generate_agent_cert MUST not raise; it should
    # lazy-reload the persisted pair and sign successfully.
    mgr = AgentManager(org_id)
    assert mgr._mastio_ca_key is None
    assert mgr._mastio_ca_cert is None

    agent_cert_pem, agent_key_pem = await mgr._generate_agent_cert("test-agent")

    # The returned cert must verify under the persisted Intermediate's
    # subject (issuer match). Without the lazy reload this call would
    # have raised RuntimeError with the cold-reader 500 message.
    agent_cert = x509.load_pem_x509_certificate(agent_cert_pem.encode())
    persisted_cert = x509.load_pem_x509_certificate(cert_pem.encode())
    assert agent_cert.issuer.rfc4514_string() == persisted_cert.subject.rfc4514_string()
    # And the agent key PEM is a parseable private key.
    assert serialization.load_pem_private_key(
        agent_key_pem.encode(), password=None,
    ) is not None


@pytest.mark.asyncio
async def test_sign_agent_cert_raises_when_pair_absent_anywhere(proxy_db):
    """When neither the KMS provider nor the legacy ``proxy_config``
    rows hold a persisted pair, the lazy reload must report failure and
    the original RuntimeError must surface with its helpful message.
    Otherwise we'd silently sign with a None CA and crash deeper in the
    crypto stack with a less-actionable trace."""
    mgr = AgentManager("org-with-no-mastio-yet")
    assert mgr._mastio_ca_key is None
    assert mgr._mastio_ca_cert is None

    with pytest.raises(RuntimeError) as exc_info:
        await mgr._generate_agent_cert("test-agent")

    # The helpful operator-facing message must survive the lazy-reload
    # detour — cold-readers depend on it to know which lifecycle hook
    # to call.
    msg = str(exc_info.value)
    assert "Mastio Intermediate CA not loaded" in msg
    assert "ensure_mastio_identity" in msg


@pytest.mark.asyncio
async def test_lazy_reload_populates_in_memory_state(proxy_db):
    """After a successful lazy reload, ``_mastio_ca_key`` and
    ``_mastio_ca_cert`` are populated on the manager. Subsequent signing
    calls hit the in-memory pair directly without paying the reload cost
    again — important so a steady stream of admin Create Agent clicks
    on a previously-broken worker doesn't re-query the DB for every
    signature."""
    org_id = "lazy-reload-state-org"
    key_pem, cert_pem = _mint_intermediate_pair(org_id)

    await set_config("mastio_ca_key", key_pem)
    await set_config("mastio_ca_cert", cert_pem)

    mgr = AgentManager(org_id)
    assert mgr._mastio_ca_key is None
    assert mgr._mastio_ca_cert is None

    reloaded = await mgr._reload_intermediate_ca_from_persistence()
    assert reloaded is True

    # In-memory state now holds the persisted pair (parsed).
    assert mgr._mastio_ca_key is not None
    assert mgr._mastio_ca_cert is not None

    # The reloaded cert must be byte-identical to what was persisted —
    # no split-brain where the lazy reload parses a different cert from
    # the one another signer would see.
    persisted_cert = x509.load_pem_x509_certificate(cert_pem.encode())
    assert (
        mgr._mastio_ca_cert.fingerprint(hashes.SHA256())
        == persisted_cert.fingerprint(hashes.SHA256())
    )

    # And the reloaded private key matches the cert's pubkey (no
    # cross-wiring from a stale prior run).
    reloaded_pub_der = mgr._mastio_ca_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_pub_der = mgr._mastio_ca_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert reloaded_pub_der == cert_pub_der


@pytest.mark.asyncio
async def test_lazy_reload_returns_false_when_only_one_row_persisted(proxy_db):
    """Partial persistence (one of the two ``proxy_config`` rows
    present, the other missing) must be treated as "no pair available"
    — the helper returns False instead of crashing on an unbound
    variable or persisting a half-populated state into memory. This
    pins the defensive behaviour for the corrupted-DB / interrupted-
    write edge case."""
    # Only the key row, no cert row.
    key_pem, _cert_pem = _mint_intermediate_pair("partial-org")
    await set_config("mastio_ca_key", key_pem)

    mgr = AgentManager("partial-org")
    reloaded = await mgr._reload_intermediate_ca_from_persistence()
    assert reloaded is False
    # Memory state stays clean — no partial assignment.
    assert mgr._mastio_ca_key is None
    assert mgr._mastio_ca_cert is None
