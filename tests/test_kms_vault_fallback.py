"""
Tests for VaultKMSProvider filesystem fallback on Vault 404.

The deadlock these tests guard against:
  - broker /readyz calls KMS.get_broker_public_key_pem()
  - KMS_BACKEND=vault, Vault not yet seeded → 404
  - Without fallback, /readyz stays 503 → helm install --wait blocks
    → post-install Job never runs → Vault never seeded → deadlock
  - With fallback, broker reads from filesystem Secret mount, becomes
    Ready, post-install Job runs, Vault gets seeded for next boot

Only 404 triggers fallback. Real Vault outages (500, timeout) must
propagate so operators are not misled.
"""
import os
from pathlib import Path

import httpx
import pytest

os.environ.setdefault("VAULT_ALLOW_HTTP", "true")

from app.kms.vault import VaultKMSProvider, VaultSecretNotFound


# A self-signed throwaway CA and key, test-only. Regenerable with:
#   openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k.pem \
#     -out /tmp/c.pem -days 1 -subj "/CN=test"
_TEST_KEY_PEM = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDd3pQw3Eh/XtAG
test-only-not-a-real-key-padding-padding-padding-padding-padding==
-----END PRIVATE KEY-----
"""


def _gen_test_cert(tmp_path: Path) -> tuple[str, str]:
    """Generate a tiny RSA CA cert + key for use as fallback."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(key_path), str(cert_path)


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    def json(self) -> dict:
        return {"data": {"data": {}}}


class _FakeClient:
    """Stub httpx.AsyncClient that returns a preconfigured response."""
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url, headers=None):
        return self._response


@pytest.fixture
def fallback_paths(tmp_path):
    return _gen_test_cert(tmp_path)


@pytest.mark.asyncio
async def test_vault_404_falls_back_to_filesystem_private_key(
    monkeypatch, fallback_paths
):
    """First boot: Vault path not seeded, filesystem Secret present."""
    key_path, cert_path = fallback_paths
    provider = VaultKMSProvider(
        vault_addr="http://fake-vault:8200",
        vault_token="t",
        secret_path="secret/data/broker",
        fallback_key_path=key_path,
        fallback_cert_path=cert_path,
    )
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: _FakeClient(_FakeResponse(404, "not found"))
    )

    pem = await provider.get_broker_private_key_pem()
    assert "PRIVATE KEY" in pem
    assert pem == Path(key_path).read_text()


@pytest.mark.asyncio
async def test_vault_404_falls_back_to_filesystem_public_key(
    monkeypatch, fallback_paths
):
    key_path, cert_path = fallback_paths
    provider = VaultKMSProvider(
        vault_addr="http://fake-vault:8200",
        vault_token="t",
        secret_path="secret/data/broker",
        fallback_key_path=key_path,
        fallback_cert_path=cert_path,
    )
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: _FakeClient(_FakeResponse(404))
    )

    pem = await provider.get_broker_public_key_pem()
    assert "PUBLIC KEY" in pem


@pytest.mark.asyncio
async def test_vault_500_does_not_fall_back(monkeypatch, fallback_paths):
    """Vault outage (500) must propagate — not be masked by fallback."""
    key_path, cert_path = fallback_paths
    provider = VaultKMSProvider(
        vault_addr="http://fake-vault:8200",
        vault_token="t",
        secret_path="secret/data/broker",
        fallback_key_path=key_path,
        fallback_cert_path=cert_path,
    )
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: _FakeClient(_FakeResponse(500, "internal error"))
    )

    with pytest.raises(RuntimeError, match="Vault returned HTTP 500"):
        await provider.get_broker_private_key_pem()


@pytest.mark.asyncio
async def test_vault_404_without_fallback_raises(monkeypatch):
    """404 and no fallback paths → must raise so caller sees the gap."""
    provider = VaultKMSProvider(
        vault_addr="http://fake-vault:8200",
        vault_token="t",
        secret_path="secret/data/broker",
    )
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: _FakeClient(_FakeResponse(404))
    )

    with pytest.raises(RuntimeError, match="not found and no filesystem fallback"):
        await provider.get_broker_private_key_pem()


@pytest.mark.asyncio
async def test_fetch_secret_raises_vault_secret_not_found_on_404(monkeypatch):
    """The typed exception is what distinguishes 404 from other errors."""
    provider = VaultKMSProvider(
        vault_addr="http://fake-vault:8200",
        vault_token="t",
        secret_path="secret/data/broker",
    )
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: _FakeClient(_FakeResponse(404))
    )

    with pytest.raises(VaultSecretNotFound):
        await provider._fetch_secret()
