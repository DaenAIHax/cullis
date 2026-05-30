"""Tests for ``cullis_sdk.providers_compat.cullis_httpx_client`` (ADR-038 Phase 0).

Covered:

1. ``_resolve_identity_files`` raises clearly when the directory is missing.
2. ``_resolve_identity_files`` raises clearly when ``agent.crt`` / ``agent.key``
   are missing (the credential, ADR-014). ``dpop.jwk`` is NOT mandatory:
   it is client-generated (RFC 9449) and the admin-minted bundle never
   ships it, so ``cullis_httpx_client`` generates + persists it on first
   use instead of raising — the same contract as ``from_identity_dir``.
3. ``cullis_httpx_client`` returns a usable ``httpx.Client`` with a
   ``_DpopTransport`` wrapping the inner transport.
4. ``_DpopTransport`` attaches a DPoP header to outbound requests.
5. ``_DpopTransport`` caches ``DPoP-Nonce`` from the response.
6. ``_DpopTransport`` retries once on ``401 use_dpop_nonce`` with the
   fresh nonce embedded in the proof.

Identity directory layout matches ``CullisClient.from_identity_dir``
(D-11 auto-discovery): ``agent.crt`` + ``agent.key`` + ``ca-chain.pem``
(optional) + ``dpop.jwk``.

No real Mastio. ``httpx.MockTransport`` plays the server side and the
DPoP key is generated ephemerally per test.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cullis_sdk.providers_compat import (
    _DpopTransport,
    _resolve_identity_files,
    cullis_httpx_client,
)
from cullis_sdk.dpop import DpopKey


def _write_identity_dir(tmp_path: Path, *, with_ca: bool = True) -> Path:
    """Materialise an identity_dir with the four-file layout."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "agent.crt").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM),
    )
    (tmp_path / "agent.key").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    DpopKey.generate(path=tmp_path / "dpop.jwk")
    if with_ca:
        # A degenerate CA bundle is fine for the file-existence check —
        # the unit tests never actually open a TLS connection.
        (tmp_path / "ca-chain.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM),
        )
    return tmp_path


def test_resolve_identity_files_missing_dir(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(FileNotFoundError) as exc:
        _resolve_identity_files(missing)
    assert str(missing) in str(exc.value)
    assert "not a directory" in str(exc.value)


def test_resolve_identity_files_missing_cert_raises(tmp_path: Path) -> None:
    # agent.crt / agent.key ARE mandatory (the credential, ADR-014) —
    # missing them must still fail loud with an operator-facing hint that
    # names the file and documents the required layout. A bare KeyError /
    # OSError without that hint sends the customer grepping the source.
    _write_identity_dir(tmp_path)
    (tmp_path / "agent.crt").unlink()

    with pytest.raises(FileNotFoundError) as exc:
        _resolve_identity_files(tmp_path)
    assert "agent.crt" in str(exc.value)
    assert "required layout" in str(exc.value)


def test_cullis_httpx_client_generates_dpop_on_first_use(tmp_path: Path) -> None:
    # dpop.jwk is client-generated (RFC 9449); the admin-minted bundle
    # never ships it. The helper must generate + persist it on first use,
    # not raise — otherwise the documented "download zip → drop-in" flow
    # FileNotFound's (regression caught by the 2026-05-30 cold-reader).
    _write_identity_dir(tmp_path)
    (tmp_path / "dpop.jwk").unlink()
    assert not (tmp_path / "dpop.jwk").exists()

    client = cullis_httpx_client(identity_dir=tmp_path)
    try:
        assert (tmp_path / "dpop.jwk").exists()  # generated on first use
    finally:
        client.close()


def test_resolve_identity_files_optional_ca_chain(tmp_path: Path) -> None:
    """Missing ca-chain.pem is OK — operator may rely on system trust
    store when the Mastio uses a publicly trusted cert."""
    _write_identity_dir(tmp_path, with_ca=False)

    cert, key, ca, dpop = _resolve_identity_files(tmp_path)
    assert cert.name == "agent.crt"
    assert key.name == "agent.key"
    assert ca is None
    assert dpop.name == "dpop.jwk"


def test_cullis_httpx_client_constructs(tmp_path: Path) -> None:
    _write_identity_dir(tmp_path)

    client = cullis_httpx_client(identity_dir=tmp_path)
    try:
        assert isinstance(client, httpx.Client)
        # The custom transport is the DPoP wrapper.
        assert isinstance(client._transport, _DpopTransport)
    finally:
        client.close()


def test_dpop_transport_attaches_header(tmp_path: Path) -> None:
    """Every outbound request grows a DPoP header signed by our key."""
    _write_identity_dir(tmp_path)
    dpop_key = DpopKey.load(tmp_path / "dpop.jwk")

    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, text="ok")

    inner = httpx.MockTransport(handler)
    transport = _DpopTransport(inner, dpop_key)

    with httpx.Client(transport=transport) as client:
        resp = client.post(
            "https://mastio.test:9443/v1/messages",
            json={"hello": "world"},
        )

    assert resp.status_code == 200
    assert "DPoP" in captured["request"].headers
    # Sanity: the header is a JWT (three b64 segments separated by `.`).
    proof = captured["request"].headers["DPoP"]
    assert proof.count(".") == 2 and len(proof) > 100


def test_dpop_transport_caches_nonce_from_response(tmp_path: Path) -> None:
    """Server-supplied ``DPoP-Nonce`` is cached for the next request."""
    _write_identity_dir(tmp_path)
    dpop_key = DpopKey.load(tmp_path / "dpop.jwk")

    issued_nonce = "server-nonce-abc-123"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"DPoP-Nonce": issued_nonce},
            text="ok",
        )

    inner = httpx.MockTransport(handler)
    transport = _DpopTransport(inner, dpop_key)

    with httpx.Client(transport=transport) as client:
        client.get("https://mastio.test:9443/health")

    assert transport._nonce == issued_nonce


def test_dpop_transport_retries_on_use_dpop_nonce(tmp_path: Path) -> None:
    """On a 401 ``use_dpop_nonce`` challenge the transport replays the
    request once with a fresh proof carrying the supplied nonce. The
    caller never sees the 401."""
    _write_identity_dir(tmp_path)
    dpop_key = DpopKey.load(tmp_path / "dpop.jwk")

    # Capture the DPoP header VALUE at the moment of each call. The
    # ``request`` object is mutated in-place between the first and
    # second handle_request, so storing the Request itself would yield
    # two references to the same object with the final header value.
    dpop_values: list[str | None] = []
    call_count = 0
    issued_nonce = "nonce-from-challenge"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        dpop_values.append(request.headers.get("DPoP"))
        if call_count == 1:
            # First call: challenge.
            return httpx.Response(
                401,
                headers={"DPoP-Nonce": issued_nonce},
                json={"error": "use_dpop_nonce"},
            )
        # Second call: accept.
        return httpx.Response(200, text="ok-after-retry")

    inner = httpx.MockTransport(handler)
    transport = _DpopTransport(inner, dpop_key)

    with httpx.Client(transport=transport) as client:
        resp = client.post(
            "https://mastio.test:9443/v1/messages",
            json={"hello": "world"},
        )

    assert resp.status_code == 200
    assert resp.text == "ok-after-retry"
    assert call_count == 2
    # Both requests had a DPoP header, but the second one carries the
    # nonce baked into the proof; the JWT bytes therefore differ.
    assert dpop_values[0] is not None and dpop_values[1] is not None
    assert dpop_values[0] != dpop_values[1]


def test_dpop_transport_does_not_retry_when_nonce_absent(tmp_path: Path) -> None:
    """A 401 without ``DPoP-Nonce`` is a real auth failure — surface it
    untouched. Replaying with the same proof would just produce another
    401 and burn an extra round-trip for no gain."""
    _write_identity_dir(tmp_path)
    dpop_key = DpopKey.load(tmp_path / "dpop.jwk")

    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(401, json={"error": "invalid_token"})

    inner = httpx.MockTransport(handler)
    transport = _DpopTransport(inner, dpop_key)

    with httpx.Client(transport=transport) as client:
        resp = client.post("https://mastio.test:9443/v1/messages")

    assert resp.status_code == 401
    assert len(calls) == 1
