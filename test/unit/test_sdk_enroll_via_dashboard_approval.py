"""Tests for ``CullisClient.enroll_via_dashboard_approval`` — the cold-reader
enrollment factory (B-2 dogfood fix, 2026-05-25).

The factory wraps the Connector-protocol enrollment surface so a
community open-source agent developer can bootstrap an identity without
hand-rolling the start → admin approve → poll-with-proof-header dance.
Three invariants the tests pin:

1. The start request payload matches the server contract: server-shape
   fingerprint (SHA-256 of DER SubjectPublicKeyInfo), domain-separated
   pop_signature, EC P-256 DPoP JWK.
2. The poll path carries the ``X-Enrollment-Proof`` header signed with
   the original enrollment key over ``"enrollment-status:v1|<sid>"``.
3. The identity-dir layout written under ``save_to/`` is exactly what
   ``from_identity_dir`` expects (agent.key + agent.crt + ca-chain.pem +
   dpop.key + meta.json), with 0600 perms on the two private-key files.

The Mastio side is faked via a small ``RequestRecorder`` that subs in
for ``httpx.Client`` — no real network, no real CA, no real admin.
``CullisClient.from_identity_dir`` is also stubbed so we don't have to
parse a real cert SAN; the test only cares about the on-disk layout and
the kwargs forwarded to the runtime constructor.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# ── Helpers ──────────────────────────────────────────────────────────


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _mint_fake_leaf_cert() -> str:
    """Build a syntactically valid PEM certificate the factory persists.

    The factory just writes ``cert_pem`` to ``agent.crt`` verbatim; no
    parsing happens inside the factory itself (``from_identity_dir`` is
    stubbed). A blob recognisable as ``-----BEGIN CERTIFICATE-----`` is
    enough for the layout assertions below.
    """
    return (
        "-----BEGIN CERTIFICATE-----\n"
        "FAKE-LEAF-FOR-DASHBOARD-APPROVAL-TEST\n"
        "-----END CERTIFICATE-----\n"
    )


def _mint_fake_chain_cert() -> str:
    """Concatenated leaf || Intermediate, as PR #929's admin path emits."""
    return _mint_fake_leaf_cert() + (
        "-----BEGIN CERTIFICATE-----\n"
        "FAKE-INTERMEDIATE-MASTIO-CA\n"
        "-----END CERTIFICATE-----\n"
    )


class _FakeResponse:
    def __init__(self, status_code: int, json_body: dict | None = None,
                 text: str = "") -> None:
        self.status_code = status_code
        self._json = json_body or {}
        self.text = text or json.dumps(self._json)

    def json(self) -> dict:
        return self._json


class _FakeMastio:
    """Tiny in-memory simulation of the Mastio enrollment endpoints.

    Records every request so the test can assert on shape; advances a
    simple state machine so polling sees ``pending`` first, then
    ``approved`` once the test flips the flag.
    """

    def __init__(self) -> None:
        self.session_id = "test-session-deadbeef"
        self.posts: list[tuple[str, dict, dict]] = []
        self.gets: list[tuple[str, dict]] = []
        self.approved: bool = False
        self.cert_pem = _mint_fake_leaf_cert()
        self.cert_chain_pem = _mint_fake_chain_cert()
        self.agent_id = "acme::test-agent"
        self.last_pubkey_pem: str | None = None

    def post(self, url: str, *, json: dict, **_) -> _FakeResponse:  # noqa: A002 — match httpx kwarg name
        self.posts.append((url, json, _))
        if url.endswith("/v1/enrollment/start"):
            self.last_pubkey_pem = json["pubkey_pem"]
            return _FakeResponse(
                201,
                {
                    "session_id": self.session_id,
                    "status": "pending",
                    "poll_url": f"https://fake-mastio/v1/enrollment/{self.session_id}/status",
                    "enroll_url": f"https://fake-mastio/enroll?session={self.session_id}",
                    "poll_interval_s": 1,
                    "expires_at": "2099-01-01T00:00:00+00:00",
                },
            )
        return _FakeResponse(404, {"detail": "unknown post"})

    def get(self, url: str, *, headers: dict | None = None, **_) -> _FakeResponse:
        self.gets.append((url, headers or {}))
        if "/status" in url:
            if not self.approved:
                return _FakeResponse(
                    200, {"session_id": self.session_id, "status": "pending"},
                )
            # Approved branch — only emit sensitive fields when the
            # proof header is present (mirror the server contract so
            # the factory's missing-proof handling fires if it
            # accidentally drops the header).
            if not (headers or {}).get("X-Enrollment-Proof"):
                return _FakeResponse(
                    200,
                    {
                        "session_id": self.session_id,
                        "status": "approved",
                        "detail": (
                            "Proof header X-Enrollment-Proof required. ..."
                        ),
                    },
                )
            return _FakeResponse(
                200,
                {
                    "session_id": self.session_id,
                    "status": "approved",
                    "agent_id": self.agent_id,
                    "cert_pem": self.cert_pem,
                    "cert_chain_pem": self.cert_chain_pem,
                    "capabilities": ["llm.chat"],
                },
            )
        return _FakeResponse(404, {"detail": "unknown get"})

    def close(self) -> None:  # match httpx.Client API
        pass


@pytest.fixture
def fake_mastio() -> _FakeMastio:
    return _FakeMastio()


@pytest.fixture
def patched_http_and_runtime(monkeypatch, fake_mastio):
    """Patch the SDK's network + runtime-constructor seams.

    Returns the captured kwargs forwarded to ``from_identity_dir`` for
    layout assertions in the happy-path test.
    """
    # 1) Network: every ``_build_proxy_http_client`` call returns the
    #    same fake. Closing it is a no-op so the factory's
    #    ``finally http.close()`` is safe.
    def _fake_builder(**kwargs):  # noqa: ARG001 — signature-compatible
        return fake_mastio

    monkeypatch.setattr(
        "cullis_sdk.client._build_proxy_http_client", _fake_builder,
    )

    # 2) Runtime constructor: capture the kwargs so the test asserts on
    #    the identity-dir layout, and return an opaque sentinel as the
    #    "client".
    calls: list[dict] = []

    def _fake_from_identity_dir(cls, mastio_url, **kwargs):  # noqa: ARG001
        calls.append({"mastio_url": mastio_url, **kwargs})
        return object()

    from cullis_sdk._client._enrollment import _EnrollmentMixin
    monkeypatch.setattr(
        _EnrollmentMixin, "from_identity_dir",
        classmethod(_fake_from_identity_dir),
    )

    # 3) Hide the insecure-tls audit prompt for verify_tls=True.
    monkeypatch.setattr(
        "cullis_sdk.client._check_insecure_tls", lambda _x: None,
    )

    return calls


# ── Happy path ───────────────────────────────────────────────────────


def test_happy_path_writes_identity_dir(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """Approved before first poll → cert + key + chain written, factory
    hands off to ``from_identity_dir``."""
    from cullis_sdk import CullisClient

    fake_mastio.approved = True  # admin already clicked Approve

    save_to = tmp_path / "agent-id"
    pending_calls: list[tuple[str, str]] = []

    client = CullisClient.enroll_via_dashboard_approval(
        "https://fake-mastio:9443",
        requester_name="Alice",
        requester_email="alice@example.com",
        reason="dogfood",
        device_info="pytest",
        save_to=save_to,
        poll_interval_s=0.0,
        timeout_s=5.0,
        on_pending=lambda sid, url: pending_calls.append((sid, url)),
    )

    # The factory returned the sentinel from the patched from_identity_dir.
    assert client is not None
    # on_pending fired exactly once with (session_id, dashboard_url).
    assert pending_calls == [
        (fake_mastio.session_id, "https://fake-mastio:9443/proxy/enrollments"),
    ]

    # Identity-dir layout — exactly what from_identity_dir reads.
    for name in ("agent.key", "agent.crt", "ca-chain.pem", "dpop.key", "meta.json"):
        assert (save_to / name).is_file(), f"missing {name}"

    # Private-key files are 0600 (umask-resistant via os.chmod).
    assert (save_to / "agent.key").stat().st_mode & 0o777 == 0o600
    assert (save_to / "dpop.key").stat().st_mode & 0o777 == 0o600

    # meta.json carries the fields the SDK expects.
    meta = json.loads((save_to / "meta.json").read_text())
    assert meta["agent_id"] == fake_mastio.agent_id
    assert meta["capabilities"] == ["llm.chat"]
    assert meta["mastio_url"] == "https://fake-mastio:9443"
    assert "enrolled_at" in meta

    # cert.crt is the leaf-only cert; ca-chain.pem is the full chain.
    assert (save_to / "agent.crt").read_text() == fake_mastio.cert_pem
    assert (save_to / "ca-chain.pem").read_text() == fake_mastio.cert_chain_pem

    # from_identity_dir was called with the persisted paths.
    call = patched_http_and_runtime[0]
    assert call["cert_path"] == save_to / "agent.crt"
    assert call["key_path"] == save_to / "agent.key"
    assert call["mastio_url"] == "https://fake-mastio:9443"


# ── Server contract: start payload shape ─────────────────────────────


def test_start_payload_matches_server_contract(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """The pop_signature must verify against the server's fingerprint
    formula (SHA-256 over DER SubjectPublicKeyInfo) AND the canonical
    domain-separated message. This is the #1 trap cold-readers hit.
    """
    from cullis_sdk import CullisClient

    fake_mastio.approved = True
    CullisClient.enroll_via_dashboard_approval(
        "https://fake-mastio:9443",
        requester_name="Alice",
        requester_email="alice@example.com",
        save_to=tmp_path / "agent-id",
        poll_interval_s=0.0,
        timeout_s=5.0,
    )

    assert len(fake_mastio.posts) == 1
    _, body, _ = fake_mastio.posts[0]
    assert body["requester_name"] == "Alice"
    assert body["requester_email"] == "alice@example.com"
    assert body["principal_type"] == "agent"
    assert body["dpop_jwk"]["kty"] == "EC"
    assert body["dpop_jwk"]["crv"] == "P-256"
    assert "x" in body["dpop_jwk"]
    assert "y" in body["dpop_jwk"]
    # PEM is a single SubjectPublicKeyInfo (EC P-256).
    pub_key = serialization.load_pem_public_key(body["pubkey_pem"].encode())
    assert isinstance(pub_key, ec.EllipticCurvePublicKey)

    # Recompute fingerprint exactly as the server does.
    der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(der).hexdigest()
    canonical = f"enrollment-pop:v1|{fingerprint}".encode()

    # Verify pop_signature using the same code path the server uses.
    sig = _b64url_decode(body["pop_signature"])
    # No exception → valid signature.
    pub_key.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))


def test_poll_carries_proof_header_signed_over_session_id(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """Every status GET MUST send ``X-Enrollment-Proof`` signed over
    ``"enrollment-status:v1|<session_id>"`` with the original enrollment
    key. Without it the server stonewalls the cert exfiltration."""
    from cullis_sdk import CullisClient

    fake_mastio.approved = True
    CullisClient.enroll_via_dashboard_approval(
        "https://fake-mastio:9443",
        requester_name="Alice",
        requester_email="alice@example.com",
        save_to=tmp_path / "agent-id",
        poll_interval_s=0.0,
        timeout_s=5.0,
    )

    assert fake_mastio.gets, "expected at least one /status poll"
    url, headers = fake_mastio.gets[0]
    assert "X-Enrollment-Proof" in headers
    proof = headers["X-Enrollment-Proof"]

    # Reconstruct the public key the start POST carried and verify the
    # proof signature: same algorithm the server uses on the receive
    # side (_verify_enrollment_proof).
    pub_key = serialization.load_pem_public_key(
        fake_mastio.last_pubkey_pem.encode(),
    )
    canonical = (
        f"enrollment-status:v1|{fake_mastio.session_id}".encode()
    )
    sig = _b64url_decode(proof)
    pub_key.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))


# ── Pending → approved transition ────────────────────────────────────


def test_polls_until_approved(
    tmp_path, fake_mastio, patched_http_and_runtime, monkeypatch,
):
    """Two pending polls, then approved. Factory keeps polling without
    raising and writes the identity-dir on success."""
    from cullis_sdk import CullisClient

    poll_count = {"n": 0}
    original_get = fake_mastio.get

    def _staged_get(url, *, headers=None, **_):
        poll_count["n"] += 1
        if poll_count["n"] >= 3:
            fake_mastio.approved = True
        return original_get(url, headers=headers, **_)

    fake_mastio.get = _staged_get  # type: ignore[assignment]

    CullisClient.enroll_via_dashboard_approval(
        "https://fake-mastio:9443",
        requester_name="Alice",
        requester_email="alice@example.com",
        save_to=tmp_path / "agent-id",
        poll_interval_s=0.0,
        timeout_s=5.0,
    )

    assert poll_count["n"] >= 3
    assert (tmp_path / "agent-id" / "agent.crt").is_file()


# ── Rejected / expired / timeout / connection ───────────────────────


def test_rejected_raises_permission_error(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """Admin clicks Reject → PermissionError carrying the reason."""
    from cullis_sdk import CullisClient

    def _reject_get(url, *, headers=None, **_):  # noqa: ARG001
        return _FakeResponse(
            200,
            {
                "session_id": fake_mastio.session_id,
                "status": "rejected",
                "rejection_reason": "not on the approved list",
            },
        )

    fake_mastio.get = _reject_get  # type: ignore[assignment]

    with pytest.raises(PermissionError, match="not on the approved list"):
        CullisClient.enroll_via_dashboard_approval(
            "https://fake-mastio:9443",
            requester_name="Alice",
            requester_email="alice@example.com",
            save_to=tmp_path / "agent-id",
            poll_interval_s=0.0,
            timeout_s=5.0,
        )


def test_expired_raises_timeout_error(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """Server returns expired → TimeoutError so the caller can retry."""
    from cullis_sdk import CullisClient

    def _expired_get(url, *, headers=None, **_):  # noqa: ARG001
        return _FakeResponse(
            200,
            {
                "session_id": fake_mastio.session_id,
                "status": "expired",
            },
        )

    fake_mastio.get = _expired_get  # type: ignore[assignment]

    with pytest.raises(TimeoutError, match="expired"):
        CullisClient.enroll_via_dashboard_approval(
            "https://fake-mastio:9443",
            requester_name="Alice",
            requester_email="alice@example.com",
            save_to=tmp_path / "agent-id",
            poll_interval_s=0.0,
            timeout_s=5.0,
        )


def test_client_side_timeout_raises_after_deadline(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """No state change at all → TimeoutError once timeout_s elapses."""
    from cullis_sdk import CullisClient

    # fake_mastio.approved stays False → always pending.
    with pytest.raises(TimeoutError, match="not approved within"):
        CullisClient.enroll_via_dashboard_approval(
            "https://fake-mastio:9443",
            requester_name="Alice",
            requester_email="alice@example.com",
            save_to=tmp_path / "agent-id",
            poll_interval_s=0.0,
            timeout_s=0.1,
        )


def test_start_failure_raises_permission_error(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """Server rejects the start request (e.g. rate-limited / bad pop)
    → PermissionError surfaces the body so the dev can debug."""
    from cullis_sdk import CullisClient

    def _bad_post(url, *, json, **_):  # noqa: ARG001, A002
        return _FakeResponse(400, text="pop_signature does not verify")

    fake_mastio.post = _bad_post  # type: ignore[assignment]

    with pytest.raises(PermissionError, match="HTTP 400"):
        CullisClient.enroll_via_dashboard_approval(
            "https://fake-mastio:9443",
            requester_name="Alice",
            requester_email="alice@example.com",
            save_to=tmp_path / "agent-id",
            poll_interval_s=0.0,
            timeout_s=5.0,
        )


# ── on_pending callback errors are swallowed ─────────────────────────


def test_on_pending_callback_exception_does_not_abort(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """A crashing on_pending must not abort enrollment. The factory
    logs and continues so a malformed CLI prompt cannot orphan a
    pending session."""
    from cullis_sdk import CullisClient

    def _boom(sid: str, url: str) -> None:
        raise RuntimeError("operator UI exploded")

    fake_mastio.approved = True
    CullisClient.enroll_via_dashboard_approval(
        "https://fake-mastio:9443",
        requester_name="Alice",
        requester_email="alice@example.com",
        save_to=tmp_path / "agent-id",
        poll_interval_s=0.0,
        timeout_s=5.0,
        on_pending=_boom,
    )

    assert (tmp_path / "agent-id" / "agent.crt").is_file()


# ── cert_chain_pem fallback ───────────────────────────────────────────


def test_missing_cert_chain_pem_skips_ca_chain_file(
    tmp_path, fake_mastio, patched_http_and_runtime,
):
    """Legacy two-tier Mastio (no Intermediate loaded) → no
    cert_chain_pem in the response. The factory must NOT write a
    half-baked ca-chain.pem or crash."""
    from cullis_sdk import CullisClient

    fake_mastio.approved = True
    fake_mastio.cert_chain_pem = None
    # Re-wire .get to drop the field entirely (mirror what the server
    # does when ``_build_cert_chain_pem`` returns None).
    original_get = fake_mastio.get

    def _no_chain_get(url, *, headers=None, **_):
        resp = original_get(url, headers=headers, **_)
        body = dict(resp.json())
        body.pop("cert_chain_pem", None)
        return _FakeResponse(resp.status_code, body)

    fake_mastio.get = _no_chain_get  # type: ignore[assignment]

    CullisClient.enroll_via_dashboard_approval(
        "https://fake-mastio:9443",
        requester_name="Alice",
        requester_email="alice@example.com",
        save_to=tmp_path / "agent-id",
        poll_interval_s=0.0,
        timeout_s=5.0,
    )

    assert (tmp_path / "agent-id" / "agent.crt").is_file()
    assert not (tmp_path / "agent-id" / "ca-chain.pem").exists()
