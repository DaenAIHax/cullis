"""Drop-in vanilla provider SDK compatibility (ADR-038 Phase 0, agnostic).

LLM-agnostic transport shim. Lets a customer keep their vanilla provider
SDK (Anthropic, OpenAI, and any other SDK that accepts an ``http_client``
+ ``base_url``) and route every call through a Mastio with mTLS + DPoP
applied automatically. The upstream provider key stays in ``proxy.env``
on the Mastio side, the agent host never sees it, and the audit chain
still records every call with the agent's identity.

Three new lines at construction time. Call sites, response handling,
tool use — all stay verbatim provider SDK. Streaming + tool-use response
shape for the Anthropic path land in Phase 1.

Anthropic SDK example (uses Mastio ``/v1/messages``, Anthropic-shape):

    import anthropic
    from cullis_sdk.providers_compat import cullis_httpx_client

    http_client = cullis_httpx_client(identity_dir="~/.cullis/scenario-b")

    client = anthropic.Anthropic(
        base_url="https://mastio.myorg.example.com:9443/v1",
        api_key="unused",         # Mastio ignores; mTLS + DPoP are real auth
        http_client=http_client,
    )

    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": "hello"}],
    )

OpenAI SDK example (uses Mastio ``/v1/chat/completions``, OpenAI-shape):

    from openai import OpenAI
    from cullis_sdk.providers_compat import cullis_httpx_client

    client = OpenAI(
        base_url="https://mastio.myorg.example.com:9443/v1",
        api_key="unused",
        http_client=cullis_httpx_client(identity_dir="~/.cullis/scenario-b"),
    )

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hello"}],
    )

Identity directory layout (matches ``CullisClient.from_identity_dir``):

    <identity_dir>/
        agent.crt        # x509 leaf cert (mTLS client identity)
        agent.key        # x509 leaf private key
        ca-chain.pem     # Mastio Intermediate + Org Root (mTLS trust)
        dpop.jwk         # EC P-256 keypair, JWK form (DPoP signer)

The helper is intentionally provider-neutral: it returns a plain
``httpx.Client``. The provider SDK chooses the path
(``/v1/messages`` vs ``/v1/chat/completions``) and the response shape;
the Mastio handles both on the same identity + audit infrastructure.

Phase 1 (next minor): streaming for Anthropic ``/v1/messages``,
tool-use response shape for Anthropic ``/v1/messages``, Google
``genai`` SDK example.
"""
from __future__ import annotations

import logging
import pathlib
import threading
from typing import Any

import httpx

from cullis_sdk.dpop import DpopKey

__all__ = ["cullis_httpx_client"]

_log = logging.getLogger("cullis_sdk.providers_compat")

_DEFAULT_TIMEOUT = 60.0


class _DpopTransport(httpx.BaseTransport):
    """httpx transport that signs every outbound request with DPoP.

    Wraps an inner ``httpx.HTTPTransport`` (or any other ``BaseTransport``)
    and intercepts the request/response pair to:

    1. Sign a DPoP proof for ``(method, htu)`` using the persistent DPoP
       key loaded from ``dpop.jwk``, attach as ``DPoP:`` header.
    2. Cache the server's ``DPoP-Nonce`` response header so subsequent
       proofs carry it (mirrors the cullis-sdk egress nonce pattern).
    3. On a ``401`` with ``use_dpop_nonce`` body marker, re-sign with the
       fresh nonce and replay the request once. Same single-retry shape
       as ``CullisClient._authed_request``.

    Thread-safe: the cached nonce is guarded by a lock so multiple
    concurrent requests through the same Anthropic client (e.g.
    parallel ``messages.create`` calls in a thread pool) sign with a
    consistent nonce view.
    """

    def __init__(
        self,
        inner: httpx.BaseTransport,
        dpop_key: DpopKey,
    ) -> None:
        self._inner = inner
        self._key = dpop_key
        self._nonce: str | None = None
        self._lock = threading.Lock()

    def _sign(self, method: str, url: httpx.URL) -> str:
        # RFC 9449 §4.2: htu is the request URL stripped of query +
        # fragment. httpx URLs split cleanly into the components.
        htu = str(url.copy_with(query=None, fragment=None))
        with self._lock:
            nonce = self._nonce
        return self._key.sign_proof(method.upper(), htu, nonce=nonce)

    def _cache_nonce(self, response: httpx.Response) -> str | None:
        nonce = response.headers.get("DPoP-Nonce")
        if nonce:
            with self._lock:
                self._nonce = nonce
        return nonce

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.headers["DPoP"] = self._sign(request.method, request.url)
        response = self._inner.handle_request(request)
        fresh_nonce = self._cache_nonce(response)

        # Single-retry on DPoP nonce challenge. The first response body
        # has to be consumed to inspect ``use_dpop_nonce``; on a 401
        # the caller never sees this body anyway (we either retry and
        # return the second response, or surface the original
        # untouched). Reading on non-401 would break streaming, so the
        # body inspection is strictly inside the 401 branch.
        if response.status_code == 401 and fresh_nonce is not None:
            try:
                response.read()
                if "use_dpop_nonce" in response.text:
                    request.headers["DPoP"] = self._sign(
                        request.method, request.url,
                    )
                    response = self._inner.handle_request(request)
                    self._cache_nonce(response)
            except Exception:
                # Body read can fail on already-streamed transports;
                # in that case we surface the original 401 untouched.
                _log.debug(
                    "DPoP nonce body inspection failed on 401; "
                    "returning original response",
                    exc_info=True,
                )

        return response

    def close(self) -> None:
        self._inner.close()


def _resolve_identity_files(
    identity_dir: str | pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path | None, pathlib.Path]:
    """Locate the identity files inside ``identity_dir``.

    Returns ``(cert, key, ca_chain_or_None, dpop_jwk_path)``. Only
    ``agent.crt`` and ``agent.key`` are mandatory — they are the
    credential (ADR-014) and cannot be regenerated client-side.
    ``ca-chain.pem`` is optional (a Mastio with a publicly trusted TLS
    cert lets the client rely on the system trust store). ``dpop.jwk``
    is the returned *path* and may not exist yet: the caller generates +
    persists it on first use, the same contract as
    ``CullisClient.from_identity_dir`` and the identity-bundle.zip NB.
    RFC 9449 keeps the DPoP key client-side, so the admin-minted bundle
    does not ship one.
    """
    base = pathlib.Path(identity_dir).expanduser().resolve()

    if not base.is_dir():
        raise FileNotFoundError(
            f"identity_dir {base} is not a directory; expected the "
            f"layout written by enrol_via_dashboard_approval / the "
            f"admin-minted identity-bundle.zip (agent.crt + agent.key "
            f"+ optional ca-chain.pem; dpop.jwk generated on first use)"
        )

    cert = base / "agent.crt"
    key = base / "agent.key"
    ca = base / "ca-chain.pem"
    dpop = base / "dpop.jwk"

    missing = [p.name for p in (cert, key) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            f"identity_dir {base} missing {', '.join(missing)}; "
            f"required layout: agent.crt + agent.key "
            f"(plus optional ca-chain.pem for Mastio Intermediate trust; "
            f"dpop.jwk is generated on first use if absent)"
        )

    return cert, key, (ca if ca.exists() else None), dpop


def cullis_httpx_client(
    *,
    identity_dir: str | pathlib.Path,
    timeout: float = _DEFAULT_TIMEOUT,
    extra_httpx_kwargs: dict[str, Any] | None = None,
) -> httpx.Client:
    """Return a ``httpx.Client`` preconfigured to talk to a Mastio.

    Loads ``agent.crt``, ``agent.key``, ``ca-chain.pem`` (optional),
    and ``dpop.jwk`` from ``identity_dir`` (auto-discovery; same layout
    as ``CullisClient.from_identity_dir``). Configures mTLS client cert
    + CA trust, and installs a transport hook that signs every outbound
    request with DPoP and handles the nonce-retry challenge.

    Pass the returned client as ``http_client=`` to
    ``anthropic.Anthropic()`` (or any other SDK that exposes the
    underlying httpx transport — OpenAI, Google ``genai``, etc.).

    :param identity_dir: directory holding the four identity files.
    :param timeout: per-request timeout in seconds, propagated to httpx.
        Anthropic SDK ``messages.create(stream=True)`` can hold a stream
        open longer than this; pass a larger value when streaming long
        completions.
    :param extra_httpx_kwargs: optional dict of additional kwargs forwarded
        to ``httpx.Client(**)``. Use for ``proxies``, ``http2``, ``limits``,
        etc. ``cert``, ``verify``, ``timeout``, and ``transport`` are set
        by this helper and cannot be overridden via this dict.
    """
    cert, key, ca, dpop_path = _resolve_identity_files(identity_dir)
    # Generate + persist the DPoP key on first use if the bundle did not
    # ship one (it never does — RFC 9449 keeps the key client-side, and
    # the identity-bundle.zip NB documents "generated on first use").
    # Mirrors CullisClient.from_identity_dir; previously this helper hard
    # -required dpop.jwk and FileNotFound'd the documented zip → drop-in
    # flow. The Mastio TOFU-accepts the proof under egress_dpop_mode
    # ``optional`` (the default); once the operator flips to ``required``
    # the jkt must be registered at enrollment, same as any agent.
    dpop_key = DpopKey.load(dpop_path) if dpop_path.exists() else DpopKey.generate(path=dpop_path)

    # Build an explicit ``ssl.SSLContext`` with the client cert chain
    # loaded into it. We avoid httpx's legacy ``cert=(crt, key)`` +
    # ``verify=<path>`` kwargs because that combination silently fails
    # mTLS handshake under some httpx + OpenSSL builds — the server
    # sees ``ssl_client_verify=NONE`` even though both files were
    # configured (reproduced 2026-05-27 ADR-038 pre-tag validation
    # against the Mastio mTLS sidecar). The explicit-SSLContext path
    # mirrors what ``CullisClient._build_proxy_http_client`` already
    # does and works against the same nginx + cert chain.
    import ssl
    if ca is not None:
        ssl_ctx = ssl.create_default_context(cafile=str(ca))
    else:
        ssl_ctx = ssl.create_default_context()
    ssl_ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))

    inner = httpx.HTTPTransport(verify=ssl_ctx)
    transport = _DpopTransport(inner, dpop_key)

    kwargs: dict[str, Any] = dict(extra_httpx_kwargs or {})
    # Drop any caller-supplied values that would conflict with our wiring.
    for reserved in ("cert", "verify", "timeout", "transport"):
        kwargs.pop(reserved, None)

    return httpx.Client(
        timeout=timeout,
        transport=transport,
        **kwargs,
    )
