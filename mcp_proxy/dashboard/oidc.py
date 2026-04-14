"""
OIDC (OpenID Connect) client for the MCP Proxy dashboard.

Supports OAuth 2.0 Authorization Code Flow with PKCE (RFC 7636).
Per-proxy OIDC config is stored in proxy_config under the keys:

  - oidc_issuer_url
  - oidc_client_id
  - oidc_client_secret

This module mirrors app/dashboard/oidc.py but is intentionally standalone:
the proxy package never imports from the broker package (see mcp_proxy
top-level rule).
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import time
from dataclasses import dataclass

import httpx
from authlib.jose import JsonWebKey
from authlib.jose import jwt as authlib_jwt

_log = logging.getLogger("mcp_proxy.dashboard.oidc")

# In-memory caches with TTL
_discovery_cache: dict[str, tuple[dict, float]] = {}
_DISCOVERY_TTL = 300  # 5 minutes

_jwks_cache: dict[str, tuple[dict, float]] = {}
_JWKS_TTL = 3600  # 1 hour


class OidcError(Exception):
    """Raised for any OIDC protocol failure."""


@dataclass
class OidcFlowState:
    state: str
    nonce: str
    code_verifier: str

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "nonce": self.nonce,
            "code_verifier": self.code_verifier,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OidcFlowState":
        return cls(
            state=d["state"],
            nonce=d["nonce"],
            code_verifier=d["code_verifier"],
        )


@dataclass
class OidcIdentity:
    sub: str
    email: str | None
    name: str | None
    issuer: str
    claims: dict


def create_oidc_state() -> OidcFlowState:
    """Generate cryptographically random state, nonce, and PKCE code_verifier."""
    return OidcFlowState(
        state=os.urandom(32).hex(),
        nonce=os.urandom(32).hex(),
        code_verifier=base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=").decode(),
    )


def _pkce_code_challenge(verifier: str) -> str:
    """Compute S256 code challenge from code verifier (RFC 7636)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def _fetch_discovery(issuer_url: str) -> dict:
    """Fetch and cache the OIDC discovery document."""
    now = time.time()
    cached = _discovery_cache.get(issuer_url)
    if cached and now - cached[1] < _DISCOVERY_TTL:
        return cached[0]

    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        if resp.status_code != 200:
            raise OidcError(
                f"OIDC discovery failed for {issuer_url}: HTTP {resp.status_code}"
            )
        doc = resp.json()

    _discovery_cache[issuer_url] = (doc, now)
    return doc


async def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch and cache the IdP's JSON Web Key Set."""
    now = time.time()
    cached = _jwks_cache.get(jwks_uri)
    if cached and now - cached[1] < _JWKS_TTL:
        return cached[0]

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        if resp.status_code != 200:
            raise OidcError(f"JWKS fetch failed: HTTP {resp.status_code}")
        jwks = resp.json()

    _jwks_cache[jwks_uri] = (jwks, now)
    return jwks


async def build_authorization_url(
    issuer_url: str,
    client_id: str,
    redirect_uri: str,
    flow_state: OidcFlowState,
) -> str:
    """Build the OIDC authorization URL with PKCE."""
    doc = await _fetch_discovery(issuer_url)
    auth_endpoint = doc.get("authorization_endpoint")
    if not auth_endpoint:
        raise OidcError("No authorization_endpoint in discovery document")

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": flow_state.state,
        "nonce": flow_state.nonce,
        "code_challenge": _pkce_code_challenge(flow_state.code_verifier),
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in auth_endpoint else "?"
    query = "&".join(
        f"{k}={httpx.URL('', params={k: v}).params[k]}" for k, v in params.items()
    )
    return f"{auth_endpoint}{sep}{query}"


async def exchange_code_for_identity(
    issuer_url: str,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    code: str,
    flow_state: OidcFlowState,
) -> OidcIdentity:
    """Exchange authorization code for ID token and extract identity."""
    doc = await _fetch_discovery(issuer_url)
    token_endpoint = doc.get("token_endpoint")
    jwks_uri = doc.get("jwks_uri")
    if not token_endpoint or not jwks_uri:
        raise OidcError("Missing token_endpoint or jwks_uri in discovery document")

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": flow_state.code_verifier,
    }
    if client_secret:
        token_data["client_secret"] = client_secret

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(token_endpoint, data=token_data)
        if resp.status_code != 200:
            raise OidcError(
                f"Token exchange failed: HTTP {resp.status_code} — {resp.text[:200]}"
            )
        token_resp = resp.json()

    id_token_str = token_resp.get("id_token")
    if not id_token_str:
        raise OidcError("No id_token in token response")

    jwks_data = await _fetch_jwks(jwks_uri)
    try:
        jwk_set = JsonWebKey.import_key_set(jwks_data)
        claims = authlib_jwt.decode(id_token_str, jwk_set)
        claims.validate()
    except Exception as exc:
        raise OidcError(f"ID token validation failed: {exc}") from exc

    token_issuer = claims.get("iss", "")
    if token_issuer.rstrip("/") != issuer_url.rstrip("/"):
        raise OidcError(
            f"Issuer mismatch: expected {issuer_url}, got {token_issuer}"
        )

    token_aud = claims.get("aud", "")
    if isinstance(token_aud, list):
        if client_id not in token_aud:
            raise OidcError(f"Audience mismatch: {client_id} not in {token_aud}")
    elif token_aud != client_id:
        raise OidcError(
            f"Audience mismatch: expected {client_id}, got {token_aud}"
        )

    if claims.get("nonce") != flow_state.nonce:
        raise OidcError("Nonce mismatch — possible replay attack")

    return OidcIdentity(
        sub=claims["sub"],
        email=claims.get("email"),
        name=claims.get("name"),
        issuer=token_issuer,
        claims=dict(claims),
    )


# ── Config helpers ──────────────────────────────────────────────────────────

OIDC_ISSUER_URL_KEY = "oidc_issuer_url"
OIDC_CLIENT_ID_KEY = "oidc_client_id"
OIDC_CLIENT_SECRET_KEY = "oidc_client_secret"


async def load_oidc_config() -> dict[str, str]:
    """Return the proxy OIDC configuration from proxy_config.

    Keys: issuer_url, client_id, client_secret. Missing entries resolve
    to empty strings so callers can test ``bool(cfg["issuer_url"])``.
    """
    from mcp_proxy.db import get_config

    return {
        "issuer_url": (await get_config(OIDC_ISSUER_URL_KEY)) or "",
        "client_id": (await get_config(OIDC_CLIENT_ID_KEY)) or "",
        "client_secret": (await get_config(OIDC_CLIENT_SECRET_KEY)) or "",
    }


async def save_oidc_config(
    issuer_url: str,
    client_id: str,
    client_secret: str | None = None,
) -> None:
    """Persist OIDC config to proxy_config. Empty client_secret is preserved
    only when explicitly passed; `None` means "leave existing value untouched"."""
    from mcp_proxy.db import set_config

    await set_config(OIDC_ISSUER_URL_KEY, issuer_url.strip())
    await set_config(OIDC_CLIENT_ID_KEY, client_id.strip())
    if client_secret is not None:
        await set_config(OIDC_CLIENT_SECRET_KEY, client_secret)


async def is_oidc_configured() -> bool:
    """Return True when the minimum OIDC config (issuer + client_id) is set."""
    cfg = await load_oidc_config()
    return bool(cfg["issuer_url"] and cfg["client_id"])
