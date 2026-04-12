"""
JWT validator — decode-only (NO token creation).

Validates RS256 tokens issued by the Cullis broker, using public keys
fetched via the JWKSClient.
"""
import logging

from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, status
import jwt as jose_jwt

from mcp_proxy.auth.jwks_client import JWKSClient
from mcp_proxy.models import TokenPayload

_log = logging.getLogger("mcp_proxy")

_TOKEN_ISSUER = "cullis-broker"
_TOKEN_AUDIENCE = "cullis"


async def decode_token(token: str, jwks_client: JWKSClient) -> TokenPayload:
    """Decode and validate an RS256 JWT signed by the broker.

    Steps:
      1. Extract kid from JWT header
      2. Look up public key via JWKSClient
      3. Verify signature, exp, iat, aud, iss
      4. Return TokenPayload

    Raises HTTPException 401 on any error.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalid or expired",
        headers={"WWW-Authenticate": 'DPoP realm="mcp-proxy", algs="ES256 PS256"'},
    )

    try:
        # Extract kid from unverified header
        unverified_header = jose_jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            _log.warning("JWT missing kid in header")
            raise credentials_exception

        # Look up public key
        try:
            rsa_key = await jwks_client.get_public_key(kid)
        except KeyError:
            _log.warning("Unknown kid in JWT: %s", kid)
            raise credentials_exception

        # Convert to PEM for PyJWT
        pub_pem = rsa_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        # Decode and verify
        raw = jose_jwt.decode(
            token,
            pub_pem,
            algorithms=["RS256", "ES256", "ES384", "ES512"],
            audience=_TOKEN_AUDIENCE,
        )

        # Verify issuer
        if raw.get("iss") != _TOKEN_ISSUER:
            _log.warning("JWT issuer mismatch: got %r, expected %r", raw.get("iss"), _TOKEN_ISSUER)
            raise credentials_exception

        return TokenPayload(**raw)

    except HTTPException:
        raise
    except jose_jwt.ExpiredSignatureError:
        _log.debug("JWT expired")
        raise credentials_exception
    except jose_jwt.InvalidTokenError as exc:
        _log.debug("JWT validation error: %s", exc)
        raise credentials_exception
    except Exception as exc:
        _log.warning("Unexpected JWT validation error: %s", exc)
        raise credentials_exception
