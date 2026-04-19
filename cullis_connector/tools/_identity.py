"""Sender-identity helpers shared by Connector tool modules.

Both `oneshot.py` and `intent.py` need to read the sender's own org
from the loaded identity bundle (cert subject ``O=<org_id>``) and to
canonicalise bare recipient handles into the ``<org>::<agent>`` form
the Mastio's ``/v1/egress/*`` endpoints require. Keeping the helpers
here avoids the circular import that would happen if ``intent.py``
tried to pull them from ``oneshot.py``.

Also hosts ``prime_sender_pubkey_cache`` — the workaround used by both
the MCP receive_oneshot tool and the dashboard inbox poller to make
``CullisClient.decrypt_oneshot`` work without a broker JWT (which
device-code-enrolled Connectors don't hold).
"""
from __future__ import annotations

import logging
import time

from cryptography import x509

from cullis_connector.state import get_state

_log = logging.getLogger("cullis_connector.tools._identity")


class PubkeyPrimeError(RuntimeError):
    """Raised when the sender pubkey cache cannot be primed via
    ``/v1/egress/resolve`` — either the Mastio call failed outright
    or the response carried no ``target_cert_pem``.

    The dashboard inbox poller catches this and skips the message
    (logging at ERROR rather than swallowing silently) so an operator
    can see the security-relevant gap in their audit log instead of
    silently falling back to the broker JWT path that no Connector
    holds a token for.
    """


def own_org_id() -> str | None:
    """Return the sender's org_id from the loaded identity's cert subject.

    The Mastio's ``/v1/egress/resolve`` rejects bare recipient names —
    it needs ``org::agent``. Enrollment writes the agent's cert with
    ``O=<org_id>`` so we can recover the sender's org even when
    ``metadata.json`` stored only the short agent_id.
    """
    state = get_state()
    identity = state.extra.get("identity")
    cert = getattr(identity, "cert", None)
    if cert is None:
        return None
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if not attrs:
        return None
    return attrs[0].value or None


def canonical_recipient(recipient_id: str) -> str:
    """Prefix the sender's org when the caller gave a bare agent name."""
    if "::" in recipient_id:
        return recipient_id
    org = own_org_id()
    if not org:
        return recipient_id
    return f"{org}::{recipient_id}"


def prime_sender_pubkey_cache(client, sender: str) -> None:
    """Seed the SDK's pubkey cache with the sender's cert via the proxy's
    resolve endpoint.

    ``CullisClient.decrypt_oneshot`` looks up the sender's cert through
    ``get_agent_public_key``, which by default hits the Court's
    federation API behind a broker JWT — and device-code Connectors
    don't hold that JWT. The local Mastio already knows the cert (it
    served it to the sender's ``/v1/egress/resolve``), so we ask
    ``/v1/egress/resolve`` for the same row and populate the SDK
    cache directly so ``decrypt_oneshot`` finds it without needing
    the broker.

    No-op on cache hit.

    **Error contract (security audit NEW #4):** Failures MUST propagate
    to the caller so the audit trail records the skip at ERROR level
    instead of the function silently falling back to the broker JWT
    path (which has no credential → surfaces as an opaque
    ``login()`` error). Specifically, raises ``PubkeyPrimeError`` when:

      - the HTTP call to ``/v1/egress/resolve`` fails (network, 4xx, 5xx),
      - the response is missing / has an empty ``target_cert_pem``,
      - the client object has no ``_pubkey_cache`` attribute (programming
        error — an incompatible client type was passed in).

    The caller (inbox poller, MCP receive_oneshot) catches and
    skips-this-message rather than crashing the poll loop.
    """
    canonical = sender if "::" in sender else canonical_recipient(sender)
    cache = getattr(client, "_pubkey_cache", None)
    if cache is None:
        raise PubkeyPrimeError(
            "client has no _pubkey_cache attribute — incompatible SDK client"
        )
    # The SDK's get_agent_public_key honours its own TTL (300s); if the
    # entry is still fresh we skip, otherwise we refetch even for known
    # senders. Without this, a stale entry left over from a previous
    # poll round causes get_agent_public_key to fall back to the broker
    # JWT path → "Not authenticated — call login() first".
    try:
        from cullis_sdk.client import _PUBKEY_CACHE_TTL as _SDK_TTL
    except Exception:  # noqa: BLE001
        _SDK_TTL = 300
    cached = cache.get(canonical)
    if cached is not None:
        _, fetched_at = cached
        if time.time() - fetched_at < _SDK_TTL:
            return
    try:
        resp = client._egress_http(
            "post",
            "/v1/egress/resolve",
            json={"recipient_id": canonical},
        )
        resp.raise_for_status()
        cert = resp.json().get("target_cert_pem")
    except PubkeyPrimeError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PubkeyPrimeError(
            f"/v1/egress/resolve call for {canonical} failed: "
            f"{exc} ({type(exc).__name__})"
        ) from exc
    if not cert:
        raise PubkeyPrimeError(
            f"/v1/egress/resolve for {canonical} returned no target_cert_pem "
            "(intra-org transport may be 'envelope' not 'mtls-only' — set "
            "PROXY_TRANSPORT_INTRA_ORG=mtls-only on the Mastio)"
        )
    cache[canonical] = (cert, time.time())
    # Mirror under the bare handle too — `decrypt_oneshot` keys on
    # whatever the inbox row carried, which can be either form.
    if sender != canonical:
        cache[sender] = (cert, time.time())
    _log.info("pubkey cached for %s (mirror=%s)", canonical, sender != canonical)
