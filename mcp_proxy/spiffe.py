"""
SPIFFE parsing utilities for the proxy.

Mirrors the subset of app/spiffe.py needed by the egress routing decision
(ADR-001 Phase 2). Kept proxy-local to preserve the broker↔proxy module
boundary; the future cullis_core shared library (roadmap Phase 1.5) will
dedupe both copies.

Accepts two recipient formats used across the codebase:
  - SPIFFE URI:    spiffe://<trust-domain>/<org>/<agent>
  - Internal form: <org>::<agent>   (no trust domain — assumed local)
"""
import re
from urllib.parse import urlparse

_SPIFFE_SCHEME = "spiffe"
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")
_PATH_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")


class InvalidRecipient(ValueError):
    """Raised when a recipient identifier cannot be parsed."""


def _is_spiffe(recipient_id: str) -> bool:
    return recipient_id.startswith("spiffe://")


def parse_spiffe(spiffe_id: str) -> tuple[str, str, str]:
    """Parse a SPIFFE URI into (trust_domain, org, agent).

    Raises InvalidRecipient on malformed input.
    """
    parsed = urlparse(spiffe_id)
    if parsed.scheme != _SPIFFE_SCHEME:
        raise InvalidRecipient(f"not a SPIFFE URI: {spiffe_id!r}")
    trust_domain = parsed.netloc
    if not trust_domain or not _TRUST_DOMAIN_RE.match(trust_domain):
        raise InvalidRecipient(f"invalid trust domain: {trust_domain!r}")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise InvalidRecipient(
            f"SPIFFE path must have 2 components (org/agent), got {len(parts)}"
        )
    org, agent = parts
    for name, value in (("org", org), ("agent", agent)):
        if not value or not _PATH_COMPONENT_RE.match(value):
            raise InvalidRecipient(f"invalid {name} component: {value!r}")
    if parsed.query or parsed.fragment:
        raise InvalidRecipient("SPIFFE URI must not have query or fragment")
    return trust_domain, org, agent


def parse_internal(internal_id: str) -> tuple[str, str]:
    """Parse an internal `org::agent` identifier into (org, agent).

    Raises InvalidRecipient if the separator is missing or components empty.
    """
    parts = internal_id.split("::", 1)
    if len(parts) != 2:
        raise InvalidRecipient(
            f"internal id must be 'org::agent', got {internal_id!r}"
        )
    org, agent = parts
    if not org or not agent:
        raise InvalidRecipient(f"empty component in internal id: {internal_id!r}")
    return org, agent


def parse_recipient(recipient_id: str) -> tuple[str | None, str, str]:
    """Parse either form into (trust_domain | None, org, agent).

    Returns None as trust_domain for internal format — callers should treat
    that as "assumed local trust domain".
    """
    if not recipient_id:
        raise InvalidRecipient("empty recipient id")
    if _is_spiffe(recipient_id):
        return parse_spiffe(recipient_id)
    org, agent = parse_internal(recipient_id)
    return None, org, agent
