"""
Egress routing decision — ADR-001 Phase 2.

Given a recipient identifier and the proxy's local (trust_domain, org),
return whether the message should route intra-org (future local delivery,
Phase 3) or cross-org (forward to broker — today's only path).

The decision is pure and has no side effects. Callers gate on the feature
flag `MCP_PROXY_INTRA_ORG_ROUTING` before acting on the intra verdict.
"""
from typing import Literal

from mcp_proxy.spiffe import InvalidRecipient, parse_recipient

Route = Literal["intra", "cross"]


def decide_route(
    recipient_id: str,
    local_org: str,
    local_trust_domain: str,
) -> Route:
    """Classify the recipient as intra-org or cross-org.

    Rules:
      - SPIFFE recipient: intra iff trust_domain AND org both match local.
      - Internal `org::agent` recipient: trust domain is implicit-local, so
        intra iff org matches local.
      - Unparseable recipient: treated as cross-org (safe default — the
        broker will reject downstream if it's also invalid).
    """
    try:
        trust_domain, org, _agent = parse_recipient(recipient_id)
    except InvalidRecipient:
        return "cross"

    if org != local_org:
        return "cross"

    if trust_domain is not None and trust_domain != local_trust_domain:
        return "cross"

    return "intra"
