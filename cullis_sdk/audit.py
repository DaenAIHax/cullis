"""Cullis Audit Envelope helpers (ADR-039).

The "Cullis Audit Envelope" is the convention that turns a tool's raw
RPC return value into a business-readable audit row on the Mastio
dashboard. Every tool in the Cullis ecosystem is expected to attach a
``_cullis_audit`` sidecar to its result — three short strings that
answer "what was the action", "what did it act on", and "what was the
outcome", in the language a CISO would use to read the log.

Without the envelope, the dashboard still shows the tool name and a
URL fallback (graceful degradation). With it, the card header reads
``Pre-trade risk check: BUY €5,000,000 FR0000571085 → approved``
instead of ``Tool invoked: risk_check``.

Spec
----

The envelope is a dict with exactly three required string fields::

    {
        "action":  "Pre-trade risk check",     # what happened (verb-phrase)
        "subject": "BUY €5,000,000 FR0000571085",  # what was acted upon
        "outcome": "approved: within mandate (1d VaR €58,150)",  # the result, business terms
    }

Mastio reads the envelope from anywhere inside the tool result by
walking the JSON tree, so you can put it at the top level alongside
``ok``/``error`` or inside a nested ``content`` block — both work.

Usage
-----

The ``envelope()`` helper attaches the envelope to an existing result
dict in one call::

    from cullis_sdk.audit import envelope

    @mcp.tool()
    async def place_order(isin: str, qty: int, price: float):
        result = await broker.execute(isin, qty, price)
        return envelope(
            result,
            action="Order placement",
            subject=f"BUY {qty:,} × {isin} @ €{price:,.2f}",
            outcome=f"filled: order #{result['order_id']}",
        )

For tools you don't own (third-party MCP servers), the dashboard falls
back to the tool name + endpoint URL automatically. You can also
override the display on the Mastio side by attaching an
``audit_template`` to the tool registry entry — see ADR-039 §4.

Field length budget
-------------------

The dashboard truncates each field at roughly the lengths below before
rendering. Stay inside these to keep the card header on one line:

* ``action``  ≤ 40 characters
* ``subject`` ≤ 80 characters
* ``outcome`` ≤ 120 characters

Longer values are accepted and stored verbatim in the audit chain;
only the rendered header is clipped.
"""
from __future__ import annotations

from typing import Any, TypeVar

T = TypeVar("T", bound=dict)


_CULLIS_AUDIT_KEY = "_cullis_audit"


def envelope(
    result: T,
    *,
    action: str,
    subject: str,
    outcome: str,
) -> T:
    """Attach a Cullis Audit Envelope to a tool result.

    Mutates ``result`` in place by adding a ``_cullis_audit`` key and
    returns the same dict so callers can ``return envelope(...)`` in
    a single line.

    Raises ``TypeError`` if ``result`` is not a dict-like object — the
    envelope only attaches to JSON object responses. For tools that
    return a list or a scalar, wrap the response in a dict before
    calling.

    Args:
        result: The tool's native return payload. Mutated in place.
        action: Verb-phrase describing what the tool did.
            E.g. "Market data lookup", "KYC screening",
            "DORA incident logged".
        subject: The thing acted upon, in human-readable form.
            E.g. an ISIN, a customer id, an incident id.
        outcome: The result of the action in business language.
            E.g. "approved: within mandate", "rejected: off universe".

    Returns:
        The same ``result`` dict, with ``_cullis_audit`` attached.
    """
    if not isinstance(result, dict):
        raise TypeError(
            "Cullis Audit Envelope can only attach to a dict result. "
            f"Got {type(result).__name__}; wrap your value in a dict first."
        )
    result[_CULLIS_AUDIT_KEY] = {
        "action": action,
        "subject": subject,
        "outcome": outcome,
    }
    return result


def make_envelope(
    *,
    action: str,
    subject: str,
    outcome: str,
) -> dict[str, str]:
    """Build a Cullis Audit Envelope as a standalone dict.

    Useful when you want to construct the envelope separately from the
    result, e.g. to share it across a try/except. The returned dict
    has the exact shape Mastio expects under ``_cullis_audit``.
    """
    return {"action": action, "subject": subject, "outcome": outcome}


def extract(payload: Any) -> dict[str, str] | None:
    """Pull a Cullis Audit Envelope out of an arbitrary JSON-ish payload.

    Mirrors the server-side reader: walks the parsed tree (dicts and
    lists) up to a small depth and returns the first ``_cullis_audit``
    object that has all three required fields. Returns ``None`` if
    nothing was found — callers should treat that as "fall back to the
    generic display path".

    Mainly useful for tests and for tools that want to forward an
    upstream envelope through their own response wrapper.
    """
    return _walk(payload, depth=0)


def _walk(node: Any, depth: int) -> dict[str, str] | None:
    if depth > 8 or node is None:
        return None
    if isinstance(node, dict):
        env = node.get(_CULLIS_AUDIT_KEY)
        if (
            isinstance(env, dict)
            and isinstance(env.get("action"), str)
            and isinstance(env.get("subject"), str)
            and isinstance(env.get("outcome"), str)
        ):
            return {
                "action": env["action"],
                "subject": env["subject"],
                "outcome": env["outcome"],
            }
        for v in node.values():
            found = _walk(v, depth + 1)
            if found is not None:
                return found
    elif isinstance(node, list):
        for v in node:
            found = _walk(v, depth + 1)
            if found is not None:
                return found
    return None


__all__ = ["envelope", "make_envelope", "extract"]
