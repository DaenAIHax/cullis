"""Shared capability validation + parse helpers for the admin surfaces.

The agent / user / workload create endpoints all accept a
``capabilities`` field. They share the same shape: a JSON array of
lowercase-identifier strings (``llm.chat``, ``mcp.tools.list``,
``custom.read``). This module pins the constraints in one place so
the three endpoints can't drift:

  * ``Capability`` — single capability token (Pydantic-validated).
  * ``CAPABILITIES_FIELD`` — ready-to-use ``Field`` for the list,
    with item + length caps that keep an abusive admin push from
    growing the row unbounded.
  * ``decode_capabilities`` — defensive parse for rows read back
    from the DB (handles legacy NULL, string, list, malformed JSON).

The caps are intentionally **policy**, not **security**: behaviourally
unknown caps no-op at every gate (the membership test compares
literal strings like ``"llm.chat"``), so they cannot escalate. The
caps are here to keep the row small and the admin UI sane.
"""
from __future__ import annotations

import json
from typing import Annotated

from pydantic import Field, StringConstraints


# Lowercase identifier, dotted segments. Matches the convention used
# in the existing static caps (``llm.chat``, ``mcp.tools.list``,
# ``http.get``, ``erp.read``). ``[a-z_]`` start prevents purely
# numeric tokens; the inner alphabet allows dots, underscores, digits.
_CAPABILITY_PATTERN = r"^[a-z_][a-z0-9_.]{0,63}$"


Capability = Annotated[
    str,
    StringConstraints(
        pattern=_CAPABILITY_PATTERN,
        min_length=1,
        max_length=64,
    ),
]


# Use this in admin BaseModels:
#
#     capabilities: list[Capability] = CAPABILITIES_FIELD
#
# Caps the list at 64 entries (no realistic operator needs more) and
# each item at 64 chars via the Capability constraint above.
CAPABILITIES_FIELD = Field(
    default_factory=list,
    max_length=64,
    description=(
        "Capability tokens granted to this principal. Each item: "
        "lowercase identifier with optional dotted segments "
        "(e.g. 'llm.chat', 'mcp.tools.list'). Empty list = "
        "zero-trust default-deny."
    ),
)


def decode_capabilities(raw: object) -> list[str]:
    """Parse a ``capabilities`` value read from a DB row.

    Tolerates the column being NULL (legacy rows pre-migration 0045),
    a Python list (some drivers may already decode JSON), a JSON
    string (the canonical encoding), or a comma-separated string
    (defensive — should not happen in practice). Returns an empty
    list on any error so the caller can fall through to zero-trust
    default-deny.
    """
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return [c for c in raw if isinstance(c, str)]
    if not isinstance(raw, str):
        return []
    try:
        loaded = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(loaded, list):
        return []
    return [c for c in loaded if isinstance(c, str)]
