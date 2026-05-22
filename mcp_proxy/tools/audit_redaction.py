"""Tool audit redaction — opt-in capture controls for regulated deployments.

The default behaviour of :func:`mcp_proxy.tools.executor._build_success_detail`
captures both ``parameters`` and ``result`` of every successful tool call into
the audit chain. That is the correct shape for an open-core demo and for
internal forensic readability, but it is the wrong shape for any deployment
that handles GDPR-regulated PII or MNPI: IBAN numbers, SSNs, deal names, and
similar values end up in an append-only table that operators with DB read can
read forever.

This module exposes two knobs to dial capture down without forcing every
operator into a fork:

* A boolean master switch per side (parameters / result) — flip to ``False``
  to redact across the board.
* A per-tool denylist of ``fnmatch`` glob patterns — flip individual tools
  (e.g. ``payments.*``) to redacted while keeping the rest captured.

The redaction surrogate keeps the audit row useful: ``_redacted: true`` plus
a ``reason`` field tells the forensic reader *that* something was elided and
*why*, without giving them the value. The original value never enters the
chain.

Defaults stay at *capture on* (backwards compatibility for existing open
deployments). Regulated operators flip the env vars at boot. See
:func:`should_redact_parameters` and :func:`should_redact_result` for the
matching logic.
"""
from __future__ import annotations

import fnmatch
from typing import Any


_REDACTED_PARAMETERS_REASON = "tool_denylist"
_REDACTED_RESULT_REASON = "tool_denylist"
_REDACTED_GLOBAL_REASON = "capture_disabled"


def _matches_any_pattern(tool_name: str, patterns: list[str]) -> bool:
    """Return True when ``tool_name`` matches any fnmatch glob in
    ``patterns``.

    The patterns are case-sensitive by design — tool names are
    case-sensitive everywhere else in the executor, so the denylist
    must be too. An empty list never matches anything.
    """
    if not patterns:
        return False
    for pattern in patterns:
        if pattern and fnmatch.fnmatchcase(tool_name, pattern):
            return True
    return False


def should_redact_parameters(
    *,
    tool_name: str | None,
    capture_enabled: bool,
    denylist: list[str],
) -> bool:
    """Return True when the executor must replace ``parameters`` with the
    redacted-marker payload before the audit row lands.

    The two switches compose: when ``capture_enabled`` is False the helper
    returns True regardless of ``denylist`` (the operator has opted out
    globally). Otherwise the denylist gates per-tool.
    """
    if not capture_enabled:
        return True
    if tool_name is None:
        return False
    return _matches_any_pattern(tool_name, denylist)


def should_redact_result(
    *,
    tool_name: str | None,
    capture_enabled: bool,
    denylist: list[str],
) -> bool:
    """Mirror of :func:`should_redact_parameters` for the ``result``
    side. Kept as a separate function so a deployment can redact
    parameters (often contains the user-typed natural-language query)
    while still capturing the structured result, or vice versa.
    """
    if not capture_enabled:
        return True
    if tool_name is None:
        return False
    return _matches_any_pattern(tool_name, denylist)


def redacted_marker(*, reason: str) -> dict[str, Any]:
    """Return the canonical surrogate dict used in place of a redacted
    value. The shape mirrors the ``_omitted`` / ``_non_serializable``
    markers in :mod:`mcp_proxy.tools.executor` so a downstream consumer
    (dashboard render, forensic export) can pattern-match on the
    ``_redacted`` flag in one pass."""
    return {"_redacted": True, "reason": reason}


# Exposed reason constants so call sites can use them by name rather than
# repeating the literal — keeps the audit shape consistent if the strings
# ever need to be tuned.
REASON_TOOL_DENYLIST = _REDACTED_PARAMETERS_REASON
REASON_CAPTURE_DISABLED = _REDACTED_GLOBAL_REASON
