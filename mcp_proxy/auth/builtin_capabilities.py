"""Single source of truth for the capability tokens shipped with the
Mastio (v0.6.4, ADR pending).

Background: a capability is the lowercase token an operator grants
to a principal (agent, user, workload) in order to authorise the
principal on a Mastio-gated endpoint. Three populations exist:

  * **Built-in** — names baked into the Mastio because they gate
    Mastio's own endpoints (chat, MCP discovery, MCP invocation,
    generic HTTP egress). They live in this module.
  * **Custom (per-tool)** — declared by MCP resources registered
    via ``POST /v1/admin/mcp-resources`` with a ``required_capability``
    column. They vary per deployment.
  * **Operator-defined** — invented by the customer's Rego policy
    (``if "compliance.signed_off" in caps``). The Mastio stores them
    verbatim and surfaces them in audit, but does not enforce
    anything beyond the policy that consumes them.

This module is the registry for the first population. Routers,
dashboard handlers, and the smoke scenarios all import from here
so a rename of e.g. ``mcp.tools.list`` lands in one PR, not five.

Adding a new built-in:

  1. Add the constant + entry in ``BUILTIN_CAPABILITIES`` below.
  2. Add the ``if X not in caps`` check on the gating router /
     handler.
  3. Add the smoke negative scenario under
     ``test/smoke/scenarios/4X_<name>_denied.sh`` (mirror 41/42).
  4. Update ``site/src/content/docs/reference/capabilities.md`` so
     the doc page stays canonical (today written by hand —
     refactor to autogen from this module is a v0.7 follow-up).

The dashboard's capability suggestion chips iterate over
``BUILTIN_CAPABILITIES.values()``; ``base.html`` exposes the dict
to every template via the ``_ctx`` helper in
``mcp_proxy.dashboard.session``.
"""
from __future__ import annotations

from typing import Final


# Constants. Use these via ``from mcp_proxy.auth.builtin_capabilities
# import LLM_CHAT, MCP_TOOLS_LIST`` so a typo in the literal string
# is a NameError, not a silent miss at the gate.

LLM_CHAT: Final[str] = "llm.chat"
"""Permits chat completions + Anthropic messages.

Gates:
  * ``POST /v1/chat/completions``  (OpenAI shape)
  * ``POST /v1/llm/chat``          (alias, same handler)
  * ``POST /v1/messages``          (Anthropic shape)
"""

MCP_TOOLS_LIST: Final[str] = "mcp.tools.list"
"""Permits the MCP discovery method.

Gates:
  * ``POST /v1/mcp`` JSON-RPC ``method=tools/list``
"""

MCP_TOOLS_CALL: Final[str] = "mcp.tools.call"
"""Permits the MCP invocation method.

Gates:
  * ``POST /v1/mcp`` JSON-RPC ``method=tools/call``  (v0.7 enforcement;
    v0.6.x relies on the per-tool ``required_capability`` field on
    the registered MCP resource)
"""

HTTP_GET: Final[str] = "http.get"
"""Permits the Mastio's built-in HTTP-GET egress tool.

Enforced via the built-in tool's ``required_capability`` (Phase 1
PR #730 builtin capability gate).
"""


# Metadata for the dashboard suggestion chips + the capabilities
# catalog page. ``order`` is the visual sort key in the chip group.
# Mirrors the README of ``docs/reference/capabilities``.

BUILTIN_CAPABILITIES: Final[dict[str, dict[str, object]]] = {
    LLM_CHAT: {
        "order": 10,
        "description": (
            "Chat completions + Anthropic messages "
            "(/v1/chat/completions, /v1/llm/chat, /v1/messages)"
        ),
        "endpoints": [
            "/v1/chat/completions",
            "/v1/llm/chat",
            "/v1/messages",
        ],
    },
    MCP_TOOLS_LIST: {
        "order": 20,
        "description": (
            "List MCP tools available to the principal "
            "(/v1/mcp tools/list)"
        ),
        "endpoints": ["/v1/mcp (tools/list)"],
    },
    MCP_TOOLS_CALL: {
        "order": 30,
        "description": (
            "Invoke MCP tools (/v1/mcp tools/call — "
            "forward-compatible, method-level enforcement lands in v0.7)"
        ),
        "endpoints": ["/v1/mcp (tools/call)"],
    },
    HTTP_GET: {
        "order": 40,
        "description": "Generic HTTP GET egress (built-in MCP tool)",
        "endpoints": ["/v1/mcp (tools/call name=http.get)"],
    },
}


def builtin_capability_list() -> list[dict[str, object]]:
    """Return ``BUILTIN_CAPABILITIES`` as a sorted list of dicts.

    Each entry carries ``name``, ``description``, ``endpoints``,
    ``order``. Shape that the dashboard template can iterate over
    without any sort gymnastics in Jinja.
    """
    out: list[dict[str, object]] = []
    for name, meta in BUILTIN_CAPABILITIES.items():
        out.append({"name": name, **meta})
    out.sort(key=lambda r: int(r["order"]))  # type: ignore[arg-type]
    return out
