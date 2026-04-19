"""Discovery tools for finding agents on the Cullis network."""
from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from cullis_connector._logging import get_logger
from cullis_connector.tools.session import _require_oneshot_client

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_log = get_logger("tools.discovery")


def register(mcp: "FastMCP") -> None:
    @mcp.tool()
    def discover_agents(
        q: str = "",
        capabilities: str = "",
        org_id: str = "",
        pattern: str = "",
    ) -> str:
        """Search for agents reachable on the Cullis network.

        Talks to the local Mastio's ``/v1/egress/peers`` endpoint via
        API-key + DPoP — no broker JWT required, so this works under
        device-code Connector enrollments where the agent's private
        key never leaves the user's machine. The Mastio returns
        intra-org peers from its local registry plus cross-org peers
        cached from the federation feed (when federation is wired).

        Args:
            q: Free-text substring against agent_id and display_name.
               Empty string lists everything visible.
            capabilities: Comma-separated capabilities; agents must
                          carry ALL of them to match.
            org_id: Restrict to a specific org.
            pattern: Glob on agent_id (e.g. 'chipfactory::*').
        """
        client = _require_oneshot_client()
        try:
            peers = client.list_peers(q=q or None, limit=200)
        except Exception as exc:  # noqa: BLE001
            _log.warning("list_peers failed: %s", exc)
            return f"Failed to list peers: {exc}"

        wanted_caps = [c.strip() for c in capabilities.split(",") if c.strip()]

        filtered = []
        for p in peers:
            if org_id and p.org_id != org_id:
                continue
            if pattern and not fnmatch.fnmatchcase(p.agent_id, pattern):
                continue
            if wanted_caps and not all(c in (p.capabilities or []) for c in wanted_caps):
                continue
            filtered.append(p)

        if not filtered:
            return "No agents found matching the search criteria."
        lines = []
        for agent in filtered:
            line = f"- {agent.display_name or agent.agent_id} ({agent.agent_id}) org={agent.org_id}"
            if agent.description:
                line += f" — {agent.description}"
            if agent.capabilities:
                line += f" [caps: {', '.join(agent.capabilities)}]"
            lines.append(line)
        return f"Found {len(filtered)} agent(s):\n" + "\n".join(lines)
