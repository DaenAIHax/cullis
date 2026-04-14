"""Local WebSocket connection manager — ADR-001 Phase 3b.

Single-process in-memory registry of internal agents that are currently
connected to the proxy's `/v1/local/ws` endpoint. Used by the local
mini-broker (Phase 3c) to decide push-vs-queue for intra-org messages.

Design simplifications vs `app/broker/ws_manager.py`:
  - No Redis Pub/Sub: the proxy is a single-process component serving
    one org, so cross-worker delivery isn't needed. HA story (multiple
    proxy replicas behind a load balancer sharing state via Redis) can
    be layered later without changing this interface.
  - No per-org cap: agents already belong to the proxy's single org.

Concurrency: `_lock` serialises connect/disconnect so a fast reconnect
replaces the stale WS atomically (no TOCTOU).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict

from fastapi import WebSocket

logger = logging.getLogger("mcp_proxy.local.ws_manager")


class LocalConnectionManager:
    def __init__(self) -> None:
        self._connections: Dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()
        self._shut_down = False

    async def connect(self, agent_id: str, websocket: WebSocket) -> None:
        """Register a WebSocket for an agent. If the agent already has a
        live connection, close it first so only the newest survives."""
        async with self._lock:
            existing = self._connections.pop(agent_id, None)
            if existing is not None:
                logger.warning(
                    "Closing previous local WS for agent %s before reconnect",
                    agent_id,
                )
                try:
                    await existing.close(code=1000, reason="reconnect")
                except Exception:
                    pass
            self._connections[agent_id] = websocket
            logger.info("Agent %s connected to local WS", agent_id)

    async def disconnect(
        self,
        agent_id: str,
        *,
        code: int = 1000,
        reason: str = "",
    ) -> None:
        async with self._lock:
            ws = self._connections.pop(agent_id, None)
        if ws is None:
            return
        try:
            await ws.close(code=code, reason=reason)
        except Exception as exc:
            logger.debug("Error closing local WS for %s: %s", agent_id, exc)
        logger.info(
            "Agent %s disconnected from local WS (code=%d reason=%s)",
            agent_id, code, reason or "-",
        )

    async def send_to_agent(self, agent_id: str, data: dict) -> bool:
        """Deliver a frame to the agent if connected. Returns True on
        success, False when the agent is offline or the send failed
        (connection will be evicted in that case)."""
        ws = self._connections.get(agent_id)
        if ws is None:
            return False
        try:
            await ws.send_json(data)
            return True
        except Exception as exc:
            logger.error("Local WS send failed for %s: %s — evicting", agent_id, exc)
            await self.disconnect(agent_id, code=1011, reason="send_failed")
            return False

    def is_connected(self, agent_id: str) -> bool:
        return agent_id in self._connections

    def connected_agents(self) -> list[str]:
        return list(self._connections)

    async def shutdown(self) -> None:
        """Close every connection. Idempotent."""
        if self._shut_down:
            return
        self._shut_down = True
        for agent_id in list(self._connections):
            await self.disconnect(agent_id, code=1012, reason="proxy_restart")
