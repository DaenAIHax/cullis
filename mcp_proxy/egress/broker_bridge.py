"""
Broker Bridge — maintains authenticated CullisClient instances per internal agent.

Each internal agent gets its own CullisClient that authenticates to the broker
using the agent's x509 cert+key (fetched from Vault/DB via AgentManager).
Clients are lazily initialized and cached with automatic retry on auth failure.
"""
import asyncio
import logging
from typing import Any

from cullis_sdk.client import CullisClient

logger = logging.getLogger("mcp_proxy.egress.broker_bridge")


class BrokerBridge:
    """Maintains authenticated CullisClient instances for internal agents.

    Each internal agent gets its own CullisClient that authenticates
    to the broker using the agent's x509 cert+key (fetched from Vault).
    Clients are lazily initialized and cached.
    """

    def __init__(self, broker_url: str, org_id: str, agent_manager: Any, *, verify_tls: bool = True):
        self._broker_url = broker_url
        self._org_id = org_id
        self._agent_manager = agent_manager
        self._verify_tls = verify_tls
        self._clients: dict[str, CullisClient] = {}
        self._lock = asyncio.Lock()

    # ── Client lifecycle ────────────────────────────────────────────

    async def _create_client(self, agent_id: str) -> CullisClient:
        """Create and authenticate a new CullisClient for an agent."""
        cert_pem, key_pem = await self._agent_manager.get_agent_credentials(agent_id)

        client = CullisClient(self._broker_url, verify_tls=self._verify_tls)
        # login_from_pem is synchronous in the SDK — run in thread to avoid blocking
        await asyncio.to_thread(
            client.login_from_pem, agent_id, self._org_id, cert_pem, key_pem,
        )
        logger.info("Authenticated CullisClient for agent: %s", agent_id)
        return client

    async def get_client(self, agent_id: str) -> CullisClient:
        """Get or create authenticated CullisClient for an agent.

        Lazy init: first call creates client and calls login_from_pem().
        Subsequent calls return cached client.
        On auth failure, evict and retry once.
        """
        # Fast path: client already cached
        if agent_id in self._clients:
            return self._clients[agent_id]

        async with self._lock:
            # Double-check after acquiring lock
            if agent_id in self._clients:
                return self._clients[agent_id]

            client = await self._create_client(agent_id)
            self._clients[agent_id] = client
            return client

    async def _evict_and_retry(self, agent_id: str) -> CullisClient:
        """Evict a cached client and create a fresh one (re-auth)."""
        async with self._lock:
            old = self._clients.pop(agent_id, None)
            if old is not None:
                try:
                    old.close()
                except Exception:
                    pass
            client = await self._create_client(agent_id)
            self._clients[agent_id] = client
            return client

    # ── Session operations ──────────────────────────────────────────

    async def open_session(
        self,
        agent_id: str,
        target_agent_id: str,
        target_org_id: str,
        capabilities: list[str],
    ) -> str:
        """Open a broker session on behalf of internal agent. Returns session_id."""
        client = await self.get_client(agent_id)
        try:
            session_id = await asyncio.to_thread(
                client.open_session, target_agent_id, target_org_id, capabilities,
            )
            logger.info(
                "Session opened: %s -> %s (session %s)",
                agent_id, target_agent_id, session_id,
            )
            return session_id
        except Exception as exc:
            # On auth-related errors, retry with fresh client
            if _is_auth_error(exc):
                logger.warning("Auth error for %s, re-authenticating: %s", agent_id, exc)
                client = await self._evict_and_retry(agent_id)
                session_id = await asyncio.to_thread(
                    client.open_session, target_agent_id, target_org_id, capabilities,
                )
                return session_id
            raise

    async def send_message(
        self,
        agent_id: str,
        session_id: str,
        payload: dict,
        recipient_agent_id: str,
    ) -> None:
        """Send E2E encrypted message via broker on behalf of internal agent."""
        client = await self.get_client(agent_id)
        try:
            await asyncio.to_thread(
                client.send, session_id, agent_id, payload, recipient_agent_id,
            )
            logger.debug(
                "Message sent: %s -> %s (session %s)", agent_id, recipient_agent_id, session_id,
            )
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning("Auth error for %s, re-authenticating: %s", agent_id, exc)
                client = await self._evict_and_retry(agent_id)
                await asyncio.to_thread(
                    client.send, session_id, agent_id, payload, recipient_agent_id,
                )
                return
            raise

    async def poll_messages(
        self, agent_id: str, session_id: str, after: int = -1,
    ) -> list[dict]:
        """Poll for new messages in a session. Returns decrypted message dicts."""
        client = await self.get_client(agent_id)
        try:
            inbox_messages = await asyncio.to_thread(
                client.poll, session_id, after,
            )
            # Convert InboxMessage objects to plain dicts for JSON serialization
            return [_inbox_to_dict(m) for m in inbox_messages]
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning("Auth error for %s, re-authenticating: %s", agent_id, exc)
                client = await self._evict_and_retry(agent_id)
                inbox_messages = await asyncio.to_thread(
                    client.poll, session_id, after,
                )
                return [_inbox_to_dict(m) for m in inbox_messages]
            raise

    async def list_sessions(
        self, agent_id: str, status: str | None = None,
    ) -> list[dict]:
        """List broker sessions for an internal agent."""
        client = await self.get_client(agent_id)
        try:
            sessions = await asyncio.to_thread(client.list_sessions, status)
            return [_session_to_dict(s) for s in sessions]
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning("Auth error for %s, re-authenticating: %s", agent_id, exc)
                client = await self._evict_and_retry(agent_id)
                sessions = await asyncio.to_thread(client.list_sessions, status)
                return [_session_to_dict(s) for s in sessions]
            raise

    async def accept_session(self, agent_id: str, session_id: str) -> None:
        """Accept a pending broker session."""
        client = await self.get_client(agent_id)
        try:
            await asyncio.to_thread(client.accept_session, session_id)
            logger.info("Session accepted: %s (agent %s)", session_id, agent_id)
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning("Auth error for %s, re-authenticating: %s", agent_id, exc)
                client = await self._evict_and_retry(agent_id)
                await asyncio.to_thread(client.accept_session, session_id)
                return
            raise

    async def close_session(self, agent_id: str, session_id: str) -> None:
        """Close a broker session."""
        client = await self.get_client(agent_id)
        try:
            await asyncio.to_thread(client.close_session, session_id)
            logger.info("Session closed: %s (agent %s)", session_id, agent_id)
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning("Auth error for %s, re-authenticating: %s", agent_id, exc)
                client = await self._evict_and_retry(agent_id)
                await asyncio.to_thread(client.close_session, session_id)
                return
            raise

    async def discover_agents(
        self,
        agent_id: str,
        capabilities: list[str] | None = None,
        q: str | None = None,
        org_id: str | None = None,
        pattern: str | None = None,
    ) -> list[dict]:
        """Discover remote agents via broker."""
        client = await self.get_client(agent_id)
        try:
            agents = await asyncio.to_thread(
                client.discover, capabilities, org_id, pattern, q,
            )
            return [_agent_info_to_dict(a) for a in agents]
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning("Auth error for %s, re-authenticating: %s", agent_id, exc)
                client = await self._evict_and_retry(agent_id)
                agents = await asyncio.to_thread(
                    client.discover, capabilities, org_id, pattern, q,
                )
                return [_agent_info_to_dict(a) for a in agents]
            raise

    # ── Shutdown ────────────────────────────────────────────────────

    async def shutdown(self) -> None:
        """Close all cached clients."""
        async with self._lock:
            for agent_id, client in self._clients.items():
                try:
                    client.close()
                    logger.debug("Closed client for %s", agent_id)
                except Exception as exc:
                    logger.warning("Error closing client for %s: %s", agent_id, exc)
            self._clients.clear()
        logger.info("BrokerBridge shutdown — all clients closed")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _is_auth_error(exc: Exception) -> bool:
    """Detect authentication-related errors that warrant a re-login."""
    import httpx as _httpx

    if isinstance(exc, _httpx.HTTPStatusError):
        return exc.response.status_code in (401, 403)
    if isinstance(exc, RuntimeError) and "not authenticated" in str(exc).lower():
        return True
    return False


def _inbox_to_dict(msg: Any) -> dict:
    """Convert an InboxMessage to a JSON-serializable dict."""
    if hasattr(msg, "__dict__"):
        d = {}
        for k, v in msg.__dict__.items():
            if not k.startswith("_"):
                d[k] = v
        return d
    return dict(msg)


def _session_to_dict(session: Any) -> dict:
    """Convert a SessionInfo to a JSON-serializable dict."""
    if hasattr(session, "__dict__"):
        return {k: v for k, v in session.__dict__.items() if not k.startswith("_")}
    return dict(session)


def _agent_info_to_dict(agent: Any) -> dict:
    """Convert an AgentInfo to a JSON-serializable dict."""
    if hasattr(agent, "__dict__"):
        return {k: v for k, v in agent.__dict__.items() if not k.startswith("_")}
    return dict(agent)
