"""
Server-Sent Events manager for real-time dashboard updates.

Connected dashboard clients receive lightweight event notifications
when data changes. The frontend uses these to trigger targeted HTMX
partial refreshes — no polling, no wasted bandwidth.
"""
import asyncio
import json
import logging
import time
from asyncio import Queue
from dataclasses import dataclass, field

_log = logging.getLogger("agent_trust.sse")

# Map audit event_type prefixes to dashboard categories
_EVENT_CATEGORY_MAP = {
    "broker.session": "sessions",
    "broker.message": "sessions",
    "broker.transaction": "sessions",
    "session_closed": "sessions",
    "policy.session_denied": "sessions",
    "registry.agent": "agents",
    "agent.cert": "agents",
    "registry.ca_certificate": "orgs",
    "registry.org": "orgs",
    "onboarding": "orgs",
    "rfq": "rfqs",
    "policy": "policies",
    "admin": "overview",
    "dashboard.oidc": "overview",
    "cert.revoked": "agents",
}


def _categorize_event(event_type: str) -> set[str]:
    """Return which dashboard pages should refresh for this event type."""
    categories = set()
    for prefix, category in _EVENT_CATEGORY_MAP.items():
        if event_type.startswith(prefix):
            categories.add(category)
    # Every mutation refreshes overview (stats) and audit
    categories.add("overview")
    categories.add("audit")
    return categories


@dataclass
class _Client:
    queue: Queue = field(default_factory=lambda: Queue(maxsize=64))
    connected_at: float = field(default_factory=time.time)
    org_id: str | None = None
    is_admin: bool = False


class DashboardSSEManager:
    """Manages SSE connections for dashboard real-time updates."""

    def __init__(self) -> None:
        self._clients: dict[int, _Client] = {}
        self._counter = 0

    def connect(self, *, org_id: str | None = None, is_admin: bool = False) -> tuple[int, Queue]:
        self._counter += 1
        client = _Client(org_id=org_id, is_admin=is_admin)
        self._clients[self._counter] = client
        _log.info("SSE client connected (id=%d, org=%s, total=%d)", self._counter, org_id, len(self._clients))
        return self._counter, client.queue

    def disconnect(self, client_id: int) -> None:
        self._clients.pop(client_id, None)
        _log.info("SSE client disconnected (id=%d, total=%d)", client_id, len(self._clients))

    async def broadcast(self, event_type: str, data: dict | None = None, org_id: str | None = None) -> None:
        """Broadcast an event to connected dashboard clients.

        Events are filtered by org_id: admin clients receive all events,
        org clients only receive events matching their org_id (or events
        without an org_id, like system-wide notifications).
        """
        if not self._clients:
            return

        categories = _categorize_event(event_type)
        payload = json.dumps({
            "event_type": event_type,
            "categories": list(categories),
            "ts": time.time(),
            **(data or {}),
        })

        disconnected = []
        for cid, client in self._clients.items():
            # Filter: admins see everything; org clients only see their org's events
            if not client.is_admin and org_id and client.org_id and client.org_id != org_id:
                continue
            try:
                client.queue.put_nowait(payload)
            except asyncio.QueueFull:
                disconnected.append(cid)
                _log.warning("SSE client %d queue full, dropping", cid)

        for cid in disconnected:
            self._clients.pop(cid, None)

    @property
    def client_count(self) -> int:
        return len(self._clients)


# Singleton
sse_manager = DashboardSSEManager()
