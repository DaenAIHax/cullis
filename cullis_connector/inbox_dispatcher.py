"""Bridge between the inbox poller and the notifier.

M2.1 produces ``InboxEvent``s on a queue; M2.2 knows how to display
them. This module is the single consumer that drains the queue,
dedupes by ``msg_id`` so a restart doesn't double-popup the same
message, and dispatches to the notifier.

Kept separate from ``inbox_poller`` so a future SSE feed (M2.4
extension) can subscribe in parallel without rewriting the producer.
"""
from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cullis_connector.inbox_poller import DashboardInboxPoller, InboxEvent
    from cullis_connector.notifier import Notifier

_log = logging.getLogger("cullis_connector.inbox_dispatcher")


class _LRUSeen:
    """Bounded set with LRU eviction, used to dedupe ``msg_id``s.

    A plain set would grow forever in long-lived dashboard processes;
    an LRU bounded at the dashboard's lifetime is enough since the
    Mastio's inbox itself ages messages out via TTL.
    """

    def __init__(self, maxsize: int = 500) -> None:
        self._maxsize = maxsize
        self._seen: OrderedDict[str, None] = OrderedDict()

    def __contains__(self, msg_id: str) -> bool:
        return msg_id in self._seen

    def add(self, msg_id: str) -> None:
        if msg_id in self._seen:
            self._seen.move_to_end(msg_id)
            return
        self._seen[msg_id] = None
        while len(self._seen) > self._maxsize:
            self._seen.popitem(last=False)


class InboxDispatcher:
    """Drains the poller queue and pushes deduped events to the notifier."""

    DASHBOARD_INBOX_URL = "http://127.0.0.1:7777/inbox"

    def __init__(
        self,
        poller: "DashboardInboxPoller",
        notifier: "Notifier",
        *,
        dedupe_size: int = 500,
        click_url: str | None = None,
    ) -> None:
        self._poller = poller
        self._notifier = notifier
        self._seen = _LRUSeen(maxsize=dedupe_size)
        self._click_url = click_url or self.DASHBOARD_INBOX_URL
        self._task: asyncio.Task | None = None

    def start(self) -> asyncio.Task:
        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self._run(), name="inbox-dispatcher")
        return self._task

    async def stop(self, *, timeout_s: float = 2.0) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await asyncio.wait_for(self._task, timeout=timeout_s)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    async def _run(self) -> None:
        _log.info("inbox dispatcher started, click_url=%s", self._click_url)
        try:
            while True:
                event = await self._poller.events.get()
                if event is self._poller.SENTINEL:
                    return
                await self._dispatch(event)
        except asyncio.CancelledError:
            raise
        finally:
            _log.info("inbox dispatcher stopped")

    async def _dispatch(self, event: "InboxEvent") -> None:
        if event.msg_id in self._seen:
            _log.debug("dedup skip msg_id=%s", event.msg_id)
            return
        self._seen.add(event.msg_id)
        # Notifiers are sync (plyer.notify is blocking on macOS at
        # least). Push to a thread so the event loop stays responsive.
        await asyncio.to_thread(
            self._notifier.notify,
            f"Message from {event.sender_agent_id}",
            event.preview(),
            on_click_url=self._click_url,
        )
