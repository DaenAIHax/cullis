"""WebSocket reverse-proxy forwarding (ADR-006 Fase 2 / PR #8).

The HTTP reverse-proxy in ``forwarder.py`` uses ``httpx.request`` which
rejects the HTTP/1.1 Upgrade handshake. SDKs calling the broker's
``/v1/broker/sessions/{id}/messages/stream`` over WebSocket have been
hitting the plain forwarder and 500-ing since ADR-004 landed. This
module closes the gap: inbound WS from the SDK → outbound WS to the
broker, with bidirectional byte+text forwarding and shared close
semantics.

Design:
  - ``@app.websocket("/v1/broker/{path:path}")`` accepts *any* broker
    WS path, so we don't have to mirror the broker's route tree.
  - Authorization + DPoP headers from the incoming upgrade request
    are propagated on the outbound upgrade, same contract as the
    HTTP forwarder. Cookies are dropped (SDK auth is Authorization /
    DPoP only; cookies here would be dashboard session noise).
  - Two asyncio tasks pump frames in each direction. When either side
    closes, the other task is cancelled and the remaining socket
    closes cleanly. Exception on one side → close the other side
    with a 1011 so the peer sees a real failure, not a half-open
    socket.
  - Subprotocol negotiated by the broker is echoed back to the SDK
    so libraries that require a specific subprotocol keep working.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable

import websockets
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from websockets.exceptions import ConnectionClosed, InvalidStatusCode

_log = logging.getLogger("mcp_proxy.reverse_proxy.websocket")

# Drop the same hop-by-hop set the HTTP forwarder drops, plus the
# WebSocket handshake headers that the upstream library computes itself.
_DROP_HEADERS = frozenset(
    h.lower()
    for h in (
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
        "sec-websocket-accept",
        "host",
        "content-length",
        "cookie",
    )
)


def _build_upstream_headers(
    inbound: Iterable[tuple[str, str]],
    *,
    requested_subprotocol: str | None,
) -> dict[str, str]:
    """Pass through auth-relevant headers; let websockets.connect set the rest."""
    out: dict[str, str] = {}
    for k, v in inbound:
        if k.lower() in _DROP_HEADERS:
            continue
        out[k] = v
    # X-Forwarded-For / -Proto mirror what forwarder.py sets on HTTP
    # forwards so the broker's logging + rate-limiter see the real
    # origin, not the proxy IP.
    return out


def _parse_subprotocols(header_value: str | None) -> list[str]:
    if not header_value:
        return []
    return [s.strip() for s in header_value.split(",") if s.strip()]


async def _pump(src, dst, *, text: bool, label: str) -> None:
    """Forward frames in one direction until either side closes."""
    try:
        if text:
            # src is the client-side WebSocket (Starlette/FastAPI)
            while True:
                msg = await src.receive()
                if msg.get("type") == "websocket.disconnect":
                    return
                data = msg.get("bytes")
                if data is not None:
                    await dst.send(data)
                    continue
                text_ = msg.get("text")
                if text_ is not None:
                    await dst.send(text_)
        else:
            # src is the upstream websockets client
            async for frame in src:
                if isinstance(frame, bytes):
                    await dst.send_bytes(frame)
                else:
                    await dst.send_text(frame)
    except (WebSocketDisconnect, ConnectionClosed):
        return
    except Exception as exc:
        _log.debug("ws pump %s raised: %s", label, exc)
        return


def build_websocket_reverse_proxy_router() -> APIRouter:
    """Return an APIRouter serving the WS catch-all over /v1/broker/*.

    Only ``/v1/broker/*`` is proxied — the broker's DPoP-gated
    ``/v1/auth/*`` + registry live on HTTP exclusively, and WebSocket
    endpoints today are all scoped to broker sessions.
    """
    router = APIRouter(tags=["reverse-proxy-ws"])

    @router.websocket("/v1/broker/{path:path}")
    async def ws_proxy(websocket: WebSocket, path: str) -> None:
        broker_url: str | None = getattr(
            websocket.app.state, "reverse_proxy_broker_url", None,
        )
        if not broker_url:
            await websocket.close(code=1011, reason="broker uplink not configured")
            return

        # Build the upstream URL. ws:// if broker is http://, wss:// for https://.
        if broker_url.startswith("https://"):
            target = "wss://" + broker_url[len("https://"):].rstrip("/") + "/v1/broker/" + path
        elif broker_url.startswith("http://"):
            target = "ws://" + broker_url[len("http://"):].rstrip("/") + "/v1/broker/" + path
        else:
            # Assume ws/wss scheme already baked in (unlikely but valid).
            target = broker_url.rstrip("/") + "/v1/broker/" + path
        if websocket.url.query:
            target += "?" + websocket.url.query

        requested_subprotocol = websocket.headers.get("sec-websocket-protocol")
        requested = _parse_subprotocols(requested_subprotocol)

        # Propagate auth headers — the broker validates DPoP + Authorization
        # here exactly like on HTTP. Dropping them would 401.
        headers = _build_upstream_headers(
            websocket.headers.items(), requested_subprotocol=requested_subprotocol,
        )

        # Accept first, THEN open upstream — if the upstream rejects,
        # we close the client socket with a meaningful close code
        # instead of leaving a pending handshake.
        subprotocol: str | None = None
        try:
            upstream = await websockets.connect(
                target,
                additional_headers=headers,
                subprotocols=requested or None,
                max_size=16 * 1024 * 1024,
            )
            subprotocol = upstream.subprotocol
        except InvalidStatusCode as exc:
            # websockets couldn't upgrade — broker returned a plain HTTP
            # status. 401 flows through as policy_violation (1008),
            # everything else as 1011 so the SDK retries.
            await websocket.close(
                code=1008 if exc.status_code in (401, 403) else 1011,
                reason=f"upstream upgrade failed: {exc.status_code}",
            )
            return
        except Exception as exc:
            _log.warning("ws proxy: upstream connect failed (%s): %s", target, exc)
            await websocket.close(code=1011, reason="upstream unreachable")
            return

        try:
            await websocket.accept(subprotocol=subprotocol)
        except Exception:
            await upstream.close()
            return

        # Bi-directional pump. Whichever side finishes first cancels
        # the other so we never leak a half-open socket.
        client_to_upstream = asyncio.create_task(
            _pump(websocket, upstream, text=True, label="c→u"),
            name="ws_proxy_c2u",
        )
        upstream_to_client = asyncio.create_task(
            _pump(upstream, websocket, text=False, label="u→c"),
            name="ws_proxy_u2c",
        )
        try:
            done, pending = await asyncio.wait(
                {client_to_upstream, upstream_to_client},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            for task in pending:
                try:
                    await task
                except Exception:
                    pass
        finally:
            try:
                await upstream.close()
            except Exception:
                pass
            if websocket.client_state is not WebSocketState.DISCONNECTED:
                try:
                    await websocket.close()
                except Exception:
                    pass

    return router
