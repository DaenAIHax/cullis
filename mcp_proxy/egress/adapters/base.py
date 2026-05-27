"""Provider adapter protocol (ADR-039).

Every concrete adapter implements ``chat_completion`` and optionally
``stream_chat_completion``. The dispatcher in ``ai_gateway.dispatch``
resolves the adapter for the configured backend, calls
``_resolve_provider_creds`` once to translate the request's model id to
``(provider, creds)``, builds a ``DispatchContext`` from the
trusted-identity envelope the router reconstructs from the DPoP-bound
mTLS cert, then delegates.

Adapters never derive identity from the request body and never re-read
the DB. The dispatcher is the trust boundary; adapters are the wire
boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

if TYPE_CHECKING:
    from mcp_proxy.config import ProxySettings as Settings
    from mcp_proxy.egress.ai_gateway import GatewayResult, StreamingDispatch
    from mcp_proxy.egress.schemas import ChatCompletionRequest


@dataclass(frozen=True)
class DispatchContext:
    """Trusted-identity envelope passed by the dispatcher into adapters.

    All fields come from the cert + DPoP reconstruction the inbound
    router already performed; the adapter does not validate them.

    ``http_client`` is populated only for the legacy Portkey backend
    (which still talks REST and accepts an injected client for test
    instrumentation). Native adapters ignore it.
    """

    agent_id: str
    org_id: str
    trace_id: str
    http_client: httpx.AsyncClient | None = None


@runtime_checkable
class ProviderAdapter(Protocol):
    """Backend-to-provider call boundary.

    ``backend_name`` is the canonical tag emitted into the audit row
    and the ``backend`` field on ``GatewayResult`` / ``StreamingDispatch``.
    It matches the value the operator sets on ``MCP_PROXY_AI_GATEWAY_BACKEND``.
    """

    backend_name: str

    async def chat_completion(
        self,
        *,
        req: "ChatCompletionRequest",
        provider: str,
        creds: dict[str, str],
        ctx: DispatchContext,
        settings: "Settings",
    ) -> "GatewayResult":
        """Run a non-streaming chat completion and return the result."""
        ...

    async def stream_chat_completion(
        self,
        *,
        req: "ChatCompletionRequest",
        provider: str,
        creds: dict[str, str],
        ctx: DispatchContext,
        settings: "Settings",
    ) -> "StreamingDispatch":
        """Open a streaming chat completion.

        Adapters that do not support streaming raise
        ``GatewayError(501, "streaming_not_implemented_for_backend:...")``.
        """
        ...
