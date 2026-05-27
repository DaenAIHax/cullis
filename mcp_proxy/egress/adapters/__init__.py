"""Provider adapter scaffolding (ADR-039).

The dispatcher in ``mcp_proxy.egress.ai_gateway`` resolves an adapter
for the configured ``ai_gateway_backend`` (and, in the new
``cullis_native`` backend, also the resolved provider) and delegates
the upstream call to it. Each backend has at least one adapter
implementation; adapters carry the per-backend wire knowledge (LiteLLM
library, Portkey REST, native provider SDK, raw HTTP) while the
dispatcher stays generic.

ADR-039 phasing:
  - Phase 1a (PR-A): factor out ``LiteLLMAdapter`` and ``PortkeyAdapter``
    from the existing ``ai_gateway.py`` monolith. Zero behaviour change
    on the wire.
  - Phase 1b (PR-B): introduce ``cullis_native`` backend with
    ``AnthropicAdapter`` (anthropic.AsyncAnthropic SDK). Default
    backend stays ``litellm_embedded``; ``cullis_native`` is opt-in
    via env var.
  - Phase 1c (PR-C): add ``OpenAIAdapter`` under ``cullis_native``
    (openai.AsyncOpenAI SDK, mostly passthrough on request shape).
  - Phase 1d (PR-D, this commit): add ``OllamaAdapter`` under
    ``cullis_native`` (raw httpx against ``/api/chat``, JSONL stream
    parsing, defense-in-depth SSRF gate on api_base).
  - Phase 1e (PR-E): flip the default backend to ``cullis_native`` and
    deprecate ``litellm_embedded`` (removed in v0.8).

See ``imp/adrs/adr-039-native-provider-adapters-server-side-drop-litellm.md``
for the full design.
"""
from __future__ import annotations

from mcp_proxy.egress.adapters.anthropic import AnthropicAdapter
from mcp_proxy.egress.adapters.base import DispatchContext, ProviderAdapter
from mcp_proxy.egress.adapters.litellm import LiteLLMAdapter
from mcp_proxy.egress.adapters.ollama import OllamaAdapter
from mcp_proxy.egress.adapters.openai import OpenAIAdapter
from mcp_proxy.egress.adapters.portkey import PortkeyAdapter


def resolve_adapter(backend: str, provider: str | None = None) -> ProviderAdapter:
    """Return the adapter instance configured for ``(backend, provider)``.

    ``provider`` is required for ``cullis_native`` (which dispatches per
    provider) and ignored for the legacy backends (``litellm_embedded``
    and ``portkey``) that resolve internally.

    Raises ``GatewayError(501)`` for unknown backend values, or for a
    ``cullis_native`` request whose provider has no native adapter yet
    (Gemini, Bedrock, Vertex — pinned to ``litellm_embedded`` until a
    customer asks).

    Adapter instances are cheap stateless objects; we create one per
    call to keep the call site obvious. If profiling ever flags this as
    hot, swap to module-level singletons.
    """
    # Local import avoids a cycle: ai_gateway imports adapters, adapters
    # raise GatewayError defined in ai_gateway.
    from mcp_proxy.egress.ai_gateway import GatewayError

    backend = backend.lower()
    if backend == "litellm_embedded":
        return LiteLLMAdapter()
    if backend == "portkey":
        return PortkeyAdapter()
    if backend == "cullis_native":
        if provider == "anthropic":
            return AnthropicAdapter()
        if provider == "openai":
            return OpenAIAdapter()
        if provider == "ollama":
            return OllamaAdapter()
        # Gemini / Bedrock / Vertex stay on litellm_embedded until a
        # customer asks; fall through to the explicit "no native
        # adapter" error so the dashboard surface gives a clear pointer
        # rather than a generic 501.
        raise GatewayError(
            501,
            f"provider_native_not_implemented:{provider or 'unknown'}",
            detail=(
                f"The cullis_native backend has no adapter for provider "
                f"{provider!r} yet. Pin "
                f"MCP_PROXY_AI_GATEWAY_BACKEND=litellm_embedded to keep "
                f"using LiteLLM for this provider."
            ),
        )
    raise GatewayError(
        501,
        f"backend_not_implemented:{backend}",
        detail=f"AI gateway backend {backend!r} is not wired.",
    )


__all__ = [
    "AnthropicAdapter",
    "DispatchContext",
    "LiteLLMAdapter",
    "OllamaAdapter",
    "OpenAIAdapter",
    "PortkeyAdapter",
    "ProviderAdapter",
    "resolve_adapter",
]
