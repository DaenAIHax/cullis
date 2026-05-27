"""Provider adapter scaffolding (ADR-039).

The dispatcher in ``mcp_proxy.egress.ai_gateway`` resolves an adapter for
the configured ``ai_gateway_backend`` and delegates the upstream call to
it. Each backend has at least one adapter implementation; adapters carry
the per-backend wire knowledge (LiteLLM library, Portkey REST, native
provider SDK, raw HTTP) while the dispatcher stays generic.

ADR-039 phasing:
  - Phase 1a (PR-A, this scaffold): factor out ``LiteLLMAdapter`` and
    ``PortkeyAdapter`` from the existing ``ai_gateway.py`` monolith. Zero
    behaviour change on the wire — same dispatch decisions, same error
    surface, same audit log line — but the dispatcher now goes through
    the adapter protocol.
  - Phase 1b-d (PR-B/C/D): introduce ``cullis_native`` backend with one
    native adapter per provider (Anthropic SDK, OpenAI SDK, Ollama HTTP).
  - Phase 1e (PR-E): flip the default backend to ``cullis_native`` and
    deprecate ``litellm_embedded`` (removed in v0.8).

See ``imp/adrs/adr-039-native-provider-adapters-server-side-drop-litellm.md``
for the full design.
"""
from __future__ import annotations

from mcp_proxy.egress.adapters.base import DispatchContext, ProviderAdapter
from mcp_proxy.egress.adapters.litellm import LiteLLMAdapter
from mcp_proxy.egress.adapters.portkey import PortkeyAdapter


def resolve_adapter(backend: str) -> ProviderAdapter:
    """Return the adapter instance configured for ``backend``.

    Raises ``GatewayError(501)`` for unknown backend values. The lookup
    is intentionally explicit (no registry import side-effects, no
    plugin discovery) so an operator misconfiguration surfaces a clear
    error on the first request rather than an obscure import-time crash.

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
    raise GatewayError(
        501,
        f"backend_not_implemented:{backend}",
        detail=f"AI gateway backend {backend!r} is not wired.",
    )


__all__ = [
    "DispatchContext",
    "LiteLLMAdapter",
    "PortkeyAdapter",
    "ProviderAdapter",
    "resolve_adapter",
]
