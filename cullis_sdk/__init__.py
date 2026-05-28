"""
cullis-sdk: Python SDK for Cullis Mastio.

Zero-trust identity, policy, and audit for autonomous AI agents in
regulated environments. The SDK talks to a self-hosted Cullis Mastio
(the org-level gateway) over mTLS + DPoP-bound requests. The Mastio
dispatches LLM calls to Anthropic, OpenAI, or Ollama through native
adapters (no third-party AI gateway library in the critical path,
ADR-039) and writes every action to a hash-chained audit log.

Canonical usage (ADR-014 mTLS-cert-as-credential)::

    from cullis_sdk import CullisClient

    # Admin minted this identity in the Mastio dashboard
    # ("Create agent manually") and sent you the identity-bundle.zip.
    client = CullisClient.from_identity_dir(
        "https://mastio.acme.local:9443",
        cert_path="/etc/cullis/agent/agent.crt",
        key_path="/etc/cullis/agent/agent.key",
        verify_tls=False,  # self-signed Org CA in dev; pin in prod
    )

    response = client.chat_completion(
        model="claude-sonnet-4-6",
        messages=[{"role": "user", "content": "Hello."}],
    )

    for tool in client.list_mcp_tools():
        print(tool["name"])

    result = client.call_mcp_tool("sanctions_lookup", {"q": "ACME"})

For vanilla Anthropic / OpenAI SDK drop-in (ADR-038 Phase 0), see
``cullis_sdk.providers_compat.cullis_httpx_client``.

See ``README.md`` for the full quickstart and architecture diagram.
"""

from cullis_sdk.client import CullisClient
from cullis_sdk._client._discovery import PubkeyFetchError
from cullis_sdk._client._websocket import WebSocketConnection
from cullis_sdk.dpop import DpopKey
from cullis_sdk.types import AgentInfo, SessionInfo, InboxMessage, RfqResult, RfqQuote
from cullis_sdk._logging import log, log_msg
from cullis_sdk._env import load_env_file, cfg

__all__ = [
    "CullisClient",
    "PubkeyFetchError",
    "WebSocketConnection",
    "DpopKey",
    "AgentInfo",
    "SessionInfo",
    "InboxMessage",
    "RfqResult",
    "RfqQuote",
    "load_env_file",
    "cfg",
    "log",
    "log_msg",
]

__version__ = "0.2.2"
