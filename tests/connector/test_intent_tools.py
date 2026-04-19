"""Tests for the intent-level MCP tools (contact / chat).

These exercise the public MCP surface, not the resolve_peer helper
(covered in test_intent_resolve_peer.py). The CullisClient is mocked
so we can drive scenario without a real Mastio.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cullis_connector.config import ConnectorConfig
from cullis_connector.state import get_state, reset_state
from cullis_connector.tools import intent
from cullis_sdk.types import AgentInfo


class _FakeFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorator


class _FakeClient:
    """Stub CullisClient used by both ``contact`` and ``chat``."""

    def __init__(
        self,
        peers: list[AgentInfo] | None = None,
        signing_key: str = "PEM",
    ) -> None:
        self._peers = peers or []
        self._signing_key_pem = signing_key
        self.sent: list[tuple[str, dict]] = []
        # Side-channel mock for send_oneshot return value.
        self._send_response = {
            "correlation_id": "corr-123",
            "msg_id": "msg-abc",
            "status": "enqueued",
        }

    def list_peers(self, q: str | None = None, limit: int = 50) -> list[AgentInfo]:
        if q is None:
            return list(self._peers)[:limit]
        ql = q.lower()
        return [
            p for p in self._peers
            if ql in p.agent_id.lower() or ql in (p.display_name or "").lower()
        ][:limit]

    def send_oneshot(self, recipient_id: str, payload: dict, **kwargs):
        self.sent.append((recipient_id, payload))
        return dict(self._send_response)


def _peer(name: str, display: str = "", org: str = "acme") -> AgentInfo:
    return AgentInfo(
        agent_id=f"{org}::{name}",
        org_id=org,
        display_name=display,
    )


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path):
    reset_state()
    get_state().config = ConnectorConfig(
        site_url="https://mastio.test",
        config_dir=tmp_path,
        verify_tls=False,
        request_timeout_s=2.0,
    )
    yield
    reset_state()


@pytest.fixture
def tools():
    mcp = _FakeFastMCP()
    intent.register(mcp)
    return mcp.tools


def _install_client(peers: list[AgentInfo]) -> _FakeClient:
    client = _FakeClient(peers=peers)
    get_state().client = client
    return client


# ── contact() ────────────────────────────────────────────────────────


def test_contact_single_match_sets_active_peer(tools):
    _install_client([_peer("mario", "Mario Rossi")])
    out = tools["contact"]("mario")
    assert "Mario Rossi" in out
    assert "acme::mario" in out
    assert get_state().last_peer_resolved == "acme::mario"


def test_contact_canonical_handle_short_circuits(tools):
    _install_client([_peer("mario", "Mario Rossi")])
    out = tools["contact"]("acme::mario")
    assert "Mario Rossi" in out
    assert get_state().last_peer_resolved == "acme::mario"


def test_contact_at_alias_normalizes(tools):
    """`mario@acme` should resolve identically to `acme::mario`."""
    _install_client([_peer("mario", "Mario Rossi")])
    out = tools["contact"]("mario@acme")
    assert "acme::mario" in out
    assert get_state().last_peer_resolved == "acme::mario"


def test_contact_zero_matches_returns_suggestions(tools):
    _install_client([
        _peer("mario", "Mario Rossi"),
        _peer("salesbot", "Sales Bot"),
    ])
    out = tools["contact"]("xyzzy")
    assert "No peer matches 'xyzzy'" in out
    # Suggestions list at least one of the existing peers.
    assert "Mario Rossi" in out or "Sales Bot" in out
    assert get_state().last_peer_resolved is None


def test_contact_zero_matches_no_peers_at_all(tools):
    _install_client([])
    out = tools["contact"]("anybody")
    assert "No peer matches" in out
    assert "nobody else has enrolled" in out


def test_contact_multiple_matches_caches_and_prompts_pick(tools):
    _install_client([
        _peer("mario", "Mario Rossi"),
        _peer("maria", "Maria Bianchi"),
        _peer("mariano", "Mariano Verdi"),
    ])
    out = tools["contact"]("mar")
    assert "Found" in out and "matches" in out
    assert "#1" in out and "#2" in out
    # Active peer NOT set yet — the user must pick.
    assert get_state().last_peer_resolved is None
    # Candidates cached for the index pick to retrieve.
    cached = get_state().extra.get("intent.last_candidates")
    assert cached is not None and len(cached) >= 2


def test_contact_index_pick_resolves_against_cache(tools):
    _install_client([
        _peer("mario", "Mario Rossi"),
        _peer("maria", "Maria Bianchi"),
    ])
    tools["contact"]("mar")  # cache populated
    out = tools["contact"]("#2")
    assert get_state().last_peer_resolved is not None
    assert get_state().last_peer_resolved.startswith("acme::")
    # Cache cleared after a successful pick so a stale '#2' doesn't
    # leak into the next round.
    assert "intent.last_candidates" not in get_state().extra
    # Bare index without # also works.
    tools["contact"]("mar")
    out = tools["contact"]("1")
    assert get_state().last_peer_resolved is not None


def test_contact_index_pick_out_of_range_falls_through_to_lookup(tools):
    """`#9` when only 2 candidates → not a valid pick → treat as a
    lookup query, which then resolves to no match."""
    _install_client([_peer("mario"), _peer("maria")])
    tools["contact"]("mar")
    out = tools["contact"]("#9")
    # No peer named "#9" exists; the lookup yields no match.
    assert "No peer matches" in out


# ── chat() ───────────────────────────────────────────────────────────


def test_chat_without_active_peer_warns_user(tools):
    _install_client([_peer("mario")])
    out = tools["chat"]("ciao")
    assert "No active peer" in out
    assert "contact" in out


def test_chat_routes_to_active_peer(tools):
    client = _install_client([_peer("mario", "Mario Rossi")])
    tools["contact"]("mario")
    out = tools["chat"]("ciao da test")
    assert "Sent to acme::mario" in out
    assert "correlation_id=corr-123" in out

    assert client.sent == [(
        "acme::mario",
        {"type": "message", "text": "ciao da test"},
    )]
    assert get_state().last_correlation_id == "corr-123"


def test_chat_send_failure_reports_error(tools):
    client = _install_client([_peer("mario")])
    tools["contact"]("mario")

    def _boom(recipient_id, payload, **kwargs):
        raise RuntimeError("network down")
    client.send_oneshot = _boom  # type: ignore[assignment]

    out = tools["chat"]("hi")
    assert "Failed to send" in out
    assert "network down" in out
