"""Intent-level MCP tools for natural-language peer interaction.

Wraps the low-level ``send_oneshot`` / ``receive_oneshot`` / ``discover``
primitives so the user can write "contact mario" / "send him hello"
instead of remembering SPIFFE handles. The low-level tools stay
exposed for power users and tests; nothing here changes the wire
format or the broker contract.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cullis_connector._logging import get_logger
from cullis_connector.state import get_state
from cullis_connector.tools.session import _require_oneshot_client
from cullis_sdk.types import AgentInfo

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_log = get_logger("tools.intent")


@dataclass(frozen=True)
class PeerCandidate:
    """A single peer match returned by :func:`resolve_peer`."""
    agent_id: str          # always canonical "<org>::<name>"
    display_name: str
    org_id: str
    score: float           # 1.0 == exact, lower == fuzzier
    scope: str             # "intra-org" | "cross-org"


def _name_only(agent_id: str) -> str:
    """Strip the org prefix from a canonical handle, if present."""
    return agent_id.split("::", 1)[1] if "::" in agent_id else agent_id


def _candidate(info: AgentInfo, score: float) -> PeerCandidate:
    return PeerCandidate(
        agent_id=info.agent_id,
        display_name=info.display_name or _name_only(info.agent_id),
        org_id=info.org_id,
        score=score,
        scope="cross-org" if info.org_id and "::" in info.agent_id and not info.agent_id.startswith(f"{info.org_id}::") else (
            "intra-org" if info.org_id else "intra-org"
        ),
    )


def resolve_peer(client, query: str, *, fuzzy_cutoff: float = 0.75) -> list[PeerCandidate]:
    """Look up peers matching ``query`` via the local Mastio.

    Strategy (cheapest first):
      1. Server-side prefilter via ``client.list_peers(q=query)``
         (substring match on agent_id / display_name).
      2. Promote exact / substring-prefix matches to score 1.0 so they
         sort above any fuzzy hits — stops a well-named typosquat
         (e.g. ``southfake``) from piggy-backing on a difflib ratio
         higher than the legitimate substring match ``south``.
      3. Rank remaining candidates with ``difflib.SequenceMatcher``
         against name + agent_id and keep only those above
         ``fuzzy_cutoff`` (default 0.75 — low enough for single-char
         typos like ``marioo`` but high enough to reject
         ``south → southfake``).
      4. If the server prefilter returned 0, fall back to listing the
         full visible peer set and re-running the fuzzy ranker — covers
         typos that don't substring-match.

    The returned list is sorted by score descending. Caller decides
    how to handle 0 / 1 / many matches (the ``contact`` MCP tool
    presents disambiguation). **Callers must never auto-select a
    single fuzzy hit** — an exact-match short-circuit is the only safe
    auto-pick path, the ``contact`` tool enforces this below.
    """
    qnorm = query.strip()
    if not qnorm:
        return []

    # If the caller already typed a canonical handle, short-circuit —
    # we don't need to invent fuzziness when they meant exactly this.
    if "::" in qnorm:
        peers = client.list_peers(q=qnorm, limit=10)
        for p in peers:
            if p.agent_id == qnorm:
                return [_candidate(p, score=1.0)]
        # Canonical handle that the Mastio doesn't know — let the
        # caller decide what to do (404 vs typo).
        return []

    # 1. Substring prefilter on the server.
    candidates = client.list_peers(q=qnorm, limit=50)

    # 2. If the prefilter is empty, broaden to the full set and
    #    rely on difflib for typos.
    if not candidates:
        candidates = client.list_peers(limit=200)

    # 3. Rank each candidate. Exact matches win outright; substring-
    #    prefix matches rank higher than arbitrary difflib ratios so a
    #    typosquat (``southfake`` containing the query ``south``) can't
    #    outrank the legitimate substring ``south``. Substring-anywhere
    #    gets a solid score but still below prefix so the obvious match
    #    surfaces first in multi-candidate disambiguation.
    scored: list[PeerCandidate] = []
    qlower = qnorm.lower()
    for info in candidates:
        name = (info.display_name or _name_only(info.agent_id)).lower()
        handle_full = info.agent_id.lower()
        handle_short = _name_only(handle_full)

        if qlower == handle_short or qlower == handle_full or qlower == name:
            score = 1.0
        elif handle_short.startswith(qlower) or name.startswith(qlower):
            # Substring-prefix — definitely intentional, definitely
            # above any fuzzy ratio.
            score = 0.95
        elif qlower in handle_short or qlower in name:
            # Substring-anywhere — still a clean prefilter hit, below
            # prefix so prefixes sort first.
            score = 0.90
        else:
            name_ratio = difflib.SequenceMatcher(None, qlower, name).ratio()
            handle_ratio = difflib.SequenceMatcher(None, qlower, handle_short).ratio()
            score = max(name_ratio, handle_ratio)

        if score >= fuzzy_cutoff:
            scored.append(_candidate(info, score=score))

    scored.sort(key=lambda c: c.score, reverse=True)
    return scored


# ── MCP tools ──────────────────────────────────────────────────────────


_CANDIDATES_KEY = "intent.last_candidates"


def _format_candidate(idx: int, c: PeerCandidate) -> str:
    return (
        f"  #{idx + 1}  {c.display_name}  ({c.agent_id})"
        f"  [{c.scope}]"
    )


def _resolve_index_pick(query: str) -> PeerCandidate | None:
    """Interpret ``contact("#2")`` / ``contact("2")`` against the
    candidate list cached from the previous ``contact`` call.
    Returns the chosen candidate or None if the input is not a pick."""
    raw = query.strip().lstrip("#")
    if not raw.isdigit():
        return None
    idx = int(raw) - 1
    candidates = get_state().extra.get(_CANDIDATES_KEY) or []
    if 0 <= idx < len(candidates):
        return candidates[idx]
    return None


def register(mcp: "FastMCP") -> None:
    @mcp.tool()
    def contact(peer: str) -> str:
        """Set the active peer for follow-up `chat` / `reply` calls.

        Looks up `peer` against the local Mastio's peer list. Accepts:
          - a bare name ("mario") or a canonical handle ("acme::mario"),
          - an org-scoped form ("mario@acme") which is also accepted,
          - an index pick ("#2" or "2") when the previous contact()
            returned multiple candidates.

        Behavior:
          - 1 match → saves as active peer, returns confirmation.
          - n matches → caches them, returns a numbered list and asks
            the user to call contact("#N") to pick.
          - 0 matches → suggests the closest names from the visible
            peer set.

        After a successful resolve, `chat(text)` will route to this
        peer without further parameters.
        """
        client = _require_oneshot_client()
        state = get_state()

        # Index pick from a previous disambiguation round?
        picked = _resolve_index_pick(peer)
        if picked is not None:
            state.last_peer_resolved = picked.agent_id
            state.extra.pop(_CANDIDATES_KEY, None)
            return f"Active peer: {picked.display_name} ({picked.agent_id})."

        # Allow "mario@chipfactory" as an alias for "chipfactory::mario".
        normalized = peer.strip()
        if "@" in normalized and "::" not in normalized:
            name, _, org = normalized.partition("@")
            normalized = f"{org}::{name}"

        try:
            candidates = resolve_peer(client, normalized)
        except Exception as exc:  # noqa: BLE001
            _log.warning("resolve_peer failed for %r: %s", peer, exc)
            return f"Lookup failed for '{peer}': {exc}"

        if not candidates:
            # Try one more pass to suggest near-misses from the full set.
            try:
                full = client.list_peers(limit=200)
            except Exception:  # noqa: BLE001
                full = []
            suggestions = [
                f"{p.display_name or p.agent_id} ({p.agent_id})"
                for p in full[:5]
            ]
            base = f"No peer matches '{peer}'."
            if suggestions:
                return base + " Did you mean:\n" + "\n".join(
                    f"  - {s}" for s in suggestions
                )
            return base + " The peer list is empty — nobody else has enrolled yet."

        # Auto-select ONLY on an exact match (score == 1.0). Fuzzy hits
        # — even when they're the only candidate — must bounce through
        # disambiguation so a typo like ``south`` can't silently land on
        # a typosquat ``southfake`` without the user confirming.
        if len(candidates) == 1 and candidates[0].score >= 1.0:
            state.last_peer_resolved = candidates[0].agent_id
            state.extra.pop(_CANDIDATES_KEY, None)
            return (
                f"Active peer: {candidates[0].display_name} "
                f"({candidates[0].agent_id})."
            )

        state.extra[_CANDIDATES_KEY] = candidates
        lines = [_format_candidate(i, c) for i, c in enumerate(candidates)]
        header = (
            f"Found {len(candidates)} match for '{peer}'"
            if len(candidates) == 1
            else f"Found {len(candidates)} matches for '{peer}'"
        )
        return (
            header + " — confirm which one you meant:\n"
            + "\n".join(lines)
            + "\n→ pick one with contact('#1'), contact('#2'), …"
        )

    @mcp.tool()
    def reply(text: str) -> str:
        """Reply to whoever sent the most recently decoded inbox message.

        After `receive_oneshot` decodes an envelope, the connector
        remembers (a) the sender as the active peer and (b) the
        msg_id as `reply_to`. `reply(text)` consumes both: it sends
        to the cached sender with the cached msg_id threaded in,
        so the recipient can correlate the response with the original
        request.

        If no message has been received and decoded yet, returns a
        prompt to call `receive_oneshot` first.
        """
        client = _require_oneshot_client()
        state = get_state()

        target = state.last_peer_resolved
        reply_to = state.last_reply_to
        if not target or not reply_to:
            return (
                "Nothing to reply to. Call receive_oneshot first to "
                "fetch a message; reply() then threads the response."
            )

        try:
            result = client.send_oneshot(
                target,
                {"type": "message", "text": text},
                reply_to=reply_to,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("reply send to %s failed: %s", target, exc)
            return f"Failed to reply to {target}: {exc}"

        state.last_correlation_id = result.get("correlation_id")
        return (
            f"Reply sent to {target} "
            f"(threaded as reply to {reply_to[:8]}…, "
            f"correlation_id={result.get('correlation_id')})."
        )

    @mcp.tool()
    def chat(text: str) -> str:
        """Send a message to the currently active peer (set by `contact`).

        Equivalent to `send_oneshot(active_peer, text)` but with no
        bookkeeping for the user. If no peer is active, returns a
        prompt to call `contact` first.
        """
        client = _require_oneshot_client()
        state = get_state()

        target = state.last_peer_resolved
        if not target:
            return (
                "No active peer. Use contact('<name>') first to pick "
                "who you want to talk to."
            )

        try:
            result = client.send_oneshot(
                target,
                {"type": "message", "text": text},
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("chat send to %s failed: %s", target, exc)
            return f"Failed to send to {target}: {exc}"

        state.last_correlation_id = result.get("correlation_id")
        return (
            f"Sent to {target} "
            f"(correlation_id={result.get('correlation_id')})."
        )
