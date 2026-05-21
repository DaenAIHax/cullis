"""KYC Screener — Claude Agent SDK variant.

Drop-in alternative to ``main.py``. Uses the official Anthropic
``claude-agent-sdk`` package: the agent loop is driven by the SDK
(bundled ``claude`` CLI), not a hand-written ``while`` loop.

Why this file exists alongside ``main.py``:

- ``main.py`` (litellm chat completions, hand-written loop) is the
  LLM-agnostic variant. It gives offline deterministic tests via
  ``MockLLMClient``, and routes chat through Cullis Mastio when paired
  with ``main_stack.py``.
- ``main_sdk.py`` (this file) is the **Claude Agent SDK variant**. It
  unlocks the Anthropic Partner Network "Claude Agent SDK" tier and
  matches Anthropic's reference architecture for finance agents.

Where Cullis governance applies in this variant:

- Each tool exposed to the SDK is a thin wrapper around the existing
  handler in ``tools.py``. The wrapper preserves the same contract:
  capability gate fires BEFORE the mock provider runs, audit chain
  records every call + result. Capability denials surface as
  structured tool results so the LLM can self-correct.
- Chat traffic flows ``ClaudeSDKClient → claude CLI → api.anthropic.com``
  (direct, NOT through Cullis Mastio). The Cullis trust boundary is
  the tool boundary, not the chat boundary. For ``main_stack.py``
  equivalent (chat through Mastio), see that file.

Run::

    pip install -e sandbox/agents-demo/[sdk]
    export ANTHROPIC_API_KEY=sk-ant-...
    python -m sandbox.agents-demo.agent_kyc_screener.main_sdk \\
        --case-id case_demo_001 --document-id doc_low_risk_retail
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parents[2]
if str(_REPO_ROOT / "sandbox" / "agents-demo") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "sandbox" / "agents-demo"))

from shared.audit_hooks import AuditChain  # noqa: E402
from shared.capability_gate import CapabilityGate, Principal  # noqa: E402

from .tools import dispatch  # noqa: E402

_log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-haiku-4-5"
CAPABILITIES_PATH = _THIS_DIR / "capabilities.yaml"
SYSTEM_PROMPT_PATH = _THIS_DIR / "system_prompt.md"
MAX_TURNS = 12


@dataclass(frozen=True)
class KYCDecision:
    case_id: str
    document_hash: str
    score: int
    outcome: str
    reasoning_summary: str
    audit_entries: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "document_hash": self.document_hash,
            "score": self.score,
            "outcome": self.outcome,
            "reasoning_summary": self.reasoning_summary,
            "audit_entries": self.audit_entries,
        }


def _import_sdk():
    """Lazy import so the file is loadable even when the SDK is not
    installed (e.g. in CI running ``main.py`` tests only)."""

    try:
        from claude_agent_sdk import (
            AssistantMessage,
            ClaudeAgentOptions,
            ClaudeSDKClient,
            TextBlock,
            create_sdk_mcp_server,
            tool,
        )
    except ImportError as exc:
        raise RuntimeError(
            "claude-agent-sdk is not installed. Run:\n"
            "    pip install -e sandbox/agents-demo/[sdk]\n"
            "or install directly:\n"
            "    pip install claude-agent-sdk"
        ) from exc
    return AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient, TextBlock, create_sdk_mcp_server, tool


def _build_kyc_tools(
    principal: Principal, gate: CapabilityGate, audit: AuditChain,
):
    """Wrap each existing handler in an @tool decorator. The handler
    already does capability gate + audit + dispatch — the wrapper is
    a thin async adapter to the SDK's MCP envelope format."""

    _AM, _OPT, _CL, _TB, _MK, tool_decorator = _import_sdk()

    def _envelope(payload: dict[str, Any]) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": json.dumps(payload)}]}

    @tool_decorator(
        "verify_identity",
        "Verify an identity document against the (mocked) Onfido / Veriff provider.",
        {"document_id": str},
    )
    async def _verify_identity(args: dict[str, Any]) -> dict[str, Any]:
        result = dispatch("verify_identity", args, principal=principal, gate=gate, audit=audit)
        return _envelope(result)

    @tool_decorator(
        "screen_sanctions",
        "Screen a (family_name, given_name, dob) tuple against mocked OFAC + EU consolidated lists and PEP register.",
        {"family_name": str, "given_name": str, "dob": str},
    )
    async def _screen_sanctions(args: dict[str, Any]) -> dict[str, Any]:
        result = dispatch("screen_sanctions", args, principal=principal, gate=gate, audit=audit)
        return _envelope(result)

    @tool_decorator(
        "query_beneficial_owners",
        "Look up the beneficial owners for a corporate entity (mock OpenCorporates).",
        {"entity_name": str},
    )
    async def _query_beneficial_owners(args: dict[str, Any]) -> dict[str, Any]:
        result = dispatch("query_beneficial_owners", args, principal=principal, gate=gate, audit=audit)
        return _envelope(result)

    @tool_decorator(
        "escalate_to_compliance",
        "Hand the case to a human compliance officer queue. MUST be called when score >= 30 or any sanctions/PEP hit.",
        {"case_id": str, "reason": str, "score": int},
    )
    async def _escalate_to_compliance(args: dict[str, Any]) -> dict[str, Any]:
        result = dispatch("escalate_to_compliance", args, principal=principal, gate=gate, audit=audit)
        return _envelope(result)

    return [_verify_identity, _screen_sanctions, _query_beneficial_owners, _escalate_to_compliance]


async def run_async(
    *,
    case_id: str,
    document_id: str,
    principal: Principal,
    model: str = DEFAULT_MODEL,
    audit: AuditChain | None = None,
) -> tuple[KYCDecision, AuditChain]:
    """Drive one KYC case through the Claude Agent SDK loop.

    Mirrors ``main.run`` but delegates the agent loop to the SDK.
    Capability + audit semantics are preserved end-to-end.
    """

    (AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient,
     TextBlock, create_sdk_mcp_server, _tool) = _import_sdk()

    audit = audit or AuditChain(agent_id="kyc_screener", org_id=principal.org_id)
    gate = CapabilityGate.from_yaml(CAPABILITIES_PATH, audit=audit)

    audit.append(
        "agent_invoked",
        {
            "agent": "kyc_screener",
            "variant": "claude-agent-sdk",
            "case_id": case_id,
            "document_id": document_id,
            "principal_id": principal.principal_id,
            "principal_type": principal.principal_type,
            "model": model,
        },
    )
    gate.require(principal, capability="kyc.read", context={"case_id": case_id})

    tools = _build_kyc_tools(principal, gate, audit)
    mcp_server = create_sdk_mcp_server(name="kyc", version="1.0.0", tools=tools)

    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT_PATH.read_text(encoding="utf-8"),
        mcp_servers={"kyc": mcp_server},
        allowed_tools=[
            "mcp__kyc__verify_identity",
            "mcp__kyc__screen_sanctions",
            "mcp__kyc__query_beneficial_owners",
            "mcp__kyc__escalate_to_compliance",
        ],
        # Pre-approve our governed tools. The Cullis capability gate
        # already fires inside each wrapper, so the SDK's permission
        # prompt would be redundant.
        permission_mode="bypassPermissions",
        max_turns=MAX_TURNS,
        model=model,
    )

    initial_prompt = (
        f"Process KYC case {case_id} for document {document_id}. "
        "Use the available tools to verify the identity, screen sanctions and PEP, "
        "query beneficial owners if the document is corporate, and decide. "
        "Output the final decision as a JSON object on the LAST line of your reply: "
        '{"case_id": ..., "document_hash": ..., "score": <0-100>, '
        '"outcome": "auto_approve"|"escalate", "reasoning_summary": ...}.'
    )

    final_text_parts: list[str] = []
    async with ClaudeSDKClient(options=options) as client:
        await client.query(initial_prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        final_text_parts.append(block.text)

    final_text = "\n".join(final_text_parts)
    audit.append(
        "agent_completed",
        {"variant": "claude-agent-sdk", "final_chars": len(final_text)},
    )

    decision = _parse_decision(final_text, case_id=case_id, document_id=document_id)
    audit.append("decision", decision.to_dict())

    return (
        KYCDecision(
            case_id=decision.case_id,
            document_hash=decision.document_hash,
            score=decision.score,
            outcome=decision.outcome,
            reasoning_summary=decision.reasoning_summary,
            audit_entries=len(audit.entries),
        ),
        audit,
    )


def run(
    *,
    case_id: str,
    document_id: str,
    principal: Principal,
    model: str = DEFAULT_MODEL,
    audit: AuditChain | None = None,
) -> tuple[KYCDecision, AuditChain]:
    """Sync wrapper around ``run_async``.

    ``anyio.run`` only accepts positional args for the target coroutine,
    so we adapt via a no-arg closure.
    """

    import anyio

    async def _adapter() -> tuple[KYCDecision, AuditChain]:
        return await run_async(
            case_id=case_id,
            document_id=document_id,
            principal=principal,
            model=model,
            audit=audit,
        )

    return anyio.run(_adapter)


def _parse_decision(content: str, *, case_id: str, document_id: str) -> KYCDecision:
    """Same parser as ``main._parse_decision``. Strips fences, finds the
    first balanced JSON object, fails closed on missing required fields."""

    import hashlib

    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", content, flags=re.IGNORECASE | re.MULTILINE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.MULTILINE)
    match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise ValueError(f"No JSON decision found in agent output: {content[:300]!r}")

    payload = json.loads(match.group(0))
    return KYCDecision(
        case_id=payload.get("case_id", case_id),
        document_hash=payload.get("document_hash")
            or hashlib.sha256(document_id.encode("utf-8")).hexdigest(),
        score=int(payload["score"]),
        outcome=payload["outcome"],
        reasoning_summary=payload.get("reasoning_summary", ""),
        audit_entries=0,
    )


def _cli() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--document-id", required=True)
    parser.add_argument("--principal-id", default="orga::kyc-screener")
    parser.add_argument("--org-id", default="orga")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    principal = Principal(
        principal_id=args.principal_id,
        principal_type="agent",
        org_id=args.org_id,
        capabilities=frozenset({"kyc.read", "kyc.submit", "kyc.escalate"}),
    )

    decision, audit = run(
        case_id=args.case_id,
        document_id=args.document_id,
        principal=principal,
        model=args.model,
    )

    print(json.dumps(decision.to_dict(), indent=2))
    last = audit.entries[-1] if audit.entries else None
    last_sig = (last.signature[:16] if last else "<empty>")
    sys.stderr.write(
        f"\n[audit] {len(audit.entries)} entries, last_sig={last_sig}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
