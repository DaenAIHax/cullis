"""DORA Vendor/TPA Compliance Reporter -- agent entry point.

Stack:
    Ollama on-prem via LiteLLM. Default model: `ollama/mistral-small`.
    Override with `CULLIS_DORA_REPORTER_MODEL` env var. Common choices:
        ollama/mistral-small      (Mistral AI, EU sovereignty default)
        ollama/qwen2.5            (lighter, strong tool calling)
        ollama/llama3.1           (Meta, broad availability)

    In live mode the user must have Ollama running locally:
        curl https://ollama.ai/install.sh | sh
        ollama pull mistral-small

    In mock mode (default for CI/tests) the model name is just an audit
    string; no Ollama runtime is required.

Cullis primitives demonstrated:
    - on-prem LLM sovereignty       -> the bank's vendor risk data never
                                          leaves the bank's perimeter while
                                          the very same data is used to
                                          draft the third-party register
                                          that names the LLM provider.
    - cross-org A2A via Court       -> `submit_to_auditor_org` mocks the
                                          sealed envelope + dual-write
                                          audit pattern.
    - role-gated capability         -> `dora.cross_org_submit` requires
                                          the `compliance_officer` role +
                                          target auditor org enrolled in
                                          the federation.

Quadrant: A2A cross-organisation (ADR-020).
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
_SANDBOX_DIR = _THIS_DIR.parent
if str(_SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(_SANDBOX_DIR))

from shared.audit_hooks import AuditChain  # noqa: E402
from shared.capability_gate import (  # noqa: E402
    CapabilityDenied,
    CapabilityGate,
    Principal,
)
from shared.llm_client import LLMClient, default_client  # noqa: E402

from .tools import HANDLERS, TOOL_SCHEMAS, dispatch  # noqa: E402

_log = logging.getLogger(__name__)

DEFAULT_MODEL = os.environ.get("CULLIS_DORA_REPORTER_MODEL", "ollama/mistral-small")
CAPABILITIES_PATH = _THIS_DIR / "capabilities.yaml"
SYSTEM_PROMPT_PATH = _THIS_DIR / "system_prompt.md"
MAX_LOOP_ITERATIONS = 16


@dataclass(frozen=True)
class DORAReport:
    report_id: str
    vendors_drafted: list[dict[str, Any]]
    summary: str
    submissions_attempted: int
    submissions_succeeded: int
    audit_entries: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "vendors_drafted": self.vendors_drafted,
            "summary": self.summary,
            "submissions_attempted": self.submissions_attempted,
            "submissions_succeeded": self.submissions_succeeded,
            "audit_entries": self.audit_entries,
        }


def run(
    *,
    report_id: str,
    target_auditor_org_id: str | None,
    principal: Principal,
    llm: LLMClient | None = None,
    audit: AuditChain | None = None,
) -> tuple[DORAReport, AuditChain]:
    """Run one DORA register-of-information cycle.

    `target_auditor_org_id` may be `None` for the "draft only, do not
    submit" scenario, or the ID of an auditor org enrolled in the
    Cullis Court federation. Submission additionally requires the
    invoking principal to carry the `compliance_officer` role; without
    it the gate denies and the agent reports the denial in the final
    summary instead of looping forever.
    """

    audit = audit or AuditChain(agent_id="dora_reporter", org_id=principal.org_id)
    gate = CapabilityGate.from_yaml(CAPABILITIES_PATH, audit=audit)
    llm = llm or default_client(default_model=DEFAULT_MODEL)

    audit.append(
        "agent_invoked",
        {
            "agent": "dora_reporter",
            "report_id": report_id,
            "target_auditor_org_id": target_auditor_org_id,
            "principal_id": principal.principal_id,
            "principal_type": principal.principal_type,
            "principal_roles": sorted(principal.roles),
            "model": DEFAULT_MODEL,
        },
    )
    gate.require(principal, capability="dora.read", context={"report_id": report_id})

    system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    user_instruction = (
        f"Run DORA Art. 28 reporting cycle {report_id} for org {principal.org_id}. "
    )
    if target_auditor_org_id:
        user_instruction += (
            f"After drafting, submit each CRITICAL entry to auditor org "
            f"'{target_auditor_org_id}'. "
        )
    else:
        user_instruction += "Draft only; do not cross-submit. "
    user_instruction += "Return the final JSON when ready."
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_instruction},
    ]

    final_content: str | None = None
    for iteration in range(MAX_LOOP_ITERATIONS):
        response = llm.complete(
            messages=messages,
            tools=TOOL_SCHEMAS,
            model=DEFAULT_MODEL,
        )
        audit.append(
            "llm_response",
            {
                "iteration": iteration,
                "model": response.model or DEFAULT_MODEL,
                "stop_reason": response.stop_reason,
                "wants_tool_call": response.wants_tool_call,
                "tool_calls": [
                    {"tool": tc.tool_name, "arguments": tc.arguments}
                    for tc in response.tool_calls
                ],
            },
        )

        if not response.wants_tool_call:
            final_content = response.content
            break

        messages.append(
            {
                "role": "assistant",
                "content": response.content or None,
                "tool_calls": [
                    {
                        "id": tc.call_id,
                        "type": "function",
                        "function": {
                            "name": tc.tool_name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in response.tool_calls
                ],
            }
        )
        for tc in response.tool_calls:
            result = dispatch(
                tc.tool_name,
                tc.arguments,
                principal=principal,
                gate=gate,
                audit=audit,
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.call_id,
                    "content": json.dumps(result),
                }
            )
    else:
        raise RuntimeError(
            f"DORA agent exceeded {MAX_LOOP_ITERATIONS} iterations without finalizing"
        )

    if final_content is None:
        raise RuntimeError("DORA agent produced no final content")

    parsed = _parse_output(final_content, report_id=report_id)
    audit.append("decision", parsed | {"audit_entries": "n/a"})

    submissions_attempted = sum(
        1 for v in parsed["vendors_drafted"] if v.get("submission_status") != "not_attempted"
    )
    submissions_succeeded = sum(
        1 for v in parsed["vendors_drafted"] if v.get("submission_status") == "submitted"
    )
    final = DORAReport(
        report_id=parsed["report_id"],
        vendors_drafted=parsed["vendors_drafted"],
        summary=parsed["summary"],
        submissions_attempted=submissions_attempted,
        submissions_succeeded=submissions_succeeded,
        audit_entries=len(audit.entries),
    )
    return final, audit


def _parse_output(content: str, *, report_id: str) -> dict[str, Any]:
    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", content, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        raise ValueError(f"DORA final content did not contain JSON: {content!r}")
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError(f"DORA final JSON could not be parsed: {exc}") from exc

    required = {"report_id", "vendors_drafted", "summary"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"DORA final JSON missing fields: {sorted(missing)}")
    if data["report_id"] != report_id:
        raise ValueError(
            f"DORA report_id mismatch: expected {report_id!r}, got {data['report_id']!r}"
        )
    if not isinstance(data["vendors_drafted"], list):
        raise ValueError("DORA vendors_drafted must be a list")
    return data


def _demo() -> None:  # pragma: no cover - manual CLI usage
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    principal = Principal(
        principal_id="elena_compliance@bank-it-01",
        principal_type="user",
        org_id="bank-it-01",
        capabilities=frozenset(
            {"dora.read", "dora.draft_report", "dora.cross_org_submit"}
        ),
        roles=frozenset({"compliance_officer"}),
    )
    report, audit = run(
        report_id="dora_2026_q2",
        target_auditor_org_id="auditor_org_demo",
        principal=principal,
    )
    print(json.dumps(report.to_dict(), indent=2))
    print(f"audit chain: {len(audit.entries)} entries, verified={audit.verify()}")


if __name__ == "__main__":  # pragma: no cover
    _demo()
