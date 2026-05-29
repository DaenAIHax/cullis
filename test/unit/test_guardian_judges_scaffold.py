"""ADR-016 Phase 1 — slow-path judge adapters scaffold.

Phase 1 ships 5 adapters (NeMo, Lakera, Portkey, OpenAI Moderation,
Llama Guard). Phase 1 tests verify the adapter contract: each adapter
imports cleanly, can be instantiated without credentials, and returns
``decision="unavailable"`` with a meaningful detail when the required
key/package is missing. The dogfood script (imp/dogfood_judges.py)
exercises the live paths against real APIs in a separate run.
"""
from __future__ import annotations

import pytest

from mcp_proxy.guardian.judges import Judge, JudgeResult


@pytest.mark.asyncio
async def test_lakera_unavailable_when_key_missing(monkeypatch):
    monkeypatch.delenv("LAKERA_API_KEY", raising=False)
    from mcp_proxy.guardian.judges.lakera import LakeraJudge
    j = LakeraJudge()
    result = await j.evaluate(b"hello world", ctx={})
    assert isinstance(result, JudgeResult)
    assert result.decision == "unavailable"
    assert "key_missing" in (result.detail or "")


@pytest.mark.asyncio
async def test_portkey_unavailable_when_key_missing(monkeypatch):
    monkeypatch.delenv("PORTKEY_API_KEY", raising=False)
    monkeypatch.delenv("PORTKEY_GUARDRAIL_ID", raising=False)
    from mcp_proxy.guardian.judges.portkey import PortkeyJudge
    j = PortkeyJudge()
    result = await j.evaluate(b"hello world", ctx={})
    assert result.decision == "unavailable"
    assert "key_missing" in (result.detail or "")


@pytest.mark.asyncio
async def test_portkey_unavailable_when_guardrail_id_missing(monkeypatch):
    """Guardrail id is the second required input — surface separately
    so the operator's setup script can tell which step they skipped."""
    monkeypatch.setenv("PORTKEY_API_KEY", "pk_test")
    monkeypatch.delenv("PORTKEY_GUARDRAIL_ID", raising=False)
    from mcp_proxy.guardian.judges.portkey import PortkeyJudge
    j = PortkeyJudge()
    result = await j.evaluate(b"hello", ctx={})
    assert result.decision == "unavailable"
    assert "config_missing" in (result.detail or "")


@pytest.mark.asyncio
async def test_openai_moderation_unavailable_when_key_missing(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from mcp_proxy.guardian.judges.openai_moderation import OpenAIModerationJudge
    j = OpenAIModerationJudge()
    result = await j.evaluate(b"hello", ctx={})
    assert result.decision == "unavailable"
    assert "key_missing" in (result.detail or "")


@pytest.mark.asyncio
async def test_llama_guard_unavailable_when_key_missing(monkeypatch):
    monkeypatch.delenv("REPLICATE_API_KEY", raising=False)
    from mcp_proxy.guardian.judges.llama_guard import LlamaGuardJudge
    j = LlamaGuardJudge()
    result = await j.evaluate(b"hello", ctx={})
    assert result.decision == "unavailable"
    assert "key_missing" in (result.detail or "")


@pytest.mark.asyncio
async def test_nemo_unavailable_when_package_missing(monkeypatch):
    """Without ``nemoguardrails`` installed the adapter returns
    unavailable, never raises."""
    from mcp_proxy.guardian.judges.nemo import NemoJudge
    j = NemoJudge()
    # Force the import path to fail by stubbing builtins.__import__.
    import builtins
    real_import = builtins.__import__

    def _import(name, *args, **kwargs):
        if name.startswith("nemoguardrails"):
            raise ImportError("simulated missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import)
    result = await j.evaluate(b"ping", ctx={})
    assert result.decision == "unavailable"
    assert "nemoguardrails_not_installed" in (result.detail or "")


def test_judge_unavailable_constructor_helper():
    """Sanity: the abstract base provides a typed ``unavailable``
    factory so adapters keep the response shape consistent."""
    r = Judge.unavailable(judge="x", detail="y")
    assert r.decision == "unavailable"
    assert r.judge == "x"
    assert r.detail == "y"


@pytest.mark.asyncio
async def test_all_judges_import_cleanly():
    """Smoke-import every adapter so Phase 1 doesn't accidentally
    break a downstream plugin's entry point. Pure import-time
    regression guard."""
    from mcp_proxy.guardian.judges.lakera import LakeraJudge  # noqa: F401
    from mcp_proxy.guardian.judges.portkey import PortkeyJudge  # noqa: F401
    from mcp_proxy.guardian.judges.openai_moderation import (
        OpenAIModerationJudge,  # noqa: F401
    )
    from mcp_proxy.guardian.judges.llama_guard import LlamaGuardJudge  # noqa: F401
    from mcp_proxy.guardian.judges.nemo import NemoJudge  # noqa: F401
