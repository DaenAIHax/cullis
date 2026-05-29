"""ADR-016 Phase 1 — fast-path tool registry.

The registry is the contract Phase 2 plugin tools register into. Tests
cover the basic register / list / overwrite / direction filter so the
plugin author has a stable surface to develop against while Phase 1 is
still in review.
"""
from __future__ import annotations

import pytest

from mcp_proxy.guardian.registry import (
    Tool,
    ToolResult,
    clear_registry,
    register_tool,
    registered_tools,
)


class _StubTool(Tool):
    name = "stub-1"
    direction = "in"

    async def evaluate(self, payload, ctx):
        return ToolResult(decision="pass")


class _StubOut(Tool):
    name = "stub-out"
    direction = "out"

    async def evaluate(self, payload, ctx):
        return ToolResult(decision="pass")


@pytest.fixture(autouse=True)
def _isolate_registry():
    clear_registry()
    yield
    clear_registry()


def test_register_and_list():
    t = _StubTool()
    register_tool(t)
    assert registered_tools() == [t]


def test_direction_filter():
    """``both`` direction tools surface in either filter; concrete
    directions filter strictly."""
    in_t = _StubTool()
    out_t = _StubOut()
    register_tool(in_t)
    register_tool(out_t)
    assert registered_tools(direction="in") == [in_t]
    assert registered_tools(direction="out") == [out_t]


def test_register_unnamed_rejected():
    class _Bad(Tool):
        async def evaluate(self, payload, ctx):
            return ToolResult(decision="pass")
    with pytest.raises(ValueError):
        register_tool(_Bad())


def test_register_overwrites_same_name():
    a = _StubTool()
    register_tool(a)
    b = _StubTool()  # different instance, same name
    register_tool(b)
    assert registered_tools() == [b]


@pytest.mark.asyncio
async def test_evaluate_roundtrip():
    t = _StubTool()
    register_tool(t)
    [the_tool] = registered_tools(direction="in")
    result = await the_tool.evaluate(b"x", {})
    assert result.decision == "pass"
