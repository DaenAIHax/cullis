"""LLM client abstraction for the reference demo agents.

The 3 agents call Claude (Sonnet 4.6, Opus 4.7) and OpenAI (GPT-5) through
the Mastio embedded LiteLLM gateway (ADR-017). This module wraps that into
a single interface and provides a deterministic `MockLLMClient` for the
test suite, so the demo runs and tests pass with `CULLIS_AGENT_DEMO_MODE=mock`
(the default) without any API key configured.

To run against real APIs, set:

    export CULLIS_AGENT_DEMO_MODE=live
    export ANTHROPIC_API_KEY=sk-ant-...
    export OPENAI_API_KEY=sk-...

LiteLLM is optional. If not installed, `live` mode falls back to vendor
SDKs directly (anthropic, openai). The wrapper normalizes responses to a
single `LLMResponse` shape regardless of backend.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolCall:
    """Normalized tool invocation requested by the LLM."""

    call_id: str
    tool_name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMResponse:
    """Normalized LLM response across Claude / OpenAI / LiteLLM."""

    content: str
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple)
    model: str = ""
    stop_reason: str = ""

    @property
    def wants_tool_call(self) -> bool:
        return len(self.tool_calls) > 0


class LLMClient:
    """Base interface. Concrete implementations: `LiteLLMClient`,
    `MockLLMClient`. The default factory picks based on env."""

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        raise NotImplementedError


class MockLLMClient(LLMClient):
    """Deterministic scripted client for tests + offline demos.

    Two modes:

    - **Scripted**: pass a list of `LLMResponse` objects via `script=`. Each
      `complete()` call pops the next one. This is what `test_e2e.py` uses.

    - **Pattern**: pass a `responder` callable `(messages, tools) -> LLMResponse`.
      Useful when the same agent runs interactively in a notebook demo.
    """

    def __init__(
        self,
        *,
        script: Iterable[LLMResponse] | None = None,
        responder: Callable[[list[dict[str, Any]], list[dict[str, Any]] | None], LLMResponse]
        | None = None,
        model: str = "mock/claude-sonnet-4-6",
    ) -> None:
        if script is None and responder is None:
            raise ValueError("MockLLMClient requires either script= or responder=")
        if script is not None and responder is not None:
            raise ValueError("MockLLMClient: pass either script= or responder=, not both")
        self._script = list(script) if script else None
        self._responder = responder
        self._model = model
        self._calls: list[dict[str, Any]] = []

    @property
    def calls(self) -> list[dict[str, Any]]:
        return list(self._calls)

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        self._calls.append({"messages": messages, "tools": tools, "model": model or self._model})
        if self._script is not None:
            if not self._script:
                raise AssertionError(
                    "MockLLMClient script exhausted; agent made more LLM calls than expected"
                )
            return self._script.pop(0)
        assert self._responder is not None  # nosec - guarded by __init__
        return self._responder(messages, tools)


class LiteLLMClient(LLMClient):
    """Routes calls through LiteLLM. Used in `live` mode."""

    def __init__(self, *, default_model: str) -> None:
        try:
            import litellm  # noqa: F401 -- imported for side effect
        except ImportError as exc:  # pragma: no cover - live-mode only
            raise RuntimeError(
                "litellm is required for live mode. Install with: "
                "pip install -e sandbox/agents-demo/[live]"
            ) from exc
        self._default_model = default_model

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:  # pragma: no cover - live-mode only
        import litellm

        resp = litellm.completion(
            model=model or self._default_model,
            messages=messages,
            tools=tools,
            **kwargs,
        )
        choice = resp.choices[0]
        message = choice.message
        content = message.content or ""
        tool_calls: list[ToolCall] = []
        raw_tool_calls = getattr(message, "tool_calls", None) or []
        for tc in raw_tool_calls:
            args_raw = tc.function.arguments
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
            except json.JSONDecodeError:
                args = {"_raw": args_raw}
            tool_calls.append(
                ToolCall(
                    call_id=tc.id,
                    tool_name=tc.function.name,
                    arguments=args,
                )
            )
        return LLMResponse(
            content=content,
            tool_calls=tuple(tool_calls),
            model=resp.model,
            stop_reason=choice.finish_reason or "",
        )


def make_tool_call(tool_name: str, arguments: dict[str, Any]) -> ToolCall:
    """Convenience helper for building `ToolCall` objects in test scripts."""

    return ToolCall(call_id=f"call_{uuid.uuid4().hex[:8]}", tool_name=tool_name, arguments=arguments)


def default_client(*, default_model: str) -> LLMClient:
    """Factory used by `main.py` entry points.

    Returns `MockLLMClient` in mock mode (default) with a friendly
    responder that just acknowledges, or `LiteLLMClient` in live mode.
    """

    mode = os.environ.get("CULLIS_AGENT_DEMO_MODE", "mock").lower()
    if mode == "live":
        return LiteLLMClient(default_model=default_model)

    def _friendly(
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
    ) -> LLMResponse:
        _log.info(
            "MockLLMClient default_client: returning canned response (set "
            "CULLIS_AGENT_DEMO_MODE=live to use real LLM)"
        )
        return LLMResponse(
            content=(
                "[mock LLM] This is a canned response. Set "
                "CULLIS_AGENT_DEMO_MODE=live with ANTHROPIC_API_KEY / "
                "OPENAI_API_KEY to invoke the real model."
            ),
            tool_calls=(),
            model=default_model,
            stop_reason="stop",
        )

    return MockLLMClient(responder=_friendly, model=default_model)
