"""Guardrail политики инструментов (T034, FR-010).

``wrap_tool_call``: если инструмент вне allow-list, middleware НЕ вызывает ``handler`` и
возвращает ``ToolMessage`` с отказом. Именно невызов handler делает запрет структурным, а не
просьбой к модели — инструмент физически не исполняется.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

from ..trace.events import GuardrailDecision
from ..trace.sink import TraceSink
from .policy import GuardrailPolicy


class ToolPolicyGuardrail(AgentMiddleware):
    def __init__(self, policy: GuardrailPolicy, sink: TraceSink) -> None:
        super().__init__()
        self._policy = policy
        self._sink = sink

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        call = request.tool_call
        name = call["name"]
        if self._policy.tool_allowed(name):
            self._sink.emit(
                GuardrailDecision(stage="tool_call", action="allow", rule_id="TOOL-ALLOW")
            )
            return handler(request)

        # Запрещённый инструмент: handler НЕ вызывается — исполнения не происходит.
        self._sink.emit(
            GuardrailDecision(
                stage="tool_call",
                action="block",
                rule_id="TOOL-ALLOWLIST",
                reason=f"tool not in allowlist: {name}",
            )
        )
        return ToolMessage(
            content=f"Инструмент {name} заблокирован политикой.",
            tool_call_id=call["id"],
        )
