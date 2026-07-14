"""Входной guardrail (T032, FR-008).

``before_model``: если во входящем сообщении детектируется инъекция, запрос НЕ доходит до модели
— middleware возвращает отказ и ``jump_to="end"``. Каждое решение (в т.ч. пропуск) журналируется.
"""

from __future__ import annotations

from typing import Any

from langchain.agents.middleware import AgentMiddleware, hook_config
from langchain_core.messages import AIMessage, HumanMessage

from ..trace.events import GuardrailDecision
from ..trace.sink import TraceSink
from .policy import GuardrailPolicy

_REFUSAL = "Запрос отклонён политикой безопасности (обнаружена возможная инъекция)."


class InputGuardrail(AgentMiddleware):
    def __init__(self, policy: GuardrailPolicy, sink: TraceSink) -> None:
        super().__init__()
        self._policy = policy
        self._sink = sink

    @hook_config(can_jump_to=["end"])
    def before_model(self, state: dict, runtime: Any) -> dict | None:  # noqa: ARG002
        last_human = _last_human(state.get("messages", []))
        if last_human is None:
            return None

        pattern = self._policy.is_injection(last_human)
        if pattern is None:
            self._sink.emit(
                GuardrailDecision(stage="input", action="allow", rule_id="INPUT-OK")
            )
            return None

        self._sink.emit(
            GuardrailDecision(
                stage="input",
                action="block",
                rule_id="INPUT-INJECTION",
                reason=f"pattern: {pattern}",
            )
        )
        return {"messages": [AIMessage(content=_REFUSAL)], "jump_to": "end"}


def _last_human(messages: list) -> str | None:
    for m in reversed(messages):
        if isinstance(m, HumanMessage):
            return m.content if isinstance(m.content, str) else str(m.content)
    return None
