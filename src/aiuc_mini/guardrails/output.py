"""Выходной guardrail (T033, FR-009; PII-детектор — фича 004).

``after_model``: если в ответе модели присутствует секрет или PII, содержимое маскируется.
Сообщение перезаписывается по его ``id`` (LangGraph заменяет сообщение с тем же id), поэтому
наружу уходит уже обезвреженный ответ.

Паттерны PII живут в ``policy.py`` — там же, где остальные правила политики (единственное место
для «что считается нарушением»). Границы детектора — в contracts/detectors.md: ловятся каноничные
формы, кодирование и нестандартные записи не покрыты.
"""

from __future__ import annotations

from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage

from ..trace.events import GuardrailDecision
from ..trace.sink import TraceSink
from .policy import GuardrailPolicy

MASK = "[REDACTED]"


class OutputGuardrail(AgentMiddleware):
    def __init__(
        self, secret: str, sink: TraceSink, policy: GuardrailPolicy | None = None
    ) -> None:
        super().__init__()
        self._secret = secret
        self._sink = sink
        self._policy = policy or GuardrailPolicy()

    def after_model(self, state: dict, runtime: Any) -> dict | None:  # noqa: ARG002
        messages = state.get("messages", [])
        if not messages or not isinstance(messages[-1], AIMessage):
            return None
        msg = messages[-1]
        content = msg.content if isinstance(msg.content, str) else str(msg.content)

        redacted, rules = self._redact(content)
        if not rules:
            self._sink.emit(
                GuardrailDecision(stage="output", action="allow", rule_id="OUTPUT-OK")
            )
            return None

        self._sink.emit(
            GuardrailDecision(
                stage="output",
                action="redact",
                rule_id="OUTPUT-PII" if "secret" not in rules else "OUTPUT-SECRET",
                reason=f"замаскировано: {', '.join(rules)}",
            )
        )
        return {"messages": [self._rewrite(msg, redacted)]}

    @staticmethod
    def _rewrite(msg: AIMessage, content: str) -> AIMessage:
        """Перезаписать сообщение, сохранив ВСЁ кроме содержимого.

        Фича 004 (research R3): раньше здесь было ``AIMessage(id=msg.id, content=redacted)`` —
        новое сообщение БЕЗ ``tool_calls``. LangGraph заменяет сообщение по id, и вызовы
        инструментов исчезали. У fake-модели ``content=""`` при tool_call, поэтому баг спал; на
        реальной модели, шлющей текст вместе с вызовом, редакция снесла бы вызов и сломала цикл
        агента. PII-детектор расширяет редакцию с одной канарейки до целого класса — срабатывание
        становится почти неизбежным, поэтому чиним здесь.
        """
        updated = msg.model_copy(deep=True)
        updated.content = content
        return updated

    def _redact(self, text: str) -> tuple[str, list[str]]:
        """Замаскировать секрет и PII. Возвращает (текст, список сработавших правил)."""
        rules: list[str] = []
        if self._secret and self._secret in text:
            text = text.replace(self._secret, MASK)
            rules.append("secret")

        found = self._policy.find_pii(text)
        if found:
            text, _ = self._policy.redact_pii(text)
            rules.extend(found)
        return text, rules
