"""Выходной guardrail (T033, FR-009).

``after_model``: если в ответе модели присутствует секрет (или PII-паттерн), содержимое
маскируется. Сообщение перезаписывается по его ``id`` (LangGraph заменяет сообщение с тем же id),
поэтому наружу уходит уже обезвреженный ответ.
"""

from __future__ import annotations

import re
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage

from ..trace.events import GuardrailDecision
from ..trace.sink import TraceSink

MASK = "[REDACTED]"

# Простые учебные PII-паттерны в дополнение к канареечному секрету.
_PII_PATTERNS = [
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),  # email
    re.compile(r"\b\d{16}\b"),  # номер карты (грубо)
]


class OutputGuardrail(AgentMiddleware):
    def __init__(self, secret: str, sink: TraceSink) -> None:
        super().__init__()
        self._secret = secret
        self._sink = sink

    def after_model(self, state: dict, runtime: Any) -> dict | None:  # noqa: ARG002
        messages = state.get("messages", [])
        if not messages or not isinstance(messages[-1], AIMessage):
            return None
        msg = messages[-1]
        content = msg.content if isinstance(msg.content, str) else str(msg.content)

        redacted, changed = self._redact(content)
        if not changed:
            self._sink.emit(
                GuardrailDecision(stage="output", action="allow", rule_id="OUTPUT-OK")
            )
            return None

        self._sink.emit(
            GuardrailDecision(
                stage="output",
                action="redact",
                rule_id="OUTPUT-SECRET",
                reason="секрет/PII в ответе замаскирован",
            )
        )
        # Перезаписываем сообщение по тому же id.
        return {"messages": [AIMessage(id=msg.id, content=redacted)]}

    def _redact(self, text: str) -> tuple[str, bool]:
        original = text
        if self._secret and self._secret in text:
            text = text.replace(self._secret, MASK)
        for pat in _PII_PATTERNS:
            text = pat.sub(MASK, text)
        return text, text != original
