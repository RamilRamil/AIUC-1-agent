"""Сценарная fake-модель для тестов (шов Принципа IV).

``ScriptedChatModel`` проигрывает заранее заданную последовательность ``AIMessage`` — включая
сообщения с ``tool_calls``. Это позволяет прогонять полный цикл ``create_agent`` детерминированно
и без API-ключей.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult


class ScriptedChatModel(BaseChatModel):
    """Отдаёт по одному ``AIMessage`` из очереди на каждый вызов. Игнорирует вход."""

    responses: list[AIMessage]
    _cursor: int = 0

    def __init__(self, responses: Sequence[AIMessage], **kwargs: Any) -> None:
        super().__init__(responses=list(responses), **kwargs)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        idx = min(self._cursor, len(self.responses) - 1)
        object.__setattr__(self, "_cursor", self._cursor + 1)
        return ChatResult(generations=[ChatGeneration(message=self.responses[idx])])

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:  # noqa: ARG002
        # Fake не использует схемы инструментов — tool_calls заданы в сценарии заранее.
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted-fake"


def tool_call_message(name: str, args: dict, call_id: str = "call_1") -> AIMessage:
    """Собрать AIMessage с одним вызовом инструмента."""
    return AIMessage(
        content="",
        tool_calls=[{"name": name, "args": args, "id": call_id, "type": "tool_call"}],
    )
