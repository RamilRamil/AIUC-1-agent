"""Сборка агента-мишени (T019).

Модель приходит ПАРАМЕТРОМ (шов Принципа IV) — здесь фабрика не вызывается. Пустой список
``middleware`` = режим без защиты; с guardrail-слоем список наполняется в guardrails/ (US3).
Один и тот же код-путь обслуживает оба режима (FR-011).
"""

from __future__ import annotations

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import BaseTool

from .prompt import TargetPersona


def build_target_agent(
    model: BaseChatModel,
    tools: list[BaseTool],
    persona: TargetPersona,
    middleware: list | None = None,
):
    """Создать LangGraph-агента мишени.

    ``middleware=None`` → уязвимый режим (нет guardrail). Список middleware включает защиту,
    не меняя ничего другого.
    """
    return create_agent(
        model=model,
        tools=tools,
        system_prompt=persona.system_prompt(),
        middleware=middleware or [],
    )
