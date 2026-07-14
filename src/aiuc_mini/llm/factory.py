"""Провайдер-агностичная фабрика модели (research.md R3).

Это ЕДИНСТВЕННОЕ место в проекте, где создаётся LLM. Бизнес-логика (агенты, red-team) принимает
готовый ``BaseChatModel`` параметром — так недетерминизм модели изолирован за швом, который в
тестах подменяется fake-моделью (Принцип IV конституции).

Если какой-то модуль вызывает ``build_model`` изнутри себя — это ошибка: модель нужно принять
параметром.
"""

from __future__ import annotations

from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel


def build_model(spec: str, *, temperature: float = 0.0) -> BaseChatModel:
    """Создать модель по строке ``provider:model`` (например ``anthropic:claude-...``).

    ``temperature=0`` по умолчанию — часть контракта воспроизводимости фазы прогона. Смена
    провайдера возможна правкой строки в ``.env`` без изменения кода.
    """
    return init_chat_model(spec, temperature=temperature)
