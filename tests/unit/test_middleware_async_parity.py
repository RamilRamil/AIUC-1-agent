"""Гейт: middleware, определяющий sync-хук, обязан определить и async-хук.

ЭТИ ГРАБЛИ РЕАЛЬНЫЕ, И Я НАСТУПАЛ НА НИХ ДВАЖДЫ:

- **фича 003**: раннер перешёл на `ainvoke` (ради честного таймаута), а `ToolPolicyGuardrail`
  имел только `wrap_tool_call`. LangChain кинул `NotImplementedError`, атаки посыпались в `ERROR`,
  и отчёт показал **«0% успешных атак, снижение 100%, контролей 11/11»** — идеальную защиту,
  потому что сломанную. Поймал только по тому, что цифры улучшились НЕОЖИДАННО;
- **фича 004**: пришлось отдельной задачей (T007) проверять, что новое правило работает на обоих
  путях.

Заметка в документации такое не удержит: следующий middleware напишут через полгода. Гейт удержит.

Проект построен на мысли «заметка — пожелание, гейт — факт». Этот тест применяет её к нашему
собственному процессу.
"""

import inspect
import pkgutil
from importlib import import_module

from langchain.agents.middleware import AgentMiddleware

import aiuc_mini.guardrails as guardrails_pkg

# Пары «синхронный хук → обязательный асинхронный двойник» (LangChain 1.x).
HOOK_PAIRS = {
    "wrap_tool_call": "awrap_tool_call",
    "wrap_model_call": "awrap_model_call",
}


def _middleware_classes() -> list[type]:
    """Все middleware проекта — найденные, а не перечисленные вручную.

    Перечислять руками бессмысленно: забыть дописать в список так же легко, как забыть сам
    async-хук.
    """
    found: list[type] = []
    for mod_info in pkgutil.iter_modules(guardrails_pkg.__path__):
        module = import_module(f"{guardrails_pkg.__name__}.{mod_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, AgentMiddleware)
                and obj is not AgentMiddleware
                and obj.__module__ == module.__name__
            ):
                found.append(obj)
    return found


def test_middleware_classes_are_discovered():
    """Страховка от «тест зелёный, потому что ничего не нашёл»."""
    classes = _middleware_classes()
    assert classes, "не найдено ни одного middleware — тест бесполезен"
    names = {c.__name__ for c in classes}
    assert "ToolPolicyGuardrail" in names


def test_sync_hook_implies_async_twin():
    """Определил sync-хук — определи и async: раннер зовёт мишень через `ainvoke`.

    Без async-двойника политика падает с NotImplementedError, а падение атак выглядит как
    идеальная защита.
    """
    problems: list[str] = []
    for cls in _middleware_classes():
        own = set(vars(cls))
        for sync_hook, async_hook in HOOK_PAIRS.items():
            if sync_hook in own and async_hook not in own:
                problems.append(f"{cls.__name__}: есть {sync_hook}, нет {async_hook}")

    assert not problems, (
        "middleware определяет sync-хук без async-двойника: "
        + "; ".join(problems)
        + ". Раннер зовёт агента через ainvoke — политика молча сломается, атаки уйдут в ERROR, "
        "и отчёт покажет идеальную защиту. Так уже было дважды (фичи 003 и 004)."
    )


def test_async_twin_is_actually_async():
    """Двойник обязан быть корутиной — иначе LangChain его не примет."""
    for cls in _middleware_classes():
        for async_hook in HOOK_PAIRS.values():
            if async_hook in vars(cls):
                assert inspect.iscoroutinefunction(vars(cls)[async_hook]), (
                    f"{cls.__name__}.{async_hook} не корутина"
                )
