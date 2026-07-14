# langchain-aiuc-mini — контекст для Claude Code

Учебный проект по безопасности AI-агентов на LangChain / LangGraph («AIUC-1 в миниатюре»).
Отдельный самостоятельный проект (НЕ связан с репозиторием SR-agent и не содержит его кода).

## Как вести работу

- Проект управляется через **Spec Kit**. Актуальная спецификация и план — в `specs/`.
  Перед реализацией читай текущую фичу (`.specify/feature.json` → каталог в `specs/`).
- Цель проекта — **опыт**: прокачка LangChain/LangGraph и предметное изучение безопасности агентов.
- Все «опасные» инструменты агента-мишени выполняются в **изоляции** (песочница, замоканный HTTP,
  временная рабочая папка). Ни одна учебная атака не должна причинять реального вреда.
- Правила проекта зафиксированы в [конституции](.specify/memory/constitution.md) v1.0.0.
  Принцип II (песочница) — NON-NEGOTIABLE: никакого `subprocess`, никаких реальных сетевых
  вызовов, никаких файловых операций вне временного корня песочницы.

<!-- SPECKIT START -->

## Текущая фича

**001-langchain-aiuc-mini** — план: [specs/001-langchain-aiuc-mini/plan.md](specs/001-langchain-aiuc-mini/plan.md)

Стек: Python 3.11+, LangChain 1.3.x (`create_agent` + agent middleware), LangGraph 1.2.x,
Pydantic 2, Typer, pytest. LLM — провайдер-агностичный `init_chat_model`, строка
`provider:model` из `.env`; в тестах подменяется fake-моделью.

Артефакты фазы планирования: [research.md](specs/001-langchain-aiuc-mini/research.md),
[data-model.md](specs/001-langchain-aiuc-mini/data-model.md),
[quickstart.md](specs/001-langchain-aiuc-mini/quickstart.md),
[contracts/](specs/001-langchain-aiuc-mini/contracts/).

Три вещи, которые легко сломать по невнимательности:
1. **Guardrail ≠ песочница.** Guardrail отключается флагом (`--no-guardrails`), и в этом режиме
   мишень обязана быть уязвимой. Песочница не отключается никогда.
2. **Судья — не LLM.** Вердикт атаки и статус контроля — чистые предикаты над trace
   (канареечный секрет, факт вызова инструмента). Самооценка модели не используется.
3. **Scorecard — чистая функция от trace.** Ни `ts`, ни абсолютных путей в агрегате, иначе
   рушится воспроизводимость (SC-006).

<!-- SPECKIT END -->
