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

- Всё окружение — **через Docker** (`docker compose run --rm test|gates|lint|aiuc`). На хост
  ничего не ставим (ни `uv sync`, ни `pytest`).
- Долгосрочная цель — постепенно покрыть все **53 контроля реального AIUC-1**; порядок и статусы
  ведёт карта покрытия (фича 002).

<!-- SPECKIT START -->

## Текущая фича

**002-aiuc-coverage-map** — план: [specs/002-aiuc-coverage-map/plan.md](specs/002-aiuc-coverage-map/plan.md)

Аналитический deliverable, НЕ реализация контролей. Единый машиночитаемый каталог
`aiuc1/catalog.yaml` (53 контроля) → генератор строит `docs/aiuc1-coverage.md` (карта + бэклог) →
валидатор-тесты под Docker. Статусы: `covered` / `technical_achievable` / `doc_only`; `partial` —
модификатор для mixed, вне агрегации. Бэклог — тематические кластеры (будущие фичи 003+).

Артефакты плана: [research.md](specs/002-aiuc-coverage-map/research.md) (классификация всех 53),
[data-model.md](specs/002-aiuc-coverage-map/data-model.md),
[contracts/catalog-schema.md](specs/002-aiuc-coverage-map/contracts/catalog-schema.md),
[quickstart.md](specs/002-aiuc-coverage-map/quickstart.md).

Ключевой инвариант честности (SC-004): `covered` нельзя проставить без ссылки на реально
существующий контроль в `scorecard/controls.py` — это проверяет `tests/coverage/test_covered_grounded.py`.

**Реализованная база (фича 001)** — стек Python 3.11+, LangChain 1.3.x (`create_agent` +
middleware), LangGraph 1.2.x, Pydantic 2, Typer. Три вещи, которые легко сломать:
1. **Guardrail ≠ песочница.** Guardrail отключается флагом; песочница — никогда.
2. **Судья — не LLM.** Вердикт — чистые предикаты над trace.
3. **Scorecard — чистая функция от trace.** Ни `ts`, ни абсолютных путей в агрегате (SC-006).

<!-- SPECKIT END -->
