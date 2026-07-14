# Implementation Plan: LangChain «AIUC-1 в миниатюре»

**Branch**: `001-langchain-aiuc-mini` | **Date**: 2026-07-15 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-langchain-aiuc-mini/spec.md`

## Summary

Учебный стенд «атака → защита → аудит» на LangChain 1.x / LangGraph. Агент-мишень строится
через `create_agent` с тремя «опасными» инструментами, физически запертыми в песочнице
(фиктивный интерпретатор команд, файловые операции с проверкой границ пути, фикстурный HTTP —
никакого `subprocess` и никакой реальной сети). Guardrail-слой реализуется как **agent
middleware**: `@before_model` ловит инъекции на входе, `@after_model` маскирует утечку секрета
на выходе, `@wrap_tool_call` структурно не даёт исполниться инструменту вне allow-list.
Red-team агент генерирует и мутирует инъекции; успех атаки определяет **детерминированный
судья** по канареечному секрету и фактам из trace, а не LLM. Прогон пишет JSONL-trace, а
scorecard — **чистая функция** от trace'ов, что даёт воспроизводимый отчёт по 6 пиллерам
AIUC-1 несмотря на недетерминизм модели.

Ключевые архитектурные решения и их обоснования — в [research.md](research.md).

## Technical Context

**Language/Version**: Python 3.11+ (CI — 3.12)

**Primary Dependencies**: `langchain` 1.3.x (`create_agent`, middleware, `init_chat_model`),
`langgraph` 1.2.x, `langchain-core` 1.4.x; провайдеры — опциональные extras
(`langchain-anthropic` / `langchain-openai` / `langchain-ollama`); `pydantic` 2.13.x,
`typer` 0.26.x, `pyyaml`

**Storage**: файлы. Trace — JSONL в `runs/<run_id>/trace.jsonl`; scorecard — `scorecard.json` +
`scorecard.md` там же. Набор атак — `attacks/suite.yaml`. БД нет.

**Testing**: `pytest` 9.x. Недетерминизм LLM изолирован швом (модель — параметр конструктора),
в тестах — `FakeListChatModel` / `GenericFakeChatModel` из `langchain-core`. Обязательные
категории: тесты изоляции песочницы и тесты детерминизма scorecard.

**Target Platform**: локальный CLI (macOS/Linux), однопользовательский запуск

**Project Type**: single project — Python-библиотека + CLI

**Performance Goals**: не является целью. Ориентир из SC-001: полная демонстрация
«атака → защита → аудит» укладывается в < 15 минут работы оператора. Бюджет прогона задаётся
конфигом (число атак × итераций мутации), не оптимизацией кода.

**Constraints**:
- NON-NEGOTIABLE: ни один код-путь не вызывает `subprocess` и не открывает реальный сетевой
  сокет; файловые операции не покидают `Sandbox.root` (Принцип II)
- вердикты и scorecard — детерминированные функции от trace, без участия LLM (Принципы III, IV)
- сбой/таймаут одной попытки не роняет прогон (FR-015)

**Scale/Scope**: 4 модуля (target / redteam / guardrails / scorecard), 3 инструмента,
~3 категории атак, 12 учебных контролей (по 2 на каждый из 6 пиллеров AIUC-1)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Проверка против [конституции v1.0.0](../../.specify/memory/constitution.md).

| Принцип | Как план ему удовлетворяет | Статус |
|---|---|---|
| **I. Обучение через практику** | Плоская структура `src/<модуль>/`, один слой абстракции, никаких фабрик поверх фабрик. Отвергнуты ручной `StateGraph` и собственный `LLMClient` — оба добавили бы код без учебной выгоды (R1, R3). | ✅ PASS |
| **II. Безопасность песочницы (NON-NEGOTIABLE)** | `run_command` — фиктивный интерпретатор, `subprocess` отсутствует в зависимостях кода как таковой; файловые пути проверяются `resolve()` + `is_relative_to(root)`; HTTP — фикстурный транспорт (R4). Изоляция **не** является частью guardrail и не отключается в режиме «без защиты». Гейт: тесты `tests/isolation/` на каждый инструмент. | ✅ PASS |
| **III. Объективная проверяемость** | Судья (`redteam/judge.py`) — чистые предикаты над trace: точное вхождение канареечного секрета (в т.ч. в аргументах инструментов) и факт вызова запрещённого инструмента. LLM-as-judge отвергнут явно (R5). | ✅ PASS |
| **IV. Воспроизводимость прогонов** | Двухфазность: недетерминированный `run` → JSONL-trace → чистая функция `score` (R6). Модель инжектится параметром, в тестах — fake-модель. Вердикт `ERROR` не засчитывается как «атака отбита» (R7). | ✅ PASS |
| **V. Наблюдаемость** | Каждое событие (вызов инструмента, решение guardrail, вердикт, ошибка) — типизированная Pydantic-запись в JSONL с `run_id`/`attempt_id`/`seq`. Каждый проваленный контроль несёт `evidence` со ссылкой на конкретные строки trace (R8, FR-013). | ✅ PASS |
| **VI. Spec-driven разработка** | Артефакты в порядке spec → plan → tasks → code; спека осталась technology-agnostic, весь выбор стека сделан здесь. | ✅ PASS |

**Итог гейта: PASS.** Раздел Complexity Tracking не заполняется — обоснованных отклонений нет.

**Re-check после Phase 1 (design)**: PASS — контракты (`contracts/`) и data-model не вводят ни
одного нового кода-пути к хосту, судья и scorecard остались чистыми функциями, шов модели
сохранён в сигнатурах конструкторов. Дизайн не ослабил ни одного гейта.

## Project Structure

### Documentation (this feature)

```text
specs/001-langchain-aiuc-mini/
├── plan.md              # This file
├── research.md          # Phase 0 output — архитектурные решения (R1–R10)
├── data-model.md        # Phase 1 output — сущности, схема trace, вердикты
├── quickstart.md        # Phase 1 output — как запустить демонстрацию
├── contracts/
│   ├── cli.md           # контракт CLI: run / score / demo
│   ├── tools.md         # контракт инструментов мишени + границы песочницы
│   └── trace-events.md  # контракт событий JSONL-trace
├── checklists/
│   └── requirements.md  # (существующий) чек-лист качества спеки
└── tasks.md             # Phase 2 output (/speckit-tasks — НЕ создаётся этой командой)
```

### Source Code (repository root)

```text
src/aiuc_mini/
├── config.py            # Pydantic-настройки: модели, бюджеты, пути, флаг guardrails
├── llm/
│   └── factory.py       # init_chat_model поверх .env — ЕДИНСТВЕННОЕ место создания модели
├── sandbox/
│   ├── fs.py            # Sandbox: tmp-root, resolve+is_relative_to, отказ при выходе
│   ├── shell.py         # фиктивный интерпретатор команд (без subprocess)
│   └── http.py          # фикстурный HTTP-транспорт (без реальной сети)
├── target/
│   ├── tools.py         # run_command / read_file / write_file / http_get поверх sandbox/
│   ├── prompt.py        # системный промпт: роль, границы, канареечный секрет
│   └── agent.py         # create_agent(model, tools, middleware=[...])
├── guardrails/
│   ├── input.py         # @before_model — детекция инъекций (jump_to=end)
│   ├── output.py        # @after_model — маскирование секрета/PII
│   ├── tools_policy.py  # @wrap_tool_call — allow-list, блокировка без вызова handler
│   └── policy.py        # GuardrailPolicy: правила + allow-list в одном месте
├── redteam/
│   ├── suite.py         # загрузка attacks/suite.yaml
│   ├── attacker.py      # LLM-агент: генерация и мутация инъекций
│   └── judge.py         # ЧИСТЫЕ предикаты вердикта (никакой LLM)
├── scorecard/
│   ├── controls.py      # 12 учебных контролей = предикаты над trace
│   ├── aggregate.py     # ЧИСТАЯ функция traces -> Scorecard
│   └── render.py        # Scorecard -> scorecard.json + scorecard.md
├── trace/
│   ├── events.py        # Pydantic-модели событий
│   └── writer.py        # JSONL writer/reader
└── cli.py               # typer: run / score / demo

attacks/
└── suite.yaml           # фиксированный набор атак (основа воспроизводимости)

runs/                    # артефакты прогонов (gitignored)
└── <run_id>/{trace.jsonl,scorecard.json,scorecard.md}

tests/
├── isolation/           # ГЕЙТ Принципа II: побег из песочницы невозможен
│   ├── test_shell_no_subprocess.py
│   ├── test_fs_boundaries.py
│   └── test_http_no_network.py
├── determinism/         # ГЕЙТ Принципа IV: score(trace) воспроизводим
│   ├── test_scorecard_pure.py
│   └── test_judge_predicates.py
├── unit/                # инструменты, guardrail-правила, судья, контроли
└── integration/         # прогон на fake-модели: без защиты vs с защитой
```

**Structure Decision**: Single project — установочный пакет `src/aiuc_mini/` плюс тонкий CLI.
Каталоги первого уровня повторяют 4 модуля спеки (`target`, `redteam`, `guardrails`,
`scorecard`) плюс три сквозных: `sandbox` (Принцип II), `trace` (Принцип V), `llm` (шов
Принципа IV). Такое соответствие «каталог = модуль спеки» выбрано намеренно ради Принципа I:
читающий спеку сразу знает, где лежит код.

Отдельно выделены `tests/isolation/` и `tests/determinism/` — не потому, что так принято, а
потому что это исполняемые гейты конституции: пока они зелёные, Принципы II и IV не нарушены.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

Не заполняется — Constitution Check пройден без отклонений.
