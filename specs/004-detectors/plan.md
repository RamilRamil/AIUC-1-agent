# Implementation Plan: Детекторы — PII, секреты в аргументах, изоляция данных

**Branch**: `004-detectors-pii-secrets` | **Date**: 2026-07-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/004-detectors/spec.md`

## Summary

Фича **добавляет защиту** (в отличие от 003, которая чинила измерение — оно уже готово и честно).
Три части:

1. **Секрет в аргументах tool-call → блокировка вызова** ([guardrails/tools_policy.py](../../src/aiuc_mini/guardrails/tools_policy.py)).
   Стенд детектирует этот вектор с фичи 001 и до сих пор не закрывал: `http_get` в allow-list, а
   выходной guardrail чистит только текст ответа. Это единственный успех атаки в защищённом
   прогоне и провал `PRIV-02`.
2. **PII-детектор** — маскирование в ответах агента и в trace (A006 → новый контроль `PRIV-04`).
3. **Контроль изоляции данных между попытками** (A005 → новый контроль `PRIV-03`): свойство
   обеспечено песочницей, но нигде не проверяется.

Плюс попутно чинится **латентный баг**: `OutputGuardrail.after_model` перезаписывает `AIMessage`
по id **без `tool_calls`** — на реальной модели, шлющей текст вместе с вызовом инструмента,
редакция снесла бы вызовы.

После фичи A005/A006 переводятся в `covered` в карте покрытия — но только через гейт
`test_covered_grounded` (фича 002), который не даст соврать.

## Technical Context

**Language/Version**: Python 3.11+ (без изменений)

**Primary Dependencies**: без новых. Детекторы — `re` из стандартной библиотеки.

**Storage**: без изменений. Формат trace **расширяется аддитивно** (новых типов событий не
вводим; PII маскируется существующим механизмом writer'а).

**Testing**: `pytest` в контейнере. Новые контроли обязаны пройти мета-тест фичи 003
(`tests/honesty/test_controls_falsifiable.py`) — то есть иметь вход, на котором проваливаются.

**Target Platform**: локальный, всё через Docker

**Project Type**: single project — правки существующих модулей `aiuc_mini`

**Performance Goals**: не применимо

**Constraints**:
- guardrail MUST работать на **обоих** путях — `wrap_tool_call` и `awrap_tool_call` (раннер зовёт
  мишень через `ainvoke` ради таймаута; забытый async-путь уже один раз тихо сломал политику);
- редакция вывода MUST сохранять `tool_calls` сообщения;
- новые контроли MUST быть `scorable` (гейт фичи 003);
- доля ложных блокировок MUST остаться ≤ 10% (SC-004 фичи 001) — новые детекторы не должны
  начать блокировать легитимное;
- `covered` в карте MUST ставиться только при реальном механизме (гейт фичи 002).

**Scale/Scope**: 3 модуля guardrail, 2 новых контроля, ~2 записи карты

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Проверка против [конституции v1.0.0](../../.specify/memory/constitution.md).

| Принцип | Как план ему удовлетворяет | Статус |
|---|---|---|
| **I. Обучение через практику** | Детекторы — простые предикаты над строкой, без ML и внешних сервисов. Учебная ценность прямая: видно, что «детектор ловит то, подо что написан». | ✅ PASS |
| **II. Безопасность песочницы (NON-NEGOTIABLE)** | Инструменты и песочница не меняются. Фича **сужает** поверхность (блокирует вызовы), а не расширяет. | ✅ PASS (не ослабляется) |
| **III. Объективная проверяемость** | Детекторы — детерминированные предикаты, никакого LLM. Новые контроли — чистые функции над trace, обязаны иметь падающий вход. | ✅ PASS |
| **IV. Воспроизводимость** | Детекторы детерминированы; scorecard остаётся чистой функцией от trace. | ✅ PASS |
| **V. Наблюдаемость** | Каждое решение детектора журналируется (блокировка по секрету, маскирование PII) — иначе нельзя отличить «сработал» от «не отработал». | ✅ PASS |
| **VI. Spec-driven разработка** | spec → clarify (в спеке) → plan → tasks → code. Границы детекторов зафиксированы в спеке заранее, а не после. | ✅ PASS |

**Итог гейта: PASS.** Complexity Tracking не заполняется.

**Заметка по Принципу V**: PII маскируется и в trace — но решение о маскировании **журналируется**,
иначе журнал молча терял бы данные, и нельзя было бы доказать, что детектор работал.

**Re-check после Phase 1**: PASS — дизайн не трогает песочницу, детекторы остаются чистыми
предикатами, новые контроли фальсифицируемы.

## Project Structure

### Documentation (this feature)

```text
specs/004-detectors/
├── plan.md              # этот файл
├── research.md          # Phase 0 — блокировка vs маскирование, состав PII, как измерить изоляцию
├── data-model.md        # Phase 1 — правило секрета, паттерн PII, контроли PRIV-03/04
├── quickstart.md        # Phase 1 — как убедиться, что дыра закрыта
├── contracts/
│   └── detectors.md     # контракт детекторов: что ловят, что НЕ ловят
├── checklists/
│   └── requirements.md  # (существующий) чек-лист качества спеки
└── tasks.md             # Phase 2 (/speckit-tasks — НЕ здесь)
```

### Source Code (repository root) — правки существующего

```text
src/aiuc_mini/
├── guardrails/
│   ├── policy.py          # + паттерны PII, + правило секрета в аргументах
│   ├── tools_policy.py    # блокировка вызова при секрете в args (sync + async пути)
│   ├── output.py          # PII-маскирование; ФИКС: сохранять tool_calls при перезаписи
│   └── __init__.py        # прокинуть secret в ToolPolicyGuardrail (сейчас его получает
│                          #   только OutputGuardrail)
├── trace/writer.py        # маскирование PII наряду с канарейкой
└── scorecard/controls.py  # + PRIV-03 (изоляция данных, A005), + PRIV-04 (PII, A006)

aiuc1/catalog.yaml         # A005 → covered/PRIV-03, A006 → covered/PRIV-04
docs/aiuc1-coverage.md     # перегенерировать (aiuc coverage)

tests/
├── unit/test_detectors.py             # правило секрета, паттерны PII, отсутствие ложных
├── unit/test_output_preserves_tool_calls.py  # регресс на латентный баг
├── integration/test_exfil_blocked.py  # 🔒 US1: эксфильтрация закрыта, PRIV-02 проходит
├── integration/test_data_isolation.py # 🔒 US3: данные попытки A недоступны в попытке B
└── honesty/test_controls_falsifiable.py  # + падающие входы для PRIV-03/PRIV-04
```

**Structure Decision**: Правки в существующих модулях; новых пакетов нет. Паттерны PII и правило
секрета кладутся в `guardrails/policy.py` — там уже живут правила политики, и это сохраняет
единственное место для «что считается нарушением».

Секрет прокидывается в `ToolPolicyGuardrail` через уже существующий параметр
`build_guardrail_middleware(secret, ...)` — новых швов не вводим.

Тесты US1 и US3 вынесены в `integration/`, а не в `honesty/`: они проверяют **работу защиты**, а
не честность измерения. `honesty/` остаётся про методологию.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

Не заполняется — Constitution Check пройден без отклонений.
