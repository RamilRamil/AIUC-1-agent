# Tasks: Карта покрытия AIUC-1 и бэклог расширения

**Feature**: `002-aiuc-coverage-map` | **Date**: 2026-07-15

**Input**: [spec.md](spec.md), [plan.md](plan.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/catalog-schema.md](contracts/catalog-schema.md),
[quickstart.md](quickstart.md)

**Tests**: включены и обязательны. Три теста `tests/coverage/` — исполняемые гейты честности
карты (аналог гейтов конституции фичи 001). Всё гоняется под Docker.

## Format: `[ID] [P?] [Story] Description`

- **[P]** — можно параллельно (разные файлы, нет незакрытых зависимостей)
- **[US1–US3]** — принадлежность к user story
- 🔒 — **гейт честности**: задача блокирует завершение фичи

## Path Conventions

Single project. Схема/генератор — `src/aiuc_mini/aiuc1/`, данные — `aiuc1/catalog.yaml`,
карта — `docs/aiuc1-coverage.md`, тесты — `tests/coverage/`. Никакой реализации контролей
безопасности эта фича не делает.

---

## Phase 1: Setup

- [X] T001 Создать подпакет `src/aiuc_mini/aiuc1/__init__.py` и каталог тестов `tests/coverage/__init__.py`
- [X] T002 [P] Создать пустой `aiuc1/catalog.yaml` с корневыми полями `version`, `source`, `controls: []`, `backlog: []` (заполнение — в US1)

**Checkpoint**: структура на месте, импорт `aiuc_mini.aiuc1` работает.

---

## Phase 2: Foundational (Blocking Prerequisites)

⚠️ Схема каталога — фундамент для всех трёх user story. Без неё нельзя ни заполнить каталог, ни
рендерить, ни валидировать.

- [X] T003 Реализовать Pydantic-схему каталога в `src/aiuc_mini/aiuc1/catalog.py` строго по
  [data-model.md](data-model.md) и [contracts/catalog-schema.md](contracts/catalog-schema.md):
  модели `Control`, `Binding`, `Partial`, `BacklogItem`, `Catalog`; enum'ы `Pillar`, `Nature`,
  `Status`, `ArtifactType`; загрузка из YAML
- [X] T004 Добавить валидаторы схемы в `src/aiuc_mini/aiuc1/catalog.py`: `pillar` согласован с
  буквой `id` (A→data_privacy…F→society); `partial` ⇔ `nature=mixed`; `status=covered` ⇒
  `binding.scorecard_control` задан и `backlog_item is None`; `status≠covered` ⇒ `backlog_item` задан
- [X] T005 [P] Реализовать чистую функцию агрегатов в `src/aiuc_mini/aiuc1/catalog.py`:
  `aggregate(catalog) -> {by_status, by_pillar, partial_count, retired_count, coverage_pct}`;
  сумма по базовым статусам == 51 (активные), retired (2) и `partial` считаются отдельно (FR-009)

**Checkpoint**: схему можно импортировать, пустой/частичный каталог валидируется, агрегаты считаются.

---

## Phase 3: User Story 1 — Полная классификация 53 контролей (P1) 🎯 MVP

**Goal**: `aiuc1/catalog.yaml` содержит все 53 контроля с корректными статусами, природой и
привязками; каталог валиден по схеме.

**Independent Test**: Загрузить каталог — ровно 53 контроля, точный набор id, у каждого есть
статус/природа/привязка; валидатор зелёный.

- [X] T006 [US1] Заполнить пиллер A (A001–A008) в `aiuc1/catalog.yaml` по классификации
  [research.md](research.md) R4: статусы, природа, привязки, `rationale`; `partial` для A004/A007
- [X] T007 [US1] Заполнить пиллер B (B001–B010) в `aiuc1/catalog.yaml` (B006 = covered → SAF-01/02)
- [X] T008 [US1] Заполнить пиллер C (C001–C012) в `aiuc1/catalog.yaml` (C004 = covered; C010–C012
  = doc-only, artifact_type=third_party_test)
- [X] T009 [US1] Заполнить пиллер D (D001–D004) в `aiuc1/catalog.yaml` (D002/D004 = third_party_test)
- [X] T010 [US1] Заполнить пиллер E (E001–E017) в `aiuc1/catalog.yaml` (E015 = covered → ACC-01;
  E007/E014 = retired; остальные doc-only)
- [X] T011 [US1] Заполнить пиллер F (F001–F002) в `aiuc1/catalog.yaml`
- [X] T012 🔒 [US1] Тест `tests/coverage/test_catalog_valid.py`: ровно 53 контроля, точный набор
  id {A001–A008,B001–B010,C001–C012,D001–D004,E001–E017,F001–F002} без дублей; E007/E014 retired;
  `pillar` согласован с id; сумма по базовым статусам == 51 (активные); `partial` ⇔ `nature=mixed`
  (FR-001, FR-009, SC-001)
- [X] T013 🔒 [US1] Тест `tests/coverage/test_covered_grounded.py`: импортировать фактические id
  контролей из `scorecard/controls.py`; каждый контроль `status=covered` MUST ссылаться на
  существующий `scorecard_control` — иначе падение (SC-004)

**Checkpoint**: каталог полон и честен; `docker compose run --rm test tests/coverage/test_catalog_valid.py
tests/coverage/test_covered_grounded.py` зелёный. Это уже самостоятельная ценность — машиночитаемая карта.

---

## Phase 4: User Story 2 — Приоритизированный бэклог (P2)

**Goal**: В каталоге определены кластеры бэклога; каждый не-`covered` контроль отнесён ровно к
одному кластеру; первый кластер — технический.

**Independent Test**: Каждый не-`covered` контроль имеет `backlog_item`, ссылающийся на
существующий кластер; кластер `priority=1` имеет `nature=technical`.

- [X] T014 [US2] Заполнить секцию `backlog:` в `aiuc1/catalog.yaml` кластерами из
  [research.md](research.md) R5 (detectors, input-moderation, tool-policy,
  output-filters, governance, attestation, society): `id`, `title`, `nature`,
  `priority`, `rationale`
- [X] T015 [US2] Проставить/выверить `backlog_item` у каждого не-`covered` контроля в
  `aiuc1/catalog.yaml` (ровно один кластер на контроль)
- [X] T016 🔒 [US2] Расширить `tests/coverage/test_catalog_valid.py`: каждый `backlog_item`
  ссылается на существующий кластер; каждый не-`covered` контроль отнесён ровно к одному кластеру
  (FR-006, SC-002); кластер `priority=1` имеет `nature=technical` (SC-006)

**Checkpoint**: бэклог полон и непротиворечив; приоритеты выставлены, первый пункт технический.

---

## Phase 5: User Story 3 — Машиночитаемый каталог → карта (P3)

**Goal**: Из каталога чистой функцией порождается `docs/aiuc1-coverage.md` (карта + бэклог +
агрегаты); CLI `aiuc coverage` собирает её; рендер детерминирован и не расходится с источником.

**Independent Test**: `aiuc coverage` печатает агрегаты и пишет `docs/aiuc1-coverage.md`; повторный
рендер побайтово совпадает; агрегаты в карте совпадают с посчитанными из каталога.

- [X] T017 [US3] Реализовать чистую функцию рендера в `src/aiuc_mini/aiuc1/render.py`:
  `render(catalog) -> str` (Markdown: таблицы по 6 пиллерам со статусами и привязками, секция
  бэклога, блок агрегатов); детерминированный порядок (контроли по id, пиллеры фиксировано)
- [X] T018 [US3] Реализовать CLI-команду `aiuc coverage` в `src/aiuc_mini/cli.py`: загрузить
  каталог, напечатать агрегаты, записать `docs/aiuc1-coverage.md` (контракт [quickstart.md](quickstart.md))
- [X] T019 [US3] Сгенерировать `docs/aiuc1-coverage.md` командой `aiuc coverage` и закоммитить как
  производный артефакт
- [X] T020 🔒 [US3] Тест `tests/coverage/test_render_pure.py`: `render(catalog) == render(catalog)`
  побайтово; результат рендера совпадает с содержимым `docs/aiuc1-coverage.md` (не разошлись,
  SC-003); агрегаты в тексте совпадают с `aggregate(catalog)`

**Checkpoint**: `aiuc coverage` работает, карта в `docs/` синхронна с каталогом, гейт SC-003 зелёный.

---

## Phase 6: Polish & Cross-Cutting

- [X] T021 [P] Обновить README: секция про карту покрытия AIUC-1 (`aiuc coverage`, ссылка на
  `docs/aiuc1-coverage.md`), явно отметить covered/achievable/doc-only и что covered проверяется тестом
- [X] T022 [P] Прогнать `docker compose run --rm lint` (ruff) и починить замечания
- [X] T023 Финальный прогон `docker compose run --rm test` — весь набор зелёный (фичи 001 + 002),
  затем сверить фактические агрегаты каталога с числами в quickstart/README (при расхождении
  править доки, не память)

---

## Dependencies & Execution Order

```
Phase 1 (Setup)
   ↓
Phase 2 (Foundational: схема + агрегаты) ← блокирует всё
   ↓
Phase 3 (US1: заполнить каталог 53) ← MVP; гейты T012, T013
   ↓
Phase 4 (US2: бэклог) ← нужен заполненный каталог; гейт T016
   ↓
Phase 5 (US3: рендер + CLI + карта) ← нужен каталог и бэклог; гейт T020
   ↓
Phase 6 (Polish)
```

### User Story Dependencies

Истории последовательны по данным: нельзя рендерить карту без каталога, нельзя проверить бэклог
без заполненных контролей. US1 самодостаточна как MVP (машиночитаемая классификация уже ценна).

### Parallel Opportunities

- **Phase 3**: T006–T011 (6 пиллеров) — правки одного файла `catalog.yaml`, поэтому
  **последовательно** (не помечены [P]); тесты T012/T013 можно писать параллельно после заполнения.
- **Phase 6**: T021, T022 параллельны.

## Implementation Strategy

### MVP (US1)

Phase 1 → 2 → 3. На выходе — валидный машиночитаемый каталог всех 53 контролей с честными
статусами (covered проверен против кода). Уже отвечает на вопрос «где мы относительно AIUC-1».

### Инкрементально

US2 добавляет план (бэклог), US3 — человекочитаемую карту и CLI. Каждая фаза самостоятельно
проверяема.

## Notes

- 🔒-задачи (T012, T013, T016, T020) — гейты честности карты. T013 (covered ↔ код) — важнейший:
  он не даёт карте соврать про покрытие.
- Эта фича НЕ реализует контролей безопасности. Если возникает соблазн «добавить guardrail» —
  это уже фича из бэклога (003+), а не эта.
- Все тесты и CLI — под Docker (`docker compose run --rm ...`), на хост ничего не ставим.

---

**Итого**: 23 задачи — Setup 2, Foundational 3, US1 8, US2 3, US3 4, Polish 3. Гейтов честности: 4.
