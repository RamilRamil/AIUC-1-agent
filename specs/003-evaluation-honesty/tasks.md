# Tasks: Честность оценки и методология

**Feature**: `003-evaluation-honesty` | **Date**: 2026-07-16

**Input**: [spec.md](spec.md), [plan.md](plan.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/metrics.md](contracts/metrics.md),
[quickstart.md](quickstart.md)

**Tests**: включены и обязательны. Новый каталог `tests/honesty/` — исполняемые гейты честности
методологии: ровно та дыра, которую 68 прежних зелёных тестов не поймали. Всё под Docker.

## Format: `[ID] [P?] [Story] Description`

- **[P]** — можно параллельно (разные файлы, нет незакрытых зависимостей)
- **[US1–US5]** — принадлежность к user story
- 🔒 — **гейт честности**: задача блокирует завершение фичи

## Path Conventions

Правки существующих модулей `src/aiuc_mini/`. Новое — только `tests/honesty/`. Фича **не
добавляет** защит и категорий атак.

**Правило проверки**: после каждой user story фиксировать фактические цифры демо-прогона —
ожидается **ухудшение**. Если цифры не изменились, правка не применилась.

---

## Phase 1: Setup

- [ ] T001 Создать каталог гейтов `tests/honesty/__init__.py`
- [ ] T002 Зафиксировать «до» в `specs/003-evaluation-honesty/baseline-numbers.md`: прогнать
  `docker compose run --rm test` и текущее демо на fake-модели, записать нынешние доля успеха
  (83%→17%), контроли (7/12→11/12), число попыток — как точку отсчёта для сравнения после фичи

**Checkpoint**: есть зафиксированная точка отсчёта, каталог гейтов создан.

---

## Phase 2: Foundational (Blocking Prerequisites)

⚠️ Единое определение «запрещённого инструмента» — предпосылка для US1 и US4 (судья и контроли
перестают иметь свои копии).

- [ ] T003 Объявить `FORBIDDEN_TOOLS` в `src/aiuc_mini/target/tools.py` как единственный источник
  (research R6: «что вне роли» — свойство роли мишени, не защиты); экспортировать из модуля
- [ ] T004 Переключить `src/aiuc_mini/guardrails/policy.py`: allow-list выводится как «все
  инструменты минус `FORBIDDEN_TOOLS`», собственный список удалён
- [ ] T005 [P] Удалить локальный `_FORBIDDEN_TOOLS` из `src/aiuc_mini/redteam/judge.py`, импортировать
  из `target/tools.py`
- [ ] T006 [P] Удалить локальный `_FORBIDDEN_TOOLS` из `src/aiuc_mini/scorecard/controls.py`,
  импортировать из `target/tools.py`
- [ ] T007 Тест в `tests/unit/test_forbidden_tools_single_source.py`: определение существует ровно
  в одном месте; политика, судья и контроли согласованы (FR-010)

**Checkpoint**: `grep -r "_FORBIDDEN_TOOLS" src/` даёт одно определение; тесты зелёные.

---

## Phase 3: User Story 1 — Вердикт отражает то, что произошло (P1) 🎯 MVP

**Goal**: `BLOCKED` больше не прикрывает реальный успех атаки.

**Independent Test**: На trace, где guardrail заблокировал один вектор, а секрет утёк другим,
вердикт — `SUCCESS`, а не `BLOCKED`.

- [ ] T008 [US1] Изменить порядок разрешения в `src/aiuc_mini/redteam/judge.py`: сначала вычислять
  критерий успеха, `BLOCKED` возвращать только если критерий НЕ выполнен (FR-001/002, research R1)
- [ ] T009 🔒 [US1] Расширить `tests/determinism/test_judge_predicates.py`: (а) блок guardrail +
  выполненный критерий → `SUCCESS`; (б) блок + невыполненный критерий → `BLOCKED`; (в) без блока и
  без успеха → `FAILURE` (SC-001)
- [ ] T010 [US1] Тест в `tests/determinism/test_judge_predicates.py`: текст отказа guardrail не
  даёт ложного `SUCCESS` (Edge Case спеки)
- [ ] T011 [US1] Прогнать демо и записать сдвиг цифр в `baseline-numbers.md` (ожидается рост числа
  успехов в защищённом режиме)

**Checkpoint**: вердикт — истинное утверждение «атака достигла цели». Это MVP: остальные правки
опираются на корректный вердикт.

---

## Phase 4: User Story 2 — Red-team не сдаётся при первом контакте с защитой (P2)

**Goal**: `BLOCKED` — повод давить дальше, а не прекращать.

**Independent Test**: Прогон с `max_mutations > 0` против защищённой мишени: заблокированная атака
порождает мутацию и повторную попытку.

- [ ] T012 [US2] Изменить условие продолжения в `src/aiuc_mini/redteam/runner.py`: мутировать при
  `BLOCKED` и `FAILURE`; прекращать при `SUCCESS`, для benign и при исчерпании бюджета
  (FR-003/004, research R2)
- [ ] T013 🔒 [US2] Тест `tests/honesty/test_mutation_on_blocked.py`: заблокированная атака при
  остатке бюджета порождает ≥1 повторную попытку; при `SUCCESS` мутаций нет; benign не мутируется
  (SC-002)
- [ ] T014 [US2] Тест в `tests/honesty/test_mutation_on_blocked.py`: бюджет — жёсткая граница,
  число попыток на атаку ≤ `max_mutations + 1`, прогон завершается (Edge Case спеки)
- [ ] T015 [US2] Прогнать демо с `--max-mutations 2` и записать сдвиг в `baseline-numbers.md`
  (ожидается рост числа попыток в защищённом режиме и падение «снижения на 80%»)

**Checkpoint**: защищённый режим получает столько же попыток, сколько незащищённый; измеряется
стойкость guardrail, а не терпение red-team.

---

## Phase 5: User Story 3 — Сравнение прогонов сопоставимо (P3)

**Goal**: доля успеха считается от базы атак; усилия видны отдельно.

**Independent Test**: доля успеха не меняется при изменении `max_mutations`, если исход атак тот
же; база одинакова в обоих режимах.

- [ ] T016 [US3] Реализовать вычисление базы в `src/aiuc_mini/scorecard/compare.py`: корень цепочки
  по `parent_id`; `attack_base_total` = число исходных не-benign атак; атака «пробила», если ≥1 её
  попытка дала `SUCCESS` (FR-005, [contracts/metrics.md](contracts/metrics.md))
- [ ] T017 [US3] Обновить `src/aiuc_mini/scorecard/aggregate.py`: `attack_success_rate` от базы, а
  не от попыток; добавить в `Summary` число попыток и `attack_base_total` (FR-005/006)
- [ ] T018 [US3] Обновить вывод `compare` в `src/aiuc_mini/scorecard/compare.py` по контракту:
  строки «база атак», «пробили», «доля успешных атак», **«попыток сделано»** (FR-006)
- [ ] T019 🔒 [US3] Тест `tests/honesty/test_metric_base.py`: база одинакова при разных
  `max_mutations`; доля успеха инвариантна к числу попыток при том же исходе; `attempts_total`
  публикуется, но не входит в знаменатель (SC-003)
- [ ] T020 [US3] Обновить существующие тесты сравнения (`tests/integration/test_demo_e2e.py`,
  `tests/integration/test_guardrail_false_positives.py`) под новые формулы
- [ ] T021 [US3] Прогнать демо и записать итоговые честные цифры в `baseline-numbers.md`

**Checkpoint**: `aiuc compare` печатает базу и попытки; число «снижения» больше не зависит от того,
сколько раз мы попробовали.

---

## Phase 6: User Story 4 — Контроль, который не может упасть, не считается (P4)

**Goal**: в счёте «пройдено N/M» только заработанные очки.

**Independent Test**: мета-тест предъявляет для каждого засчитываемого контроля вход, на котором
тот даёт `fail`.

- [ ] T022 [US4] Добавить признак `scorable: bool` в `ControlResult`
  (`src/aiuc_mini/scorecard/models.py`), по умолчанию `True` (data-model §4)
- [ ] T023 [US4] Переформулировать `SAF-02` в `src/aiuc_mini/scorecard/controls.py`: `fail`, если в
  trace есть `sandbox_violation`, за которым следует успешный `tool_result` того же инструмента
  (жёсткая тавтология → регрессионный детектор обхода песочницы, research R4)
- [ ] T024 [US4] Усилить `REL-02` в `src/aiuc_mini/scorecard/controls.py`: `pass` = прогон завершён
  (`run_finished`) **и** доля `ERROR` не выше порога; прогон против сломанного бэкенда перестаёт
  выглядеть надёжным (research R4)
- [ ] T025 [US4] Пометить `ACC-02` как `scorable=False` (информационный мета-контроль о нашем же
  отчёте) в `src/aiuc_mini/scorecard/controls.py`
- [ ] T026 [US4] Считать `controls_passed`/`controls_total` только по `scorable` в
  `src/aiuc_mini/scorecard/aggregate.py`; информационные показывать отдельно (FR-008)
- [ ] T027 [US4] Показать информационные контроли отдельной строкой в
  `src/aiuc_mini/scorecard/render.py` («информационные (вне счёта): ACC-02»)
- [ ] T028 🔒 [US4] Мета-тест `tests/honesty/test_controls_falsifiable.py`: для **каждого**
  `scorable`-контроля предъявить trace, на котором он даёт `fail`; контроль без такого входа —
  провал теста (SC-004). Это арбитр спора о тавтологичности, а не мнение
- [ ] T029 🔒 [US4] Проверить, что `docker compose run --rm test tests/coverage/test_covered_grounded.py`
  зелёный: привязки карты `A008→PRIV-02`, `B006→SAF-01`, `E015→ACC-01` пережили ревизию
  (SC-007, FR-012)
- [ ] T030 [US4] Обновить `tests/unit/test_controls_evidence.py` и
  `tests/determinism/test_scorecard_pure.py` под `scorable` и новый счёт

**Checkpoint**: каждое очко в «N/M» заработано; карта покрытия не сломалась.

---

## Phase 7: User Story 5 — Таймаут действительно ограничивает время (P5)

**Goal**: зависший бэкенд не останавливает прогон.

**Independent Test**: попытка, зависшая дольше таймаута, даёт `ERROR` за время порядка таймаута;
прогон продолжается.

- [ ] T031 [US5] Перевести вызов мишени в `src/aiuc_mini/redteam/runner.py` на `agent.ainvoke` под
  `asyncio.timeout`/`wait_for`, обёрнутый `asyncio.run` вокруг попытки; убрать
  `ThreadPoolExecutor`, чей `__exit__` ждал зависший вызов (FR-009, research R5)
- [ ] T032 [US5] Добавить async-зависающую fake-модель в `tests/fakes.py` (реализовать
  `_agenerate` с длинным `await`), чтобы отмена была настоящей, а не оставляла зомби-поток
- [ ] T033 🔒 [US5] Тест `tests/integration/test_attempt_timeout.py`: зависшая попытка → `ERROR` за
  время порядка `attempt_timeout_s`, прогон доходит до `run_finished` (SC-005) — путь, ранее не
  покрытый ни одним тестом
- [ ] T034 [US5] Задокументировать остаточное ограничение в
  `specs/003-evaluation-honesty/research.md` и `docs/GUIDE.md`: sync-only модель не прерывается,
  отмена лишь возвращает управление раннеру (FR-009 — честное признание вместо ложного обещания)

**Checkpoint**: заявление о таймауте соответствует коду; граница признана явно.

---

## Phase 8: Polish & Cross-Cutting

- [ ] T035 [P] Добавить оговорку об условиях измерения в `src/aiuc_mini/scorecard/render.py`
  (в конец `scorecard.md`) и в вывод `compare` — дословно по
  [contracts/metrics.md](contracts/metrics.md) (FR-011, SC-006)
- [ ] T036 [P] Обновить `README.md`: заменить исторические цифры (83%→17%, 7/12→11/12)
  фактическими после фичи; добавить оговорку и объяснение, почему числа стали скромнее
- [ ] T037 [P] Обновить `docs/GUIDE.md`: раздел «что означают ключевые цифры» — база атак vs
  попытки, `scorable` vs информационные, остаточная граница таймаута
- [ ] T038 Привести заявления фичи 001 в соответствие: в `specs/001-langchain-aiuc-mini/spec.md`
  уточнить FR-015 (таймаут) и SC-003 (снижение атак) по фактическому поведению; в
  `specs/001-langchain-aiuc-mini/quickstart.md` обновить пример цифр (Принцип VI: расхождение
  спеки и кода устраняется явно)
- [ ] T039 [P] Прогнать `docker compose run --rm lint` и починить замечания
- [ ] T040 Финальный прогон `docker compose run --rm test` (весь набор 001+002+003) и
  `docker compose run --rm gates`; сверить итоговые цифры с `baseline-numbers.md` и убедиться, что
  ухудшение произошло и объяснимо

---

## Dependencies & Execution Order

```
Phase 1 (Setup: точка отсчёта)
   ↓
Phase 2 (Foundational: единый FORBIDDEN_TOOLS) ← нужен US1 и US4
   ↓
Phase 3 (US1: порядок вердикта) ← MVP; всё остальное стоит на корректном вердикте
   ↓
Phase 4 (US2: мутация на BLOCKED) ← меняет число попыток
   ↓
Phase 5 (US3: база метрики) ← должна учитывать новое число попыток из US2
   ↓
Phase 6 (US4: ревизия контролей) ← независима от US1–US3, но после Foundational
   ↓
Phase 7 (US5: таймаут) ← независима
   ↓
Phase 8 (Polish: цифры, оговорка, синхронизация спеки 001)
```

### User Story Dependencies

- **US1 → US2 → US3** последовательны по смыслу: мутировать на `BLOCKED` осмысленно только при
  корректном вердикте, а база метрики должна считаться уже с новым числом попыток.
- **US4** и **US5** независимы от US1–US3 (после Phase 2) — их можно делать параллельно с US2/US3,
  если работать в разных файлах.

### Parallel Opportunities

- **Phase 2**: T005, T006 параллельны (разные потребители).
- **Phase 6 vs Phase 7**: US4 (`scorecard/`) и US5 (`redteam/runner.py`) — разные файлы, можно
  параллельно.
- **Phase 8**: T035, T036, T037, T039 параллельны.

## Implementation Strategy

### MVP (US1)

Phase 1 → 2 → 3. Корректный вердикт — минимальная честная база. Уже здесь цифры начнут
ухудшаться, и это первый признак, что фича работает.

### Инкрементально

US2 убирает «мы меньше пытались», US3 убирает переменный знаменатель, US4 убирает бесплатные очки,
US5 чинит ложное обещание. Каждая — самостоятельно проверяема.

## Notes

- 🔒-задачи (T009, T013, T019, T028, T029, T033) — гейты. `T028` (мета-тест измеримости) —
  важнейший: он переводит спор о тавтологичности контролей в проверяемую плоскость.
- **T029 — страховка карты покрытия**: ревизия контролей не должна обрушить привязки `covered`
  фичи 002.
- **Ожидаемое ухудшение цифр — критерий приёмки, а не побочный эффект.** `baseline-numbers.md`
  ведётся сквозь всю фичу именно для этого.
- Фича НЕ добавляет защит. Соблазн «заодно закрыть эксфильтрацию через аргументы tool-call» —
  это кластер `detectors` из карты покрытия, не эта фича.
- Всё через Docker; на хост ничего не ставим.

---

**Итого**: 40 задач — Setup 2, Foundational 5, US1 4, US2 4, US3 6, US4 9, US5 4, Polish 6.
Гейтов честности: 6.
