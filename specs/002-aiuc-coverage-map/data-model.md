# Phase 1 — Data Model

**Feature**: `002-aiuc-coverage-map` | **Date**: 2026-07-15 | **Plan**: [plan.md](plan.md)

Модели — Pydantic v2, поверх `aiuc1/catalog.yaml`. Каталог — единственный источник истины;
всё остальное (Markdown-карта, агрегаты) выводится из него.

---

## 1. Control (запись каталога)

Одна запись = один контроль AIUC-1.

| Поле | Тип | Правила |
|---|---|---|
| `id` | `str` | идентификатор стандарта: `A001`…`F002`; уникален; матчит `^[A-F]\d{3}$` |
| `pillar` | `Pillar` | `data_privacy` \| `security` \| `safety` \| `reliability` \| `accountability` \| `society` — выводится из буквы id и должен ей соответствовать |
| `title` | `str` | краткое человекочитаемое описание контроля |
| `nature` | `Nature` | `technical` \| `organizational` \| `mixed` |
| `status` | `Status` | `covered` \| `technical_achievable` \| `doc_only` \| `retired` (для 2 отозванных E007/E014) |
| `binding` | `Binding` | привязка (см. §2) |
| `rationale` | `str` | почему такой статус/природа |
| `partial` | `Partial \| None` | заполнено только для `nature=mixed` (см. §3) |
| `backlog_item` | `str \| None` | id кластера бэклога; `None` для `covered` и `retired` |

**Инварианты**:
- `pillar` MUST соответствовать префиксу `id` (A→data_privacy, B→security, C→safety,
  D→reliability, E→accountability, F→society);
- `status=covered` ⇒ `binding.scorecard_control` заполнено и `backlog_item is None`;
- `status=retired` ⇒ освобождён от правил покрытия и бэклога (это E007/E014);
- `status ∈ {technical_achievable, doc_only}` ⇒ `backlog_item` заполнено (контроль обязан попасть в план);
- `partial` заполнено ⇔ `nature=mixed`.

---

## 2. Binding (привязка)

Что закрывает или закроет контроль.

| Поле | Тип | Смысл |
|---|---|---|
| `kind` | `Literal["scorecard_control","attack_category","guardrail_rule","artifact"]` | тип привязки |
| `scorecard_control` | `str \| None` | id существующего контроля scorecard (`SEC-01`…) — обязателен для `covered` |
| `stand_mechanism` | `str \| None` | свободное указание на механизм стенда (песочница, guardrail-правило, категория атаки) |
| `artifact_type` | `ArtifactType \| None` | для `doc_only`: `policy` \| `runbook` \| `attestation` \| `third_party_test` |

**Инвариант** (SC-004): если `Control.status=covered`, то `scorecard_control` MUST быть непустым
и MUST присутствовать среди фактических id в `scorecard/controls.py` (проверяет тест).

---

## 3. Partial (разбивка mixed-контроля)

| Поле | Тип | Смысл |
|---|---|---|
| `technical` | `str` | что в контроле технически достижимо кодом |
| `documentable` | `str` | что в контроле — организационное/документируемое |

Присутствует только у mixed. Не влияет на агрегацию по базовым статусам (из clarify).

---

## 4. BacklogItem (кластер бэклога)

Отдельная секция каталога: определения кластеров, на которые ссылаются `Control.backlog_item`.

| Поле | Тип | Правила |
|---|---|---|
| `id` | `str` | `003-detectors`, `004-input-moderation`, … (номер будущей фичи + слаг) |
| `title` | `str` | название кластера |
| `nature` | `Literal["technical","organizational"]` | природа работы |
| `priority` | `int` | порядок в бэклоге; 1 = первый (MUST быть техническим — SC-006) |
| `rationale` | `str` | обоснование приоритета |

**Инварианты**:
- каждый `Control.backlog_item` (не-None) MUST ссылаться на существующий `BacklogItem.id`;
- каждый не-`covered` контроль отнесён ровно к одному кластеру (FR-006, SC-002);
- кластер с `priority=1` MUST иметь `nature=technical` (SC-006).

---

## 5. Catalog (корень)

| Поле | Тип |
|---|---|
| `version` | `str` — версия карты (FR-011) |
| `source` | `str` — ссылка на источник (aiuc-1.com/evidence) + дата |
| `controls` | `list[Control]` — ровно 53 |
| `backlog` | `list[BacklogItem]` |

**Инварианты**:
- `len(controls) == 53`; множество `id` в точности равно
  {A001..A008, B001..B010, C001..C012, D001..D004, E001..E015, F001..F002};
- никаких дублей id.

---

## 6. Aggregates (вычисляемые, не хранимые)

Чистая функция от `Catalog`:

| Агрегат | Правило |
|---|---|
| `by_status` | число контролей по каждому базовому статусу; **сумма == 51** (активные, FR-009) |
| `by_pillar` | число активных контролей по каждому пиллеру |
| `partial_count` | число контролей с `partial` (отдельно, не в сумме статусов) |
| `retired_count` | число `retired` (2: E007, E014) |
| `coverage_pct` | доля `covered` от активных (51) |

**Инвариант воспроизводимости** (Принцип IV): агрегаты и Markdown-рендер — чистые функции от
каталога; тот же каталог даёт тот же результат побайтово.

---

## Схема связей

```
catalog.yaml
   ├── controls[53] ──> Binding ──(covered)──> scorecard/controls.py  [тест SC-004]
   │        │
   │        └──(не covered)──> backlog_item ──> BacklogItem
   │
   └── backlog[] ──> BacklogItem (priority, nature)

Catalog ──[чистая функция render]──> docs/aiuc1-coverage.md   [тест SC-003]
Catalog ──[чистая функция aggregate]──> by_status / by_pillar  [тест FR-009]
```
