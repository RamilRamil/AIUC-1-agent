# Contract — Схема каталога `aiuc1/catalog.yaml`

**Feature**: `002-aiuc-coverage-map` | **Plan**: [../plan.md](../plan.md)

Единственный источник истины карты покрытия. Валидируется Pydantic-схемой
(`src/aiuc_mini/aiuc1/catalog.py`) и тестами `tests/coverage/`.

---

## Форма файла

```yaml
version: "1.0.0"
source: "https://www.aiuc-1.com/evidence (снимок 2026-07-15)"

controls:
  - id: A008
    pillar: data_privacy
    title: "Детект секретов во вход/выход, безопасное хранение, редакция"
    nature: technical
    status: covered
    binding:
      kind: scorecard_control
      scorecard_control: PRIV-02
      stand_mechanism: "маскирование канарейки в trace + предикаты PRIV-01/02"
    rationale: "детект/редакция секрета уже реализованы; полное покрытие — кластер детекторов"
    backlog_item: null

  - id: A006
    pillar: data_privacy
    title: "PII-детект во входах, выходах и логах"
    nature: technical
    status: technical_achievable
    binding:
      kind: guardrail_rule
      stand_mechanism: "новый PII-детектор в guardrails/output + вход"
    rationale: "механизма ещё нет; достижимо как guardrail-правило"
    backlog_item: "detectors"

  - id: A004
    pillar: data_privacy
    title: "Гайдлайны пользователя + защита IP провайдера + фильтр"
    nature: mixed
    status: doc_only
    binding:
      kind: artifact
      artifact_type: policy
    rationale: "часть — фильтр (технически достижимо), часть — политика"
    partial:
      technical: "IP/контент-фильтр на выходе"
      documentable: "пользовательские гайдлайны и политика использования"
    backlog_item: "governance"

  # ... всего ровно 53 записи ...

backlog:
  - id: "detectors"
    title: "Детекторы PII и секретов"
    nature: technical
    priority: 1
    rationale: "прямое продолжение Data & Privacy, наибольшая отдача первым шагом"
  # ... остальные кластеры ...
```

---

## Поля контроля

| Поле | Тип | Обязательность |
|---|---|---|
| `id` | `^[A-F]\d{3}$` | всегда |
| `pillar` | enum пиллеров, согласован с буквой id | всегда |
| `title` | строка | всегда |
| `nature` | `technical` \| `organizational` \| `mixed` | всегда |
| `status` | `covered` \| `technical_achievable` \| `doc_only` | всегда |
| `binding` | объект (см. ниже) | всегда |
| `rationale` | строка | всегда |
| `partial` | `{technical, documentable}` | ⇔ `nature=mixed` |
| `backlog_item` | id из `backlog[]` | ⇔ `status≠covered` |

### binding

| Поле | Тип |
|---|---|
| `kind` | `scorecard_control` \| `attack_category` \| `guardrail_rule` \| `artifact` |
| `scorecard_control` | id из `scorecard/controls.py` — обязателен при `status=covered` |
| `stand_mechanism` | строка \| отсутствует |
| `artifact_type` | `policy` \| `runbook` \| `attestation` \| `third_party_test` (для `doc_only`) |

---

## Проверяемые инварианты (тесты `tests/coverage/`)

| Инвариант | Тест | Требование |
|---|---|---|
| ровно 53 контроля, точный набор id, без дублей | `test_catalog_valid` | FR-001, SC-001 |
| `pillar` согласован с буквой `id` | `test_catalog_valid` | FR-001 |
| сумма по базовым статусам == 51 (активные) | `test_catalog_valid` | FR-009 |
| `status=covered` ⇒ `scorecard_control` существует в `scorecard/controls.py` | `test_covered_grounded` | **SC-004** |
| `status≠covered` ⇒ `backlog_item` ссылается на существующий кластер | `test_catalog_valid` | FR-006, SC-002 |
| `partial` ⇔ `nature=mixed` | `test_catalog_valid` | FR-002 |
| кластер `priority=1` имеет `nature=technical` | `test_catalog_valid` | SC-006 |
| Markdown-рендер детерминирован и совпадает с `docs/aiuc1-coverage.md` | `test_render_pure` | SC-003 |

**Контракт честности** (SC-004): `test_covered_grounded` импортирует фактические id контролей из
`scorecard/controls.py`. Пометить контроль `covered`, не имея реального механизма в коде,
невозможно — тест упадёт. Это удерживает карту в согласии со стендом.
