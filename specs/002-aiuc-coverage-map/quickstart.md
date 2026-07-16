# Quickstart — Карта покрытия AIUC-1

**Feature**: `002-aiuc-coverage-map` | **Plan**: [plan.md](plan.md)

Цель: получить честную карту «где мы относительно 53 контролей AIUC-1» и приоритизированный
бэклог расширения. Всё через Docker.

> ⚠️ Описание целевого состояния после `/speckit-implement`. Кода пока нет.

---

## 1. Построить карту из каталога

Источник истины — `aiuc1/catalog.yaml`. Карта `docs/aiuc1-coverage.md` порождается из него:

```bash
docker compose run --rm aiuc coverage
```

Печатает агрегаты и (пере)генерирует `docs/aiuc1-coverage.md`:

```
AIUC-1 coverage (version 1.0.0)
  всего 53 (активных 51, retired 2)
  covered:              3 / 51   (5.9%)
  technical-achievable: 14 / 51
  doc-only:             34 / 51
  partial (mixed):      7
По пиллерам: A 8 | B 10 | C 12 | D 4 | E 15 | F 2
Карта: docs/aiuc1-coverage.md
```

---

## 2. Прочитать карту

`docs/aiuc1-coverage.md` — таблица по 6 пиллерам. Каждая строка:

```markdown
| A008 Детект секретов | technical | ✅ covered | PRIV-02 + маскирование trace |
| A006 PII-детект | technical | 🔧 achievable | → detectors |
| A004 IP-фильтр + гайдлайны | mixed | 📄 doc-only (partial) | policy; tech: фильтр / doc: политика |
```

Легенда статусов:
- **✅ covered** — уже реализовано; в привязке стоит id существующего контроля scorecard;
- **🔧 achievable** — технически достижимо кодом; в привязке — кластер бэклога (`→ detectors`);
- **📄 doc-only** — организационное; представимо только артефактом (policy/runbook/attestation);
- **(partial)** — mixed-контроль: часть техническая, часть документируемая.

---

## 3. Прочитать бэклог

В конце карты — приоритизированный список кластеров (будущих фич):

```markdown
## Бэклог расширения
1. detectors (technical) — Детекторы PII/секретов: A006, A008, A005
2. input-moderation (technical) — Модерация входа: B002, B004, B005
3. tool-policy (technical) — Политика tool-call + HITL: A003, D003
...
7. attestation (organizational) — Стороннее тестирование: C010–C012, D002, D004
```

Первый пункт всегда технический (SC-006) — с него и начинать следующую фичу.

---

## 4. Проверить честность карты (гейты)

```bash
docker compose run --rm test tests/coverage/
```

Что проверяется:
- ровно 53 контроля, верные id, сумма по базовым статусам == 51 (активные; E007/E014 retired);
- **ни один `covered` не ссылается на несуществующий контроль scorecard** (SC-004) — карта не
  может соврать про покрытие, пока тест зелёный;
- Markdown порождён из каталога и не разошёлся с ним (SC-003).

---

## 5. Как расширять покрытие дальше

1. Выбрать первый кластер из бэклога (технический).
2. Завести под него фичу через Spec Kit (`/speckit-specify`).
3. Реализовать: новая категория атаки + guardrail + предикат scorecard.
4. В `aiuc1/catalog.yaml` перевести закрытые контроли в `covered`, проставив
   `binding.scorecard_control` на новый контроль.
5. Прогнать `tests/coverage/` — если `covered` проставлен без реального механизма, тест упадёт.
6. Перегенерировать карту (`aiuc coverage`).

Так карта остаётся честной и всегда отражает фактическое состояние кода.

---

## Что читать дальше

- [research.md](research.md) — предварительная классификация всех 53 контролей
- [data-model.md](data-model.md) — схема каталога
- [contracts/catalog-schema.md](contracts/catalog-schema.md) — контракт YAML и инварианты-тесты
