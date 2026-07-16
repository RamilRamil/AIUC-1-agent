# Карта покрытия AIUC-1

> Порождается из `aiuc1/catalog.yaml` командой `aiuc coverage`. Вручную не редактировать.

**Версия:** 1.0.0  
**Источник:** https://www.aiuc-1.com/evidence (снимок 2026-07-15); 53 контроля, E007/E014 retired

## Сводка

- Всего контролей стандарта: **53** (активных 51, retired 2)
- ✅ covered (реализовано): **3**
- 🔧 technical-achievable (достижимо кодом): **14**
- 📄 doc-only (документируемо): **34**
- из них mixed с `partial`: **7**
- покрытие (covered от активных): **5.9%**

Легенда: ✅ covered — есть реальный механизм (в привязке — id контроля scorecard); 🔧 achievable — достижимо кодом (в привязке — кластер бэклога); 📄 doc-only — организационный контроль (артефакт policy/runbook/attestation); ⊘ retired — отозван стандартом.

## A. Data & Privacy

| Контроль | Природа | Статус | Привязка |
|---|---|---|---|
| A001 Establish input data policy | organizational | 📄 doc-only | artifact: policy → governance |
| A002 Establish output data policy | organizational | 📄 doc-only | artifact: policy → governance |
| A003 Limit AI agent data access | technical | 🔧 achievable | scoping доступа/идентичность агента в tool-policy → tool-policy |
| A004 Protect IP & trade secrets | mixed | 📄 doc-only (partial) | artifact: policy → governance |
| A005 Prevent cross-customer data exposure | technical | 🔧 achievable | изоляция данных попытки поверх песочницы → detectors |
| A006 Prevent PII leakage | technical | 🔧 achievable | новый PII-детектор во входе/выходе/логах → detectors |
| A007 Prevent IP violations | mixed | 📄 doc-only (partial) | artifact: policy → governance |
| A008 Prevent leakage of credentials and secrets | technical | ✅ covered | scorecard: PRIV-02 |

## B. Security

| Контроль | Природа | Статус | Привязка |
|---|---|---|---|
| B001 Third-party testing of adversarial robustness | mixed | 📄 doc-only (partial) | artifact: attestation → attestation |
| B002 Detect adversarial input | technical | 🔧 achievable | детектор adversarial-входа в guardrails/input → input-moderation |
| B003 Manage public release of technical details | organizational | 📄 doc-only | artifact: policy → governance |
| B004 Prevent AI endpoint scraping | technical | 🔧 achievable | rate-limit / anomaly-детект → input-moderation |
| B005 Implement real-time input filtering | technical | 🔧 achievable | модерация входа с правилами → input-moderation |
| B006 Prevent unauthorized AI agent actions | technical | ✅ covered | scorecard: SAF-01 |
| B007 Enforce user access privileges to AI systems | organizational | 📄 doc-only | artifact: policy → governance |
| B008 Protect AI system deployment environment | technical | 📄 doc-only | artifact: policy → governance |
| B009 Limit output over-exposure | technical | 🔧 achievable | лимиты объёма/точности вывода в guardrails/output → output-filters |
| B010 Promote secure patterns in generated code | technical | 🔧 achievable | проверки безопасных дефолтов в генерируемом коде → output-filters |

## C. Safety

| Контроль | Природа | Статус | Привязка |
|---|---|---|---|
| C001 Define AI risk taxonomy | organizational | 📄 doc-only | artifact: policy → governance |
| C002 Conduct pre-deployment testing | mixed | 📄 doc-only (partial) | artifact: attestation → attestation |
| C003 Prevent harmful outputs | technical | 🔧 achievable | фильтр вредного вывода в guardrails/output → output-filters |
| C004 Prevent out-of-scope outputs | technical | 🔧 achievable | детект out-of-scope в guardrails/output → output-filters |
| C005 Prevent agent-specific high risk outputs | technical | 🔧 achievable | риск-детект по таксономии в guardrails/output → output-filters |
| C006 Prevent output vulnerabilities | technical | 🔧 achievable | санитизация вывода, метки доверия → output-filters |
| C007 Flag high risk outputs for human review | mixed | 📄 doc-only (partial) | artifact: runbook → governance |
| C008 Monitor AI risk categories | mixed | 📄 doc-only (partial) | artifact: runbook → governance |
| C009 Enable real-time feedback and intervention | mixed | 📄 doc-only (partial) | artifact: runbook → governance |
| C010 Third-party testing for harmful outputs | organizational | 📄 doc-only | artifact: third_party_test → attestation |
| C011 Third-party testing for out-of-scope outputs | organizational | 📄 doc-only | artifact: third_party_test → attestation |
| C012 Third-party testing for customer-defined risk | organizational | 📄 doc-only | artifact: third_party_test → attestation |

## D. Reliability

| Контроль | Природа | Статус | Привязка |
|---|---|---|---|
| D001 Prevent hallucinated outputs | technical | 🔧 achievable | groundedness-фильтр, цитаты, confidence-метки → output-filters |
| D002 Third-party testing for hallucinations | organizational | 📄 doc-only | artifact: third_party_test → attestation |
| D003 Restrict unsafe tool calls | technical | 🔧 achievable | валидация tool-call + human-approval (LangChain HITL middleware) → tool-policy |
| D004 Third-party testing of tool calls | organizational | 📄 doc-only | artifact: third_party_test → attestation |

## E. Accountability

| Контроль | Природа | Статус | Привязка |
|---|---|---|---|
| E001 AI failure plan for security breaches | organizational | 📄 doc-only | artifact: runbook → governance |
| E002 AI failure plan for harmful outputs | organizational | 📄 doc-only | artifact: runbook → governance |
| E003 AI failure plan for hallucinations | organizational | 📄 doc-only | artifact: runbook → governance |
| E004 Assign accountability | organizational | 📄 doc-only | artifact: policy → governance |
| E005 Document data storage security | organizational | 📄 doc-only | artifact: policy → governance |
| E006 Conduct vendor due diligence | organizational | 📄 doc-only | artifact: policy → governance |
| E007 [Retired] Document system change approvals | organizational | ⊘ retired | — |
| E008 Review internal processes | organizational | 📄 doc-only | artifact: policy → governance |
| E009 Monitor third-party access | organizational | 📄 doc-only | artifact: policy → governance |
| E010 Establish AI acceptable use policy | organizational | 📄 doc-only | artifact: policy → governance |
| E011 Record processing locations | organizational | 📄 doc-only | artifact: policy → governance |
| E012 Document regulatory compliance | organizational | 📄 doc-only | artifact: policy → governance |
| E013 Implement quality management system | organizational | 📄 doc-only | artifact: policy → governance |
| E014 [Retired] Share transparency reports | organizational | ⊘ retired | — |
| E015 Log AI system activity | technical | ✅ covered | scorecard: ACC-01 |
| E016 Implement AI disclosure mechanisms | organizational | 📄 doc-only | artifact: policy → governance |
| E017 Document system transparency policy | organizational | 📄 doc-only | artifact: policy → governance |

## F. Society

| Контроль | Природа | Статус | Привязка |
|---|---|---|---|
| F001 Prevent AI cyber misuse | organizational | 📄 doc-only | artifact: policy → society |
| F002 Prevent catastrophic misuse | organizational | 📄 doc-only | artifact: policy → society |

## Бэклог расширения

Тематические кластеры будущих фич (первый — технический). Каждый не-covered контроль отнесён ровно к одному кластеру.

1. **detectors** (technical) — Детекторы PII/секретов и изоляция данных: A005, A006  
   _прямое продолжение Data & Privacy; новые guardrail-детекторы + предикаты — максимальная отдача первым шагом_
2. **input-moderation** (technical) — Модерация входа и anomaly-детект: B002, B004, B005  
   _расширяет входной guardrail: детект adversarial-входа, rate-limit, фильтрация_
3. **tool-policy** (technical) — Политика tool-call и human-approval (HITL): A003, D003  
   _scoping доступа и валидация tool-call через LangChain HITL middleware_
4. **output-filters** (technical) — Фильтры вывода и надёжность: B009, B010, C003, C004, C005, C006, D001  
   _фильтры вредного/out-of-scope вывода, лимиты объёма, groundedness_
5. **governance** (organizational) — Governance-артефакты (политики, планы, runbook'и): A001, A002, A004, A007, B003, B007, B008, C001, C007, C008, C009, E001, E002, E003, E004, E005, E006, E008, E009, E010, E011, E012, E013, E016, E017  
   _весь организационный пласт Accountability и политики — документация, не прогон_
6. **attestation** (organizational) — Стороннее тестирование (attestation): B001, C002, C010, C011, C012, D002, D004  
   _ежеквартальные сторонние тесты и аттестация — требуют внешнего аудитора_
7. **society** (organizational) — Society: кибер- и катастрофический мисьюз: F001, F002  
   _предотвращение мисьюза — процесс и надзор, за пределами локального стенда_

