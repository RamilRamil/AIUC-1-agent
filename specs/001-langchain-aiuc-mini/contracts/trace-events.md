# Contract — События JSONL-trace

**Feature**: `001-langchain-aiuc-mini` | **Plan**: [../plan.md](../plan.md)

Trace — единственный источник истины для scorecard (Принцип V). Формат: JSONL, одна строка =
одно событие, `model_dump_json()` от Pydantic-модели.

---

## Общие поля

| Поле | Тип | Смысл |
|---|---|---|
| `type` | `str` | дискриминатор события |
| `run_id` | `str` | прогон |
| `attempt_id` | `str \| null` | попытка (`null` для событий уровня прогона) |
| `seq` | `int` | строго возрастающий счётчик в пределах прогона |
| `ts` | `str` (ISO-8601) | время события |

**Инвариант**: `ts` присутствует в trace, но **MUST NOT** влиять на scorecard — иначе
детерминизм отчёта сломается (Принцип IV). Агрегация читает `seq`, а не `ts`.

**Инвариант маскирования**: значение канареечного секрета **MUST** заменяться на `<CANARY>`
при записи любого события, кроме `verdict.leaked_via`. Иначе журнал сам стал бы каналом утечки
секрета — а мы им же и измеряем утечки.

---

## Каталог событий

### `run_started`
| Поле | Тип |
|---|---|
| `config` | объект `Config` (без ключей провайдера) |
| `suite_hash` | `str` — sha256 набора атак |
| `guardrails_enabled` | `bool` |

### `attempt_started`
| Поле | Тип |
|---|---|
| `attack_id` | `str` |
| `category` | `direct_injection \| role_bypass \| secret_exfiltration` |
| `payload` | `str` |
| `parent_id` | `str \| null` — заполнено для мутаций (FR-007) |
| `is_benign` | `bool` — легитимная задача-контроль (FR-016) |

### `guardrail_decision`
| Поле | Тип |
|---|---|
| `stage` | `input \| output \| tool_call` |
| `action` | `allow \| block \| redact` |
| `rule_id` | `str` |
| `reason` | `str` |

Пишется на **каждом** решении, включая `allow` — иначе нельзя доказать контроль `ACC-01`
(«каждое решение журналировано») и нельзя отличить «guardrail пропустил» от «guardrail не
отработал вовсе».

### `tool_call`
| Поле | Тип |
|---|---|
| `tool` | `str` |
| `args` | `dict` |
| `blocked` | `bool` — `true`, если `wrap_tool_call` вернул `ToolMessage` вместо вызова handler |

**Важно**: `args` пишутся **до** исполнения и **до** маскирования проверяются судьёй на
канарейку (критерий `canary_in_tool_args`). В сам trace `args` идут уже с маской.

### `tool_result`
| Поле | Тип |
|---|---|
| `tool` | `str` |
| `result` | `str` |
| `error` | `str \| null` |

### `sandbox_violation`
| Поле | Тип |
|---|---|
| `tool` | `str` |
| `attempted` | `str` — что именно пытались сделать (путь, команда, URL) |
| `rule` | `str` — какой инвариант песочницы сработал |

Это событие означает: атака попыталась выйти за песочницу и **была остановлена физически**.
Питает контроль `SAF-01`.

### `agent_response`
| Поле | Тип |
|---|---|
| `content` | `str` — финальный ответ (с маской) |
| `redacted` | `bool` — сработало ли маскирование на выходе (FR-009) |

### `verdict`
| Поле | Тип |
|---|---|
| `verdict` | `SUCCESS \| FAILURE \| BLOCKED \| ERROR` |
| `criterion` | `str` — какой `SuccessCriterion` применялся |
| `leaked_via` | `output \| tool_args \| null` — **единственное поле, где секрет допустим в открытом виде** |
| `rationale` | `str` — машинное обоснование, не текст от LLM |

### `attempt_error`
| Поле | Тип |
|---|---|
| `error_type` | `timeout \| llm_error \| internal` |
| `message` | `str` |

Порождает вердикт `ERROR` (FR-015). **MUST NOT** трактоваться как успех защиты — иначе упавший
LLM-бэкенд выглядел бы идеальным guardrail'ом.

### `run_finished`
| Поле | Тип |
|---|---|
| `attempts_total` | `int` |
| `attacks_succeeded` | `int` |
| `errors` | `int` |

---

## Контракт для scorecard

`aggregate(events: list[TraceEvent]) -> Scorecard` — **чистая функция**:

- зависит только от содержимого событий (кроме `ts`);
- контроли обходятся в фиксированном порядке (сортировка по `id`);
- `Evidence.trace_line` — 0-based номер строки в `trace.jsonl`, что даёт отчёту прямую,
  проверяемую ссылку на доказательство (FR-013).

Это свойство проверяется тестом `tests/determinism/test_scorecard_pure.py`:
`aggregate(events) == aggregate(events)` побайтово, на зафиксированном trace-фикстуре.
