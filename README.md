# langchain-aiuc-mini

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Учебный проект по безопасности AI-агентов на **LangChain / LangGraph** — «AIUC-1 в миниатюре».

Цель — прокачать практический опыт работы с LangChain и предметно изучить безопасность
агентов через связку **атака → защита → аудит**, структурированную по 6 пиллерам риска
стандарта [AIUC-1](https://www.aiuc-1.com/) (Security, Data & Privacy, Reliability, Safety,
Accountability, Society).

## Модули

1. **Target-агент** — уязвимая мишень с «опасными» инструментами (shell / файлы / HTTP) в песочнице.
2. **Red-team агент** — сам генерирует и мутирует prompt-инъекции против мишени *(пиллер Security)*.
3. **Guardrail-слой** — фильтрует вход/выход, ограничивает вызовы инструментов, ловит утечку PII/секрета *(Data & Privacy, Reliability)*.
4. **Scorecard** — прогоняет набор атак и выдаёт отчёт «сколько учебных контролей AIUC-1 пройдено» *(Safety, Accountability)*.

> Образовательный проект. «Контроли AIUC-1» — упрощённые учебные проверки, вдохновлённые
> пиллерами стандарта, а не сертификационные требования. Все «опасные» инструменты выполняются
> в изоляции и не причиняют реального вреда.

## Статус

Управляется через **Spec Kit**. Текущая фича: [specs/001-langchain-aiuc-mini](specs/001-langchain-aiuc-mini/spec.md).

Правила проекта (изоляция песочницы, объективные критерии, воспроизводимость, наблюдаемость)
зафиксированы в [конституции](.specify/memory/constitution.md).

Пройдено: `/speckit-constitution` → `/speckit-specify` → `/speckit-plan` → `/speckit-tasks`.
Следующий шаг: `/speckit-implement` (кода пока нет — только спецификация, план и 51 задача).

План и обоснования решений: [plan.md](specs/001-langchain-aiuc-mini/plan.md),
[research.md](specs/001-langchain-aiuc-mini/research.md),
[tasks.md](specs/001-langchain-aiuc-mini/tasks.md).

## Лицензия

[MIT](LICENSE) © 2026 Ramil Mustafin
