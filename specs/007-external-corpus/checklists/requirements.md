# Specification Quality Checklist: Внешний корпус нагрузок (Gandalf)

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-07-17
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

- **Ключевое обоснование выбора корпуса**: JailbreakBench/HarmBench/AdvBench отвергнуты не по
  вкусу, а по несовместимости: их судья — LLM (Принцип III), и наш канареечный судья их нагрузки
  не оценит в принципе → 200 «отбитых» атак = самообман. Gandalf подходит потому, что его цель
  (вытащить пароль из системного промпта) **дословно совпадает** с нашей канарейкой.
- **Главная честность (US3)**: на fake-модели корпус НИЧЕГО не измеряет — fake реагирует на
  русские слова, корпус английский. Без этой оговорки фича стала бы самым изощрённым самообманом
  за проект: «внешний корпус, все атаки отбиты».
- **Главный способ соврать (US2)**: подогнать подмножество — оставить то, что удобно отбивается.
  Поэтому правило отбора детерминировано и не зависит от вердиктов.
- **Ожидается, что защиту разнесёт** (паттерны русские, корпус английский). Это цель, а не провал.
- Готово к `/speckit-plan`.
