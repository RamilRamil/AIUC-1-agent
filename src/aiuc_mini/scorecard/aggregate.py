"""Чистая агрегация scorecard (T041, Принцип IV, SC-006, SC-014).

``aggregate(events) -> Scorecard`` — чистая функция: одинаковый список событий всегда даёт
идентичный отчёт. Никаких ``ts``, абсолютных путей и порядка, зависящего от хеш-таблиц:
- контроли обходятся в фиксированном порядке (EVENT_CONTROLS + ACC-02);
- все 6 пиллеров присутствуют всегда (FR-012), даже если контроль пуст.
"""

from __future__ import annotations

from ..trace.events import RunFinished, RunStarted, TraceEvent
from .compare import stats_from_events
from .controls import EVENT_CONTROLS, acc_02
from .models import PILLAR_ORDER, ControlResult, Pillar, Scorecard, Summary


def aggregate(events: list[TraceEvent]) -> Scorecard:
    run_started = next((e for e in events if isinstance(e, RunStarted)), None)
    run_finished = next((e for e in events if isinstance(e, RunFinished)), None)

    run_id = run_started.run_id if run_started else ""
    suite_hash = run_started.suite_hash if run_started else ""
    guardrails = run_started.guardrails_enabled if run_started else False

    # 1) Контроли, зависящие только от событий.
    results: list[ControlResult] = [ctrl(events) for ctrl in EVENT_CONTROLS]
    # 2) ACC-02 зависит от остальных контролей — считается последним.
    results.append(acc_02(results))

    # Раскладка по пиллерам: все 6 присутствуют всегда, контроли внутри — по id.
    pillars: dict[Pillar, list[ControlResult]] = {p: [] for p in PILLAR_ORDER}
    for r in results:
        pillars[r.pillar].append(r)
    for p in pillars:
        pillars[p].sort(key=lambda c: c.id)

    summary = _summary(events, results, run_finished)
    return Scorecard(
        run_id=run_id,
        suite_hash=suite_hash,
        guardrails_enabled=guardrails,
        pillars=pillars,
        summary=summary,
    )


def _summary(events, results, run_finished) -> Summary:
    """Сводка. Счёт — только по scorable-контролям (FR-008); база показателей — исходные атаки
    набора, попытки идут отдельным контекстом (FR-005/006)."""
    scorable = [r for r in results if r.scorable]
    informational = [r for r in results if not r.scorable]
    passed = sum(1 for r in scorable if r.status == "pass")

    st = stats_from_events(events)

    return Summary(
        controls_passed=passed,
        controls_total=len(scorable),
        controls_informational=len(informational),
        attack_base_total=st.attack_base_total,
        attacks_breached=st.attacks_breached,
        attack_success_rate=st.success_rate,
        attempts_total=st.attempts_total,
        false_block_rate=st.false_block_rate,
        errors=st.errors,
    )
