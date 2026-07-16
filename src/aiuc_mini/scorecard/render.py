"""Рендер scorecard в JSON и Markdown (T043).

Оба представления — из одной модели ``Scorecard``. JSON машиночитаем и детерминирован
(``sort_keys``); Markdown — таблица по 6 пиллерам с evidence как ``trace.jsonl:<line>`` (FR-013).
"""

from __future__ import annotations

import json
from pathlib import Path

from ..trace.writer import read_trace
from .aggregate import aggregate
from .compare import EVALUATION_CAVEAT
from .models import PILLAR_ORDER, PILLAR_TITLES, Scorecard


def to_json(card: Scorecard) -> str:
    return json.dumps(card.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)


def to_markdown(card: Scorecard) -> str:
    mode = "с защитой" if card.guardrails_enabled else "без защиты"
    s = card.summary
    informational = [
        c.id for results in card.pillars.values() for c in results if not c.scorable
    ]
    lines = [
        f"# Scorecard AIUC-1 — прогон `{card.run_id}` ({mode})",
        "",
        f"- suite_hash: `{card.suite_hash}`",
        f"- контролей пройдено: **{s.controls_passed}/{s.controls_total}**",
        # База показателей — атаки, а не попытки (FR-005); попытки — контекст усилий (FR-006).
        f"- база атак: **{s.attack_base_total}** исходных; пробили: "
        f"**{s.attacks_breached}/{s.attack_base_total}**",
        f"- доля успешных атак: **{s.attack_success_rate:.0%}**",
        f"- попыток сделано: {s.attempts_total} (включая мутации; в знаменатель не входят)",
        f"- ложные блокировки: **{s.false_block_rate:.0%}**",
        f"- ошибок попыток: {s.errors}",
    ]
    if informational:
        lines.append(
            f"- информационные (вне счёта): {', '.join(sorted(informational))}"
        )
    lines.append("")

    for pillar in PILLAR_ORDER:
        lines.append(f"## {PILLAR_TITLES[pillar]}")
        lines.append("")
        lines.append("| Контроль | Статус | Обоснование |")
        lines.append("|---|---|---|")
        for c in card.pillars[pillar]:
            mark = "✅ pass" if c.status == "pass" else "❌ fail"
            if not c.scorable:
                mark += " ⓘ"
            rationale = c.rationale
            if c.status == "fail" and c.evidence:
                refs = ", ".join(f"trace.jsonl:{e.trace_line}" for e in c.evidence)
                rationale = f"{rationale} ({refs})"
            lines.append(f"| {c.id} {c.title} | {mark} | {rationale} |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("ⓘ — информационный контроль: показывается, но очка в счёт не даёт.")
    lines.append("")
    lines.append(EVALUATION_CAVEAT)
    lines.append("")
    return "\n".join(lines)


def build_scorecard(run_dir: Path) -> Scorecard:
    events = read_trace(Path(run_dir) / "trace.jsonl")
    return aggregate(events)


def render_run(run_dir: Path, fmt: str = "both") -> list[Path]:
    """Построить и записать scorecard рядом с trace. Возвращает пути записанных файлов."""
    run_dir = Path(run_dir)
    card = build_scorecard(run_dir)
    written: list[Path] = []
    if fmt in ("json", "both"):
        p = run_dir / "scorecard.json"
        p.write_text(to_json(card), encoding="utf-8")
        written.append(p)
    if fmt in ("md", "both"):
        p = run_dir / "scorecard.md"
        p.write_text(to_markdown(card), encoding="utf-8")
        written.append(p)
    return written
