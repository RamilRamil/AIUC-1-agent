"""Рендер карты таксономии (T010).

Чистая функция: тот же YAML даёт тот же Markdown побайтово (Принцип IV).

ОТДЕЛЬНЫЙ артефакт от scorecard — намеренно (FR-008, SC-006). Это два разных утверждения:
«проверяется N из M применимых классов» — про широту, «отражено 100% атак» — про глубину на той
узкой полоске, что проверяется. По отдельности каждая цифра врёт: первая занижает, вторая льстит.
"""

from __future__ import annotations

from pathlib import Path

from .model import Taxonomy, coverage

_MARK = {
    "tested": "✅ tested",
    "gap": "🕳 gap",
    "not_applicable": "— n/a",
}


def render(taxonomy: Taxonomy) -> str:
    cov = coverage(taxonomy)
    lines: list[str] = [
        f"# Карта покрытия таксономии атак — {taxonomy.name}",
        "",
        "> Порождается из `taxonomy/owasp-llm-top10.yaml` командой `aiuc taxonomy`. "
        "Вручную не редактировать.",
        "",
        f"**Версия списка:** {taxonomy.version}  ",
        f"**Источник:** {taxonomy.source}",
        "",
        "## Сводка",
        "",
        f"- ✅ tested (проверяем): **{cov.by_status['tested']}**",
        f"- 🕳 gap (применимо, но не проверяем): **{cov.by_status['gap']}**",
        f"- — not_applicable (нет предмета в архитектуре): **{cov.by_status['not_applicable']}**",
        "",
        f"**Проверяется {cov.by_status['tested']} из {cov.applicable_total} применимых классов "
        f"({cov.tested_share:.0%}).**",
        "",
        "## Категории",
        "",
        "| Категория | Статус | Обоснование | Атаки |",
        "|---|---|---|---|",
    ]
    for c in sorted(taxonomy.categories, key=lambda c: c.id):
        attacks = ", ".join(f"`{a}`" for a in c.attacks) if c.attacks else "—"
        rationale = " ".join(c.rationale.split())
        lines.append(f"| **{c.id}** {c.title} | {_MARK[c.status]} | {rationale} | {attacks} |")
    lines.append("")

    lines += [
        "---",
        "",
        "## Как читать эту цифру",
        "",
        "Покрытие таксономии — про **широту**: сколько классов атак стенд вообще проверяет.",
        "Доля отражённых атак в `scorecard.md` — про **глубину**: насколько хорошо он держится",
        "на той узкой полоске, которую проверяет.",
        "",
        "Вместе они читаются правильно: *стенд отражает атаки из тех классов, которые умеет",
        "проверять, а умеет он меньшинство.* По отдельности каждая врёт — первая занижает,",
        "вторая льстит. Поэтому отчёты намеренно разделены.",
        "",
        "**Что это НЕ решает.** Из внешнего списка взяты **категории**; **нагрузки** написаны",
        "внутри проекта. Классификация показывает, каких классов атак стенд не проверяет вовсе,",
        "но не делает нагрузки представительными. Полное устранение самоподтверждаемости требует",
        "внешнего корпуса нагрузок.",
        "",
        "**Правило статусов.** `tested` не ставится за «что-то похожее» — отдалённо смежное это",
        "`gap`. `not_applicable` обосновывается отсутствующей частью архитектуры, а не",
        "отсутствием желания.",
        "",
    ]
    return "\n".join(lines)


def render_to_file(taxonomy: Taxonomy, out: Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(taxonomy) + "\n", encoding="utf-8")
    return out
