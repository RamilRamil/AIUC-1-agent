"""Рендер карты покрытия из каталога (T017).

Чистая функция ``render(catalog) -> str``: тот же каталог даёт тот же Markdown побайтово
(Принцип IV). ``docs/aiuc1-coverage.md`` — производное от ``aiuc1/catalog.yaml`` и вручную не
редактируется (SC-003).
"""

from __future__ import annotations

from pathlib import Path

from .catalog import BASE_STATUSES, Catalog, aggregate

_PILLAR_ORDER = ["data_privacy", "security", "safety", "reliability", "accountability", "society"]
_PILLAR_TITLES = {
    "data_privacy": "A. Data & Privacy",
    "security": "B. Security",
    "safety": "C. Safety",
    "reliability": "D. Reliability",
    "accountability": "E. Accountability",
    "society": "F. Society",
}
_STATUS_MARK = {
    "covered": "✅ covered",
    "technical_achievable": "🔧 achievable",
    "doc_only": "📄 doc-only",
    "retired": "⊘ retired",
}
_STATUS_TITLE = {
    "covered": "уже реализовано",
    "technical_achievable": "достижимо кодом",
    "doc_only": "только документируемо",
}


def render(catalog: Catalog) -> str:
    agg = aggregate(catalog)
    lines: list[str] = []

    lines += [
        "# Карта покрытия AIUC-1",
        "",
        "> Порождается из `aiuc1/catalog.yaml` командой `aiuc coverage`. Вручную не редактировать.",
        "",
        f"**Версия:** {catalog.version}  ",
        f"**Источник:** {catalog.source}",
        "",
        "## Сводка",
        "",
        f"- Всего контролей стандарта: **{len(catalog.controls)}** "
        f"(активных {sum(agg.by_status.values())}, retired {agg.retired_count})",
        f"- ✅ covered (реализовано): **{agg.by_status['covered']}**",
        f"- 🔧 technical-achievable (достижимо кодом): **{agg.by_status['technical_achievable']}**",
        f"- 📄 doc-only (документируемо): **{agg.by_status['doc_only']}**",
        f"- из них mixed с `partial`: **{agg.partial_count}**",
        f"- покрытие (covered от активных): **{agg.coverage_pct}%**",
        "",
        "Легенда: ✅ covered — есть реальный механизм (в привязке — id контроля scorecard); "
        "🔧 achievable — достижимо кодом (в привязке — кластер бэклога); 📄 doc-only — "
        "организационный контроль (артефакт policy/runbook/attestation); ⊘ retired — отозван "
        "стандартом.",
        "",
    ]

    # Контроли по пиллерам.
    by_pillar: dict[str, list] = {p: [] for p in _PILLAR_ORDER}
    for c in catalog.controls:
        by_pillar[c.pillar].append(c)

    for pillar in _PILLAR_ORDER:
        controls = sorted(by_pillar[pillar], key=lambda c: c.id)
        lines.append(f"## {_PILLAR_TITLES[pillar]}")
        lines.append("")
        lines.append("| Контроль | Природа | Статус | Привязка |")
        lines.append("|---|---|---|---|")
        for c in controls:
            binding = _binding_str(c)
            partial = " (partial)" if c.partial is not None else ""
            lines.append(
                f"| {c.id} {c.title} | {c.nature} | {_STATUS_MARK[c.status]}{partial} | {binding} |"
            )
        lines.append("")

    # Бэклог.
    lines.append("## Бэклог расширения")
    lines.append("")
    lines.append("Тематические кластеры будущих фич (первый — технический). Каждый не-covered "
                 "контроль отнесён ровно к одному кластеру.")
    lines.append("")
    for item in sorted(catalog.backlog, key=lambda b: b.priority):
        members = sorted(c.id for c in catalog.controls if c.backlog_item == item.id)
        lines.append(
            f"{item.priority}. **{item.id}** ({item.nature}) — {item.title}: "
            f"{', '.join(members)}  "
        )
        lines.append(f"   _{item.rationale}_")
    lines.append("")

    return "\n".join(lines)


def _binding_str(control) -> str:
    b = control.binding
    if control.status == "covered":
        return f"scorecard: {b.scorecard_control}"
    if control.status == "retired":
        return "—"
    if b.kind == "artifact" and b.artifact_type:
        return f"artifact: {b.artifact_type} → {control.backlog_item}"
    return f"{b.stand_mechanism or b.kind} → {control.backlog_item}"


def render_to_file(catalog: Catalog, out: Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(catalog) + "\n", encoding="utf-8")
    return out


# Проверка соответствия базовых статусов (для внешних потребителей).
assert set(BASE_STATUSES) <= set(_STATUS_MARK)
