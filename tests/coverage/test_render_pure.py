"""Гейт: рендер детерминирован и не разошёлся с docs/ (T020, SC-003)."""

from pathlib import Path

from aiuc_mini.aiuc1.catalog import Catalog, aggregate
from aiuc_mini.aiuc1.render import render

CATALOG = Path("aiuc1/catalog.yaml")
DOC = Path("docs/aiuc1-coverage.md")


def _catalog() -> Catalog:
    return Catalog.load(CATALOG)


def test_render_is_deterministic():
    cat = _catalog()
    assert render(cat) == render(cat)


def test_rendered_matches_committed_doc():
    """docs/aiuc1-coverage.md должен быть порождён из текущего каталога (не разошёлся)."""
    cat = _catalog()
    expected = render(cat) + "\n"
    actual = DOC.read_text(encoding="utf-8")
    assert actual == expected, (
        "docs/aiuc1-coverage.md разошёлся с каталогом — перегенерируйте: `aiuc coverage`"
    )


def test_aggregates_appear_in_rendered_map():
    cat = _catalog()
    agg = aggregate(cat)
    text = render(cat)
    assert f"**{agg.by_status['covered']}**" in text
    assert f"**{agg.by_status['technical_achievable']}**" in text
    assert f"**{agg.by_status['doc_only']}**" in text
    # Сумма активных явно присутствует.
    assert f"активных {sum(agg.by_status.values())}" in text
