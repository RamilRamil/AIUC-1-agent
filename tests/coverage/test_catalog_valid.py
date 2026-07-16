"""Гейт: каталог валиден и полон (T012, T016; FR-001/006/009, SC-001/002/006)."""

from pathlib import Path

from aiuc_mini.aiuc1.catalog import (
    ACTIVE_TOTAL,
    EXPECTED_IDS,
    RETIRED_IDS,
    TOTAL_IDS,
    Catalog,
    aggregate,
)

CATALOG = Path("aiuc1/catalog.yaml")


def _catalog() -> Catalog:
    return Catalog.load(CATALOG)


def test_exactly_53_controls_with_correct_ids():
    cat = _catalog()
    assert len(cat.controls) == TOTAL_IDS == 53
    assert {c.id for c in cat.controls} == EXPECTED_IDS


def test_pillar_matches_id_letter():
    letter_pillar = {
        "A": "data_privacy", "B": "security", "C": "safety",
        "D": "reliability", "E": "accountability", "F": "society",
    }
    for c in _catalog().controls:
        assert c.pillar == letter_pillar[c.id[0]], f"{c.id}: пиллер не согласован"


def test_base_status_sum_equals_active_total():
    agg = aggregate(_catalog())
    assert sum(agg.by_status.values()) == ACTIVE_TOTAL == 51
    assert agg.retired_count == len(RETIRED_IDS) == 2


def test_retired_are_exactly_e007_e014():
    retired = {c.id for c in _catalog().controls if c.status == "retired"}
    assert retired == RETIRED_IDS


def test_partial_iff_mixed():
    for c in _catalog().controls:
        assert (c.partial is not None) == (c.nature == "mixed"), c.id


def test_every_non_covered_has_valid_backlog_item():
    cat = _catalog()
    backlog_ids = {b.id for b in cat.backlog}
    for c in cat.controls:
        if c.status in ("covered", "retired"):
            assert c.backlog_item is None, f"{c.id}: не должен иметь backlog_item"
        else:
            assert c.backlog_item in backlog_ids, f"{c.id}: неизвестный backlog_item"


def test_first_backlog_cluster_is_technical():
    cat = _catalog()
    first = min(cat.backlog, key=lambda b: b.priority)
    assert first.priority == 1
    assert first.nature == "technical", "первый кластер бэклога должен быть техническим (SC-006)"


def test_pillar_counts_match_standard():
    agg = aggregate(_catalog())
    # Активные по пиллерам (E: 17 всего − 2 retired = 15).
    assert agg.by_pillar == {
        "data_privacy": 8, "security": 10, "safety": 12,
        "reliability": 4, "accountability": 15, "society": 2,
    }
