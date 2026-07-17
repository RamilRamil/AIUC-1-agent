"""T009: таксономия валидна и полна (SC-001, FR-002)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from aiuc_mini.taxonomy.model import (
    EXPECTED_IDS,
    STATUSES,
    TOTAL_CATEGORIES,
    Category,
    Taxonomy,
    coverage,
)

TAXONOMY = Path("taxonomy/owasp-llm-top10.yaml")


def _taxonomy() -> Taxonomy:
    return Taxonomy.load(TAXONOMY)


def test_exactly_ten_categories_with_correct_ids():
    tax = _taxonomy()
    assert len(tax.categories) == TOTAL_CATEGORIES == 10
    assert {c.id for c in tax.categories} == EXPECTED_IDS


def test_version_and_source_present():
    """FR-010: версия внешнего списка явная — смена версии не должна быть тихим дрейфом."""
    tax = _taxonomy()
    assert tax.version == "2025"
    assert "owasp" in tax.source.lower()


def test_every_category_has_status_and_rationale():
    for c in _taxonomy().categories:
        assert c.status in STATUSES
        assert c.rationale.strip(), f"{c.id}: пустое обоснование"


def test_status_sum_equals_ten():
    cov = coverage(_taxonomy())
    assert sum(cov.by_status.values()) == TOTAL_CATEGORIES == 10


def test_coverage_is_share_of_applicable():
    """Доля считается от ПРИМЕНИМОГО, а не от всех 10: неприменимое — не пробел."""
    tax = _taxonomy()
    cov = coverage(tax)
    assert cov.applicable_total == 10 - cov.by_status["not_applicable"]
    assert cov.tested_share == cov.by_status["tested"] / cov.applicable_total


def test_stand_covers_a_minority_honestly():
    """Ожидается скромное покрытие. Низкая цифра — честный результат, а не провал."""
    cov = coverage(_taxonomy())
    assert cov.by_status["tested"] < cov.applicable_total, (
        "стенд заявляет, что проверяет ВСЁ применимое — подозрительно; проверьте, не подогнаны "
        "ли статусы (tested за «что-то похожее» запрещён)"
    )


def test_tested_without_attacks_is_rejected():
    """Схема не даёт объявить tested без атак."""
    with pytest.raises(ValidationError):
        Category(id="LLM01", title="X", status="tested", rationale="r", attacks=[])


def test_attacks_on_non_tested_is_rejected():
    with pytest.raises(ValidationError):
        Category(id="LLM01", title="X", status="gap", rationale="r", attacks=["a"])


def test_incomplete_taxonomy_is_rejected():
    """Пропущенная категория — ошибка, а не молчаливое сокращение списка."""
    tax = _taxonomy()
    with pytest.raises(ValidationError):
        Taxonomy(
            name=tax.name,
            version=tax.version,
            source=tax.source,
            categories=tax.categories[:-1],
        )
