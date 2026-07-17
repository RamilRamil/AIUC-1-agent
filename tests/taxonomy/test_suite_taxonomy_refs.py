"""T025: каждая атака привязана к существующей категории (SC-003, FR-005)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from aiuc_mini.redteam.suite import AttackCase, AttackSuite
from aiuc_mini.taxonomy.model import Taxonomy

SUITE = Path("attacks/suite.yaml")
TAXONOMY = Path("taxonomy/owasp-llm-top10.yaml")


def test_every_attack_references_existing_category():
    """Набор замкнут на внешнюю меру: тихое расползание категорий невозможно."""
    known = {c.id for c in Taxonomy.load(TAXONOMY).categories}
    for attack in AttackSuite.load(SUITE).attacks:
        assert attack.taxonomy in known, (
            f"{attack.id}: ссылка на несуществующую категорию '{attack.taxonomy}'"
        )


def test_invalid_reference_is_rejected_at_load():
    """FR-005: несуществующая категория — ошибка загрузки, а не молчаливый пропуск."""
    with pytest.raises(ValidationError):
        AttackCase(
            id="x",
            category="direct_injection",
            payload="p",
            success_criterion={"kind": "canary_in_output"},
            taxonomy="NOPE-99",
        )


def test_taxonomy_is_required():
    """Без привязки набор снова замкнулся бы сам на себя."""
    with pytest.raises(ValidationError):
        AttackCase(
            id="x",
            category="direct_injection",
            payload="p",
            success_criterion={"kind": "canary_in_output"},
        )


def test_all_attack_categories_are_used_by_taxonomy():
    """Обратная связь: атаки, на которые ссылается таксономия, реально существуют.

    Дополняет `test_tested_grounded` с другой стороны: там проверяется, что tested не врёт;
    здесь — что привязка атак ведёт в существующие категории.
    """
    tax = Taxonomy.load(TAXONOMY)
    attack_ids = {a.id for a in AttackSuite.load(SUITE).attacks}
    referenced = {a for c in tax.categories for a in c.attacks}
    assert referenced <= attack_ids, (
        f"таксономия ссылается на несуществующие атаки: {sorted(referenced - attack_ids)}"
    )
