"""Гейт: `tested` нельзя объявить — только заслужить (T008, FR-003, SC-002).

Прямой аналог `test_covered_grounded` из фичи 002. Тот приём себя оправдал: карта покрытия
AIUC-1 ни разу не соврала, потому что статус нельзя было объявить — его можно было только
заслужить наличием механизма в коде.

Здесь то же самое: категория внешнего списка считается проверяемой, только если на неё реально
ссылаются атаки набора.
"""

from pathlib import Path

from aiuc_mini.redteam.suite import AttackSuite
from aiuc_mini.taxonomy.model import Taxonomy

TAXONOMY = Path("taxonomy/owasp-llm-top10.yaml")
SUITE = Path("attacks/suite.yaml")


def _attack_ids() -> set[str]:
    return {a.id for a in AttackSuite.load(SUITE).attacks}


def test_every_tested_category_has_real_attacks():
    """Категория `tested` ссылается только на существующие атаки набора."""
    taxonomy = Taxonomy.load(TAXONOMY)
    actual = _attack_ids()
    assert actual, "не удалось загрузить набор атак"

    tested = [c for c in taxonomy.categories if c.status == "tested"]
    assert tested, "ожидается хотя бы одна проверяемая категория"

    for cat in tested:
        assert cat.attacks, f"{cat.id}: tested без атак"
        missing = [a for a in cat.attacks if a not in actual]
        assert not missing, (
            f"{cat.id}: tested ссылается на несуществующие атаки {missing} "
            f"(доступны: {sorted(actual)}). Статус нельзя объявить — только заслужить."
        )


def test_non_tested_categories_claim_no_attacks():
    """`gap` и `not_applicable` не ссылаются на атаки: ссылка означала бы проверку."""
    for cat in Taxonomy.load(TAXONOMY).categories:
        if cat.status != "tested":
            assert not cat.attacks, f"{cat.id}: статус {cat.status}, но указаны атаки"


def test_not_applicable_is_justified_by_architecture():
    """FR-004: `not_applicable` обосновывается свойством стенда, а не нежеланием.

    Формулировка «мы это не делаем» недостаточна — это `gap`. Проверяем, что обоснование
    ссылается на отсутствующую в архитектуре часть.
    """
    architectural_markers = ("нет ", "не обучает", "не строит", "нечего")
    for cat in Taxonomy.load(TAXONOMY).categories:
        if cat.status == "not_applicable":
            low = cat.rationale.lower()
            assert any(m in low for m in architectural_markers), (
                f"{cat.id}: обоснование not_applicable должно указывать на отсутствующую часть "
                f"архитектуры, а не на отсутствие желания"
            )
