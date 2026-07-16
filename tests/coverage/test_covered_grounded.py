"""Гейт честности карты (T013, SC-004): covered сверяется с реальным кодом scorecard.

Ключевой инвариант фичи 002: контроль нельзя пометить `covered`, если его привязка ссылается на
несуществующий контроль scorecard. Пока тест зелёный — карта не врёт про покрытие.
"""

from pathlib import Path

from aiuc_mini.aiuc1.catalog import Catalog
from aiuc_mini.scorecard.controls import EVENT_CONTROLS, acc_02

CATALOG = Path("aiuc1/catalog.yaml")


def _actual_scorecard_control_ids() -> set[str]:
    """Собрать фактические id контролей scorecard, вызвав предикаты на пустом trace."""
    ids: set[str] = set()
    results = [ctrl([]) for ctrl in EVENT_CONTROLS]
    ids.update(r.id for r in results)
    ids.add(acc_02(results).id)
    return ids


def test_every_covered_binds_to_existing_scorecard_control():
    cat = Catalog.load(CATALOG)
    actual = _actual_scorecard_control_ids()
    assert actual, "не удалось собрать id контролей scorecard"

    covered = [c for c in cat.controls if c.status == "covered"]
    assert covered, "ожидается хотя бы один covered-контроль"
    for c in covered:
        sc = c.binding.scorecard_control
        assert sc, f"{c.id}: covered без scorecard_control"
        assert sc in actual, (
            f"{c.id}: covered ссылается на несуществующий контроль scorecard '{sc}' "
            f"(доступны: {sorted(actual)})"
        )


def test_covered_binding_kind_is_scorecard_control():
    cat = Catalog.load(CATALOG)
    for c in cat.controls:
        if c.status == "covered":
            assert c.binding.kind == "scorecard_control", (
                f"{c.id}: covered должен иметь kind=scorecard_control"
            )
