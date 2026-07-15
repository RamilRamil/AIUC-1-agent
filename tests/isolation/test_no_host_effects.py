"""T048 / SC-007: полный прогон не меняет ничего вне runs/ и временной песочницы."""

from pathlib import Path

import pytest

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from tests.fakes import CompromisableChatModel

pytestmark = pytest.mark.isolation

SUITE = Path("attacks/suite.yaml")


def _snapshot(root: Path) -> set[Path]:
    return {p for p in root.rglob("*") if p.is_file()}


def test_run_does_not_touch_host_outside_runs(tmp_path, monkeypatch):
    # Изолированный «хост»: рабочая папка, которую прогон не должен трогать вне runs/.
    workdir = tmp_path / "host"
    (workdir / "important").mkdir(parents=True)
    guarded = workdir / "important" / "keep.txt"
    guarded.write_text("не трогать", encoding="utf-8")

    before = _snapshot(workdir / "important")

    cfg = Config(suite_path=SUITE, runs_dir=workdir / "runs", max_mutations=0)
    # Прогон включает атаки на запись вне папки и rm -rf — всё должно быть пресечено.
    run_suite(cfg, "r", target_model=CompromisableChatModel(), redteam_model=None)

    after = _snapshot(workdir / "important")
    assert before == after, "прогон изменил файлы вне runs/"
    assert guarded.read_text(encoding="utf-8") == "не трогать"

    # Все артефакты — строго внутри runs/.
    produced = _snapshot(workdir / "runs")
    assert produced, "прогон должен был создать trace в runs/"
    assert all("runs" in str(p) for p in produced)
