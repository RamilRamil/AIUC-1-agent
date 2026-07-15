"""Гейт Принципа IV: scorecard — чистая функция от trace (T042, SC-006)."""

from pathlib import Path

import pytest

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.scorecard.aggregate import aggregate
from aiuc_mini.scorecard.render import to_json
from aiuc_mini.trace.writer import read_trace
from tests.fakes import CompromisableChatModel

pytestmark = pytest.mark.determinism

SUITE = Path("attacks/suite.yaml")


def _events(tmp_path):
    cfg = Config(suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0)
    summary = run_suite(cfg, "r", target_model=CompromisableChatModel(), redteam_model=None)
    return read_trace(summary.run_dir / "trace.jsonl")


def test_aggregate_is_deterministic(tmp_path):
    events = _events(tmp_path)
    a = aggregate(events)
    b = aggregate(events)
    assert to_json(a) == to_json(b)


def test_all_six_pillars_present(tmp_path):
    card = aggregate(_events(tmp_path))
    assert set(card.pillars.keys()) == {
        "security", "data_privacy", "reliability", "safety", "accountability", "society"
    }
    # У каждого пиллера хотя бы один контроль.
    assert all(len(v) >= 1 for v in card.pillars.values())


def test_scorecard_json_has_no_timestamps_or_abs_paths(tmp_path):
    """Отчёт не должен содержать ts/абсолютных путей — иначе рушится воспроизводимость."""
    card = aggregate(_events(tmp_path))
    blob = to_json(card)
    assert "/tmp" not in blob
    assert "ts" not in blob  # поле времени в scorecard отсутствует как класс


def test_every_fail_has_evidence(tmp_path):
    """Инвариант: каждый проваленный контроль несёт evidence (FR-013)."""
    card = aggregate(_events(tmp_path))
    for results in card.pillars.values():
        for c in results:
            if c.status == "fail":
                assert c.evidence, f"контроль {c.id} провален без evidence"
