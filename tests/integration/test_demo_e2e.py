"""T047: demo-логика отрабатывает end-to-end на fake-модели без ключей API."""

from pathlib import Path

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.scorecard.compare import compare_runs
from aiuc_mini.scorecard.render import build_scorecard, render_run
from tests.fakes import CompromisableChatModel

SUITE = Path("attacks/suite.yaml")


def test_full_cycle_baseline_vs_protected(tmp_path):
    base_cfg = Config(suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0)
    prot_cfg = Config(
        suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0, guardrails_enabled=True
    )

    model = CompromisableChatModel
    base = run_suite(base_cfg, "baseline", target_model=model(), redteam_model=None)
    prot = run_suite(prot_cfg, "protected", target_model=model(), redteam_model=None)

    render_run(base.run_dir)
    render_run(prot.run_dir)
    assert (base.run_dir / "scorecard.md").exists()
    assert (prot.run_dir / "scorecard.json").exists()

    base_card = build_scorecard(base.run_dir)
    prot_card = build_scorecard(prot.run_dir)

    # Связка «атака → защита»: защита не хуже по успеху атак и по числу пройденных контролей.
    assert prot_card.summary.attack_success_rate <= base_card.summary.attack_success_rate
    assert prot_card.summary.controls_passed >= base_card.summary.controls_passed

    # compare требует одинакового suite_hash и не падает.
    report = compare_runs(base.run_dir, prot.run_dir)
    assert "Сравнение прогонов" in report


def test_compare_rejects_mismatched_suite(tmp_path):
    import pytest

    cfg = Config(suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0)
    run = run_suite(cfg, "one", target_model=CompromisableChatModel(), redteam_model=None)

    # Подсовываем «другой» suite_hash во второй прогон, переписав RunStarted.
    other = tmp_path / "runs" / "two"
    other.mkdir(parents=True)
    trace = (run.run_dir / "trace.jsonl").read_text(encoding="utf-8")
    (other / "trace.jsonl").write_text(trace.replace(run_hash(trace), "deadbeef"), "utf-8")

    with pytest.raises(ValueError):
        compare_runs(run.run_dir, other)


def run_hash(trace: str) -> str:
    import json

    for line in trace.splitlines():
        obj = json.loads(line)
        if obj.get("type") == "run_started":
            return obj["suite_hash"]
    raise AssertionError("run_started не найден")
