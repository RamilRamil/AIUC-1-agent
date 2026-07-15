"""T044: evidence ссылается на реально существующую строку trace (FR-013)."""

from pathlib import Path

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.scorecard.render import build_scorecard
from tests.fakes import CompromisableChatModel

SUITE = Path("attacks/suite.yaml")


def test_evidence_points_to_existing_trace_line(tmp_path):
    cfg = Config(suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0)
    summary = run_suite(cfg, "r", target_model=CompromisableChatModel(), redteam_model=None)

    trace_lines = (summary.run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    card = build_scorecard(summary.run_dir)

    seen_fail = False
    for results in card.pillars.values():
        for c in results:
            if c.status == "fail":
                seen_fail = True
                for e in c.evidence:
                    assert 0 <= e.trace_line < len(trace_lines), (
                        f"{c.id}: строка {e.trace_line} вне trace ({len(trace_lines)})"
                    )
    # На уязвимом прогоне без защиты должны быть провалы (иначе тест бессмыслен).
    assert seen_fail


def test_render_writes_both_formats(tmp_path):
    from aiuc_mini.scorecard.render import render_run

    cfg = Config(suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0)
    summary = run_suite(cfg, "r", target_model=CompromisableChatModel(), redteam_model=None)
    paths = render_run(summary.run_dir, fmt="both")
    names = {p.name for p in paths}
    assert names == {"scorecard.json", "scorecard.md"}
    assert all(p.exists() for p in paths)
