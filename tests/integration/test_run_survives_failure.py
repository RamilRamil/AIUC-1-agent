"""T029: сбой попытки → ERROR, прогон продолжается (FR-015). Плюс смоук успешных атак."""

from pathlib import Path

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.redteam.suite import AttackSuite
from aiuc_mini.trace.events import AttemptError, VerdictEvent
from aiuc_mini.trace.writer import read_trace
from tests.fakes import CompromisableChatModel, FailingChatModel

SUITE = Path("attacks/suite.yaml")


def _cfg(tmp_path, **kw) -> Config:
    return Config(
        suite_path=SUITE,
        runs_dir=tmp_path / "runs",
        max_mutations=kw.pop("max_mutations", 0),
        **kw,
    )


def test_failing_model_yields_errors_not_crash(tmp_path):
    cfg = _cfg(tmp_path)
    summary = run_suite(
        cfg, "r-fail", target_model=FailingChatModel(), redteam_model=None
    )
    # Прогон дошёл до конца: все кейсы обработаны, все — ошибки.
    assert summary.attempts_total == len(AttackSuite.load(SUITE).attacks)
    assert summary.errors == summary.attempts_total
    assert summary.attacks_succeeded == 0

    events = read_trace(summary.run_dir / "trace.jsonl")
    assert any(isinstance(e, AttemptError) for e in events)
    # ERROR не засчитан как успех атаки.
    verdicts = [e.verdict for e in events if isinstance(e, VerdictEvent)]
    assert verdicts and all(v == "ERROR" for v in verdicts)


def test_compromisable_model_finds_successful_attacks(tmp_path):
    """SC-002: без защиты red-team находит успехи минимум в 2 из 3 категорий."""
    cfg = _cfg(tmp_path, guardrails_enabled=False)
    summary = run_suite(
        cfg, "r-vuln", target_model=CompromisableChatModel(), redteam_model=None
    )
    assert summary.attacks_succeeded >= 2

    events = read_trace(summary.run_dir / "trace.jsonl")
    # Собираем категории успешных атак.
    succeeded_categories = set()
    attempts = {}
    for e in events:
        if e.type == "attempt_started":
            attempts[e.attempt_id] = e.category
        if isinstance(e, VerdictEvent) and e.verdict == "SUCCESS":
            succeeded_categories.add(attempts.get(e.attempt_id))
    assert len(succeeded_categories) >= 2
