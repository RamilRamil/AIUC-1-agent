"""T033 / SC-005: зависшая попытка ограничена по времени, прогон продолжается.

Путь, который до фичи 003 не был покрыт ни одним тестом — и в коде не работал:
`ThreadPoolExecutor.__exit__` звал `shutdown(wait=True)` и ждал зависший вызов, из-за чего
заявленный FR-015 таймаут был иллюзорным.
"""

import time
from pathlib import Path

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.trace.events import AttemptError, VerdictEvent
from aiuc_mini.trace.writer import read_trace
from tests.fakes import HangingChatModel

SUITE = Path("attacks/suite.yaml")

TIMEOUT = 0.5
HANG = 30.0


def test_hanging_attempt_is_bounded_and_run_continues(tmp_path):
    """Зависшая попытка → ERROR за время порядка таймаута; прогон доходит до конца."""
    cfg = Config(
        suite_path=SUITE,
        runs_dir=tmp_path / "runs",
        max_mutations=0,
        attempt_timeout_s=TIMEOUT,
    )

    started = time.monotonic()
    summary = run_suite(
        cfg, "hang", target_model=HangingChatModel(hang_seconds=HANG), redteam_model=None
    )
    elapsed = time.monotonic() - started

    events = read_trace(summary.run_dir / "trace.jsonl")

    # Прогон дошёл до конца, а не встал намертво.
    assert any(e.type == "run_finished" for e in events), "прогон не завершился"

    # Все попытки — таймауты, ни одна не засчитана успехом защиты.
    verdicts = [e.verdict for e in events if isinstance(e, VerdictEvent)]
    assert verdicts and all(v == "ERROR" for v in verdicts)
    timeouts = [
        e for e in events if isinstance(e, AttemptError) and e.error_type == "timeout"
    ]
    assert timeouts, "не зафиксировано ни одного события таймаута"

    # Ключевое: время прогона определяется таймаутом, а не длиной зависания.
    # 8 попыток × 0.5с ≈ 4с; при сломанном бounde было бы ≥ 30с (одно зависание).
    assert elapsed < HANG, (
        f"прогон занял {elapsed:.1f}с при зависании {HANG}с — таймаут не ограничивает время"
    )


def test_timeout_error_is_not_counted_as_defense_success(tmp_path):
    """ERROR ≠ «атака отбита»: упавший бэкенд не должен выглядеть идеальным guardrail."""
    from aiuc_mini.scorecard.compare import _stats

    cfg = Config(
        suite_path=SUITE,
        runs_dir=tmp_path / "runs",
        max_mutations=0,
        attempt_timeout_s=TIMEOUT,
    )
    summary = run_suite(
        cfg, "hang2", target_model=HangingChatModel(hang_seconds=HANG), redteam_model=None
    )
    stats = _stats(summary.run_dir)
    assert stats.errors > 0
    assert stats.attacks_breached == 0
    # Ни одна атака не «пробила», но и защита не получила очков — это ошибки, а не успехи.
    assert summary.errors == summary.attempts_total
