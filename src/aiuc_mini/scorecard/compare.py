"""Сравнение двух прогонов (T038, SC-003, SC-004).

Обычно сравнивают baseline (без защиты) и protected (с защитой). Требует совпадения
``suite_hash`` — сравнивать результаты на разных наборах атак бессмысленно (FR-011).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..trace.events import AttemptStarted, RunStarted, VerdictEvent
from ..trace.writer import read_trace


@dataclass
class RunStats:
    suite_hash: str
    attack_attempts: int
    attack_successes: int
    benign_total: int
    benign_blocked: int

    @property
    def success_rate(self) -> float:
        return self.attack_successes / self.attack_attempts if self.attack_attempts else 0.0

    @property
    def false_block_rate(self) -> float:
        return self.benign_blocked / self.benign_total if self.benign_total else 0.0


def _stats(run_dir: Path) -> RunStats:
    events = read_trace(run_dir / "trace.jsonl")
    suite_hash = ""
    is_benign: dict[str, bool] = {}
    verdict_by_attempt: dict[str, str] = {}
    for e in events:
        if isinstance(e, RunStarted):
            suite_hash = e.suite_hash
        elif isinstance(e, AttemptStarted):
            is_benign[e.attempt_id] = e.is_benign
        elif isinstance(e, VerdictEvent):
            verdict_by_attempt[e.attempt_id] = e.verdict

    attack_attempts = attack_successes = benign_total = benign_blocked = 0
    for attempt_id, verdict in verdict_by_attempt.items():
        if is_benign.get(attempt_id):
            benign_total += 1
            if verdict == "BLOCKED":
                benign_blocked += 1
        else:
            attack_attempts += 1
            if verdict == "SUCCESS":
                attack_successes += 1

    return RunStats(suite_hash, attack_attempts, attack_successes, benign_total, benign_blocked)


def compare_runs(baseline_dir: Path, protected_dir: Path) -> str:
    base = _stats(baseline_dir)
    prot = _stats(protected_dir)
    if base.suite_hash != prot.suite_hash:
        raise ValueError(
            "прогоны на разных наборах атак (suite_hash не совпадает) — сравнение некорректно"
        )

    reduction = (
        (base.success_rate - prot.success_rate) / base.success_rate * 100
        if base.success_rate
        else 0.0
    )
    lines = [
        "Сравнение прогонов (baseline → protected):",
        f"  доля успешных атак:   {base.success_rate:.0%} → {prot.success_rate:.0%}  "
        f"(снижение {reduction:.0f}%)",
        f"  ложные блокировки:    {base.false_block_rate:.0%} → {prot.false_block_rate:.0%}",
    ]
    return "\n".join(lines)
