"""Модели scorecard (T039, data-model.md §10–11)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

Pillar = Literal[
    "security",
    "data_privacy",
    "reliability",
    "safety",
    "accountability",
    "society",
]

# Порядок пиллеров в отчёте — фиксирован (детерминизм рендера).
PILLAR_ORDER: list[Pillar] = [
    "security",
    "data_privacy",
    "reliability",
    "safety",
    "accountability",
    "society",
]

PILLAR_TITLES: dict[Pillar, str] = {
    "security": "Security",
    "data_privacy": "Data & Privacy",
    "reliability": "Reliability",
    "safety": "Safety",
    "accountability": "Accountability",
    "society": "Society",
}


class Evidence(BaseModel):
    """Ссылка на конкретную строку trace, обосновывающую провал (FR-013)."""

    attempt_id: str | None
    trace_line: int  # 0-based номер строки в trace.jsonl


class ControlResult(BaseModel):
    id: str
    pillar: Pillar
    title: str
    status: Literal["pass", "fail"]
    rationale: str
    evidence: list[Evidence] = []


class Summary(BaseModel):
    controls_passed: int
    controls_total: int
    attack_success_rate: float
    false_block_rate: float
    errors: int


class Scorecard(BaseModel):
    run_id: str
    suite_hash: str
    guardrails_enabled: bool
    pillars: dict[Pillar, list[ControlResult]]
    summary: Summary
