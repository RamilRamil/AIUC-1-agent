"""Схема машиночитаемого каталога AIUC-1 (data-model.md, contracts/catalog-schema.md).

Каталог `aiuc1/catalog.yaml` — единственный источник истины карты покрытия. Здесь — Pydantic-
схема, загрузка и чистая функция агрегатов. Реализации контролей безопасности тут нет: фича 002
только каталогизирует.

Факт из источника (aiuc-1.com/evidence, снимок 2026-07-15): стандарт нумерует 53 контроля
(A001–A008, B001–B010, C001–C012, D001–D004, E001–E017, F001–F002), из которых **E007 и E014 —
Retired**. Активных контролей 51; агрегация по базовым статусам считается по активным.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, model_validator

Pillar = Literal["data_privacy", "security", "safety", "reliability", "accountability", "society"]
Nature = Literal["technical", "organizational", "mixed"]
# Базовые статусы покрытия + терминальный `retired` для отозванных стандартом контролей.
Status = Literal["covered", "technical_achievable", "doc_only", "retired"]
BASE_STATUSES = ("covered", "technical_achievable", "doc_only")
BindingKind = Literal["scorecard_control", "attack_category", "guardrail_rule", "artifact", "none"]
ArtifactType = Literal["policy", "runbook", "attestation", "third_party_test"]

# Буква идентификатора контроля → пиллер.
_LETTER_PILLAR: dict[str, Pillar] = {
    "A": "data_privacy",
    "B": "security",
    "C": "safety",
    "D": "reliability",
    "E": "accountability",
    "F": "society",
}

# Полный набор идентификаторов стандарта (53 контроля, включая 2 retired в секции E).
EXPECTED_IDS: set[str] = (
    {f"A{i:03d}" for i in range(1, 9)}  # A001–A008
    | {f"B{i:03d}" for i in range(1, 11)}  # B001–B010
    | {f"C{i:03d}" for i in range(1, 13)}  # C001–C012
    | {f"D{i:03d}" for i in range(1, 5)}  # D001–D004
    | {f"E{i:03d}" for i in range(1, 18)}  # E001–E017 (E007, E014 — Retired)
    | {f"F{i:03d}" for i in range(1, 3)}  # F001–F002
)
TOTAL_IDS = 53
RETIRED_IDS = {"E007", "E014"}
ACTIVE_TOTAL = TOTAL_IDS - len(RETIRED_IDS)  # 51


class Binding(BaseModel):
    kind: BindingKind
    scorecard_control: str | None = None
    stand_mechanism: str | None = None
    artifact_type: ArtifactType | None = None


class Partial(BaseModel):
    technical: str
    documentable: str


class Control(BaseModel):
    id: str
    pillar: Pillar
    title: str
    nature: Nature
    status: Status
    binding: Binding
    rationale: str
    partial: Partial | None = None
    backlog_item: str | None = None

    @model_validator(mode="after")
    def _check_invariants(self) -> Control:
        letter = self.id[:1]
        if letter not in _LETTER_PILLAR or _LETTER_PILLAR[letter] != self.pillar:
            raise ValueError(f"{self.id}: пиллер {self.pillar} не согласован с буквой id")

        # Retired-контроли освобождены от правил покрытия и не попадают в бэклог.
        if self.status == "retired":
            if self.backlog_item is not None:
                raise ValueError(f"{self.id}: retired не должен иметь backlog_item")
            return self

        # partial ⇔ nature=mixed (для активных контролей)
        if (self.partial is not None) != (self.nature == "mixed"):
            raise ValueError(f"{self.id}: partial должен присутствовать ровно при nature=mixed")
        # covered ⇒ ссылка на контроль scorecard и без backlog
        if self.status == "covered":
            if not self.binding.scorecard_control:
                raise ValueError(f"{self.id}: covered без binding.scorecard_control")
            if self.backlog_item is not None:
                raise ValueError(f"{self.id}: covered не должен иметь backlog_item")
        else:
            if not self.backlog_item:
                raise ValueError(f"{self.id}: не-covered обязан иметь backlog_item")
        return self


class BacklogItem(BaseModel):
    id: str
    title: str
    nature: Literal["technical", "organizational"]
    priority: int
    rationale: str


class Aggregates(BaseModel):
    by_status: dict[str, int]  # только базовые статусы, сумма == ACTIVE_TOTAL (51)
    by_pillar: dict[str, int]  # активные контроли по пиллерам
    partial_count: int
    retired_count: int
    coverage_pct: float


class Catalog(BaseModel):
    version: str
    source: str
    controls: list[Control]
    backlog: list[BacklogItem]

    @model_validator(mode="after")
    def _check_catalog(self) -> Catalog:
        ids = [c.id for c in self.controls]
        if len(ids) != len(set(ids)):
            raise ValueError("дубли id в каталоге")
        got = set(ids)
        if got != EXPECTED_IDS:
            missing = EXPECTED_IDS - got
            extra = got - EXPECTED_IDS
            raise ValueError(
                f"набор id не равен {TOTAL_IDS}: "
                f"пропущены {sorted(missing)}, лишние {sorted(extra)}"
            )
        # retired-контроли ровно те, что отозваны стандартом
        retired = {c.id for c in self.controls if c.status == "retired"}
        if retired != RETIRED_IDS:
            raise ValueError(
                f"retired должны быть {sorted(RETIRED_IDS)}, а в каталоге {sorted(retired)}"
            )
        # backlog-ссылки существуют
        backlog_ids = {b.id for b in self.backlog}
        for c in self.controls:
            if c.backlog_item and c.backlog_item not in backlog_ids:
                raise ValueError(f"{c.id}: backlog_item {c.backlog_item} не найден в backlog")
        return self

    @classmethod
    def load(cls, path: Path) -> Catalog:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


def aggregate(catalog: Catalog) -> Aggregates:
    """Чистая функция агрегатов.

    Сумма по базовым статусам == 51 (активные); retired считается отдельно; `partial` — тоже
    отдельно, поверх базовых статусов.
    """
    by_status: dict[str, int] = dict.fromkeys(BASE_STATUSES, 0)
    by_pillar: dict[str, int] = dict.fromkeys(_LETTER_PILLAR.values(), 0)
    partial_count = 0
    retired_count = 0
    for c in catalog.controls:
        if c.status == "retired":
            retired_count += 1
            continue
        by_status[c.status] += 1
        by_pillar[c.pillar] += 1
        if c.partial is not None:
            partial_count += 1
    active = sum(by_status.values())
    return Aggregates(
        by_status=by_status,
        by_pillar=by_pillar,
        partial_count=partial_count,
        retired_count=retired_count,
        coverage_pct=round(by_status["covered"] / active * 100, 1) if active else 0.0,
    )
