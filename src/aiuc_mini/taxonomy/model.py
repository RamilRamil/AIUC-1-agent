"""Схема внешней таксономии атак (data-model.md, contracts/taxonomy.md).

`taxonomy/owasp-llm-top10.yaml` — источник истины. Это первая мера в проекте, приходящая **не от
нас**: категории берутся из OWASP Top 10 for LLM Applications, на который ссылается и сам AIUC-1.

ГЛАВНОЕ ПРАВИЛО (contracts/taxonomy.md): `tested` не ставится за «что-то похожее». Если
проверяется лишь отдалённо смежное — это `gap`. Иначе внешний список превращается в новый способ
поставить себе галочку, и вся затея теряет смысл.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, model_validator

Status = Literal["tested", "gap", "not_applicable"]
STATUSES: tuple[Status, ...] = ("tested", "gap", "not_applicable")

_ID_RE = re.compile(r"^LLM\d{2}$")

# Полный набор идентификаторов OWASP LLM Top 10 (2025).
EXPECTED_IDS: set[str] = {f"LLM{i:02d}" for i in range(1, 11)}
TOTAL_CATEGORIES = 10


class Category(BaseModel):
    id: str
    title: str
    status: Status
    rationale: str
    attacks: list[str] = []

    @model_validator(mode="after")
    def _check(self) -> Category:
        if not _ID_RE.match(self.id):
            raise ValueError(f"{self.id}: id должен быть вида LLM01…LLM10")
        if not self.rationale.strip():
            raise ValueError(f"{self.id}: обоснование обязательно")
        # tested ⇒ есть атаки; иначе статус нельзя было бы заслужить (FR-003).
        if self.status == "tested" and not self.attacks:
            raise ValueError(f"{self.id}: tested без ссылок на атаки")
        # не-tested ⇒ атак нет: ссылки на атаки означают проверку, а её нет.
        if self.status != "tested" and self.attacks:
            raise ValueError(f"{self.id}: атаки указаны при статусе {self.status}")
        return self


class Coverage(BaseModel):
    by_status: dict[str, int]
    applicable_total: int   # 10 − not_applicable
    tested_share: float     # доля ПРИМЕНИМОГО, которое проверяется


class Taxonomy(BaseModel):
    name: str
    version: str
    source: str
    categories: list[Category]

    @model_validator(mode="after")
    def _check(self) -> Taxonomy:
        ids = [c.id for c in self.categories]
        if len(ids) != len(set(ids)):
            raise ValueError("дубли id категорий")
        if set(ids) != EXPECTED_IDS:
            missing = EXPECTED_IDS - set(ids)
            extra = set(ids) - EXPECTED_IDS
            raise ValueError(
                f"набор категорий не равен {TOTAL_CATEGORIES}: "
                f"пропущены {sorted(missing)}, лишние {sorted(extra)}"
            )
        return self

    @classmethod
    def load(cls, path: Path) -> Taxonomy:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


def coverage(taxonomy: Taxonomy) -> Coverage:
    """Чистая функция покрытия.

    ВАЖНО (FR-008, SC-006): это про **широту** — сколько классов атак стенд вообще проверяет.
    Не смешивать с долей отражённых атак из scorecard (это про **глубину** на той узкой полоске,
    что проверяется). По отдельности каждая цифра врёт: первая занижает, вторая льстит.
    """
    by_status: dict[str, int] = dict.fromkeys(STATUSES, 0)
    for c in taxonomy.categories:
        by_status[c.status] += 1
    applicable = len(taxonomy.categories) - by_status["not_applicable"]
    return Coverage(
        by_status=by_status,
        applicable_total=applicable,
        tested_share=(by_status["tested"] / applicable if applicable else 0.0),
    )
