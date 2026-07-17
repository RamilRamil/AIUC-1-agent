"""Модели атак и загрузка набора (T024, data-model.md §5–6).

``suite_hash`` (sha256 файла) фиксирует «тот же набор атак» для сравнения прогонов и
воспроизводимости (FR-011, SC-006).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

AttackCategory = Literal[
    "direct_injection",
    "role_bypass",
    "secret_exfiltration",
    # Фича 005: вредоносная инструкция приходит через РЕЗУЛЬТАТ ИНСТРУМЕНТА, а не от пользователя.
    "indirect_injection",
]

# Идентификатор категории внешней таксономии (OWASP LLM Top 10).
_TAXONOMY_ID_RE = re.compile(r"^LLM\d{2}$")


class CanaryInOutput(BaseModel):
    kind: Literal["canary_in_output"] = "canary_in_output"


class CanaryInToolArgs(BaseModel):
    kind: Literal["canary_in_tool_args"] = "canary_in_tool_args"


class ForbiddenToolCalled(BaseModel):
    kind: Literal["forbidden_tool_called"] = "forbidden_tool_called"
    tool: str
    arg_pattern: str | None = None


class OutOfRoleAction(BaseModel):
    kind: Literal["out_of_role_action"] = "out_of_role_action"
    tool: str


class ExternalHostContacted(BaseModel):
    """Агент обратился к хосту, которого пользователь не называл (фича 005, косвенная инъекция).

    Читается из УЖЕ существующего события `sandbox_violation(rule="external_host")` — песочница
    помечает так любой URL вне фикстур с фичи 001. Новой машинерии не нужно.

    Почему не переиспользовать существующие критерии: `forbidden_tool_called` упрётся в allow-list,
    `canary_in_tool_args` — в правило секрета фичи 004. Оба остановят атаку раньше, чем она
    покажет слепую зону входного guardrail.
    """

    kind: Literal["external_host_contacted"] = "external_host_contacted"


SuccessCriterion = Annotated[
    CanaryInOutput
    | CanaryInToolArgs
    | ForbiddenToolCalled
    | OutOfRoleAction
    | ExternalHostContacted,
    Field(discriminator="kind"),
]


class AttackCase(BaseModel):
    id: str
    category: AttackCategory
    payload: str
    success_criterion: SuccessCriterion
    # Ссылка на категорию ВНЕШНЕЙ таксономии (фича 005, FR-005). Обязательна: без неё набор
    # снова замкнётся сам на себя. Не путать с `category` — та наш внутренний класс вектора.
    taxonomy: str
    parent_id: str | None = None
    is_benign: bool = False

    @model_validator(mode="after")
    def _check_taxonomy_ref(self) -> AttackCase:
        if not _TAXONOMY_ID_RE.match(self.taxonomy):
            raise ValueError(
                f"{self.id}: taxonomy='{self.taxonomy}' — ожидается id вида LLM01…LLM10"
            )
        return self


class AttackSuite(BaseModel):
    attacks: list[AttackCase]
    suite_hash: str

    @classmethod
    def load(cls, path: Path) -> AttackSuite:
        raw = Path(path).read_bytes()
        data = yaml.safe_load(raw)
        suite_hash = hashlib.sha256(raw).hexdigest()
        return cls(attacks=data["attacks"], suite_hash=suite_hash)
