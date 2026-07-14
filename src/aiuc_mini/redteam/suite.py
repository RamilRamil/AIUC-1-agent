"""Модели атак и загрузка набора (T024, data-model.md §5–6).

``suite_hash`` (sha256 файла) фиксирует «тот же набор атак» для сравнения прогонов и
воспроизводимости (FR-011, SC-006).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, Field

AttackCategory = Literal["direct_injection", "role_bypass", "secret_exfiltration"]


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


SuccessCriterion = Annotated[
    CanaryInOutput | CanaryInToolArgs | ForbiddenToolCalled | OutOfRoleAction,
    Field(discriminator="kind"),
]


class AttackCase(BaseModel):
    id: str
    category: AttackCategory
    payload: str
    success_criterion: SuccessCriterion
    parent_id: str | None = None
    is_benign: bool = False


class AttackSuite(BaseModel):
    attacks: list[AttackCase]
    suite_hash: str

    @classmethod
    def load(cls, path: Path) -> AttackSuite:
        raw = Path(path).read_bytes()
        data = yaml.safe_load(raw)
        suite_hash = hashlib.sha256(raw).hexdigest()
        return cls(attacks=data["attacks"], suite_hash=suite_hash)
