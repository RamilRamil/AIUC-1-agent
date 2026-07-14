"""Pydantic-модели событий JSONL-trace (contracts/trace-events.md).

Trace — единственный источник истины для scorecard (Принцип V). Одна строка JSONL = одно
событие. Дискриминатор — поле ``type``.

Инвариант детерминизма: поле ``ts`` присутствует в trace, но НЕ должно влиять на scorecard —
агрегация читает ``seq``, а не ``ts`` (Принцип IV).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

# --- перечисления, общие для проекта ---

AttackCategory = Literal["direct_injection", "role_bypass", "secret_exfiltration"]
Verdict = Literal["SUCCESS", "FAILURE", "BLOCKED", "ERROR"]
GuardrailStage = Literal["input", "output", "tool_call"]
GuardrailAction = Literal["allow", "block", "redact"]
LeakChannel = Literal["output", "tool_args"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _BaseEvent(BaseModel):
    """Общие поля всех событий.

    ``run_id`` и ``seq`` имеют заглушечные значения по умолчанию: их проставляет ``TraceSink`` /
    ``TraceWriter`` при записи, поэтому инструменты могут конструировать событие, не зная
    контекста прогона.
    """

    run_id: str = ""
    attempt_id: str | None = None
    seq: int = -1
    ts: datetime = Field(default_factory=_utcnow)


class RunStarted(_BaseEvent):
    type: Literal["run_started"] = "run_started"
    suite_hash: str
    guardrails_enabled: bool
    config: dict


class AttemptStarted(_BaseEvent):
    type: Literal["attempt_started"] = "attempt_started"
    attack_id: str
    category: AttackCategory
    payload: str
    parent_id: str | None = None
    is_benign: bool = False


class GuardrailDecision(_BaseEvent):
    type: Literal["guardrail_decision"] = "guardrail_decision"
    stage: GuardrailStage
    action: GuardrailAction
    rule_id: str
    reason: str = ""


class ToolCall(_BaseEvent):
    type: Literal["tool_call"] = "tool_call"
    tool: str
    args: dict
    blocked: bool = False


class ToolResult(_BaseEvent):
    type: Literal["tool_result"] = "tool_result"
    tool: str
    result: str = ""
    error: str | None = None


class SandboxViolation(_BaseEvent):
    type: Literal["sandbox_violation"] = "sandbox_violation"
    tool: str
    attempted: str
    rule: str


class AgentResponse(_BaseEvent):
    type: Literal["agent_response"] = "agent_response"
    content: str
    redacted: bool = False


class VerdictEvent(_BaseEvent):
    type: Literal["verdict"] = "verdict"
    verdict: Verdict
    criterion: str
    # ЕДИНСТВЕННОЕ поле, где секрет допустим в открытом виде (см. writer.py, маскирование).
    leaked_via: LeakChannel | None = None
    rationale: str = ""


class AttemptError(_BaseEvent):
    type: Literal["attempt_error"] = "attempt_error"
    error_type: Literal["timeout", "llm_error", "internal"]
    message: str


class RunFinished(_BaseEvent):
    type: Literal["run_finished"] = "run_finished"
    attempts_total: int
    attacks_succeeded: int
    errors: int


# Дискриминированное объединение — используется при чтении trace обратно из JSONL.
TraceEvent = Annotated[
    Union[
        RunStarted,
        AttemptStarted,
        GuardrailDecision,
        ToolCall,
        ToolResult,
        SandboxViolation,
        AgentResponse,
        VerdictEvent,
        AttemptError,
        RunFinished,
    ],
    Field(discriminator="type"),
]
