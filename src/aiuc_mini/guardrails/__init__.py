"""Сборка guardrail-слоя (T035).

``build_guardrail_middleware`` возвращает список middleware для ``create_agent``. Порядок:
вход → инструменты → выход. Тот же агент, тот же код-путь — разница лишь в наличии этого списка
(FR-011).
"""

from __future__ import annotations

from ..trace.sink import TraceSink
from .input import InputGuardrail
from .output import OutputGuardrail
from .policy import GuardrailPolicy
from .tools_policy import ToolPolicyGuardrail

__all__ = ["build_guardrail_middleware", "GuardrailPolicy"]


def build_guardrail_middleware(
    secret: str, sink: TraceSink, policy: GuardrailPolicy | None = None
) -> list:
    policy = policy or GuardrailPolicy()
    return [
        InputGuardrail(policy, sink),
        ToolPolicyGuardrail(policy, sink),
        OutputGuardrail(secret, sink),
    ]
