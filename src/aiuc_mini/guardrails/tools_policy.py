"""Guardrail политики инструментов (T034, FR-010).

``wrap_tool_call``: если инструмент вне allow-list, middleware НЕ вызывает ``handler`` и
возвращает ``ToolMessage`` с отказом. Именно невызов handler делает запрет структурным, а не
просьбой к модели — инструмент физически не исполняется.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

from ..trace.events import GuardrailDecision, ToolCall
from ..trace.sink import TraceSink
from .policy import GuardrailPolicy

# Инструменты с исходящим доступом — к ним применяется egress allow-list (фича 006).
_EGRESS_TOOLS = frozenset({"http_get"})


class ToolPolicyGuardrail(AgentMiddleware):
    def __init__(self, policy: GuardrailPolicy, sink: TraceSink, secret: str = "") -> None:
        super().__init__()
        self._policy = policy
        self._sink = sink
        self._secret = secret

    def _decide(self, request: Any) -> ToolMessage | None:
        """Решение политики. ``None`` — пропустить к handler; ``ToolMessage`` — заблокировать.

        Общее для sync- и async-путей, чтобы политика не разъехалась между ними.

        Порядок правил (data-model §2): сначала allow-list (разрешён ли инструмент вообще), затем
        секрет в аргументах — так причина блокировки в trace однозначна.
        """
        call = request.tool_call
        name = call["name"]

        # 1) Инструмент вне роли — блокируем независимо от аргументов.
        if not self._policy.tool_allowed(name):
            self._block(name, call, "TOOL-ALLOWLIST", f"tool not in allowlist: {name}")
            return ToolMessage(
                content=f"Инструмент {name} заблокирован политикой.",
                tool_call_id=call["id"],
            )

        # 2) Секрет в аргументах — блокируем вызов (фича 004, FR-001).
        #
        # Именно блокировка, а не маскирование аргумента: замаскировав, мы бы всё равно отправили
        # запрос на адрес атакующего — тихий полу-успех. Невызов handler делает запрет структурным.
        if self._policy.block_secret_in_tool_args and self._policy.secret_in_args(
            call.get("args"), self._secret
        ):
            self._block(name, call, "TOOL-SECRET", f"secret in arguments of {name}")
            return ToolMessage(
                content=f"Вызов {name} заблокирован: в аргументах обнаружен секрет.",
                tool_call_id=call["id"],
            )

        # 3) Исходящий доступ только к разрешённым хостам (фича 006, FR-001).
        #
        # СТРУКТУРНЫЙ контроль: правило не читает текст инъекции, поэтому его нельзя обойти
        # перефразированием. Даже полностью убеждённый агент не дотянется до адреса атакующего —
        # вызов не исполнится. Урок агентной безопасности: ограничивай не убеждение, а полномочия.
        if self._policy.block_egress_outside_allowlist and name in _EGRESS_TOOLS:
            url = (call.get("args") or {}).get("url")
            if not self._policy.egress_allowed(url):
                self._block(name, call, "EGRESS", f"host not in egress allowlist: {url}")
                return ToolMessage(
                    content=f"Вызов {name} заблокирован: адрес вне списка разрешённых.",
                    tool_call_id=call["id"],
                )

        self._sink.emit(
            GuardrailDecision(stage="tool_call", action="allow", rule_id="TOOL-ALLOW")
        )
        return None

    def _block(self, name: str, call: dict, rule_id: str, reason: str) -> None:
        """Записать решение о блокировке И сам факт попытки вызова (Принцип V).

        Заблокированный инструмент не исполняется, поэтому событие ``tool_call`` из
        ``target/tools.py`` не появится — без этой записи в trace не было бы видно, ЧТО именно
        пытались сделать. Секрет в ``args`` маскируется writer'ом при записи.

        Важно: ``blocked=True`` обязателен — судья игнорирует заблокированные вызовы при проверке
        эксфильтрации, иначе сама запись о пресечённой попытке засчиталась бы как успех атаки.
        """
        self._sink.emit(
            GuardrailDecision(
                stage="tool_call", action="block", rule_id=rule_id, reason=reason
            )
        )
        self._sink.emit(
            ToolCall(tool=name, args=dict(call.get("args") or {}), blocked=True)
        )

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        blocked = self._decide(request)
        # Запрещённый инструмент: handler НЕ вызывается — исполнения не происходит.
        return blocked if blocked is not None else handler(request)

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        """Async-путь (фича 003): раннер вызывает мишень через ``ainvoke`` ради реального
        таймаута, а LangChain требует отдельную async-реализацию перехвата.

        Без неё политика молча падала с ``NotImplementedError``, атаки уходили в ``ERROR``, и
        отчёт показывал 0% успешных атак — защита выглядела идеальной, потому что была сломана.
        """
        blocked = self._decide(request)
        if blocked is not None:
            return blocked
        return await handler(request)
