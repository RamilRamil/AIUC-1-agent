"""TraceSink — тонкий контекст попытки поверх TraceWriter.

Инструменты и guardrail'ы конструируют события, не зная ``run_id`` и текущего ``attempt_id``.
Sink проставляет их и делегирует запись writer'у (который назначает ``seq`` и маскирует секрет).
"""

from __future__ import annotations

from .events import TraceEvent
from .writer import TraceWriter


class TraceSink:
    def __init__(self, writer: TraceWriter, run_id: str) -> None:
        self._writer = writer
        self.run_id = run_id
        self.attempt_id: str | None = None

    def emit(self, event: TraceEvent) -> TraceEvent:
        event.run_id = self.run_id
        event.attempt_id = self.attempt_id
        return self._writer.emit(event)
