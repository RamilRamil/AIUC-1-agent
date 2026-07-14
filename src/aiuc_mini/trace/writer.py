"""Запись и чтение JSONL-trace (contracts/trace-events.md, T009).

Две ответственности:
1. Монотонный ``seq`` в пределах прогона — это то, что делает JSONL восстановимой историей.
2. Маскирование канареечного секрета: значение секрета заменяется на ``<CANARY>`` при записи
   ЛЮБОГО события, кроме поля ``verdict.leaked_via``. Иначе журнал сам стал бы каналом утечки
   секрета — а мы им же и измеряем утечки (Принцип V + инвариант data-model.md §2).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from .events import TraceEvent, VerdictEvent

MASK = "<CANARY>"

_ADAPTER: TypeAdapter[TraceEvent] = TypeAdapter(TraceEvent)


def _mask(value: Any, secret: str) -> Any:
    """Рекурсивно заменить секрет в строках вложенной структуры."""
    if not secret:
        return value
    if isinstance(value, str):
        return value.replace(secret, MASK)
    if isinstance(value, dict):
        return {k: _mask(v, secret) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask(v, secret) for v in value]
    return value


class TraceWriter:
    """Пишет события в ``<run_dir>/trace.jsonl``, назначая ``seq`` и маскируя секрет."""

    def __init__(self, run_dir: Path, secret: str = "") -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / "trace.jsonl"
        self._secret = secret
        self._seq = 0
        # Открываем в режиме дозаписи: trace стримится и переживает падение прогона.
        self._fh = self.path.open("a", encoding="utf-8")

    def emit(self, event: TraceEvent) -> TraceEvent:
        """Присвоить ``seq`` и записать событие (с маскированием) одной строкой JSONL."""
        event.seq = self._seq
        self._seq += 1

        data = event.model_dump(mode="json")
        # verdict.leaked_via — единственное место, где секрет допустим; остальное маскируем.
        # Само поле leaked_via хранит лишь канал ("output"/"tool_args"), не значение секрета,
        # поэтому безопасно маскировать всю запись целиком.
        data = _mask(data, self._secret)

        self._fh.write(json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n")
        self._fh.flush()
        return event

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> TraceWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_trace(path: Path) -> list[TraceEvent]:
    """Прочитать trace обратно в типизированные события (для судьи и scorecard)."""
    events: list[TraceEvent] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(_ADAPTER.validate_python(json.loads(line)))
    return events


__all__ = ["TraceWriter", "read_trace", "MASK", "VerdictEvent"]
