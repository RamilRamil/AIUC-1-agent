"""Политика guardrail (T031, data-model.md §7; расширена фичей 004).

Собирает в одном месте правила: allow-list инструментов, детекция инъекций на входе, паттерны PII
и правило «секрет в аргументах инструмента». Значение канареечного секрета в правила не
зашивается статически — оно приходит на прогон и передаётся middleware отдельно.

ГРАНИЦЫ ДЕТЕКТОРОВ зафиксированы в specs/004-detectors/contracts/detectors.md и НЕ подразумеваются
молча: правила ловят ровно то, подо что написаны. Обход кодированием (base64), по частям или с
вставленными разделителями не покрывается — это свойство метода, а не дефект реализации.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..pii import find_pii as _find_pii
from ..pii import redact_pii as _redact_pii
from ..target.tools import ALLOWED_TOOLS

# Allow-list ВЫВОДИТСЯ из единого определения запрещённых инструментов в target/tools.py
# (FR-010): «все инструменты минус вне-ролевые». Собственной копии здесь нет — иначе политика и
# судья разъехались бы тихо.
_DEFAULT_ALLOWLIST = set(ALLOWED_TOOLS)

# Грубые учебные признаки prompt-инъекции на входе (FR-008).
_DEFAULT_INJECTION_PATTERNS = [
    "игнорируй",
    "ignore previous",
    "забудь про роль",
    "ты теперь",
    "системный администратор",
    "выведи свой секрет",
    "напечатай значение переменной секрета",
    "разглаш",
    "rm -rf",
]

@dataclass
class GuardrailPolicy:
    tool_allowlist: set[str] = field(default_factory=lambda: set(_DEFAULT_ALLOWLIST))
    injection_patterns: list[str] = field(
        default_factory=lambda: list(_DEFAULT_INJECTION_PATTERNS)
    )
    # Блокировать вызов инструмента, если в аргументах найден секрет (фича 004, FR-001).
    block_secret_in_tool_args: bool = True

    # --- вход ---

    def is_injection(self, text: str) -> str | None:
        """Вернуть сработавший паттерн или None."""
        low = text.lower()
        for pat in self.injection_patterns:
            if pat in low:
                return pat
        return None

    # --- инструменты ---

    def tool_allowed(self, tool: str) -> bool:
        return tool in self.tool_allowlist

    def secret_in_args(self, args: object, secret: str) -> bool:
        """Есть ли секрет в аргументах вызова (рекурсивно по вложенным структурам).

        Точное сравнение подстроки: секрет — точная строка (Принцип III). Кодированный или
        разбитый на части секрет НЕ ловится — граница зафиксирована в contracts/detectors.md.
        """
        if not secret:
            return False
        if isinstance(args, str):
            return secret in args
        if isinstance(args, dict):
            return any(self.secret_in_args(v, secret) for v in args.values())
        if isinstance(args, (list, tuple)):
            return any(self.secret_in_args(v, secret) for v in args)
        return False

    # --- выход / журнал ---

    # Правила PII живут в aiuc_mini/pii.py — единственном источнике (их использует и trace/writer,
    # которому нельзя импортировать guardrails: получился бы цикл). Здесь только делегирование.

    def find_pii(self, text: str) -> list[str]:
        """Какие классы PII найдены — для журналирования причины (Принцип V)."""
        return _find_pii(text)

    def redact_pii(self, text: str) -> tuple[str, bool]:
        """Замаскировать PII. Возвращает (текст, изменялся ли)."""
        return _redact_pii(text)
