"""Файловая песочница (contracts/tools.md, Принцип II — NON-NEGOTIABLE).

Границы проверяются структурно: любой путь резолвится и обязан лежать внутри ``root``. Это
отбивает ``../``, абсолютные пути и symlink-escape. Нарушение → ``SandboxViolation`` (не тихий
пропуск — иначе атака выглядела бы отбитой, хотя её просто не заметили).

Песочница — это НЕ guardrail. Guardrail отключается флагом, песочница — никогда.
"""

from __future__ import annotations

import tempfile
from pathlib import Path


class SandboxViolation(Exception):
    """Попытка выйти за границы песочницы. Несёт, что именно пытались сделать, и какое правило
    сработало — для события ``sandbox_violation`` в trace."""

    def __init__(self, attempted: str, rule: str) -> None:
        super().__init__(f"sandbox violation [{rule}]: {attempted}")
        self.attempted = attempted
        self.rule = rule


class Sandbox:
    """Изолированная рабочая среда для инструментов агента-мишени.

    - ``root`` — временный каталог; всё файловое действие заперто внутри него;
    - ``http_fixtures`` — словарь ``url -> ответ`` для фикстурного HTTP (см. http.py);
    - реального ``subprocess`` и реальной сети не существует ни на одном код-пути.
    """

    def __init__(
        self,
        files: dict[str, str] | None = None,
        http_fixtures: dict[str, str] | None = None,
    ) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="aiuc_sandbox_")).resolve()
        self.http_fixtures = dict(http_fixtures or {})
        for rel, content in (files or {}).items():
            self.write_file(rel, content)

    # --- границы ---

    def _resolve(self, path: str) -> Path:
        """Резолвить путь относительно root и проверить, что он не покидает песочницу."""
        candidate = (self.root / path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise SandboxViolation(attempted=path, rule="path_escape")
        return candidate

    # --- файловые операции ---

    def read_file(self, path: str) -> str:
        target = self._resolve(path)
        if not target.is_file():
            raise SandboxViolation(attempted=path, rule="not_found")
        return target.read_text(encoding="utf-8")

    def write_file(self, path: str, content: str) -> None:
        target = self._resolve(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def list_dir(self, path: str = ".") -> list[str]:
        target = self._resolve(path)
        if not target.is_dir():
            raise SandboxViolation(attempted=path, rule="not_a_dir")
        return sorted(p.name for p in target.iterdir())

    # --- жизненный цикл ---

    def cleanup(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()
