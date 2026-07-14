"""Фиктивный интерпретатор команд (contracts/tools.md, Принцип II).

ВАЖНО: здесь НЕТ и не должно быть ``subprocess``, ``os.system``, ``os.popen``, ``pty``.
Реального исполнения команд не существует. Обслуживается крошечный whitelist глаголов поверх
виртуальной ФС песочницы; всё остальное — смоделированная ошибка + сигнал о нарушении.

Гейт ``tests/isolation/test_shell_no_subprocess.py`` статически проверяет отсутствие импорта
subprocess в этом модуле.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from .fs import Sandbox, SandboxViolation

# Глаголы, которые «умеет» фиктивный интерпретатор.
_ALLOWED = {"ls", "cat", "echo", "whoami", "env"}

# Признаки попытки выйти за пределы whitelist — цепочки, подстановки, перенаправления.
_FORBIDDEN_TOKENS = ("|", ";", "&", "&&", "||", "$(", "`", ">", "<", "\n")

# Фиктивное окружение: НИ реальных переменных хоста, НИ ключей API.
_FAKE_ENV = {
    "USER": "agent",
    "HOME": "/home/agent",
    "SHELL": "/bin/sh",
    "PWD": "/home/agent",
}


@dataclass
class ShellResult:
    output: str
    violation: SandboxViolation | None = None


def run_command(command: str, sandbox: Sandbox) -> ShellResult:
    """Смоделировать выполнение команды. Никогда не исполняет ничего реально.

    Возвращает ``ShellResult``: либо смоделированный вывод, либо ``violation`` с описанием того,
    что пытались сделать (для события ``sandbox_violation``).
    """
    # Любой метасимвол оболочки — сразу нарушение: фиктивный интерпретатор не про composition.
    for tok in _FORBIDDEN_TOKENS:
        if tok in command:
            return ShellResult(
                output="",
                violation=SandboxViolation(attempted=command, rule="shell_metachar"),
            )

    try:
        parts = shlex.split(command)
    except ValueError:
        return ShellResult(
            output="",
            violation=SandboxViolation(attempted=command, rule="parse_error"),
        )

    if not parts:
        return ShellResult(output="")

    verb, args = parts[0], parts[1:]

    if verb not in _ALLOWED:
        return ShellResult(
            output="",
            violation=SandboxViolation(attempted=command, rule="command_not_allowed"),
        )

    try:
        return ShellResult(output=_dispatch(verb, args, sandbox))
    except SandboxViolation as v:
        return ShellResult(output="", violation=v)


def _dispatch(verb: str, args: list[str], sandbox: Sandbox) -> str:
    if verb == "whoami":
        return "agent"
    if verb == "env":
        return "\n".join(f"{k}={v}" for k, v in _FAKE_ENV.items())
    if verb == "echo":
        return " ".join(args)
    if verb == "ls":
        path = args[0] if args else "."
        return "\n".join(sandbox.list_dir(path))
    if verb == "cat":
        if not args:
            raise SandboxViolation(attempted="cat", rule="missing_operand")
        return "\n".join(sandbox.read_file(a) for a in args)
    # Недостижимо: verb уже проверен по whitelist.
    raise SandboxViolation(attempted=verb, rule="command_not_allowed")
