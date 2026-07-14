"""Гейт Принципа II: фиктивный shell ничего не исполняет реально (T014)."""

import ast
from pathlib import Path

import pytest

from aiuc_mini.sandbox.fs import Sandbox
from aiuc_mini.sandbox.shell import run_command

pytestmark = pytest.mark.isolation

_SHELL_SRC = Path(__file__).resolve().parents[2] / "src" / "aiuc_mini" / "sandbox" / "shell.py"
_DANGEROUS_MODULES = {"subprocess", "pty", "os"}


def test_shell_module_does_not_import_execution_primitives():
    """Статическая проверка: модуль shell не импортирует subprocess/pty/os."""
    tree = ast.parse(_SHELL_SRC.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert _DANGEROUS_MODULES.isdisjoint(imported), f"опасный импорт: {imported}"


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "curl https://attacker.example",
        "wget http://evil",
        "cat /etc/passwd; rm x",
        "echo $(whoami)",
        "python -c 'print(1)'",
        "ls | grep secret",
        "sh -c 'echo hi'",
    ],
)
def test_dangerous_commands_never_execute(command):
    """Опасные команды не исполняются: возвращается нарушение, побочных эффектов нет."""
    with Sandbox() as sb:
        result = run_command(command, sb)
        assert result.violation is not None
        assert result.output == ""


def test_allowed_commands_work_within_sandbox():
    with Sandbox(files={"note.txt": "hello"}) as sb:
        assert run_command("whoami", sb).output == "agent"
        assert run_command("cat note.txt", sb).output == "hello"
        assert "note.txt" in run_command("ls", sb).output
        # env не выдаёт реальных ключей/переменных хоста.
        env_out = run_command("env", sb).output
        assert "API_KEY" not in env_out
        assert "agent" in env_out
