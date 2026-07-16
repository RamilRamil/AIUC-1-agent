"""T007 / FR-010: «запрещённый инструмент» определён ровно в одном месте.

Раньше определение жило тремя копиями (политика guardrail, судья, контроли scorecard). Копии
разъехались бы тихо: судья считал бы успехом то, что политика уже разрешила.
"""

import ast
from pathlib import Path

from aiuc_mini.guardrails.policy import GuardrailPolicy
from aiuc_mini.redteam.judge import is_forbidden_tool
from aiuc_mini.scorecard.controls import FORBIDDEN_TOOLS as CONTROLS_FORBIDDEN
from aiuc_mini.target.tools import ALL_TOOLS, ALLOWED_TOOLS, FORBIDDEN_TOOLS

_SRC = Path(__file__).resolve().parents[2] / "src" / "aiuc_mini"


def test_definition_exists_only_in_target_tools():
    """Литеральное определение множества запрещённых инструментов — только в target/tools.py."""
    definers: list[str] = []
    for path in _SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            # Ищем присваивание FORBIDDEN_TOOLS = <литерал>, а не импорт.
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                if any("FORBIDDEN_TOOLS" in t for t in targets):
                    definers.append(str(path.relative_to(_SRC)))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if "FORBIDDEN_TOOLS" in node.target.id:
                    definers.append(str(path.relative_to(_SRC)))
    assert definers == ["target/tools.py"], f"определение должно быть одно, найдено: {definers}"


def test_all_consumers_agree():
    """Политика, судья и контроли читают одно и то же определение."""
    policy = GuardrailPolicy()
    for tool in FORBIDDEN_TOOLS:
        assert is_forbidden_tool(tool), f"судья не считает {tool} запрещённым"
        assert not policy.tool_allowed(tool), f"политика разрешает запрещённый {tool}"
    assert CONTROLS_FORBIDDEN is FORBIDDEN_TOOLS


def test_allowlist_is_derived_not_duplicated():
    """Allow-list = все инструменты минус запрещённые (не отдельный список)."""
    assert ALLOWED_TOOLS == ALL_TOOLS - FORBIDDEN_TOOLS
    policy = GuardrailPolicy()
    assert policy.tool_allowlist == set(ALLOWED_TOOLS)
