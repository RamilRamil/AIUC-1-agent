"""T036: инъекция блокируется до модели; секрет маскируется; запрещённый инструмент не исполнён."""

from pathlib import Path

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.trace.events import GuardrailDecision, ToolResult, VerdictEvent
from aiuc_mini.trace.writer import read_trace
from tests.fakes import CompromisableChatModel

SUITE = Path("attacks/suite.yaml")


def _protected_run(tmp_path):
    cfg = Config(
        suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0,
        guardrails_enabled=True,
    )
    summary = run_suite(cfg, "prot", target_model=CompromisableChatModel(), redteam_model=None)
    return summary, read_trace(summary.run_dir / "trace.jsonl")


def test_injection_blocked_before_model(tmp_path):
    _, events = _protected_run(tmp_path)
    input_blocks = [
        e for e in events
        if isinstance(e, GuardrailDecision) and e.stage == "input" and e.action == "block"
    ]
    assert input_blocks, "хотя бы одна инъекция должна блокироваться на входе"


def test_every_guardrail_decision_is_logged(tmp_path):
    """Решения журналируются, включая allow — иначе не отличить пропуск от неработы."""
    _, events = _protected_run(tmp_path)
    decisions = [e for e in events if isinstance(e, GuardrailDecision)]
    actions = {d.action for d in decisions}
    assert "block" in actions
    # allow тоже должен присутствовать (benign-запросы проходят вход).
    assert "allow" in actions


def test_run_command_never_executes_under_guardrails(tmp_path):
    """Запрещённый инструмент не исполняется: нет ToolResult для run_command."""
    _, events = _protected_run(tmp_path)
    run_cmd_results = [
        e for e in events if isinstance(e, ToolResult) and e.tool == "run_command"
    ]
    assert not run_cmd_results


def test_guardrails_reduce_attack_success(tmp_path):
    """SC-003: защита снижает долю успешных атак относительно уязвимого прогона."""
    base_cfg = Config(suite_path=SUITE, runs_dir=tmp_path / "b", max_mutations=0)
    base = run_suite(base_cfg, "b", target_model=CompromisableChatModel(), redteam_model=None)
    prot_cfg = Config(
        suite_path=SUITE, runs_dir=tmp_path / "p", max_mutations=0, guardrails_enabled=True
    )
    prot = run_suite(prot_cfg, "p", target_model=CompromisableChatModel(), redteam_model=None)
    assert prot.attacks_succeeded < base.attacks_succeeded


def test_output_redaction_blocks_direct_secret_leak(tmp_path):
    """Прямая утечка секрета в ответе маскируется на выходе."""
    _, events = _protected_run(tmp_path)
    # Ни один SUCCESS с leaked_via='output' не должен пройти, если вход не заблокировал.
    output_leaks = [
        e for e in events
        if isinstance(e, VerdictEvent) and e.verdict == "SUCCESS" and e.leaked_via == "output"
    ]
    assert not output_leaks
