"""T021 / SC-005: данные одной попытки недоступны другой (A005).

Свойство обеспечено песочницей (новая на каждую попытку) с фичи 001, но до фичи 004 нигде не
проверялось — а непроверяемое свойство имеет обыкновение тихо ломаться.
"""

from pathlib import Path

from langchain_core.messages import AIMessage

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.sandbox.fs import Sandbox
from aiuc_mini.scorecard.render import build_scorecard
from aiuc_mini.trace.writer import read_trace
from tests.fakes import CompromisableChatModel, ScriptedChatModel

SUITE = Path("attacks/suite.yaml")


def test_sandboxes_are_separate_per_attempt():
    """Прямая проверка свойства: две песочницы не видят файлов друг друга."""
    with Sandbox() as a, Sandbox() as b:
        a.write_file("secret_note.txt", "данные попытки A")
        assert a.root != b.root
        assert "secret_note.txt" not in b.list_dir(".")


def test_written_data_not_visible_to_next_attempt(tmp_path):
    """FR-007: файл, записанный в одной попытке, недоступен в следующей."""
    cfg = Config(
        suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0, guardrails_enabled=False
    )
    summary = run_suite(
        cfg,
        "iso",
        target_model=CompromisableChatModel(),
        redteam_model=ScriptedChatModel([AIMessage(content="x")]),
    )
    events = read_trace(summary.run_dir / "trace.jsonl")

    # benign-02 пишет status.txt. Ни одна другая попытка не должна прочитать записанное им.
    card = build_scorecard(summary.run_dir)
    priv_03 = next(c for c in card.pillars["data_privacy"] if c.id == "PRIV-03")
    assert priv_03.status == "pass", f"изоляция нарушена: {priv_03.rationale}"
    assert events, "trace пуст"


def test_isolation_control_is_in_scorecard(tmp_path):
    """FR-008: A005 виден в отчёте, а не только в тесте."""
    cfg = Config(suite_path=SUITE, runs_dir=tmp_path / "runs", max_mutations=0)
    summary = run_suite(
        cfg,
        "iso2",
        target_model=CompromisableChatModel(),
        redteam_model=ScriptedChatModel([AIMessage(content="x")]),
    )
    card = build_scorecard(summary.run_dir)
    ids = {c.id for c in card.pillars["data_privacy"]}
    assert "PRIV-03" in ids, "контроль изоляции отсутствует в scorecard"
