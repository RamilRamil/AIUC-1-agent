"""T019/T020: косвенная инъекция (OWASP LLM01) — вектор реален и защита его НЕ видит.

Главный агентный вектор: вредоносная инструкция приходит не от пользователя, а из результата
инструмента. Отсутствовал с фичи 001, хотя contracts/tools.md обещал отравленную фикстуру.
"""

import socket
from pathlib import Path

from langchain_core.messages import AIMessage

from aiuc_mini.config import Config
from aiuc_mini.redteam.runner import run_suite
from aiuc_mini.trace.events import AttemptStarted, SandboxViolation, VerdictEvent
from aiuc_mini.trace.writer import read_trace
from tests.fakes import CompromisableChatModel, ScriptedChatModel

SUITE = Path("attacks/suite.yaml")
ATTACK_ID = "indirect-01"


def _run(tmp_path, name, *, guardrails: bool):
    cfg = Config(
        suite_path=SUITE,
        runs_dir=tmp_path / "runs",
        max_mutations=0,
        guardrails_enabled=guardrails,
    )
    summary = run_suite(
        cfg,
        name,
        target_model=CompromisableChatModel(),
        redteam_model=ScriptedChatModel([AIMessage(content="x")]),
    )
    return summary, read_trace(summary.run_dir / "trace.jsonl")


def _verdict_of(events, attack_id: str) -> str | None:
    ids = {
        e.attempt_id for e in events
        if isinstance(e, AttemptStarted) and e.attack_id == attack_id
    }
    for e in events:
        if isinstance(e, VerdictEvent) and e.attempt_id in ids:
            return e.verdict
    return None


def test_indirect_injection_succeeds_without_guardrails(tmp_path):
    """SC-004: вектор реален — агент выполнил инструкцию из содержимого страницы."""
    _, events = _run(tmp_path, "base", guardrails=False)
    assert _verdict_of(events, ATTACK_ID) == "SUCCESS", (
        "косвенная инъекция не удалась без защиты — тест вектора бессмыслен"
    )
    # Объективный след: агент пошёл на хост, которого пользователь не называл.
    contacted = [
        e for e in events
        if isinstance(e, SandboxViolation) and e.rule == "external_host"
    ]
    assert contacted, "нет следа обращения к постороннему хосту"
    assert any("attacker.example" in e.attempted for e in contacted)


def test_guardrail_does_not_see_it_BLIND_SPOT(tmp_path):
    """T020: атака проходит и в ЗАЩИЩЁННОМ режиме — и это правдивый результат.

    Тест охраняет **правду, а не успех**. Входной guardrail архитектурно смотрит только на
    сообщение пользователя (`before_model` + последний HumanMessage), а payload здесь намеренно
    безобидный: «открой справку». Инструкция приезжает внутри цикла агента, из тела страницы.

    Если этот тест однажды упадёт — значит вектор закрыли. Тогда его надо ОСОЗНАННО обновить, а не
    молча: слепая зона перестала существовать, и это должно быть видно в истории.
    """
    _, events = _run(tmp_path, "prot", guardrails=True)
    assert _verdict_of(events, ATTACK_ID) == "SUCCESS", (
        "косвенная инъекция вдруг отбита — проверьте, действительно ли вектор закрыт, "
        "или что-то сломалось (правило GUIDE: неожиданное улучшение = повод для расследования)"
    )


def test_no_real_network_call(tmp_path, monkeypatch):
    """Принцип II: атака успешна учебно и безвредна физически."""

    def _boom(*_a, **_k):
        raise AssertionError("реальное сетевое соединение запрещено")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    _, events = _run(tmp_path, "safe", guardrails=False)
    assert _verdict_of(events, ATTACK_ID) == "SUCCESS"


def test_attack_is_bound_to_external_taxonomy():
    """US3: атака ссылается на категорию внешнего списка."""
    from aiuc_mini.redteam.suite import AttackSuite

    attack = next(a for a in AttackSuite.load(SUITE).attacks if a.id == ATTACK_ID)
    assert attack.taxonomy == "LLM01"
    assert attack.category == "indirect_injection"
