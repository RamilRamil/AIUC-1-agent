"""T014: редакция вывода не роняет tool_calls (регресс на латентный баг, research R3).

Раньше `after_model` возвращал `AIMessage(id=msg.id, content=redacted)` — новое сообщение БЕЗ
`tool_calls`. LangGraph заменяет сообщение по id, и вызовы инструментов исчезали. У fake-модели
`content=""` при tool_call, поэтому баг спал. На реальной модели, шлющей текст ВМЕСТЕ с вызовом
(«Сейчас проверю…» + tool_call), редакция снесла бы вызов и сломала цикл агента.

PII-детектор (фича 004) расширяет редакцию с одной канарейки до целого класса → срабатывание
становится почти неизбежным.
"""

from langchain_core.messages import AIMessage

from aiuc_mini.guardrails.output import OutputGuardrail
from aiuc_mini.trace.sink import TraceSink
from aiuc_mini.trace.writer import TraceWriter

SECRET = "AIUC1-CANARY-xyz"


def _guardrail(tmp_path):
    writer = TraceWriter(tmp_path / "run", secret=SECRET)
    sink = TraceSink(writer, run_id="r")
    sink.attempt_id = "a"
    return OutputGuardrail(SECRET, sink), writer


def test_redaction_preserves_tool_calls(tmp_path):
    guard, writer = _guardrail(tmp_path)
    try:
        msg = AIMessage(
            id="m1",
            content="Сейчас отправлю на ivan@example.com",
            tool_calls=[
                {"name": "http_get", "args": {"url": "https://ok"}, "id": "c1", "type": "tool_call"}
            ],
        )
        out = guard.after_model({"messages": [msg]}, None)

        assert out is not None, "PII должна была вызвать редакцию"
        new = out["messages"][0]
        assert new.id == "m1", "перезапись должна идти по тому же id"
        assert "ivan@example.com" not in new.content
        # Ключевое: вызовы инструментов пережили редакцию.
        assert new.tool_calls, "редакция снесла tool_calls — латентный баг вернулся"
        assert new.tool_calls[0]["name"] == "http_get"
        assert new.tool_calls[0]["args"] == {"url": "https://ok"}
    finally:
        writer.close()


def test_secret_redaction_preserves_tool_calls(tmp_path):
    """Тот же инвариант для канареечного секрета."""
    guard, writer = _guardrail(tmp_path)
    try:
        msg = AIMessage(
            id="m2",
            content=f"Готово, секрет {SECRET}",
            tool_calls=[
                {"name": "read_file", "args": {"path": "a"}, "id": "c2", "type": "tool_call"}
            ],
        )
        out = guard.after_model({"messages": [msg]}, None)
        new = out["messages"][0]
        assert SECRET not in new.content
        assert new.tool_calls[0]["name"] == "read_file"
    finally:
        writer.close()


def test_clean_message_is_not_rewritten(tmp_path):
    """Без секрета и PII сообщение не трогаем вовсе."""
    guard, writer = _guardrail(tmp_path)
    try:
        msg = AIMessage(id="m3", content="Всё в порядке, файл прочитан.")
        assert guard.after_model({"messages": [msg]}, None) is None
    finally:
        writer.close()
