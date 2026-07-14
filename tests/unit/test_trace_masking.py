"""T010: журнал не становится каналом утечки; seq строго возрастает."""

from aiuc_mini.trace.events import AgentResponse, ToolCall, VerdictEvent
from aiuc_mini.trace.writer import MASK, TraceWriter, read_trace

SECRET = "AIUC1-CANARY-abc123"


def test_secret_is_masked_in_all_events(tmp_path):
    with TraceWriter(tmp_path / "run", secret=SECRET) as w:
        w.emit(AgentResponse(run_id="r", seq=0, content=f"вот секрет: {SECRET}"))
        w.emit(ToolCall(run_id="r", seq=0, tool="http_get", args={"url": f"x?d={SECRET}"}))

    raw = (tmp_path / "run" / "trace.jsonl").read_text(encoding="utf-8")
    assert SECRET not in raw
    assert MASK in raw


def test_verdict_leaked_via_channel_is_preserved(tmp_path):
    """leaked_via хранит канал, не значение — маскирование его не ломает."""
    with TraceWriter(tmp_path / "run", secret=SECRET) as w:
        w.emit(
            VerdictEvent(
                run_id="r",
                seq=0,
                verdict="SUCCESS",
                criterion="canary_in_tool_args",
                leaked_via="tool_args",
            )
        )
    events = read_trace(tmp_path / "run" / "trace.jsonl")
    assert events[0].leaked_via == "tool_args"


def test_seq_is_monotonic(tmp_path):
    with TraceWriter(tmp_path / "run", secret=SECRET) as w:
        for _ in range(5):
            w.emit(AgentResponse(run_id="r", seq=999, content="x"))
    events = read_trace(tmp_path / "run" / "trace.jsonl")
    assert [e.seq for e in events] == [0, 1, 2, 3, 4]
