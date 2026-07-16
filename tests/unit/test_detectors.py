"""T005/T018: правило секрета в аргументах и PII-детектор.

Границы детекторов — contracts/detectors.md. Тесты фиксируют не только что ловится, но и что
НЕ ловится: обход кодированием — реальная возможность, стенд не делает вид, что её закрывает.
"""

import pytest

from aiuc_mini.guardrails.policy import GuardrailPolicy
from aiuc_mini.pii import PII_MASK, find_pii, redact_pii
from aiuc_mini.trace.events import AgentResponse
from aiuc_mini.trace.writer import TraceWriter, read_trace

SECRET = "AIUC1-CANARY-abc123"


# --- правило секрета в аргументах ---


@pytest.mark.parametrize(
    "args",
    [
        {"url": f"https://x/?d={SECRET}"},
        {"path": "a", "content": f"note {SECRET}"},
        {"nested": {"deep": [f"{SECRET}"]}},
        {"items": ["ok", {"k": f"x{SECRET}y"}]},
    ],
)
def test_secret_found_in_args(args):
    assert GuardrailPolicy().secret_in_args(args, SECRET)


@pytest.mark.parametrize(
    "args",
    [
        {"url": "https://ok.example"},
        {"path": "readme.txt"},
        {"nested": {"deep": ["ничего интересного"]}},
        {},
    ],
)
def test_no_false_positive_without_secret(args):
    """FR-003: вызовы без секрета не блокируются."""
    assert not GuardrailPolicy().secret_in_args(args, SECRET)


def test_empty_secret_never_matches():
    assert not GuardrailPolicy().secret_in_args({"url": "x"}, "")


def test_encoded_secret_is_not_caught_documented_limit():
    """Граница (contracts/detectors.md): кодированный секрет НЕ ловится.

    Это не дефект, а свойство метода — точное сравнение подстроки. Тест фиксирует границу, чтобы
    она была явной, а не обнаружилась однажды в проде.
    """
    import base64

    encoded = base64.b64encode(SECRET.encode()).decode()
    assert not GuardrailPolicy().secret_in_args({"url": f"?d={encoded}"}, SECRET)


# --- PII-детектор ---


@pytest.mark.parametrize(
    "text,expected",
    [
        ("напишите на ivan@example.com", ["email"]),
        ("карта 4276 1600 1234 5678", ["card"]),
        ("телефон +7 999 123-45-67", ["phone"]),
    ],
)
def test_pii_detected(text, expected):
    assert find_pii(text) == expected


def test_pii_redacted():
    text = "почта ivan@example.com, карта 4276160012345678"
    redacted, changed = redact_pii(text)
    assert changed
    assert "ivan@example.com" not in redacted
    assert "4276160012345678" not in redacted
    assert PII_MASK in redacted


def test_text_without_pii_unchanged():
    """FR-006: ложные срабатывания ломали бы benign-задачи."""
    text = "Прочитал файл readme.txt, всё в порядке. Статус 200, версия 1.0.0."
    redacted, changed = redact_pii(text)
    assert not changed
    assert redacted == text


def test_pii_masked_in_trace(tmp_path):
    """FR-005: журнал не должен быть каналом утечки — даже без guardrail."""
    with TraceWriter(tmp_path / "run", secret=SECRET) as w:
        w.emit(AgentResponse(content="контакт: ivan@example.com, карта 4276160012345678"))

    raw = (tmp_path / "run" / "trace.jsonl").read_text(encoding="utf-8")
    assert "ivan@example.com" not in raw
    assert "4276160012345678" not in raw
    assert PII_MASK in raw

    events = read_trace(tmp_path / "run" / "trace.jsonl")
    assert not find_pii(events[0].content)
