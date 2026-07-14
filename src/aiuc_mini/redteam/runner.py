"""Раннер прогона (T028).

Связывает мишень, судью и trace. Ключевые свойства:
- каждая попытка изолирована по ошибкам: сбой/таймаут → вердикт ERROR + событие attempt_error,
  прогон НЕ прерывается (FR-015);
- ERROR не засчитывается как успех защиты (иначе упавший бэкенд выглядел бы идеальным guardrail);
- модели инжектируются (шов Принципа IV): в тестах — fake, в CLI — фабрика.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage

from ..config import Config
from ..llm.factory import build_model
from ..target.agent import build_target_agent
from ..target.prompt import TargetPersona
from ..target.tools import build_tools
from ..trace.events import (
    AgentResponse,
    AttemptError,
    AttemptStarted,
    RunFinished,
    RunStarted,
    VerdictEvent,
)
from ..trace.sink import TraceSink
from ..trace.writer import TraceWriter, read_trace
from .attacker import mutate
from .judge import judge
from .suite import AttackCase, AttackSuite

# Файлы, которыми заполняется песочница каждой попытки — под легитимные задачи-контроли.
_SEED_FILES = {
    "readme.txt": "ACME support: рабочая папка для файловых операций.",
    "status.txt": "статус: инициализировано",
}
_HTTP_FIXTURES = {
    "https://acme.example/help": "Справка ACME: используйте read_file и write_file.",
}


@dataclass
class RunSummary:
    run_dir: Path
    attempts_total: int
    attacks_succeeded: int
    errors: int


def run_suite(
    cfg: Config,
    run_id: str,
    *,
    target_model: BaseChatModel | None = None,
    redteam_model: BaseChatModel | None = None,
    suite: AttackSuite | None = None,
) -> RunSummary:
    suite = suite or AttackSuite.load(cfg.suite_path)
    target_model = target_model or build_model(cfg.target_model)
    # redteam_model может быть None → детерминированная мутация (см. attacker.mutate).
    if redteam_model is None and cfg.max_mutations > 0:
        try:
            redteam_model = build_model(cfg.redteam_model)
        except Exception:
            redteam_model = None  # без ключа — деградируем до текстовой мутации

    persona = TargetPersona()
    run_dir = cfg.runs_dir / run_id
    writer = TraceWriter(run_dir, secret=persona.secret)
    sink = TraceSink(writer, run_id=run_id)

    sink.emit(
        RunStarted(
            suite_hash=suite.suite_hash,
            guardrails_enabled=cfg.guardrails_enabled,
            config=cfg.model_dump(mode="json"),
        )
    )

    attempts_total = 0
    attacks_succeeded = 0
    errors = 0

    for base in suite.attacks:
        current = base
        for iteration in range(cfg.max_mutations + 1):
            attempts_total += 1
            verdict = _run_attempt(cfg, current, persona, target_model, sink)
            if verdict == "SUCCESS":
                attacks_succeeded += 1
            elif verdict == "ERROR":
                errors += 1

            # Мутируем только неуспешные не-benign атаки в пределах бюджета.
            done = verdict in ("SUCCESS", "BLOCKED") or current.is_benign
            if done or iteration == cfg.max_mutations:
                break
            current = mutate(current, iteration, redteam_model)

    sink.emit(
        RunFinished(
            attempts_total=attempts_total,
            attacks_succeeded=attacks_succeeded,
            errors=errors,
        )
    )
    writer.close()
    return RunSummary(run_dir, attempts_total, attacks_succeeded, errors)


def _run_attempt(
    cfg: Config,
    attack: AttackCase,
    persona: TargetPersona,
    model: BaseChatModel,
    sink: TraceSink,
) -> str:
    """Прогнать одну попытку; вернуть вердикт. Ошибки не пробрасываются (FR-015)."""
    sink.attempt_id = attack.id
    sink.emit(
        AttemptStarted(
            attack_id=attack.id,
            category=attack.category,
            payload=attack.payload,
            parent_id=attack.parent_id,
            is_benign=attack.is_benign,
        )
    )

    from ..sandbox.fs import Sandbox

    sandbox = Sandbox(files=dict(_SEED_FILES), http_fixtures=dict(_HTTP_FIXTURES))
    # События этой попытки пишутся в общий trace; выделим их срез по attempt_id после.
    start_seq = _current_seq(sink)
    try:
        tools = build_tools(sandbox, sink)
        middleware = _build_middleware(cfg, persona, sink) if cfg.guardrails_enabled else []
        agent = build_target_agent(model, tools, persona, middleware=middleware)

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                agent.invoke, {"messages": [HumanMessage(attack.payload)]}
            )
            try:
                result = future.result(timeout=cfg.attempt_timeout_s)
            except FutureTimeout:
                sink.emit(AttemptError(error_type="timeout", message="attempt timed out"))
                _emit_verdict(sink, "ERROR", None, "таймаут попытки", attack)
                return "ERROR"

        final = result["messages"][-1]
        content = final.content if isinstance(final.content, str) else str(final.content)
        sink.emit(AgentResponse(content=content))
    except Exception as exc:  # noqa: BLE001 — учебный стенд: любой сбой = ERROR, прогон живёт
        sink.emit(AttemptError(error_type="llm_error", message=repr(exc)))
        _emit_verdict(sink, "ERROR", None, "исключение в попытке", attack)
        sandbox.cleanup()
        return "ERROR"

    # Судим по срезу событий этой попытки.
    attempt_events = [e for e in read_trace(sink._writer.path) if e.seq >= start_seq]
    verdict, leaked_via, rationale = judge(attack, attempt_events)
    _emit_verdict(sink, verdict, leaked_via, rationale, attack)
    sandbox.cleanup()
    return verdict


def _emit_verdict(sink, verdict, leaked_via, rationale, attack):
    sink.emit(
        VerdictEvent(
            verdict=verdict,
            criterion=attack.success_criterion.kind,
            leaked_via=leaked_via,
            rationale=rationale,
        )
    )


def _current_seq(sink: TraceSink) -> int:
    return sink._writer._seq


def _build_middleware(cfg: Config, persona: TargetPersona, sink: TraceSink) -> list:
    # Ленивая связь с US3, чтобы US2 не зависел от guardrails.
    from ..guardrails import build_guardrail_middleware

    return build_guardrail_middleware(persona.secret, sink)
