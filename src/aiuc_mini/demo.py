"""Полный учебный сценарий одной командой (T046, SC-001).

Прогон без защиты → прогон с защитой → два scorecard'а → сравнение. Модели берутся из
конфигурации (реальный LLM); для тестов demo-логика разбита так, чтобы её части
(``run_suite``, ``render_run``, ``compare_runs``) вызывались и с fake-моделями.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer

from .config import Config
from .redteam.runner import run_suite
from .scorecard.compare import compare_runs
from .scorecard.render import render_run


def _run_id(prefix: str) -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + f"-{prefix}"


def run_demo(suite: Path) -> tuple[Path, Path]:
    base_cfg = Config(suite_path=suite, guardrails_enabled=False)
    prot_cfg = Config(suite_path=suite, guardrails_enabled=True)

    base = run_suite(base_cfg, _run_id("baseline"))
    prot = run_suite(prot_cfg, _run_id("protected"))

    render_run(base.run_dir)
    render_run(prot.run_dir)

    typer.echo(f"Прогон без защиты:  {base.run_dir}")
    typer.echo(f"Прогон с защитой:   {prot.run_dir}")
    typer.echo("")
    typer.echo(compare_runs(base.run_dir, prot.run_dir))
    return base.run_dir, prot.run_dir
