"""CLI стенда (contracts/cli.md).

На фазе US1 реализована заготовка ``run`` — она поднимает мишень и пишет trace. Полный прогон
набора атак, guardrail, scorecard и demo добавляются в US2–US4.
"""

from __future__ import annotations

from datetime import UTC, datetime

import typer

app = typer.Typer(
    add_completion=False,
    help="AIUC-1 в миниатюре — учебный стенд «атака → защита → аудит».",
)


def _new_run_id(prefix: str) -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + f"-{prefix}"


@app.command()
def run(
    guardrails: bool = typer.Option(
        False, "--guardrails/--no-guardrails", help="Защищённый или уязвимый режим."
    ),
    suite: str = typer.Option("attacks/suite.yaml", help="Файл набора атак."),
    max_mutations: int = typer.Option(2, help="Бюджет мутаций на атаку."),
    attempt_timeout: float = typer.Option(60.0, help="Таймаут одной попытки, с."),
    out: str = typer.Option("runs", help="Корень артефактов."),
) -> None:
    """Прогнать набор атак против мишени и записать trace (US2 наполнит логику прогона)."""
    from pathlib import Path

    from .config import Config
    from .redteam.runner import run_suite

    cfg = Config(
        guardrails_enabled=guardrails,
        max_mutations=max_mutations,
        attempt_timeout_s=attempt_timeout,
        suite_path=Path(suite),
        runs_dir=Path(out),
    )
    prefix = "protected" if guardrails else "baseline"
    run_id = _new_run_id(prefix)
    summary = run_suite(cfg, run_id)
    typer.echo(f"trace: {summary.run_dir / 'trace.jsonl'}")
    typer.echo(
        f"попыток: {summary.attempts_total}  успешных атак: {summary.attacks_succeeded}  "
        f"ошибок: {summary.errors}"
    )


@app.command()
def score(run_dir: str, format: str = typer.Option("both", help="md|json|both")) -> None:
    """Построить scorecard по существующему trace (US4)."""
    from pathlib import Path

    from .scorecard.render import render_run

    paths = render_run(Path(run_dir), fmt=format)
    for p in paths:
        typer.echo(f"scorecard: {p}")


@app.command()
def compare(baseline_dir: str, protected_dir: str) -> None:
    """Сравнить два прогона (US3)."""
    from pathlib import Path

    from .scorecard.compare import compare_runs

    typer.echo(compare_runs(Path(baseline_dir), Path(protected_dir)))


@app.command()
def demo(suite: str = typer.Option("attacks/suite.yaml", help="Файл набора атак.")) -> None:
    """Полный учебный сценарий одной командой (US4)."""
    from pathlib import Path

    from .demo import run_demo

    run_demo(Path(suite))


@app.command()
def coverage(
    catalog: str = typer.Option("aiuc1/catalog.yaml", help="Файл каталога контролей AIUC-1."),
    out: str = typer.Option("docs/aiuc1-coverage.md", help="Куда записать карту."),
) -> None:
    """Построить карту покрытия AIUC-1 из каталога (фича 002)."""
    from pathlib import Path

    from .aiuc1.catalog import Catalog, aggregate
    from .aiuc1.render import render_to_file

    cat = Catalog.load(Path(catalog))
    agg = aggregate(cat)
    active = sum(agg.by_status.values())
    typer.echo(f"AIUC-1 coverage (version {cat.version})")
    typer.echo(
        f"  всего {len(cat.controls)} (активных {active}, retired {agg.retired_count})"
    )
    typer.echo(
        f"  covered {agg.by_status['covered']} / achievable "
        f"{agg.by_status['technical_achievable']} / doc-only {agg.by_status['doc_only']}"
        f"  (partial {agg.partial_count})"
    )
    _letter = {
        "data_privacy": "A", "security": "B", "safety": "C",
        "reliability": "D", "accountability": "E", "society": "F",
    }
    pillars = "  ".join(f"{_letter[k]} {v}" for k, v in agg.by_pillar.items())
    typer.echo(f"  по пиллерам (активные): {pillars}")
    path = render_to_file(cat, Path(out))
    typer.echo(f"Карта: {path}")


if __name__ == "__main__":
    app()
