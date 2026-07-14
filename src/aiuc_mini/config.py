"""Конфигурация прогона (data-model.md §1).

Всё, что влияет на результат прогона, живёт здесь — это половина контракта воспроизводимости
(вторая половина — фиксированный набор атак ``attacks/suite.yaml``).

Инвариант: ``Config`` НЕ хранит секретов провайдера. API-ключи читает сам ``init_chat_model``
из окружения, и они никогда не попадают ни в ``Config``, ни в trace.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    """Настройки одного прогона. Читаются из окружения / ``.env`` с префиксом ``LLM_`` там,
    где это модели, и напрямую для остального."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Модели в формате ``provider:model`` для init_chat_model (см. llm/factory.py).
    target_model: str = Field(
        default="anthropic:claude-haiku-4-5-20251001",
        validation_alias="LLM_TARGET",
    )
    redteam_model: str = Field(
        default="anthropic:claude-haiku-4-5-20251001",
        validation_alias="LLM_REDTEAM",
    )

    # Режим прогона: False = уязвимый (без защиты), True = защищённый (FR-011).
    guardrails_enabled: bool = False

    # Бюджет мутаций на одну атаку (FR-007).
    max_mutations: int = Field(default=2, ge=0)

    # Таймаут одной попытки; при превышении — вердикт ERROR, прогон продолжается (FR-015).
    attempt_timeout_s: float = Field(default=60.0, gt=0)

    # Фиксированный набор атак и корень артефактов.
    suite_path: Path = Path("attacks/suite.yaml")
    runs_dir: Path = Path("runs")
