# Учебный стенд AIUC-1-mini. Всё окружение — внутри контейнера, на хост ничего не ставится.
FROM python:3.12-slim

# uv — быстрый менеджер пакетов; ставим из официального образа.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Сначала только манифесты и lock — слой с зависимостями кешируется отдельно от кода.
COPY pyproject.toml uv.lock README.md LICENSE ./

# Устанавливаем зависимости строго по локу (без самого проекта — код добавится ниже).
RUN uv sync --extra anthropic --no-install-project --frozen

# Код проекта.
COPY src ./src
COPY attacks ./attacks
COPY aiuc1 ./aiuc1
COPY taxonomy ./taxonomy
COPY tests ./tests

# Доустанавливаем сам пакет aiuc-mini в окружение.
RUN uv sync --extra anthropic --frozen

ENTRYPOINT ["uv", "run"]
CMD ["aiuc", "--help"]
