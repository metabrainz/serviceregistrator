FROM python:3.8-slim-buster

ENV \
  # python:
  PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PYTHONDONTWRITEBYTECODE=1 \
  # pip:
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  # poetry:
  POETRY_VERSION=1.4.2 \
  POETRY_NO_INTERACTION=1 \
  POETRY_VIRTUALENVS_CREATE=false \
  POETRY_CACHE_DIR='/var/cache/pypoetry' \
  PATH="$PATH:/root/.local/bin"

# System deps:
RUN apt-get update \
  && apt-get install --no-install-recommends -y \
    bash \
    curl \
  # Cleaning cache:
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Installing `poetry` package manager:
# https://github.com/python-poetry/poetry
RUN curl -sSL https://install.python-poetry.org | python - \
  && poetry --version

WORKDIR /code
COPY . /code/

RUN poetry install --no-interaction --no-ansi --only main

ENTRYPOINT ["serviceregistrator"]
