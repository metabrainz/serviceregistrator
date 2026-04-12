#!/bin/bash

uv run python -m pytest -v --cov=serviceregistrator tests/
uv run ruff check serviceregistrator tests
uv run ruff format --check serviceregistrator tests
uvx ty check serviceregistrator
