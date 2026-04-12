#!/bin/bash

uv run python -m pytest -v --cov=serviceregistrator tests/
uv run flake8 --show-source --statistics --count
uv run pylint -j0 --exit-zero serviceregistrator tests
