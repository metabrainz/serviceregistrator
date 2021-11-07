#!/bin/bash

poetry run python -m pytest -v --cov=serviceregistrator tests/
poetry run flake8 --show-source --statistics --count
poetry run pylint -j0 --exit-zero serviceregistrator tests
