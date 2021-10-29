#!/usr/bin/env bash

[ ! -e "pyproject.toml" ] && exit 1

VER=$(grep '^version' pyproject.toml |cut -d '"' -f2|sed 's/^/v/')
git tag "$VER" && git rev-list -n 1 "$VER" && git tag --list 'v*'|tail -1
