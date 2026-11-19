#!/usr/bin/env bash
# MobileProxy launcher for macOS / Linux. Arguments are passed through, e.g. ./run.sh --proxy-port 8888
set -e
cd "$(dirname "$0")"
if command -v uv >/dev/null 2>&1; then
  exec uv run mobileproxy "$@"
fi
PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
  echo "Python >= 3.12 is required (or install uv: https://docs.astral.sh/uv/)." >&2
  exit 1
fi
if [ ! -x .venv/bin/mobileproxy ] || [ pyproject.toml -nt .venv/.installed ]; then
  "$PY" -m venv .venv
  .venv/bin/python -m pip install -q --upgrade pip
  .venv/bin/python -m pip install -q -e .
  touch .venv/.installed
fi
exec .venv/bin/mobileproxy "$@"
