#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if python3 -m pytest --version >/dev/null 2>&1; then
  python3 -m pytest tests/dynamic_analysis_unit tests/test_dynamic_pipeline.py tests/test_callback_delivery.py -q
else
  VENV="${FATHOM_TEST_VENV:-/tmp/fathom-dynamic-test-venv}"
  if [[ ! -x "$VENV/bin/python" ]]; then
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install pytest
  fi
  "$VENV/bin/python" -m pytest tests/dynamic_analysis_unit tests/test_dynamic_pipeline.py tests/test_callback_delivery.py -q
fi

