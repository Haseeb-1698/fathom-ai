#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

VENV="${FATHOM_TEST_VENV:-/tmp/fathom-dynamic-test-venv}"
if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
fi

"$VENV/bin/python" -m pip show pytest >/dev/null 2>&1 || "$VENV/bin/python" -m pip install pytest
"$VENV/bin/python" -m pip show coverage >/dev/null 2>&1 || "$VENV/bin/python" -m pip install coverage

"$VENV/bin/python" -m coverage erase
"$VENV/bin/python" -m coverage run \
  --branch \
  --include='*/server/dynamic/*.py,*/server/cape_integration.py' \
  -m pytest tests/dynamic_analysis_unit tests/test_dynamic_pipeline.py tests/test_callback_delivery.py -q
"$VENV/bin/python" -m coverage report -m

