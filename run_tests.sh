#!/usr/bin/env bash
# Usage: ./run_tests.sh [unit|integration|all]     (default: all)   No AWS account, no cost.
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements-dev.txt
case "${1:-all}" in
  unit)        pytest tests/unit ;;
  integration) pytest tests/integration ;;
  all)         pytest tests/unit && pytest tests/integration ;;
  *) echo "usage: $0 [unit|integration|all]"; exit 2 ;;
esac
