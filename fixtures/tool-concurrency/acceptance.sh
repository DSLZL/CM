#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
  python3 -B ci/scripts/tool_concurrency.py produce
else
  python3 -B fixtures/tool-concurrency/driver.py "$@"
fi
