#!/usr/bin/env bash
set -euo pipefail
python3 -B "$CM_SOURCE_DIR/ci/scripts/runtime_sdk.py" produce
