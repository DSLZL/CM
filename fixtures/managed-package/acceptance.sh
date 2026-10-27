#!/usr/bin/env bash
set -euo pipefail
python3 -B "$CM_SOURCE_DIR/ci/scripts/managed_package.py" produce
