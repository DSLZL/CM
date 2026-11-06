#!/usr/bin/env bash
set -euo pipefail
exec python3 -B ci/scripts/runtime_consumer.py produce
