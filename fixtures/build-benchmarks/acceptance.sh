#!/usr/bin/env bash
set -euo pipefail
python3 -B ci/scripts/build_benchmarks.py collect
