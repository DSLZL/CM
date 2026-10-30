#!/usr/bin/env bash
set -euo pipefail
python3 -B ci/scripts/review_before_send.py produce
