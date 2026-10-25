#!/usr/bin/env python3
"""Real exec_command payload: explicit file barriers, no timing-based oracle."""
import sys
from pathlib import Path
import subprocess
import time

barriers, label = Path(sys.argv[1]), sys.argv[2]
assert label in ("A", "B")
(barriers / (label + ".entered")).touch(exist_ok=False)
deadline = time.monotonic() + 45
while not (barriers / (label + ".release")).exists():
    if time.monotonic() >= deadline:
        raise TimeoutError("Missing explicit tool release")
    time.sleep(0.01)
(barriers / (label + ".exiting")).touch(exist_ok=False)
print("cm-real-tool-" + sys.argv[2] + "-ok")
if len(sys.argv) > 3 and sys.argv[3] == "long":
    fixture = Path(sys.argv[1]).parent
    text = fixture / ("rg-" + sys.argv[2] + ".txt")
    text.write_text("CM-RG-REAL-HELPER\n", encoding="utf-8")
    subprocess.run(["/inputs/host/codex-path/rg", "CM-RG-REAL-HELPER", str(text)], check=True)
    (fixture / ("completed-" + sys.argv[2])).write_text("real-command-exit-0\n")
    # Fit the upstream model cap while exceeding the fixture Mod's 256-token budget.
    print("0123456789abcdef" * 256)
    print("cm-real-tool-" + sys.argv[2] + "-ok")
