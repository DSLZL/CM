#!/usr/bin/env python3
"""Real exec_command payload: explicit socket barriers, no timing-based oracle."""
import socket
import sys
from pathlib import Path
import subprocess

with socket.socket(socket.AF_UNIX) as connection:
    connection.connect(sys.argv[1])
    connection.sendall((sys.argv[2] + ":entered\n").encode())
    if connection.recv(1) != b"R":
        raise RuntimeError("Missing explicit tool release")
    connection.sendall((sys.argv[2] + ":exiting\n").encode())
print("cm-real-tool-" + sys.argv[2] + "-ok")
if len(sys.argv) > 3 and sys.argv[3] == "long":
    fixture = Path(sys.argv[1]).parent
    text = fixture / ("rg-" + sys.argv[2] + ".txt")
    text.write_text("CM-RG-REAL-HELPER\n", encoding="utf-8")
    subprocess.run(["/inputs/host/codex-path/rg", "CM-RG-REAL-HELPER", str(text)], check=True)
    (fixture / ("completed-" + sys.argv[2])).write_text("real-command-exit-0\n")
    print("0123456789abcdef" * 1024)
    print("cm-real-tool-" + sys.argv[2] + "-ok")
