#!/usr/bin/env python3
"""Real exec_command payload: explicit socket barriers, no timing-based oracle."""
import socket
import sys

with socket.socket(socket.AF_UNIX) as connection:
    connection.connect(sys.argv[1])
    connection.sendall((sys.argv[2] + ":entered\n").encode())
    if connection.recv(1) != b"R":
        raise RuntimeError("Missing explicit tool release")
    connection.sendall((sys.argv[2] + ":exiting\n").encode())
print("cm-real-tool-" + sys.argv[2] + "-ok")
