#!/usr/bin/env python3
"""Native PTY mechanism probe; no Codex CLI or business acceptance."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import tty

TOKEN = """CM terminal 中文 "quoted" 'single' ; $(false)""".encode()
READY = b"CM-PTY-READY\n"
DONE = b"CM-PTY-RESULT "


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def child(mode):
    if not all(os.isatty(fd) for fd in (0, 1, 2)):
        print(json.dumps({"status": "rejected", "reason": "not-a-terminal"}), flush=True)
        return 4
    pid = os.getpid()
    sid, group, foreground = os.getsid(0), os.getpgrp(), os.tcgetpgrp(0)
    assert pid == sid == group == foreground
    assert len({os.fstat(fd).st_rdev for fd in (0, 1, 2)}) == 1
    with open("/dev/tty", "rb", buffering=0) as terminal:
        assert os.isatty(terminal.fileno()) and os.tcgetpgrp(terminal.fileno()) == pid
    window = struct.unpack("HHHH", fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))
    assert window == (40, 140, 0, 0)
    original = termios.tcgetattr(0)
    signal.signal(signal.SIGINT, interrupted)
    code = 0
    try:
        tty.setraw(0, when=termios.TCSANOW)
        assert termios.tcgetattr(0)[3] & (termios.ICANON | termios.ECHO | termios.ISIG) == 0
        os.write(1, READY)
        payload = bytearray()
        while len(payload) < len(TOKEN):
            block = os.read(0, len(TOKEN) - len(payload))
            assert block, "Terminal input ended early"
            payload.extend(block)
        assert bytes(payload) == TOKEN, payload
        if mode == "controlled-error":
            raise ValueError("controlled terminal failure")
        assert mode == "input", "Interrupt probe did not receive its signal"
        os.write(1, b"CM-PTY-ECHO " + bytes(payload) + b"\n")
    except ValueError as error:
        assert mode == "controlled-error" and str(error) == "controlled terminal failure"
        code = 19
    except KeyboardInterrupt:
        assert mode == "interrupt"
        code = 130
    finally:
        termios.tcsetattr(0, termios.TCSANOW, original)
        assert termios.tcgetattr(0) == original
    print(DONE.decode() + json.dumps({"status": "pass", "mode": mode, "pid": pid, "session": sid,
        "process_group": group, "foreground_group": foreground, "window": window,
        "controlling_terminal": True, "restored": True, "exit_code": code}), flush=True)
    return code


def receive(master, output, marker):
    deadline = time.monotonic() + 10
    while marker not in output:
        assert time.monotonic() < deadline, "Timed out waiting for native terminal marker: " + repr(marker)
        if select.select([master], [], [], 0.1)[0]:
            block = os.read(master, 65536)
            assert block, "Native terminal output ended early"
            output.extend(block)
            assert len(output) <= 65536, "Native terminal output limit"


def main():
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--child"]
    denied = subprocess.run([*command, "input"], stdin=subprocess.DEVNULL, capture_output=True,
        start_new_session=True, timeout=10, check=False)
    assert denied.returncode == 4 and not denied.stderr
    assert json.loads(denied.stdout) == {"status": "rejected", "reason": "not-a-terminal"}
    cases = []
    for mode, expected_code in (("input", 0), ("controlled-error", 19), ("interrupt", 130)):
        started = time.monotonic()
        master, slave = pty.openpty()
        process = None
        output = bytearray()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
            original = termios.tcgetattr(slave)

            def child_terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)

            process = subprocess.Popen([*command, mode], stdin=slave, stdout=slave, stderr=slave,
                close_fds=True, preexec_fn=child_terminal)
            receive(master, output, READY)
            if mode == "interrupt":
                os.killpg(process.pid, signal.SIGINT)
            else:
                assert os.write(master, TOKEN) == len(TOKEN)
            receive(master, output, DONE)
            receive(master, output, b"}")
            assert process.wait(timeout=10) == expected_code, bytes(output)
            assert termios.tcgetattr(slave) == original, "Child did not restore the shared terminal"
            rows = [json.loads(line.split(DONE, 1)[1]) for line in output.splitlines() if line.startswith(DONE)]
            assert len(rows) == 1
            row = rows[0]
            assert row["status"] == "pass" and row["mode"] == mode and row["exit_code"] == expected_code
            assert row["pid"] == row["session"] == row["process_group"] == row["foreground_group"] == process.pid
            assert row["controlling_terminal"] and row["restored"] and row["window"] == [40, 140, 0, 0]
            if mode == "input":
                assert b"CM-PTY-ECHO " + TOKEN + b"\n" in output
            cases.append({**row, "parent_verified_restoration": True, "elapsed_seconds": round(time.monotonic() - started, 3)})
        finally:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            os.close(master)
            os.close(slave)
    print(json.dumps({"status": "pass", "scope": "native-PTY-mechanism-only", "cases": cases,
        "no_terminal_rejected": True, "unicode_input": True, "codex_cli_or_TUI_acceptance": "not_run"}))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child" and sys.argv[2] in ("input", "controlled-error", "interrupt"):
        raise SystemExit(child(sys.argv[2]))
    if sys.argv[1:]:
        raise SystemExit("Expected no arguments, or the private --child mode")
    main()
