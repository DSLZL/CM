"""Safe live CI progress; detailed product output stays in the evidence files."""
from contextlib import contextmanager
import datetime
from functools import wraps
import inspect
import json
from pathlib import Path
import re
import subprocess
import threading
import time

PREFIX = "CM progress: "


def emit(label, status, started):
    assert re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,160}", label)
    print(PREFIX + json.dumps({"stage": label, "status": status,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)


@contextmanager
def stage(label):
    started = time.monotonic()
    emit(label, "start", started)
    try:
        yield
    except BaseException:
        emit(label, "failed", started)
        raise
    else:
        emit(label, "done", started)


def case(argument=None):
    def decorate(function):
        @wraps(function)
        def measured(*args, **kwargs):
            label = function.__qualname__
            if argument:
                value = inspect.signature(function).bind(*args, **kwargs).arguments[argument]
                label += "/" + (value.name if isinstance(value, Path) else value)
            with stage(label):
                return function(*args, **kwargs)
        return measured
    return decorate


def run(logs, label, command, timeout):
    logfile = logs / (label + ".log")
    stopped = threading.Event()
    started = time.monotonic()

    def relay():
        heartbeat = time.monotonic()
        with logfile.open() as reader:
            while True:
                for line in reader:
                    if not line.startswith(PREFIX):
                        continue
                    record = json.loads(line[len(PREFIX):])
                    assert set(record) == {"stage", "status", "elapsed_seconds", "time_utc"}
                    assert record["status"] in ("start", "done", "failed", "running")
                    assert re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,160}", record["stage"])
                    assert isinstance(record["elapsed_seconds"], (int, float)) and 0 <= record["elapsed_seconds"] < 86400
                    assert isinstance(record["time_utc"], str) and re.fullmatch(r"[0-9T:.+Z-]{1,40}", record["time_utc"])
                    print(line, end="", flush=True)
                if stopped.is_set():
                    return
                if time.monotonic() - heartbeat >= 30:
                    emit(label, "running", started)
                    heartbeat = time.monotonic()
                stopped.wait(0.2)

    emit(label, "start", started)
    result = None
    with logfile.open("w") as stream:
        thread = threading.Thread(target=relay, daemon=True)
        thread.start()
        try:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, close_fds=True, timeout=timeout)
        finally:
            stopped.set()
            thread.join()
            elapsed = round(time.monotonic() - started, 3)
            code = result.returncode if result is not None else None
            emit(label, "done" if code == 0 else "failed", started)
            with (logs / "consumer-phase-results.jsonl").open("a") as phases:
                phases.write(json.dumps({"phase": label, "return_code": code,
                    "elapsed_seconds": elapsed, "log": logfile.name}) + "\n")
        print("CM CI:", label, "return code", result.returncode, "log", logfile.name, flush=True)
        return result


def self_check():
    import contextlib
    import io
    import sys
    import tempfile
    with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()) as output:
        result = run(Path(directory), "progress-self-check", [sys.executable, "-c",
            "print('private product output'); print('CM progress: ' + "
            "__import__('json').dumps(dict(stage='case', status='done', elapsed_seconds=0, time_utc='2026-10-28T00:00:00+00:00')))"], 5)
        assert result.returncode == 0
        assert "private product output" not in output.getvalue()
        assert '"stage": "case"' in output.getvalue()
        assert "private product output" in (Path(directory) / "progress-self-check.log").read_text()
    try:
        with contextlib.redirect_stdout(io.StringIO()) as output, stage("failure-self-check"):
            raise ValueError("private exception detail")
    except ValueError:
        assert '"status": "failed"' in output.getvalue() and "private exception detail" not in output.getvalue()
