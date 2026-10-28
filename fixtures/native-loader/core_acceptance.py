"""Packaged CLI -> real Core -> builtin exec_command. Actions worker only."""
import gzip
import hashlib
import http.server
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import threading
import time

import ci_progress

_INPUT_ROOT = None
_INPUT_DIGESTS = {}
_INPUT_DIGEST_STATS = {"computed": 0, "reused": 0, "hashed_bytes": 0, "avoided_bytes": 0}


def enable_input_digest_cache():
    global _INPUT_ROOT
    assert os.statvfs("/inputs").f_flag & os.ST_RDONLY, "Digest reuse requires a read-only input mount"
    _INPUT_ROOT = Path("/inputs")


def input_digest_stats():
    return {"read_only_root": str(_INPUT_ROOT) if _INPUT_ROOT is not None else None, **_INPUT_DIGEST_STATS}


def input_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def sha(path):
    readonly = _INPUT_ROOT is not None and path.is_relative_to(_INPUT_ROOT) and path.resolve().is_relative_to(_INPUT_ROOT)
    stamp = input_stamp(path.stat()) if readonly else None
    # Only verified read-only inputs reuse digests; writable state and the outer final audit always rehash.
    if readonly and stamp in _INPUT_DIGESTS:
        _INPUT_DIGEST_STATS["reused"] += 1
        _INPUT_DIGEST_STATS["avoided_bytes"] += stamp[3]
        return _INPUT_DIGESTS[stamp]
    with path.open("rb") as stream:
        value = hashlib.file_digest(stream, "sha256").hexdigest()
    if readonly:
        assert input_stamp(path.stat()) == stamp, "Read-only input changed while hashing"
        _INPUT_DIGESTS[stamp] = value
        _INPUT_DIGEST_STATS["computed"] += 1
        _INPUT_DIGEST_STATS["hashed_bytes"] += stamp[3]
    return value


def check_input_digest_cache():
    import tempfile
    import types
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        inputs = root / "inputs"
        inputs.mkdir()
        payload, writable = inputs / "payload", root / "writable"
        payload.write_bytes(b"before")
        writable.write_bytes(b"mutable")
        (inputs / "alias").symlink_to("payload")
        (inputs / "escape").symlink_to(writable)
        with patch.dict(globals(), _INPUT_ROOT=inputs, _INPUT_DIGESTS={},
                _INPUT_DIGEST_STATS={key: 0 for key in _INPUT_DIGEST_STATS}), \
                patch.object(hashlib, "file_digest", wraps=hashlib.file_digest) as hashes:
            original = sha(payload)
            assert sha(inputs / "alias") == original and hashes.call_count == 1
            before = payload.stat()
            payload.write_bytes(b"after!")
            os.utime(payload, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert sha(payload) != original and hashes.call_count == 2
            sha(writable)
            sha(writable)
            sha(inputs / "escape")
            sha(inputs / "escape")
            assert hashes.call_count == 6, "Writable or escaping inputs reused a digest"
            with patch.object(os, "statvfs", return_value=types.SimpleNamespace(f_flag=0)):
                try:
                    enable_input_digest_cache()
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Writable input mount enabled digest reuse")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def trace_rows(path, *, waiting=False):
    if not path.exists():
        return []
    # Only a newline completes a record; a nested object can end with a brace.
    lines = path.read_bytes().split(b"\n")
    if lines[-1] and not waiting:
        raise ValueError("Unterminated runtime trace record: " + str(path))
    return [json.loads(line) for line in lines[:-1]]


def await_barrier(predicate, process, label, timeout=30):
    deadline = time.monotonic() + timeout
    while not predicate():
        if process.poll() is not None:
            raise RuntimeError("CLI exited before barrier: " + label)
        if time.monotonic() >= deadline:
            raise TimeoutError("Missing explicit barrier: " + label)
        # Polling detects an event; elapsed time/absence is never a success oracle.
        threading.Event().wait(0.01)


class Tools:
    def __init__(self, path):
        self.path = path
        self.condition = threading.Condition()
        self.events = []
        self.error = None
        self.path.mkdir()
        self.closed = False
        self.thread = threading.Thread(target=self.watch, daemon=True)
        self.thread.start()

    def record(self, label):
        with self.condition:
            self.events.append({"seq": len(self.events) + 1, "event": label})
            self.condition.notify_all()

    def watch(self):
        try:
            while not self.closed:
                for marker in sorted(self.path.iterdir()):
                    label, _, event = marker.name.partition(".")
                    assert label in ("A", "B") and event in ("entered", "release", "exiting"), marker
                    assert not marker.is_symlink() and marker.is_file() and marker.stat().st_size == 0, marker
                    if event != "release" and not self.has(label + ":" + event):
                        if event == "exiting":
                            assert self.has(label + ":entered") and self.has(label + ":release")
                        self.record(label + ":" + event)
                threading.Event().wait(0.01)
        except Exception as error:
            with self.condition:
                self.error = repr(error)
                self.condition.notify_all()

    def has(self, label):
        with self.condition:
            return any(event["event"] == label for event in self.events)

    def release(self, label):
        with self.condition:
            assert self.has(label + ":entered")
            self.record(label + ":release")
            (self.path / (label + ".release")).touch(exist_ok=False)

    def close(self):
        self.closed = True
        self.thread.join(timeout=2)


def decode_request(handler):
    body = handler.rfile.read(int(handler.headers["Content-Length"]))
    encoding = handler.headers.get("Content-Encoding", "")
    if encoding == "gzip":
        body = gzip.decompress(body)
    elif encoding:
        raise RuntimeError("Unsupported fixture HTTP request encoding: " + encoding)
    return json.loads(body)


def cli_arguments(binary, cwd, endpoint, sandboxed=False):
    return [str(binary), "-c", 'model_provider="cm_fixture"',
            "-c", 'model_providers.cm_fixture.name="CM local fixture"',
            "-c", "model_providers.cm_fixture.base_url=" + json.dumps(endpoint + "/v1"),
            "-c", 'model_providers.cm_fixture.wire_api="responses"',
            "-c", "model_providers.cm_fixture.requires_openai_auth=false",
            "-c", "model_providers.cm_fixture.supports_websockets=false",
            "-c", "features.code_mode=false", "-c", "features.code_mode_only=false",
            "-c", "features.unified_exec=true", "-c", "features.shell_snapshot=false",
            "-c", "features.plugins=false", "-c", "features.apps=false", "-c", "analytics.enabled=false",
            *(["-c", 'approval_policy="never"'] if sandboxed else []),
            "exec", "--skip-git-repo-check", "--ephemeral", "--json",
            *(["--sandbox", "workspace-write"] if sandboxed else
              ["--dangerously-bypass-approvals-and-sandbox"]), "-C", str(cwd),
            "-m", "gpt-5.4", "CM deterministic local acceptance"]


@ci_progress.case("directory")
def run_case(root, directory, binary, home, mod_loaded, scenario="parallel", mode="",
             extra_env=None, command_prefix=(), expected_releases=1, restrictive=None,
             sandboxed=False, long_output=False, requested_limit=None, cm_options=()):
    assert os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
    restrictive = mod_loaded if restrictive is None else restrictive
    directory.mkdir(parents=True)
    trace = directory / "core-trace.jsonl"
    tools = Tools(directory / "tool-barriers")
    requests = []
    errors = []
    process_ref = []
    initial_response_sent = threading.Event()

    def call(label):
        command = shlex.join(["python3", "-B", str(root / "fixtures/native-loader/tool_barrier.py"),
                              str(tools.path), label, *(["long"] if long_output else [])])
        return {"type": "response.output_item.done", "item": {
            "type": "function_call", "call_id": "cm-" + label.lower(),
            "name": "exec_command", "arguments": json.dumps({
                "cmd": command, "login": False, "yield_time_ms": 30000, "timeout_ms": 60000,
                **({"max_output_tokens": requested_limit} if requested_limit is not None else {}),
            })}}

    class Provider(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                request = decode_request(self)
                outputs = [item for item in request.get("input", [])
                           if item.get("type") == "function_call_output" and item.get("call_id") in ("cm-a", "cm-b")]
                requests.append({"path": self.path, "outputs": outputs,
                                 "tools": request.get("tools"), "parallel_tool_calls": request.get("parallel_tool_calls")})
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()

                def send(event):
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                    self.wfile.flush()

                send({"type": "response.created", "response": {"id": "cm-response-" + str(len(requests))}})
                if len(requests) == 1:
                    send(call("A"))
                    if scenario in ("parallel", "cancel-waiting"):
                        deadline = time.monotonic() + 30
                        with tools.condition:
                            if not tools.condition.wait_for(lambda: tools.has("A:entered"),
                                                            max(0, deadline - time.monotonic())):
                                raise TimeoutError("A did not actually enter during streamed tool dispatch")
                        send(call("B"))
                else:
                    expected = {"cm-a", "cm-b"}
                    if not expected <= {item["call_id"] for item in outputs}:
                        raise AssertionError("Real Core tool results did not reach the next provider request")
                    encoded = json.dumps(outputs)
                    if (requested_limit is None or requested_limit > 32) and not all("cm-real-tool-" + label + "-ok" in encoded for label in ("A", "B")):
                        raise AssertionError("Expected actual tool outputs are missing")
                    send({"type": "response.output_item.done", "item": {
                        "type": "message", "id": "cm-final", "role": "assistant",
                        "content": [{"type": "output_text", "text": "CM fixture complete"}]}})
                send({"type": "response.completed", "response": {"id": "cm-response-" + str(len(requests)),
                      "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}})
                if len(requests) == 1:
                    initial_response_sent.set()
                self.close_connection = True
            except Exception as error:
                errors.append(repr(error))
                self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    endpoint = "http://127.0.0.1:" + str(server.server_port)
    assert all(key.startswith("CM_") for key in (extra_env or {}))
    # The process helper transfers its environment over an observed socket; never inherit CI credentials.
    inherited = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR") if key in os.environ}
    env = {**inherited, "CODEX_HOME": str(home), "CODEX_SQLITE_HOME": str(home),
           "HOME": str(directory / "home"), "CM_NATIVE_TRACE": str(trace),
           "CM_FIXTURE_MODE": mode, "CM_FIXTURE_EVENTS": str(directory / "mod-events.jsonl"),
           "CODEX_API_KEY": "cm-controlled-fixture-only", "OPENAI_API_KEY": "cm-controlled-fixture-only",
           **(extra_env or {})}
    Path(env["HOME"]).mkdir()
    assert not any(key.startswith(("ACTIONS_", "GITHUB_", "GH_")) for key in env)
    cli = cli_arguments(binary, directory, endpoint, sandboxed=sandboxed)
    args = [*command_prefix, cli[0], *cm_options, *cli[1:]]
    stdout = directory / "stdout.jsonl"
    stderr = directory / "stderr.log"
    return_code = None
    try:
        with stdout.open("w") as out, stderr.open("w") as err:
            process = subprocess.Popen(args, cwd=directory, env=env, stdout=out, stderr=err,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            process_ref.append(process)
            if scenario in ("callback-failure", "output-limit-failure"):
                return_code = process.wait(timeout=40)
                assert return_code != 0, "Required policy failure must fail the real Core invocation"
            else:
                await_barrier(lambda: tools.has("A:entered"), process, "actual A handler")
                if scenario == "cancel-executing":
                    await_barrier(initial_response_sent.is_set, process, "provider finished A response")
                    process.send_signal(signal.SIGINT)
                elif restrictive:
                    await_barrier(lambda: any(row["event"] == "write-gate-blocked"
                        and row["detail"]["call_id"] == "cm-b" for row in trace_rows(trace, waiting=True)),
                        process, "actual B write-gate blocked")
                    assert not tools.has("B:entered"), "B entered while A still owns the execution gate"
                    if scenario == "cancel-waiting":
                        await_barrier(initial_response_sent.is_set, process, "provider finished A/B response")
                        process.send_signal(signal.SIGINT)
                    else:
                        tools.release("A")
                        await_barrier(lambda: tools.has("B:entered"), process, "serial B after A release")
                        tools.release("B")
                else:
                    await_barrier(lambda: tools.has("B:entered"), process, "parallel B before A release")
                    tools.release("B")
                    tools.release("A")
                return_code = process.wait(timeout=45)
                if scenario == "parallel":
                    assert return_code == 0, stderr.read_text()
                else:
                    # Record exact exit code; cancellation is proven by missing admission and lease drain.
                    assert "stopped" in [row["event"] for row in trace_rows(trace)], "Cancellation did not drain runtime"
        rows = trace_rows(trace)
        decisions = {row["detail"]["call_id"]: row for row in rows if row["event"] == "policy-decision"}
        if scenario in ("callback-failure", "output-limit-failure"):
            failure_event = "policy-failed" if scenario == "callback-failure" else "output-limit-failed"
            assert any(row["event"] == failure_event for row in rows)
            if scenario == "callback-failure":
                assert not any(row["event"] == "handler-started" for row in rows)
            assert not any(tools.has(label + ":entered") for label in ("A", "B"))
            assert len(requests) == 1, "Fatal policy error must not retry the model"
            assert sum(row["event"] == "userdata-released" for row in rows) == expected_releases
            assert sum(row["event"] == "stopped" for row in rows) == 1
            assert "panicked at" not in stderr.read_text(), "Policy failure must use the normal turn error path"
        elif scenario == "parallel":
            assert set(decisions) == {"cm-a", "cm-b"}
            assert all(row["detail"]["original_parallel"] is True for row in decisions.values())
            assert all(row["detail"]["final_parallel"] is (not restrictive) for row in decisions.values())
            assert all(row["detail"]["decision"] == (1 if restrictive else 0) for row in decisions.values())
            ids = {(row["detail"]["thread_id"], row["detail"]["turn_id"]) for row in decisions.values()}
            assert len(ids) == 1 and all(all(value for value in pair) for pair in ids)
            def sequence(event, call_id):
                return next(row["seq"] for row in rows if row["event"] == event and row["detail"]["call_id"] == call_id)
            if restrictive:
                assert sequence("handler-finished", "cm-a") < sequence("gate-admitted", "cm-b")
                assert sequence("gate-admitted", "cm-b") < sequence("handler-started", "cm-b")
                assert all(row["detail"]["guard"] == "write" for row in decisions.values())
            else:
                names = [entry["event"] for entry in tools.events]
                assert names.index("B:entered") < names.index("A:release")
                assert all(row["detail"]["guard"] == "read" for row in decisions.values())
            assert len(requests) == 2, "Unexpected model retries/continuations"
        elif scenario == "cancel-waiting":
            assert not any(row["event"] == "handler-started" and row["detail"]["call_id"] == "cm-b" for row in rows)
            assert any(row["event"] == "dispatch-finished" and row["detail"]["call_id"] == "cm-b" for row in rows)
        assert not errors, errors
        assert not tools.error, tools.error
        result = {"status": "pass", "command": args, "return_code": return_code,
                  "scenario": scenario, "mod_loaded": mod_loaded, "trace": trace.name,
                  "stdout": stdout.name, "stderr": stderr.name,
                  "events": tools.events, "provider_requests": requests, "environment_keys": sorted(env),
                  "executable_sha256": sha(binary)}
        write(directory / "result.json", result)
        return result
    finally:
        for process in process_ref:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if not (directory / "result.json").exists():
            write(directory / "result.json", {
                "status": "failed", "command": args,
                "return_code": process_ref[0].returncode if process_ref else None,
                "events": tools.events, "provider_requests": requests, "errors": errors,
                "environment_keys": sorted(env),
            })
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
        tools.close()
