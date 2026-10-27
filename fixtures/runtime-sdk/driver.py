#!/usr/bin/env python3
"""Exercise the packaged CLI and precompiled SDK Mods in the compiler-free consumer."""
import collections
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native-loader"))
import core_acceptance as core

INPUTS = Path("/inputs")
BINARY = INPUTS / "host/bin/codex"
EVIDENCE = Path("/evidence/m02")
PROFILE = Path("/profile/m02")


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    core.write(path, value)


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines(keepends=True) if line.endswith("\n")]


def install(home, owners=("lifecycle-audit", "example-tool"), variant="normal"):
    import mod_manifest
    installed = home / "mods"
    if installed.exists():
        shutil.rmtree(installed)
    for owner in owners:
        shutil.copytree(INPUTS / "mods/m02" / owner / (variant if owner == "example-tool" else "normal"), installed / owner)
    home.mkdir(parents=True, exist_ok=True)
    mod_manifest.selection(home, list(owners))


def environment(home, directory, mode="handles", old_handle=None):
    inherited = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR") if key in os.environ}
    result = {**inherited, "HOME": str(directory / "home"), "CODEX_HOME": str(home), "CODEX_SQLITE_HOME": str(home),
        "CM_NATIVE_TRACE": str(directory / "native.jsonl"), "CM_RUNTIME_EVENTS": str(directory / "events.jsonl"),
        "CM_RUNTIME_MODE": mode, "CM_RUNTIME_BARRIER": str(directory / "release"),
        "CODEX_API_KEY": "cm-controlled-fixture-only", "OPENAI_API_KEY": "cm-controlled-fixture-only"}
    if old_handle:
        result["CM_RUNTIME_OLD_HANDLE"] = old_handle
    Path(result["HOME"]).mkdir(parents=True)
    assert not any(key.startswith(("ACTIONS_", "GITHUB_", "GH_")) for key in result)
    return result


def text_values(value):
    if isinstance(value, dict):
        return " ".join(text_values(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(text_values(item) for item in value)
    return value if isinstance(value, str) else ""


class Provider:
    def __init__(self, *, tool=True, tool_error=False):
        self.requests = []
        self.errors = []
        self.tool = tool
        self.tool_error = tool_error
        self.condition = threading.Condition()
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    request = core.decode_request(self)
                    encoded = text_values(request.get("input", []))
                    tokens = re.findall(r"CM_M02_([a-z0-9_-]+)", encoded)
                    assert tokens, "Actual user input did not reach the model"
                    token = tokens[-1]
                    call_id = "cm-m02-" + token
                    outputs = [item for item in request.get("input", []) if
                               item.get("type") == "function_call_output" and item.get("call_id") == call_id]
                    with parent.condition:
                        parent.requests.append({"token": token, "input": request.get("input"),
                            "tools": request.get("tools"), "outputs": outputs})
                        parent.condition.notify_all()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()

                    def send(event):
                        self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                        self.wfile.flush()

                    send({"type": "response.created", "response": {"id": "cm-m02-" + token}})
                    if parent.tool and not outputs:
                        send({"type": "response.output_item.done", "item": {"type": "function_call",
                            "call_id": call_id, "name": "example-tool__echo",
                            "arguments": json.dumps({"value": token})}})
                    else:
                        if parent.tool:
                            output = text_values(outputs)
                            if parent.tool_error:
                                assert "controlled tool failure" in output, outputs
                            else:
                                value = json.loads(outputs[0]["output"])
                                assert value["owner"] == "example-tool" and value["arguments"]["value"] == token, value
                        send({"type": "response.output_item.done", "item": {"type": "message", "id": "cm-final-" + token,
                            "role": "assistant", "content": [{"type": "output_text", "text": "M02 complete " + token}]}})
                    send({"type": "response.completed", "response": {"id": "cm-m02-" + token,
                        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}})
                    self.close_connection = True
                except Exception as error:
                    parent.errors.append(repr(error))
                    self.close_connection = True

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = "http://127.0.0.1:" + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def command(directory, endpoint, transport="stdio", mode="new", thread_id=None, token="embedded"):
    arguments = core.cli_arguments(BINARY, directory, endpoint, sandboxed=True)
    if transport == "stdio":
        return arguments[:arguments.index("exec")] + ["app-server", "--listen", "stdio://"]
    arguments.remove("--ephemeral")
    arguments[-1] = "CM_M02_" + token
    if mode != "new":
        arguments[-1:-1] = [mode, thread_id]
    return arguments


class Client:
    def __init__(self, directory, home, provider, mode="handles", old_handle=None):
        self.directory = directory
        directory.mkdir(parents=True)
        self.provider = provider
        self.command = command(directory, provider.endpoint)
        self.stderr = (directory / "stderr.log").open("w")
        self.process = subprocess.Popen(self.command, env=environment(home, directory, mode, old_handle),
            cwd=directory, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            text=True, bufsize=1, close_fds=True)
        self.messages = []
        self.condition = threading.Condition()
        self.reader_error = None
        self.counter = 0

        def listen():
            try:
                with (directory / "stdout.jsonl").open("w") as output:
                    for line in self.process.stdout:
                        output.write(line)
                        output.flush()
                        message = json.loads(line)
                        with self.condition:
                            self.messages.append(message)
                            self.condition.notify_all()
            except BaseException as error:
                self.reader_error = repr(error)
            finally:
                with self.condition:
                    self.condition.notify_all()

        self.reader = threading.Thread(target=listen, daemon=True)
        self.reader.start()
        self.call("initialize", {"clientInfo": {"name": "cm-m02", "version": "1"},
            "capabilities": {"experimentalApi": True}})
        self.send({"method": "initialized", "params": {}})

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def wait(self, predicate, timeout=45):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                for message in self.messages:
                    if predicate(message):
                        return message
                if self.reader_error or self.process.poll() is not None:
                    raise AssertionError(("App Server exited before response", self.reader_error, self.process.poll()))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("App Server response/notification missing")
                self.condition.wait(min(remaining, 0.1))

    def call(self, method, params):
        self.counter += 1
        identity = self.counter
        self.send({"id": identity, "method": method, "params": params})
        response = self.wait(lambda value: value.get("id") == identity)
        assert "error" not in response, response
        return response["result"]

    def start(self):
        return self.call("thread/start", {"cwd": str(self.directory), "model": "gpt-5.4",
            "approvalPolicy": "never", "sandbox": "workspace-write", "ephemeral": False})["thread"]["id"]

    def mappings(self, label):
        mappings = [line for line in Path("/proc", str(self.process.pid), "maps").read_text().splitlines()
            if "/memfd:cm-mod-v1" in line and "x" in line.split()[1]]
        assert len({tuple(line.split()[3:5]) for line in mappings}) == 2, mappings
        write(self.directory / (label + "-native-maps.json"), {"pid": self.process.pid, "executable_mappings": mappings})
        return sorted(mappings)

    def turn(self, thread_id, token, *, interrupt=False, release=False, failure=False, mutate=None):
        result = self.call("turn/start", {"threadId": thread_id,
            "input": [{"type": "text", "text": "CM_M02_" + token, "text_elements": []}]})
        turn_id = result["turn"]["id"]
        if interrupt or release or mutate:
            core.await_barrier(lambda: any(row["event"] == "worker-entered" for row in
                rows(self.directory / "events.jsonl")), self.process, "native worker barrier")
            if mutate:
                mutate()
            if interrupt:
                self.call("turn/interrupt", {"threadId": thread_id, "turnId": turn_id})
            else:
                (self.directory / "release").touch()
        completed = self.wait(lambda value: value.get("method") == "turn/completed"
            and value.get("params", {}).get("turn", {}).get("id") == turn_id)
        status = completed["params"]["turn"]["status"]
        assert status == ("interrupted" if interrupt else "failed" if failure else "completed"), completed
        return {"thread": thread_id, "turn": turn_id, "status": status}

    def close(self, *, failure=False):
        if self.process.poll() is None:
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise AssertionError("App Server shutdown did not finish")
        finally:
            self.reader.join(timeout=2)
            self.stderr.close()
            write(self.directory / "result.json", {"command": self.command, "return_code": self.process.returncode,
                "provider_requests": self.provider.requests, "provider_errors": self.provider.errors})
        assert (code != 0) if failure else (code == 0), (code, (self.directory / "stderr.log").read_text())
        assert not self.provider.errors, self.provider.errors


def settled(directory, *, pinned=False, failed=False, modules=2):
    events = rows(directory / "events.jsonl")
    native = core.trace_rows(directory / "native.jsonl")
    dispatched = [row for row in events if row["event"] == "dispatch"]
    released = [row["request"] for row in events if row["event"] == "request-release"]
    assert len(released) == len(set(released)), "request_release called twice"
    active = {row["request"] for row in dispatched} - set(released)
    assert bool(active) is pinned, (active, pinned)
    for handle in released:
        returns = [index for index, row in enumerate(events) if row["event"] == "dispatch-return" and row["request"] == handle]
        release = next(index for index, row in enumerate(events) if row["event"] == "request-release" and row["request"] == handle)
        assert len(returns) == 1 and returns[0] < release
        cancel_returns = [index for index, row in enumerate(events) if row["event"] == "cancel-return" and row["request"] == handle]
        assert not cancel_returns or cancel_returns[-1] < release
    if pinned:
        assert not any(row["event"] == "userdata-release" and row["owner"] == "example-tool" for row in events)
        assert sum(row["event"] == "userdata-release" for row in events) == modules - 1
        assert any(row["event"] == "runtime-scope-failed" and "pinned" in json.dumps(row) for row in native)
    else:
        assert bool(any(row["event"] == "runtime-scope-failed" for row in native)) is failed
        assert sum(row["event"] == "userdata-release" for row in events) == modules
    successful = collections.Counter(json.dumps(row["detail"]["request"], sort_keys=True) for row in native
        if row["event"] == "runtime-complete" and row["detail"]["code"] == 0)
    assert all(count == 1 for count in successful.values())
    cancelled = collections.Counter(json.dumps(row["detail"]["request"], sort_keys=True) for row in native
        if row["event"] == "runtime-request-cancel")
    assert all(count == 1 for count in cancelled.values()) and not successful.keys() & cancelled.keys()
    return {"requests": len(dispatched), "released_once": len(released), "pinned_requests": sorted(active),
        "completion_terminal_deliveries": len(successful), "cancel_terminal_deliveries": len(cancelled),
        "events": str(directory / "events.jsonl"),
        "native_trace": str(directory / "native.jsonl")}


def business_evidence(provider, *, tool=True, historical_context=False):
    assert provider.requests
    for request in provider.requests:
        names = [item.get("name") for item in request["tools"] if item.get("type") == "function"]
        assert "exec_command" in names, "Built-in tool disappeared"
        assert names.count("example-tool__echo") == (1 if tool else 0)
        if tool or not historical_context:
            assert ("CM_SECTION_example-tool" in text_values(request["input"])) is tool
    if tool:
        assert any(request["outputs"] for request in provider.requests), "Native JSON output never reached the model"
    return {"model_requests": len(provider.requests), "builtin_exec_command_retained": True,
        "native_json_output_model_visible": tool, "current_cm_section_supplied": tool,
        "prior_world_state_history_allowed": historical_context}


def embedded(name, home, *, mode="new", thread_id=None):
    directory = EVIDENCE / name
    directory.mkdir(parents=True)
    provider = Provider()
    arguments = command(directory, provider.endpoint, "embedded", mode, thread_id, name)
    try:
        with (directory / "stdout.jsonl").open("w") as out, (directory / "stderr.log").open("w") as err:
            result = subprocess.run(arguments, env=environment(home, directory), cwd=directory, stdout=out, stderr=err, timeout=90)
        write(directory / "result.json", {"command": arguments, "return_code": result.returncode,
            "provider_requests": provider.requests, "provider_errors": provider.errors})
        assert result.returncode == 0 and not provider.errors, (directory / "stderr.log").read_text()
        identity = next(row["thread_id"] for row in rows(directory / "stdout.jsonl") if row.get("type") == "thread.started")
        events = rows(directory / "events.jsonl")
        starts = [row for row in events if row["event"] == "dispatch" and row["kind"] == 1]
        assert len(starts) == 1 and starts[0]["mod_before"] == starts[0]["thread_before"] == 0
        turns = [row for row in events if row["event"] == "dispatch" and row["kind"] == 6]
        assert len(turns) == 1 and turns[0]["turn_before"] == 0
        return {"thread": identity, "business": business_evidence(provider), "lifetime": settled(directory)}
    finally:
        provider.close()


def rejection(name, variant="normal", mutate=None):
    home = PROFILE / name
    install(home, variant=variant)
    if mutate:
        mutate(home)
    directory = EVIDENCE / name
    directory.mkdir(parents=True)
    provider = Provider()
    arguments = command(directory, provider.endpoint, "embedded", token=name)
    try:
        with (directory / "stdout.jsonl").open("w") as out, (directory / "stderr.log").open("w") as err:
            result = subprocess.run(arguments, env=environment(home, directory), cwd=directory, stdout=out, stderr=err, timeout=60)
        stderr = (directory / "stderr.log").read_text()
        native = core.trace_rows(directory / "native.jsonl")
        report = {"command": arguments, "return_code": result.returncode, "provider_requests": provider.requests, "stderr": stderr}
        write(directory / "result.json", report)
        assert result.returncode != 0 and "CM " in stderr and not provider.requests
        assert not any(row["event"] == "ready" for row in native), native
        assert "example-tool" in stderr, stderr
        return {"case": name, "variant": variant, "diagnostic": stderr, "provider_requests": 0}
    finally:
        provider.close()


def self_check():
    assert text_values({"a": [{"text": "CM_M02_one"}, {"output": "native"}]}) == "CM_M02_one native"
    assert re.findall(r"CM_M02_([a-z0-9_-]+)", "CM_M02_first CM_M02_last")[-1] == "last"
    test = command(Path("/work"), "http://127.0.0.1:1234", "embedded", "resume", "thread", "test")
    assert "--ephemeral" not in test and test[-3:] == ["resume", "thread", "CM_M02_test"]
    assert command(Path("/work"), "http://127.0.0.1:1234")[-3:] == ["app-server", "--listen", "stdio://"]


def matrix():
    import mod_manifest
    import runtime_sdk
    EVIDENCE.mkdir(parents=True)
    producer = read(INPUTS / "producer.json")
    frozen = producer["host"]
    before = core.sha(BINARY)
    assert before == frozen["executable_sha256"]
    authored = producer["runtime_sdk"]
    assert authored["status"] == "pass" and authored["native_scope_probe"]["status"] == "pass"
    native_evidence = EVIDENCE / "native-core"
    native_evidence.mkdir()
    for name in ("m02-native-probe.json", "m02-native-scopes.json", "m02-native-events.jsonl", "m02-native-trace.jsonl"):
        shutil.copyfile(Path("/fixture") / name, native_evidence / name)
    home = PROFILE / "embedded"
    install(home)
    first = embedded("embedded-new", home)
    resumed = embedded("embedded-resume", home, mode="resume", thread_id=first["thread"])
    forked = embedded("embedded-fork", home, mode="fork", thread_id=first["thread"])
    assert resumed["thread"] == first["thread"] != forked["thread"]
    scope_home = PROFILE / "stdio"
    install(scope_home)
    provider = Provider()
    client = Client(EVIDENCE / "stdio-scopes", scope_home, provider)
    try:
        thread_id = client.start()
        turns = [client.turn(thread_id, "stdio-first"), client.turn(thread_id, "stdio-second")]
        live = client.call("thread/resume", {"threadId": thread_id})
        assert live["thread"]["id"] == thread_id
        fork = client.call("thread/fork", {"threadId": thread_id})["thread"]["id"]
        assert fork != thread_id
        turns.append(client.turn(fork, "stdio-fork"))
        unsubscribed = client.call("thread/unsubscribe", {"threadId": thread_id})
        assert unsubscribed["status"] == "unsubscribed", unsubscribed
        replacement_cwd = client.directory / "rebuilt-work"
        replacement_cwd.mkdir()
        rebuilt = client.call("thread/resume", {"threadId": thread_id, "cwd": str(replacement_cwd)})
        assert rebuilt["thread"]["id"] == thread_id and rebuilt["cwd"] == str(replacement_cwd), rebuilt
        turns.append(client.turn(thread_id, "stdio-rebuilt"))
    finally:
        client.close()
        provider.close()
    public_business = business_evidence(provider)
    scope_lifetime = settled(EVIDENCE / "stdio-scopes")
    scope_events = rows(EVIDENCE / "stdio-scopes/events.jsonl")
    starts = [row for row in scope_events if row["event"] == "dispatch" and row["kind"] == 1]
    assert len(starts) == 3 and len({row["thread_scope"] for row in starts}) == 3
    assert len({row["mod_scope"] for row in starts}) == 1
    lifecycle_counts = collections.Counter(row["kind"] for row in scope_events if row["event"] == "dispatch")
    assert lifecycle_counts[2] == lifecycle_counts[5] == 3
    assert lifecycle_counts[6] == lifecycle_counts[7] == 4
    assert lifecycle_counts[3] >= 1
    old_stop = next(index for index, row in enumerate(scope_events) if row["event"] == "dispatch"
        and row["kind"] == 5 and row["thread_scope"] == starts[0]["thread_scope"])
    assert old_stop < scope_events.index(starts[-1]), "Cold reconfiguration started before the old scope stopped"
    for kind, field in ((1, "thread_scope"), (6, "turn_scope")):
        selected = [row for row in scope_events if row["event"] == "dispatch" and row["kind"] == kind]
        assert len({row[field] for row in selected}) == len(selected)
        assert all(row["thread_before" if kind == 1 else "turn_before"] == 0 for row in selected)

    cancellations = []
    for mode in ("async", "cancel", "late", "noncooperative", "timeout"):
        case_home = PROFILE / mode
        install(case_home)
        service = Provider()
        test = Client(EVIDENCE / mode, case_home, service, mode=mode)
        try:
            identity = test.start()
            outcome = test.turn(identity, mode, interrupt=mode in ("cancel", "late", "noncooperative"),
                release=mode == "async", failure=mode == "timeout")
        finally:
            test.close(failure=mode in ("noncooperative", "timeout"))
            service.close()
        lifetime = settled(EVIDENCE / mode, pinned=mode == "noncooperative", failed=mode == "timeout")
        records = rows(EVIDENCE / mode / "events.jsonl")
        complete = [row for row in records if row["event"] == "worker-complete"]
        if mode == "async":
            assert len(complete) == 1 and complete[0]["code"] == 0
            business_evidence(service)
        elif mode != "noncooperative":
            assert len(complete) == 1 and complete[0]["code"] == 8
        if mode == "timeout":
            assert any(row["event"] == "runtime-request-cancel" and row["detail"]["timeout"]
                for row in core.trace_rows(EVIDENCE / mode / "native.jsonl"))
        cancellations.append({"mode": mode, "turn": outcome, "lifetime": lifetime, "completion": complete})

    restart_home = PROFILE / "restart"
    install(restart_home)
    service = Provider()
    running = Client(EVIDENCE / "restart-live", restart_home, service, mode="async")
    library_maps = {}
    def mutate_profile():
        library_maps["active_before_mutation"] = running.mappings("active-before")
        install(restart_home, owners=("lifecycle-audit",))
        library_maps["active_after_mutation"] = running.mappings("active-after")
    try:
        identity = running.start()
        live_outcome = running.turn(identity, "profile-mutated", mutate=mutate_profile)
        assert running.call("thread/resume", {"threadId": identity})["thread"]["id"] == identity
        library_maps["after_live_resume"] = running.mappings("after-live-resume")
        assert all(value == library_maps["active_before_mutation"] for value in library_maps.values())
        running.turn(identity, "after-live-resume")
    finally:
        running.close()
        service.close()
    business_evidence(service)
    live_lifetime = settled(EVIDENCE / "restart-live")
    live_events = rows(EVIDENCE / "restart-live/events.jsonl")
    assert sum(row["event"] == "init" for row in live_events) == 2
    assert sum(row["event"] == "dispatch" and row["kind"] == 1 for row in live_events) == 1
    previous = next(row["request"] for row in rows(EVIDENCE / "restart-live/events.jsonl") if row["event"] == "dispatch")
    replacement = Provider(tool=False)
    restarted = Client(EVIDENCE / "restart-cold", restart_home, replacement, old_handle=previous)
    try:
        cold = restarted.call("thread/resume", {"threadId": identity})["thread"]["id"]
        assert cold == identity
        cold_outcome = restarted.turn(cold, "cold-resume")
    finally:
        restarted.close()
        replacement.close()
    business_evidence(replacement, tool=False, historical_context=True)
    cold_lifetime = settled(EVIDENCE / "restart-cold", modules=1)
    cold_events = rows(EVIDENCE / "restart-cold/events.jsonl")
    assert {row["owner"] for row in cold_events} == {"lifecycle-audit"}
    assert any(row["event"] == "old-process-handle" and row["code"] == 5 for row in cold_events)
    cold_start = next(row for row in cold_events if row["event"] == "dispatch" and row["kind"] == 1)
    assert cold_start["mod_before"] == cold_start["thread_before"] == 0

    errors = []
    for mode in ("lifecycle-error", "turn-error", "context-error", "tool-error", "callback-error", "panic", "stop-error", "release-error", "bounds"):
        error_home = PROFILE / mode
        install(error_home)
        directory = EVIDENCE / mode
        directory.mkdir(parents=True)
        service = Provider(tool_error=mode == "tool-error")
        arguments = command(directory, service.endpoint, "embedded", token=mode)
        try:
            with (directory / "stdout.jsonl").open("w") as out, (directory / "stderr.log").open("w") as err:
                result = subprocess.run(arguments, env=environment(error_home, directory, mode), cwd=directory,
                    stdout=out, stderr=err, timeout=90)
            write(directory / "result.json", {"command": arguments, "return_code": result.returncode, "provider_requests": service.requests})
            if mode in ("tool-error", "bounds"):
                assert result.returncode == 0
                business_evidence(service)
            elif mode in ("stop-error", "release-error"):
                assert result.returncode != 0
                business_evidence(service)
                events = rows(directory / "events.jsonl")
                assert sum(row["event"] == "userdata-release" for row in events) == 2
            elif mode in ("callback-error", "panic"):
                assert result.returncode != 0 and len(service.requests) == 1
                assert not service.errors, service.errors
            else:
                assert result.returncode != 0 and not service.requests, "Required callback error reached the model"
            if mode == "bounds":
                assert any(row["event"] == "bounds" and row["quota_recovered"] for row in rows(directory / "events.jsonl"))
            else:
                assert "controlled" in (directory / "stderr.log").read_text() + (directory / "stdout.jsonl").read_text() or mode == "tool-error"
            errors.append({"mode": mode, "return_code": result.returncode, "model_requests": len(service.requests)})
        finally:
            service.close()

    rejected = [rejection("abi-" + variant, variant) for variant in runtime_sdk.NEGATIVE]
    def change(home, transform):
        path = home / "mods/example-tool"
        import tomllib
        value = tomllib.loads((path / "mod.toml").read_text())
        transform(value)
        mod_manifest.manifest(path, value)
    rejected.append(rejection("manifest-reserved", mutate=lambda home: change(home,
        lambda value: value["contributions"][0].update(resource="exec_command"))))
    rejected.append(rejection("manifest-name-collision", mutate=lambda home: change(home,
        lambda value: value["contributions"][1].update(id="shadow", kind="tool",
            capability="runtime.tool.v1", resource="example-tool__echo"))))
    assert "shadow" in rejected[-1]["diagnostic"] and "echo" in rejected[-1]["diagnostic"]

    handle_events = [row for row in scope_events if row["event"] in
        ("handle-probes", "previous-handles", "cross-owner-handle")]
    assert any(row["event"] == "cross-owner-handle" for row in handle_events)
    assert any(row["event"] == "previous-handles" and row["old_turn"] != 0 for row in handle_events)
    assert core.sha(BINARY) == before
    reports = (
        {"authoring": authored, "ffi_boundary": "C DTOs, opaque handles and copied byte buffers"},
        {"embedded": first, "stdio": public_business, "private_builtin_order": authored["native_scope_probe"]["builtin_before_mod"],
         "required_error_gates": errors},
        {"embedded_new_resume_fork": [first, resumed, forked], "stdio_turns": turns,
         "live_resume_keeps_runtime": live["thread"]["id"], "scopes": scope_lifetime,
         "lifecycle_counts": dict(lifecycle_counts),
         "unsubscribed_configuration_rebuild": rebuilt,
         "private_thread_manager": authored["native_scope_probe"]},
        {"rejected": rejected, "builtin_names_retained": public_business["builtin_exec_command_retained"]},
        {"checks": handle_events, "old_process": [row for row in cold_events if row["event"] == "old-process-handle"],
         "private_registry_state": authored["native_scope_probe"], "memory_persistence": "process-local only"},
        {"cases": cancellations, "required_errors": errors, "ordinary_reentry": "current Host unit test and per-Mod native-entry guard"},
        {"live": live_outcome, "live_lifetime": live_lifetime, "library_mappings": library_maps,
         "cold": cold_outcome, "cold_lifetime": cold_lifetime, "old_handle_rejected": True,
         "same_cli_executable_sha256": before, "compilation_during_consumption": 0, "active_libraries_unloaded": 0},
    )
    for name, report in zip(runtime_sdk.REPORTS, reports, strict=True):
        write(Path("/evidence") / name, {"status": "behavior_pass", **report})
    write(EVIDENCE / "suite.json", {"status": "pass", "reports": list(runtime_sdk.REPORTS)})


if __name__ == "__main__":
    matrix()
