#!/usr/bin/env python3
"""Seven isolated G03 cases; run only inside the compiler-free hosted consumer."""
from contextlib import contextmanager
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci/scripts"))
import ci_progress
import mod_manifest

INPUTS = Path("/inputs")
BINARY = INPUTS / "host/bin/codex"
OWNER = "org.example.tool-concurrency"
CAPABILITY = "core.turn_tool_concurrency.v1"


def module(relative):
    path = Path(__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location("cm_g03_" + path.parent.name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    module("turn-budget/driver.py").write(path, value)


def rows(directory):
    return module("runtime-sdk/driver.py").rows(directory / "native.jsonl")


def install(home, *, enabled=True, budget=None, configured=None, code_mode=False, leaf_dir=None):
    sdk = module("runtime-sdk/driver.py")
    sdk.install(home)
    owners = ["lifecycle-audit", "example-tool"]
    if enabled:
        shutil.copytree(INPUTS / "mods/g03/tool-concurrency", home / "mods" / OWNER)
        owners.append(OWNER)
    selection = {"format_version": 2, "enabled": owners}
    if budget is not None:
        a = "org.example.turn-budget"
        shutil.copytree(INPUTS / "mods/g02a/turn-budget", home / "mods" / a)
        owners.append(a)
        selection["mods"] = {a: {"policy": module("turn-budget/driver.py").policy(budget)}}
    mod_manifest.write_toml(home / "cm-runtime.toml", selection)
    config = {"model_catalog_json": "/fixture/concurrency-models.json", "features": {"code_mode": code_mode}}
    if configured is not None:
        config["tool_concurrency"] = configured
    if leaf_dir is not None:
        config["mcp_servers"] = {"g03": {"command": "/usr/bin/python3", "args": ["-B", str(Path(__file__)),
            "mcp", str(leaf_dir)], "startup_timeout_sec": 30, "tool_timeout_sec": 90}}
    mod_manifest.write_toml(home / "config.toml", config)


def report(case, result, *, changed=False):
    assert not changed
    sha = module("runtime-sdk/driver.py").core.sha
    write(Path("/evidence") / ("concurrency-" + case + ".json"), {
        "status": "behavior_pass", "case": case, "result": result,
        "host_executable_sha256": sha(BINARY),
        "mod_payload_sha256": sha(INPUTS / "mods/g03/tool-concurrency/payload.so")})
    write(Path("/evidence/concurrency") / case / "suite.json", {"status": "pass", "case": case})


def request(client, method, params):
    client.counter += 1
    identity = client.counter
    client.send({"id": identity, "method": method, "params": params})
    return client.wait(lambda row: row.get("id") == identity)


def begin(client, thread, token, limit=None):
    params = {"threadId": thread, "input": [{"type": "text", "text": "CM_M02_" + token, "text_elements": []}]}
    if limit is not None:
        params["cmToolConcurrency"] = limit
    result = request(client, "turn/start", params)
    assert "error" not in result, result
    return result["result"]["turn"]["id"]


def complete(client, turn, status="completed"):
    return module("turn-budget/driver.py").complete(client, turn, status)


@contextmanager
def session(case, name, *, limit=None, code_mode=False, cells=0, held=False, budget=None,
            enabled=True, home=None, native_mode="handles"):
    directory = Path("/evidence/concurrency") / case / name
    leaf_dir = directory / "leaves"
    leaf_dir.mkdir(parents=True)
    if home is None:
        home = Path("/profile/concurrency") / case / name
        install(home, configured=limit, code_mode=code_mode, leaf_dir=leaf_dir if cells else None,
            enabled=enabled, budget=budget)
    sdk = module("runtime-sdk/driver.py")
    make_command = sdk.command
    sdk.command = lambda *args, **kwargs: ["features.code_mode=true" if code_mode and part == "features.code_mode=false"
        else part for part in make_command(*args, **kwargs)]
    provider = Provider(cells=cells, code_mode=code_mode, held=held)
    client = None
    try:
        client = sdk.Client(directory / "host", home, provider, mode=native_mode,
            launch_home=home if (home / "cm-profile.json").exists() else None)
        yield client, provider, home, directory
    finally:
        (leaf_dir / "release").touch()
        provider.release.set()
        try:
            if client is not None:
                client.close()
        finally:
            provider.close()


class Provider:
    def __init__(self, *, cells=0, code_mode=False, held=False):
        self.requests, self.errors = [], []
        self.release = threading.Event()
        if not held:
            self.release.set()
        parent = self
        sdk = module("runtime-sdk/driver.py")

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    body = sdk.core.decode_request(self)
                    tokens = re.findall(r"CM_M02_([a-z0-9_-]+)", sdk.text_values(body.get("input", [])))
                    assert tokens, "Missing actual user input"
                    token = tokens[-1]
                    title = sdk.title_request(body)
                    outputs = [item for item in body.get("input", []) if item.get("type") in
                        ("function_call_output", "custom_tool_call_output")]
                    parent.requests.append({"token": token, "purpose": "title" if title else "business",
                        "input": body.get("input"), "tools": body.get("tools"), "outputs": outputs})
                    assert parent.release.wait(45), "Provider barrier timed out"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()

                    def send(value):
                        self.wfile.write(("data: " + json.dumps(value) + "\n\n").encode())
                        self.wfile.flush()

                    identity = "g03-" + token + "-" + str(len(parent.requests))
                    send({"type": "response.created", "response": {"id": identity}})
                    items = []
                    if not title and cells and not outputs:
                        if code_mode:
                            for cell in range(cells):
                                code = '// @exec: {"yield_time_ms":1}\n' + \
                                    'const t=ALL_TOOLS.find(t=>t.name.includes("g03")&&t.name.endsWith("echo"));' + \
                                    'if(!t)throw Error("missing MCP leaf");' + \
                                    'await Promise.all([0,1].map(i=>tools[t.name]({id:' + json.dumps(token + "-" + str(cell) + "-") + \
                                    '+i})));text("g03 cell complete");'
                                items.append({"type": "custom_tool_call", "name": "exec",
                                    "call_id": "g03-exec-" + token + "-" + str(cell), "input": code})
                        else:
                            names = re.findall(r'"name":\s*"([^"]*g03[^\"]*echo)"', json.dumps(body.get("tools")))
                            assert names, "MCP leaf not advertised"
                            items = [{"type": "function_call", "name": names[0], "call_id": "g03-leaf-" + str(i),
                                "arguments": json.dumps({"id": token + "-" + str(i)})} for i in range(cells)]
                    elif not title and code_mode and outputs:
                        # Wait only on each cell's latest output, never resubmit an already completed cell.
                        latest = {}
                        for output in outputs:
                            text = sdk.text_values(output.get("output"))
                            found = re.search(r"Script running with cell ID ([a-zA-Z0-9_-]+)", text)
                            call = output.get("call_id", "")
                            if found:
                                latest[found[1]] = True
                            elif call.startswith("g03-wait-"):
                                latest[call[len("g03-wait-"):].rsplit("-", 1)[0]] = False
                        items = [{"type": "function_call", "name": "wait",
                            "call_id": "g03-wait-" + cell + "-" + str(len(parent.requests)),
                            "arguments": json.dumps({"cell_id": cell, "yield_time_ms": 1000})}
                            for cell, running in latest.items() if running]
                    if not items:
                        items = [{"type": "message", "id": identity + "-final", "role": "assistant",
                            "content": [{"type": "output_text", "text": json.dumps({"title": "G03 fixture"})
                                if title else "G03 complete " + token}]}]
                    for item in items:
                        send({"type": "response.output_item.done", "item": item})
                    send({"type": "response.completed", "response": {"id": identity,
                        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}})
                    self.close_connection = True
                except (BrokenPipeError, ConnectionResetError):
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
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        assert not self.errors, self.errors


def mcp():
    """Controlled read-only MCP leaves with a real, externally released entry barrier."""
    directory = Path(sys.argv[2])
    output_lock = threading.Lock()

    def respond(identity, result):
        with output_lock:
            print(json.dumps({"jsonrpc": "2.0", "id": identity, "result": result}), flush=True)

    def leaf(message):
        value = message["params"]["arguments"]["id"]
        assert re.fullmatch(r"[a-z0-9_-]+", value)
        (directory / (value + ".entered")).touch()
        deadline = time.monotonic() + 60
        while not (directory / "release").exists():
            assert time.monotonic() < deadline, "Unreleased controlled leaf"
            time.sleep(0.01)
        respond(message["id"], {"content": [{"type": "text", "text": "leaf complete " + value}], "isError": False})

    workers = []
    for line in sys.stdin:
        message = json.loads(line)
        method = message.get("method")
        if method == "initialize":
            respond(message["id"], {"protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}}, "serverInfo": {"name": "g03-controlled-leaf", "version": "1"}})
        elif method == "tools/list":
            respond(message["id"], {"tools": [{"name": "echo", "description": "Controlled read-only G03 leaf",
                "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]},
                "annotations": {"readOnlyHint": True, "destructiveHint": False}}]})
        elif method == "tools/call":
            worker = threading.Thread(target=leaf, args=(message,))
            workers.append(worker)
            worker.start()
        elif "id" in message:
            assert method == "ping", message
            respond(message["id"], {})
    for worker in workers:
        worker.join(timeout=65)
        assert not worker.is_alive()


def probe(case, name, *, fault=None):
    sdk = module("runtime-sdk/driver.py")
    suffix = "probe" if fault is None else "backend-" + fault
    directory = Path("/evidence/concurrency") / case / suffix
    directory.mkdir(parents=True)
    home = Path("/profile/concurrency") / case / suffix
    install(home)
    metadata = read(Path("/fixture/concurrency-producer.json"))["probe" if fault is None else "backend_probe"]
    env = {**sdk.environment(home, directory, mode="quiet-barrier" if case == "cancellation" else "handles"),
        **metadata["test_environment"],
        "CM_CONCURRENCY_PROBE_PROFILE": str(home), "CM_CONCURRENCY_PROBE_CASE": case,
        "CM_CONCURRENCY_PROBE_REPORT": str(directory / "probe.json")}
    if fault is not None:
        env["CM_CONCURRENCY_BACKEND_FAULT"] = fault
    command = [metadata["path"], "--ignored", "--exact", name, "--nocapture"]
    result = subprocess.run(command, env=env, cwd=directory, capture_output=True, text=True, timeout=120)
    (directory / "stdout.log").write_text(result.stdout)
    (directory / "stderr.log").write_text(result.stderr)
    write(directory / "result.json", {"command": command, "return_code": result.returncode,
        "probe_sha256": sdk.core.sha(Path(metadata["path"])), "production_cli_sha256": sdk.core.sha(BINARY)})
    assert result.returncode == 0 and "1 passed" in result.stdout, (result.stdout, result.stderr)
    value = read(directory / "probe.json")
    assert value["status"] == "pass" and value["case"] == case and value["separate_from_cli"]
    return value


def bound_run(case, name, limit, *, code_mode, cells):
    with session(case, name, limit=limit, code_mode=code_mode, cells=cells) as (client, provider, home, directory):
        turn = begin(client, client.start(), name)
        trace_dir = directory / "host"
        sdk = module("runtime-sdk/driver.py")
        sdk.core.await_barrier(lambda: len(list((directory / "leaves").glob("*.entered"))) == limit
            and sum(row["event"] == "tool-concurrency-wait" for row in rows(trace_dir)) > limit,
            client.process, "N admitted leaves and another actual waiter")
        (directory / "leaves/release").touch()
        complete(client, turn)
    trace = rows(trace_dir)
    running, peak, acquired, released = set(), 0, [], []
    for row in trace:
        event, detail = row["event"], row["detail"]
        if event == "tool-concurrency-acquired":
            assert detail["call_id"] not in running
            running.add(detail["call_id"])
            acquired.append(detail)
            peak = max(peak, len(running))
            assert len(running) <= limit
        elif event == "tool-concurrency-released":
            assert detail["call_id"] in running
            running.remove(detail["call_id"])
            released.append(detail)
    assert not running and len(acquired) == len(released) == cells * (2 if code_mode else 1)
    assert peak == limit, (peak, limit)
    roles = [row["detail"] for row in trace if row["event"] == "tool-concurrency-role"]
    orchestrators = {row["call_id"] for row in roles if row["role"] == "orchestration"}
    assert not orchestrators & {row["call_id"] for row in acquired}
    if code_mode:
        assert orchestrators and any(row["tool"].endswith("wait") for row in roles), roles
        assert all(row["source"] == "code-mode" for row in acquired)
        assert all(row["parent"] is not None for row in roles if row["role"] == "leaf")
        assert len({row["detail"]["cell_id"] for row in trace if row["event"] == "code-mode-cell"}) == cells
        assert any(row["event"] == "code-mode-transport" for row in trace)
    return {"turn": turn, "limit": limit, "peak": peak, "leaf_count": len(acquired),
        "orchestration_calls": sorted(orchestrators), "code_mode": code_mode, "trace": str(trace_dir / "native.jsonl")}


@ci_progress.case()
def value_flow():
    values = []
    for configured, explicit in ((None, None), (1, None), (2, 1), (None, 1024)):
        name = "config-" + str(configured).lower() + "-turn-" + str(explicit).lower()
        with session("value-flow", name, limit=configured) as (client, provider, home, directory):
            turn = begin(client, client.start(), name, explicit)
            complete(client, turn)
        trace = [row["detail"] for row in rows(directory / "host") if row["event"] == "tool-concurrency-turn"]
        assert any(row["turn"] == turn and row["effective"] == (explicit if explicit is not None else configured) for row in trace), trace
        values.append({"configured": configured, "requested": explicit, "turn": turn, "core": trace})
    with session("value-flow", "invalid") as (client, provider, home, directory):
        thread = client.start()
        for invalid in (0, -1, 1025, 4294967296, 1.5):
            rejected = request(client, "turn/start", {"threadId": thread, "cmToolConcurrency": invalid,
                "input": [{"type": "text", "text": "CM_M02_invalid", "text_elements": []}]})
            assert "error" in rejected, rejected
        assert not provider.requests
    sdk = module("runtime-sdk/driver.py")
    for limit in (1, 2, 1024):
        name = "exec-" + str(limit)
        directory = Path("/evidence/concurrency/value-flow") / name
        directory.mkdir(parents=True)
        home = Path("/profile/concurrency/value-flow") / name
        install(home)
        provider = Provider()
        try:
            command = sdk.command(directory, provider.endpoint, "embedded", token=name)
            command[1:1] = ["--tool-concurrency", str(limit)]
            result = subprocess.run(command, env=sdk.environment(home, directory), cwd=directory,
                capture_output=True, text=True, timeout=90)
            write(directory / "result.json", {"command": command, "return_code": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr})
            assert result.returncode == 0, result.stderr
            assert any(row["event"] == "tool-concurrency-turn" and row["detail"]["effective"] == limit for row in rows(directory))
        finally:
            provider.close()
    review = module("review-before-send/driver.py")
    home = Path("/profile/concurrency/value-flow/tui")
    # The existing PTY helper requires a managed profile.
    management = module("turn-budget/driver.py")
    management.cm(home, Path("/evidence/concurrency/value-flow/tui-install"), "init")
    management.cm(home, Path("/evidence/concurrency/value-flow/tui-install"), "install", INPUTS / "mods/g03/tool-concurrency.cmod")
    tui = review.Terminal("concurrency-value-flow", "tui", home, reviewed=False,
        launch_args=("--tool-concurrency", "2"))
    try:
        tui.send("CM_M02_g03tui\r")
        tui.wait(lambda: any(row["event"] == "tool-concurrency-turn" and row["detail"]["effective"] == 2
            for row in tui.native()), "TUI typed concurrency reaches Core")
    finally:
        tui.close(True)
    shutil.move(str(tui.directory), "/evidence/concurrency/value-flow/tui")
    report("value-flow", {"stdio_core_values": values, "invalid_before_business": True,
        "exec_cli_limits": [1, 2, 1024], "embedded_tui_limit": 2})


@ci_progress.case()
def steer():
    value = probe("steer", "session::turn_input::tests::cm_tool_concurrency_steer")
    with session("steer", "stdio", limit=1, held=True) as (client, provider, home, directory):
        thread = client.start()
        turn = begin(client, thread, "steer")
        module("runtime-sdk/driver.py").core.await_barrier(lambda: bool(provider.requests), client.process, "active provider")
        for limit in (2, 1, None):
            params = {"threadId": thread, "expectedTurnId": turn,
                "input": [{"type": "text", "text": "CM_M02_steer", "text_elements": []}]}
            if limit is not None:
                params["cmToolConcurrency"] = limit
            response = request(client, "turn/steer", params)
            assert ("error" in response) is (limit == 2), response
        provider.release.set()
        complete(client, turn)
    assert any(row["event"] == "tool-concurrency-steer-rejected" and row["detail"]["before_queue"]
        for row in rows(directory / "host"))
    report("steer", {"core_concurrent_admission": value, "stdio_same_and_omitted_inherit": True})


@ci_progress.case()
def leaf_bound():
    results = [bound_run("leaf-bound", "direct-" + str(n), n, code_mode=False, cells=4) for n in (1, 2)]
    results += [bound_run("leaf-bound", "nested-" + str(n), n, code_mode=True, cells=2) for n in (1, 2)]
    report("leaf-bound", {"actual_production_host": results})


@ci_progress.case()
def lock_domains():
    value = probe("lock-domains", "thread_manager::tests::cm_concurrency_probe::cm_tool_concurrency_core")
    nested = bound_run("lock-domains", "nested-one", 1, code_mode=True, cells=2)
    assert value["independent_runtime_locks"]
    report("lock-domains", {"actual_core_lock_domains": value, "n1_production_nested_completion": nested})


@ci_progress.case()
def cancellation():
    value = probe("cancellation", "thread_manager::tests::cm_concurrency_probe::cm_tool_concurrency_core")
    for flag in ("cancelled_waiter", "finishes_on_cancellation", "panic_and_outer_drop", "old_scope_rejected",
            "same_text_new_scope", "native_quiet_and_result_handoff", "scope_close_rejects_waiters"):
        assert value[flag]
    # The accepted original A terminates the real C turn before a second model sample.
    with session("cancellation", "budget-terminal", limit=1, cells=3, budget=1) as (client, provider, home, directory):
        turn = begin(client, client.start(), "budget-terminal")
        sdk = module("runtime-sdk/driver.py")
        sdk.core.await_barrier(lambda: bool(list((directory / "leaves").glob("*.entered"))), client.process, "A+C leaf entered")
        (directory / "leaves/release").touch()
        complete(client, turn, "failed")
    budget = module("turn-budget/driver.py")
    admissions = budget.admissions(directory / "host", turn)
    assert budget.charged(admissions) == [1]
    assert sum(row["detail"].get("error", {}).get("code") == "sampling_budget_exhausted" for row in admissions) == 1
    with session("cancellation", "interrupt", limit=1, cells=3) as (client, provider, home, directory):
        thread = client.start()
        turn = begin(client, thread, "interrupt")
        sdk.core.await_barrier(lambda: any(row["event"] == "tool-concurrency-acquired" for row in rows(directory / "host")),
            client.process, "running leaf")
        client.call("turn/interrupt", {"threadId": thread, "turnId": turn})
        (directory / "leaves/release").touch()
        complete(client, turn, "interrupted")
    report("cancellation", {"actual_core_lifetimes": value, "original_a_budget_terminal": admissions,
        "production_turn_interrupt": True})


@ci_progress.case()
def backend_scope():
    value = probe("backend-scope", "thread_manager::tests::cm_tool_concurrency_backend")
    backend_rejections = [probe("backend-scope",
        "app_server_session::cm_concurrency_backend_probe::cm_tool_concurrency_backend_rejection", fault=fault)
        for fault in ("missing", "wrong-build", "wrong-capability", "disabled")]
    with session("backend-scope", "current") as (client, provider, home, directory):
        initialized = next(row["result"] for row in client.messages if row.get("id") == 1)
        backend = initialized["cmToolConcurrency"]
        assert backend["version"] == 1 and backend["capability"] == CAPABILITY and backend["providerEnabled"]
        assert backend["hostBuildId"] == read(INPUTS / "producer.json")["host"]["host_identity"]["host_build_id"]
    with session("backend-scope", "no-provider", enabled=False) as (client, provider, home, directory):
        thread = client.start()
        rejected = request(client, "turn/start", {"threadId": thread, "cmToolConcurrency": 1,
            "input": [{"type": "text", "text": "CM_M02_no_provider", "text_elements": []}]})
        assert "error" in rejected and not provider.requests, rejected
    positive = bound_run("backend-scope", "model-mcp", 1, code_mode=False, cells=2)
    assert value["hook_leaf_permits"] == 0 and value["hook_concurrency_support"] == "unsupported"
    report("backend-scope", {"current_typed_backend": backend, "model_mcp_covered": positive,
        "actual_hook_negative_probe": value, "old_wrong_backend_validation": backend_rejections,
        "scope": "ToolCallRuntime leaves only; hooks and unrelated processes excluded"})


@ci_progress.case()
def plug_and_play():
    sdk = module("runtime-sdk/driver.py")
    budget = module("turn-budget/driver.py")
    sha = sdk.core.sha
    frozen = sha(BINARY)
    directory = Path("/evidence/concurrency/plug-and-play")
    home = Path("/profile/concurrency/plug-and-play/managed")
    budget.cm(home, directory, "init")
    budget.cm(home, directory, "install", INPUTS / "mods/g03/tool-concurrency.cmod")
    budget.cm(home, directory, "install", INPUTS / "mods/g02a/turn-budget.cmod")
    with session("plug-and-play", "original-a-c", home=home) as (client, provider, _, run):
        turn = begin(client, client.start(), "original-a-c", 1)
        complete(client, turn)
    plan = next(row["detail"]["plan"] for row in rows(run / "host") if row["event"] == "ready")
    assert "sampling_budget" in plan["phases"] and "tool_concurrency" in plan["phases"]
    stable = (home / "cm-profile.json").read_bytes()
    conflict = Path("/work/concurrency-conflict")
    shutil.copytree(INPUTS / "mods/g03/tool-concurrency", conflict)
    manifest = tomllib.loads((conflict / "mod.toml").read_text())
    manifest["id"] = "org.example.conflicting-concurrency"
    mod_manifest.manifest(conflict, manifest)
    rejected = budget.cm(home, directory, "install", conflict, success=False)
    assert rejected["code"] == "exclusive_conflict" and (home / "cm-profile.json").read_bytes() == stable
    budget.cm(home, directory, "disable", OWNER)
    with session("plug-and-play", "disabled", home=home) as (client, provider, _, run):
        turn = begin(client, client.start(), "disabled")
        complete(client, turn)
    budget.cm(home, directory, "enable", OWNER)
    budget.cm(home, directory, "remove", OWNER)
    with session("plug-and-play", "removed", home=home) as (client, provider, _, run):
        turn = begin(client, client.start(), "removed")
        complete(client, turn)
        assert not any(row["event"] == "tool-concurrency-acquired" for row in rows(run / "host"))
    assert sha(BINARY) == frozen
    producer = read(Path("/fixture/concurrency-producer.json"))
    assert producer["author"]["payload_sha256"] == sha(INPUTS / "mods/g03/tool-concurrency/payload.so")
    report("plug-and-play", {"same_frozen_host": frozen, "original_a": producer["original_a"],
        "original_c": producer["parent_abc_handoff"], "loading_conflict_before_native": rejected,
        "install_disable_enable_remove_restart": True, "parent_abc_acceptance": "not_run"})


if __name__ == "__main__":
    {"value-flow": value_flow, "steer": steer, "leaf-bound": leaf_bound, "lock-domains": lock_domains,
     "cancellation": cancellation, "backend-scope": backend_scope, "plug-and-play": plug_and_play, "mcp": mcp}[sys.argv[1]]()
