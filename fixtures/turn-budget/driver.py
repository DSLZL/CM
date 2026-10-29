#!/usr/bin/env python3
"""Six independently checkpointed cases against the frozen, packaged Host H."""
from contextlib import contextmanager
import hashlib
import http.server
import importlib.util
import json
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
OWNER = "org.example.turn-budget"
CAPABILITY = "core.turn_sampling_budget.v1"


def sdk_module():
    path = Path(__file__).resolve().parents[1] / "runtime-sdk/driver.py"
    spec = importlib.util.spec_from_file_location("cm_budget_sdk", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def policy(limit, sources=None):
    return {"max_main_samples": limit, "session_sources": sources or ["cli", "vscode", "exec"],
        "request_kinds": ["turn"]}


def install(home, limit, *, sources=None, budget=True):
    sdk_module().install(home)
    enabled = ["lifecycle-audit", "example-tool"]
    if budget:
        shutil.copytree(INPUTS / "mods/g02a/turn-budget", home / "mods" / OWNER)
        enabled.append(OWNER)
    selection = {"format_version": 2, "enabled": enabled}
    if limit is not None and budget:
        selection["mods"] = {OWNER: {"policy": policy(limit, sources)}}
    mod_manifest.write_toml(home / "cm-runtime.toml", selection)


class Provider:
    def __init__(self, *, desired=2, retry=False, held=False):
        self.requests, self.errors = [], []
        self.desired, self.retry = desired, retry
        self.condition = threading.Condition()
        self.release = threading.Event()
        if not held:
            self.release.set()
        parent = self
        sdk = sdk_module()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    request = sdk.core.decode_request(self)
                    tokens = re.findall(r"CM_M02_([a-z0-9_-]+)", sdk.text_values(request.get("input", [])))
                    assert tokens, "User input did not reach provider"
                    token = tokens[-1]
                    title = sdk.title_request(request)
                    with parent.condition:
                        previous = [row for row in parent.requests if row["token"] == token and row["purpose"] == "business"]
                        failed = parent.retry and not previous and not title
                        logical = sum(row["status"] == 200 for row in previous) + 1
                        parent.requests.append({"token": token, "purpose": "title" if title else "business",
                            "status": 503 if failed else 200, "logical": logical, "input": request.get("input", []),
                            "outputs": [item for item in request.get("input", []) if item.get("type") == "function_call_output"]})
                        parent.condition.notify_all()
                    assert parent.release.wait(45), "Provider barrier was not released"
                    if failed:
                        body = b'{"error":{"message":"controlled transport retry","type":"server_error"}}'
                        self.send_response(503)
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(body)
                    else:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Connection", "close")
                        self.end_headers()

                        def send(value):
                            self.wfile.write(("data: " + json.dumps(value) + "\n\n").encode())
                            self.wfile.flush()

                        identity = "cm-budget-" + token + "-" + str(logical)
                        send({"type": "response.created", "response": {"id": identity}})
                        if not title and logical < parent.desired:
                            send({"type": "response.output_item.done", "item": {"type": "function_call",
                                "call_id": identity, "name": "example-tool__echo", "arguments": json.dumps({"value": token})}})
                        else:
                            send({"type": "response.output_item.done", "item": {"type": "message", "id": identity + "-final",
                                "role": "assistant", "content": [{"type": "output_text", "text":
                                    json.dumps({"title": "Budget fixture"}) if title else "Budget complete " + token}]}})
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

    def entered(self, token):
        deadline = time.monotonic() + 45
        with self.condition:
            while not any(row["token"] == token and row["purpose"] == "business" for row in self.requests):
                remaining = deadline - time.monotonic()
                assert remaining > 0 and not self.errors, ("Provider request missing", self.errors)
                self.condition.wait(min(remaining, 0.1))

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@contextmanager
def session(case, name, limit, *, desired=2, retry=False, held=False, sources=None,
            budget=True, home=None, mode="handles", setup=None):
    sdk = sdk_module()
    directory = Path("/evidence/g02a") / case / name
    if home is None:
        home = Path("/profile/g02a") / case / name
        install(home, limit, sources=sources, budget=budget)
    if setup:
        setup(home, directory)
    provider = Provider(desired=desired, retry=retry, held=held)
    client = None
    try:
        client = sdk.Client(directory, home, provider, mode=mode,
            launch_home=home if (home / "cm-profile.json").exists() else None)
        yield client, provider, home, directory
    finally:
        provider.release.set()
        try:
            if client:
                client.close()
                sdk.settled(directory)
                native = sdk.core.trace_rows(directory / "native.jsonl")
                loaded = any(row["event"] == "init-complete" and row["detail"].get("mod") == OWNER for row in native)
                if loaded:
                    released = [row for row in native if row["event"] == "userdata-released" and row["detail"]["mod"] == OWNER]
                    assert len(released) == 1 and released[0]["detail"]["count"] == 1, released
                    assert not any(row["seq"] > released[0]["seq"] and row["event"].startswith("runtime-")
                        and row["detail"].get("mod") == OWNER for row in native), "Callback after budget userdata release"
        finally:
            provider.close()


def begin(client, thread, token):
    return client.call("turn/start", {"threadId": thread,
        "input": [{"type": "text", "text": "CM_M02_" + token, "text_elements": []}]})["turn"]["id"]


def complete(client, turn, expected):
    value = client.wait(lambda row: row.get("method") == "turn/completed"
        and row.get("params", {}).get("turn", {}).get("id") == turn)
    assert value["params"]["turn"]["status"] == expected, value
    return value


def admissions(directory, turn=None):
    rows = sdk_module().core.trace_rows(directory / "native.jsonl")
    return [row["detail"] for row in rows if row["event"] == "sampling-budget-admission"
        and (turn is None or row["detail"]["turn"] == turn)]


def charged(rows):
    assert len({json.dumps(row["turn_handle"], sort_keys=True) for row in rows}) <= 1, "Runtime scope changed within a turn"
    return [row["detail"]["used"] for row in rows if row["detail"].get("charged")]


def business_requests(provider):
    return [row for row in provider.requests if row["purpose"] == "business"]


def native_probe(*required):
    value = read(Path("/fixture/g02a-native-probe.json"))
    assert value["status"] == "pass" and value["separate_from_cli"] and value["compilation_reused_from_m02"]
    for key in required:
        assert value["scope_report"][key] is True, key
    assert value["cli_executable_sha256"] == sha(BINARY)
    return value


def report(case, result):
    write(Path("/evidence") / ("budget-" + case + ".json"), {"status": "behavior_pass", "case": case,
        "result": result, "host_executable_sha256": sha(BINARY),
        "mod_payload_sha256": sha(INPUTS / "mods/g02a/turn-budget/payload.so")})
    write(Path("/evidence/g02a") / case / "suite.json", {"status": "pass", "case": case})


@ci_progress.case()
def counting():
    runs = []
    for limit in (1, 2):
        with session("counting", "limit-" + str(limit), limit, desired=limit + 1) as (client, provider, home, directory):
            turn = begin(client, client.start(), "limit-" + str(limit))
            complete(client, turn, "failed")
            rows = admissions(directory, turn)
            assert charged(rows) == list(range(1, limit + 1)), rows
            assert len(business_requests(provider)) == limit
            assert sum(row["detail"].get("error", {}).get("code") == "sampling_budget_exhausted" for row in rows) == 1
            runs.append({"limit": limit, "turn": turn, "admissions": rows, "http_requests": len(business_requests(provider))})
    with session("counting", "transport-retry", 2, retry=True) as (client, provider, home, directory):
        turn = begin(client, client.start(), "transport-retry")
        complete(client, turn, "completed")
        assert charged(admissions(directory, turn)) == [1, 2]
        assert [row["status"] for row in business_requests(provider)] == [503, 200, 200]
        runs.append({"transport_retry_http_attempts": 3, "logical_admissions": 2})
    report("counting", {"runs": runs, "unmatched_kind": native_probe("unmatched_kind")})


def stop_reply():
    value = json.load(sys.stdin)
    with Path(sys.argv[2]).open("a") as stream:
        stream.write(json.dumps(value) + "\n")
    print(json.dumps({"decision": "block", "reason": "CM budget Stop continuation"}))


def stop_hook(home, directory):
    command = "/usr/bin/python3 -B /fixture/fixtures/turn-budget/driver.py " + stop_reply.__name__
    command += " " + str(home / "budget-stop.jsonl")
    mod_manifest.write_toml(home / "config.toml", {"features": {"hooks": True}})
    write(home / "hooks.json", {"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": command, "timeout": 10}]}]}})


def pending_reply():
    entered = Path(sys.argv[2])
    write(entered, json.load(sys.stdin))
    deadline = time.monotonic() + 20
    while not entered.with_suffix(".release").exists():
        assert time.monotonic() < deadline, "Pending-input barrier was not released"
        time.sleep(0.01)
    print("{}")


def pending_hook(home, directory):
    command = "/usr/bin/python3 -B /fixture/fixtures/turn-budget/driver.py " + pending_reply.__name__
    command += " " + str(home / "budget-pending-entered.json")
    mod_manifest.write_toml(home / "config.toml", {"features": {"hooks": True}})
    write(home / "hooks.json", {"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": command, "timeout": 30}]}]}})


def trust_stop_hook(client, home, directory):
    entries = client.call("hooks/list", {"cwds": [str(directory)]})["data"]
    assert len(entries) == 1 and not entries[0]["warnings"], entries
    hooks = entries[0]["hooks"]
    assert len(hooks) == 1, hooks
    hook = hooks[0]
    expected = read(home / "hooks.json")["hooks"]["Stop"][0]["hooks"][0]
    assert hook["sourcePath"] == str(home / "hooks.json") and hook["command"] == expected["command"], hook
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", hook["currentHash"]), hook
    client.call("config/batchWrite", {"edits": [{"keyPath": "hooks.state",
        "value": {hook["key"]: {"trusted_hash": hook["currentHash"]}}, "mergeStrategy": "upsert"}],
        "reloadUserConfig": True})
    write(directory / "trusted-stop-hook.json", hook)


@ci_progress.case()
def reentry():
    with session("reentry", "pending-input", 1, desired=1, setup=pending_hook) as (client, provider, home, directory):
        trust_stop_hook(client, home, directory)
        thread = client.start()
        turn = begin(client, thread, "pending-main")
        entered = home / "budget-pending-entered.json"
        sdk_module().core.await_barrier(entered.exists, client.process, "Stop after post-sampling input snapshot")
        client.call("turn/steer", {"threadId": thread, "expectedTurnId": turn,
            "input": [{"type": "text", "text": "CM_M02_pending-extra", "text_elements": []}]})
        entered.with_suffix(".release").touch()
        complete(client, turn, "failed")
        rows = admissions(directory, turn)
        assert charged(rows) == [1] and len(business_requests(provider)) == 1
        history = client.call("thread/read", {"threadId": thread, "includeTurns": True})
        assert "CM_M02_pending-extra" in sdk_module().text_values(history), history
        write(directory / "history.json", history)
        write(directory / "pending-stop-barrier.json", read(entered))
    with session("reentry", "stop-continuation", 1, desired=1, setup=stop_hook) as (client, provider, home, directory):
        trust_stop_hook(client, home, directory)
        turn = begin(client, client.start(), "stop-continuation")
        complete(client, turn, "failed")
        rows = admissions(directory, turn)
        assert charged(rows) == [1] and len(business_requests(provider)) == 1
        hooks = sdk_module().rows(home / "budget-stop.jsonl")
        assert len(hooks) == 1 and hooks[0]["stop_hook_active"] is False, hooks
        write(directory / "stop-inputs.json", hooks)
    report("reentry", {"pending_input_outer_reentry_preserved_budget": True, "stop_continuation_preserved_budget": True,
        "core_probe": native_probe("same_object_reentry", "step_rebuild", "model_change")})


@ci_progress.case()
def terminal():
    with session("terminal", "failed-turn", 1, mode="async") as (client, provider, home, directory):
        thread = client.start()
        turn = begin(client, thread, "terminal-main")
        sdk = sdk_module()
        sdk.core.await_barrier(lambda: any(row["event"] == "worker-entered" for row in
            sdk.rows(directory / "events.jsonl")), client.process, "native tool before pending input")
        client.call("turn/steer", {"threadId": thread, "expectedTurnId": turn,
            "input": [{"type": "text", "text": "CM_M02_terminal-retained", "text_elements": []}]})
        (directory / "release").touch()
        completed = complete(client, turn, "failed")
        history = client.call("thread/read", {"threadId": thread, "includeTurns": True})
        encoded = sdk_module().text_values(history)
        assert "CM_M02_terminal-retained" in encoded and "terminal-main" in encoded, history
        native = sdk_module().rows(directory / "events.jsonl")
        assert any(row["event"] == "dispatch" and row["kind"] == 10 for row in native), native
        turns = [row for row in client.messages if row.get("method") == "turn/completed"
            and row.get("params", {}).get("turn", {}).get("id") == turn]
        errors = [row for row in client.messages if row.get("method") == "error" and row.get("params", {}).get("turnId") == turn]
        assert len(turns) == len(errors) == 1 and errors[0]["params"]["willRetry"] is False, (turns, errors)
        assert "sampling_budget_exhausted" in sdk_module().text_values(errors)
        assert len(business_requests(provider)) == 1 and charged(admissions(directory, turn)) == [1]
        # A subsequent real turn proves the failed RegularTask is gone and its history remains usable.
        provider.desired = 1
        later = begin(client, thread, "terminal-next")
        complete(client, later, "completed")
        latest = business_requests(provider)[-1]
        outputs = [item for item in latest["input"] if item.get("type") == "function_call_output"]
        assert outputs and "terminal-main" in sdk_module().text_values(outputs), latest
        assert "CM_M02_terminal-retained" in sdk_module().text_values(latest["input"])
        write(directory / "history.json", history)
        write(directory / "terminal.json", {"completion": completed, "errors": errors, "later_turn": later,
            "retained_tool_outputs": outputs})
    report("terminal", {"one_error_and_failed_completion": True, "no_outer_resampling": True,
        "pending_input_and_tool_output_retained": True, "subsequent_turn_completed": True})


@ci_progress.case()
def scope():
    with session("scope", "new-turns", 2) as (client, provider, home, directory):
        thread = client.start()
        ids = []
        for token in ("scope-first", "scope-second"):
            turn = begin(client, thread, token)
            complete(client, turn, "completed")
            assert charged(admissions(directory, turn)) == [1, 2]
            ids.append(turn)
        assert ids[0] != ids[1]
    for name, options in (("no-policy", {"limit": None}), ("undeclared-source", {"limit": 1, "sources": ["exec"]}),
                          ("disabled", {"limit": 1, "budget": False})):
        with session("scope", name, **options) as (client, provider, home, directory):
            turn = begin(client, client.start(), name)
            complete(client, turn, "completed")
            assert len(business_requests(provider)) == 2 and not charged(admissions(directory, turn))
    report("scope", {"new_turns_independent": True, "default_and_undeclared_source": True,
        "core_probe": native_probe("same_text_id_new_scope", "undeclared_isolated_default", "concurrent_limit")})


@ci_progress.case()
def cancellation_recovery():
    with session("cancellation-recovery", "provider-cancel", 1, held=True) as (client, provider, home, directory):
        thread = client.start()
        interrupted = begin(client, thread, "provider-cancel")
        provider.entered("provider-cancel")
        client.call("turn/interrupt", {"threadId": thread, "turnId": interrupted})
        provider.release.set()
        complete(client, interrupted, "interrupted")
        assert len(business_requests(provider)) == 1 and charged(admissions(directory, interrupted)) == [1]
        provider.desired = 1
        later = begin(client, thread, "after-provider-cancel")
        complete(client, later, "completed")
        assert charged(admissions(directory, later)) == [1]
    with session("cancellation-recovery", "native-cancel", 2, mode="async") as (client, provider, home, directory):
        thread = client.start()
        interrupted = client.turn(thread, "native-cancel", interrupt=True)
        assert interrupted["status"] == "interrupted"
        assert charged(admissions(directory, interrupted["turn"])) == [1]
        resumed = client.turn(thread, "after-cancel", release=True)
        assert resumed["status"] == "completed"
        assert charged(admissions(directory, resumed["turn"])) == [1, 2]
        cancelled = sdk_module().rows(directory / "events.jsonl")
        assert any(row["event"] == "cancel-return" for row in cancelled)
        saved_thread, saved_home = thread, home
    for method in ("thread/resume", "thread/fork"):
        name = method.split("/")[1]
        with session("cancellation-recovery", "new-process-" + name, 2, home=saved_home) as (client, provider, home, directory):
            restored = client.call(method, {"threadId": saved_thread, "cwd": str(directory),
                "model": "gpt-5.4", "approvalPolicy": "never", "sandbox": "workspace-write"})["thread"]["id"]
            turn = begin(client, restored, "new-process-" + name)
            complete(client, turn, "completed")
            assert charged(admissions(directory, turn)) == [1, 2]
    probe = native_probe("cancel_before_charge", "closed_scope_rejected", "shutdown")
    assert probe["scope_report"]["persistent_recovery_error"] == "sampling_budget_recovery_unsupported"
    report("cancellation-recovery", {"provider_cancel_no_extra_sampling": True,
        "native_cancel_quiet_release": True, "new_process_resume_and_fork_are_new_turns": True,
        "unfinished_budget_restoration": "unsupported", "core_probe": probe})


def cm(home, directory, *arguments, success=True, binary=BINARY):
    sdk = sdk_module()
    home.parent.mkdir(parents=True, exist_ok=True)
    directory = directory / ("operation-" + str(len(list(directory.glob("operation-*")))))
    directory.mkdir(parents=True, exist_ok=True)
    before = {name: (directory / name).exists() for name in ("native.jsonl", "events.jsonl")}
    command = [str(binary), "cm", "--home", str(home), *map(str, arguments)]
    result = subprocess.run(command, env=sdk.environment(home, directory), cwd=directory,
        capture_output=True, text=True, timeout=90)
    value = json.loads(result.stdout) if result.returncode == 0 else next(
        (json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")), {})
    assert (result.returncode == 0) is success, (command, result.returncode, result.stderr)
    if not success:
        assert value["already_native_executed"] is False, value
    assert all((directory / name).exists() == exists for name, exists in before.items()), "Management executed native Mod"
    write(directory / ("command-" + str(len(list(directory.glob("command-*.json")))) + ".json"),
        {"command": command, "return_code": result.returncode, "result": value})
    return value


def active(home):
    return (home / "cm-profile.json").read_bytes()


@ci_progress.case()
def plug_and_play():
    case = "plug-and-play"
    home = Path("/profile/g02a") / case / "managed"
    management = Path("/evidence/g02a") / case / "management"
    before_h = sha(BINARY)
    before_a = sha(INPUTS / "mods/g02a/turn-budget/payload.so")
    for package in (INPUTS / "mods/m02/lifecycle-audit/normal", INPUTS / "mods/m02/example-tool/normal",
                    INPUTS / "mods/g02a/turn-budget.cmod"):
        cm(home, management, "install", package)
    mod_manifest.write_toml(home / "cm-runtime.toml", {"format_version": 2, "enabled": [],
        "mods": {OWNER: {"policy": policy(1)}}})
    cm(home, management, "lock")

    def business(name, expected):
        sdk = sdk_module()
        directory = Path("/evidence/g02a") / case / name
        directory.mkdir(parents=True)
        provider = Provider()
        arguments = sdk.command(directory, provider.endpoint, "embedded", token=name)[1:]
        command = [str(BINARY), "cm", "--home", str(home), "launch", "--", *arguments]
        try:
            with (directory / "stdout.jsonl").open("w") as out, (directory / "stderr.log").open("w") as err:
                result = subprocess.run(command, env=sdk.environment(home, directory), cwd=directory,
                    stdout=out, stderr=err, timeout=90)
            write(directory / "result.json", {"command": command, "return_code": result.returncode,
                "provider_requests": provider.requests, "provider_errors": provider.errors})
            assert (result.returncode != 0) is (expected == "failed"), (directory / "stderr.log").read_text()
            assert not provider.errors, provider.errors
            assert len(business_requests(provider)) == (1 if expected == "failed" else 2)
            sdk.settled(directory)
            native = sdk.core.trace_rows(directory / "native.jsonl")
            ready = next(row["detail"] for row in native if row["event"] == "ready")
            assert ready["plan"]["host"]["executable_sha256"] == before_h
            loaded = any(row["event"] == "init-complete" and row["detail"].get("mod") == OWNER for row in native)
            if loaded:
                released = [row for row in native if row["event"] == "userdata-released" and row["detail"]["mod"] == OWNER]
                assert len(released) == 1 and released[0]["detail"]["count"] == 1, released
                assert not any(row["seq"] > released[0]["seq"] and row["event"].startswith("runtime-")
                    and row["detail"].get("mod") == OWNER for row in native), "Callback after budget userdata release"
            return admissions(directory)
        finally:
            provider.close()

    assert charged(business("enabled", "failed")) == [1]
    cm(home, management, "disable", OWNER)
    assert not charged(business("disabled", "completed"))
    cm(home, management, "enable", OWNER)
    stable = active(home)
    conflict = Path("/work/g02a-conflict")
    shutil.copytree(INPUTS / "mods/g02a/turn-budget", conflict)
    fields = tomllib.loads((conflict / "mod.toml").read_text())
    fields["id"] = "org.example.other-budget"
    mod_manifest.manifest(conflict, fields)
    rejected = cm(home, management, "install", conflict, success=False)
    assert rejected["code"] == "exclusive_conflict", rejected
    assert active(home) == stable
    unsupported = Path("/work/g02a-unsupported")
    shutil.copytree(INPUTS / "mods/g02a/turn-budget", unsupported)
    fields = tomllib.loads((unsupported / "mod.toml").read_text())
    fields["id"] = "org.example.unsupported-budget"
    fields["compat"]["required_capabilities"].append("core.turn_sampling_budget.v999")
    mod_manifest.manifest(unsupported, fields)
    rejected_capability = cm(home, management, "install", unsupported, success=False)
    assert rejected_capability["code"] == "unknown_capability", rejected_capability
    assert active(home) == stable
    legacy = read(Path("/fixture/g02a-legacy-host.json"))
    old_binary = Path(legacy["path"])
    assert sha(old_binary) == legacy["host"]["executable_sha256"]
    old_home = Path("/profile/g02a") / case / "legacy-host"
    cm(old_home, management, "install", INPUTS / "mods/m02/lifecycle-audit/normal", binary=old_binary)
    old_stable = active(old_home)
    old_api = cm(old_home, management, "install", INPUTS / "mods/g02a/turn-budget.cmod",
        success=False, binary=old_binary)
    assert old_api["code"] == "compatibility" and active(old_home) == old_stable, old_api
    # Keep the real old binary; lower only the manifest API floor to reach its capability check.
    old_candidate = Path("/work/g02a-old-capability")
    shutil.copytree(INPUTS / "mods/g02a/turn-budget", old_candidate)
    fields = tomllib.loads((old_candidate / "mod.toml").read_text())
    fields["compat"]["host_api_min"] = "0.6.0"
    mod_manifest.manifest(old_candidate, fields)
    old_capability = cm(old_home, management, "install", old_candidate, success=False, binary=old_binary)
    assert old_capability["code"] == "unknown_capability" and active(old_home) == old_stable, old_capability
    assert sha(old_binary) == legacy["host"]["executable_sha256"]
    assert charged(business("after-rejection", "failed")) == [1]
    cm(home, management, "remove", OWNER)
    assert not charged(business("removed", "completed"))
    assert sha(BINARY) == before_h and sha(INPUTS / "mods/g02a/turn-budget/payload.so") == before_a
    report(case, {"managed_install_disable_enable_remove": True, "conflict_rejected_before_native": rejected,
        "missing_capability_rejected_before_native": rejected_capability, "successful_profile_preserved": True,
        "legacy_host": {"origin": legacy["origin"], "host": legacy["host"],
            "api_rejection": old_api, "capability_rejection": old_capability, "successful_profile_preserved": True},
        "host_and_mod_bytes_unchanged": True, "runtime_build_requests": 0})


def self_check():
    from tempfile import TemporaryDirectory
    from unittest.mock import Mock

    assert policy(2)["request_kinds"] == ["turn"]
    with TemporaryDirectory() as temporary:
        home = Path(temporary)
        for setup in (pending_hook, stop_hook):
            setup(home, home / "evidence")
            expected = read(home / "hooks.json")["hooks"]["Stop"][0]["hooks"][0]
            hook = {"key": "fixture-stop", "sourcePath": str(home / "hooks.json"),
                "command": expected["command"], "currentHash": "sha256:" + "a" * 64}
            client = Mock()
            client.call.side_effect = [{"data": [{"warnings": [], "hooks": [hook]}]}, {}]
            trust_stop_hook(client, home, home / "evidence")
            assert tomllib.loads((home / "config.toml").read_text())["features"]["hooks"] is True
            method, request = client.call.call_args.args
            assert method == "config/batchWrite" and request["reloadUserConfig"] is True
            assert request["edits"][0]["value"] == {"fixture-stop": {"trusted_hash": "sha256:" + "a" * 64}}
    # The six entries must remain independently fingerprintable; no all-cases wrapper.
    from retry import projection
    text = Path(__file__).read_text()
    names = ("counting", "reentry", "terminal", "scope", "cancellation_recovery", "plug_and_play")
    original = {name: projection(text, (name,)) for name in names}
    changed = text.replace('runs = []', 'runs = ["controlled test-only change"]', 1)
    assert original["counting"] != projection(changed, ("counting",))
    assert all(original[name] == projection(changed, (name,)) for name in names if name != "counting")
    shared = text.replace('"max_main_samples": limit', '"max_main_samples": limit + 1', 1)
    assert all(original[name] != projection(shared, (name,)) for name in names)


if __name__ == "__main__":
    {"counting": counting, "reentry": reentry, "terminal": terminal, "scope": scope,
     "cancellation-recovery": cancellation_recovery, "plug-and-play": plug_and_play,
     "stop_reply": stop_reply, "pending_reply": pending_reply, "self-check": self_check}[sys.argv[1]]()
