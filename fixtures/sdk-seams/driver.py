#!/usr/bin/env python3
"""Compiler-free G06 cases. Production H and private probes keep separate identities."""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import tomllib

sys.path.insert(0, "/fixture/ci/scripts")
sys.path.insert(0, "/fixture/fixtures/native-loader")
import ci_progress
import core_acceptance as core
import mod_manifest
import runtime_cases
from sdk_seams import REPORTS

INPUTS = Path("/inputs")
WORK = Path("/work")
PROFILE = Path("/profile")
EVIDENCE = Path("/evidence")
BINARY = INPUTS / "host/bin/codex"
CORE_PROBE = INPUTS / "probes/cm-concurrency-core"


def module(relative):
    path = Path("/fixture/fixtures") / relative
    spec = importlib.util.spec_from_file_location("cm_seams_" + path.parent.name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def report(index, key, value):
    rows = [{} for _ in REPORTS]
    rows[index] = {key: value}
    return rows


def install(home, variants=("a/v1",), *, reverse=False):
    home.mkdir(parents=True, exist_ok=True)
    owners = []
    for index, variant in enumerate(reversed(variants) if reverse else variants):
        package = home / "mods" / (str(index) + "-" + variant.replace("/", "-"))
        shutil.copytree(INPUTS / "mods/g06" / variant, package)
        owners.append(tomllib.loads((package / "mod.toml").read_text())["id"])
    mod_manifest.selection(home, sorted(owners))
    return home


def change(home, owner, field, value):
    def update(fields):
        target = fields
        for key in field[:-1]:
            target = target[key]
        if value is None:
            del target[field[-1]]
        else:
            target[field[-1]] = value
    mod_manifest.mutate(home, owner, update)


def environment(home, directory, **extra):
    directory.mkdir(parents=True, exist_ok=True)
    user = directory / "home"
    user.mkdir(exist_ok=True)
    return {"PATH": "/usr/bin:/bin:/inputs/host/codex-path", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "TERM": "dumb", "HOME": str(user), "CODEX_HOME": str(home), "CODEX_SQLITE_HOME": str(home),
        "CM_SEAMS_EVENTS": str(directory / "events.jsonl"), "CM_NATIVE_TRACE": str(directory / "native.jsonl"), **extra}


def events(directory):
    return {"native": core.trace_rows(directory / "native.jsonl"),
            "mods": core.trace_rows(directory / "events.jsonl")}


def no_native(value):
    assert not value["mods"], "Metadata operation loaded native code"
    assert not any(row["event"] in ("dlopen-start", "entry-start", "init-start", "ready") for row in value["native"])


def command(home, arguments, directory, *, good=True, binary=BINARY, extra=None, timeout=90):
    argv = [str(binary), *map(str, arguments)]
    result = subprocess.run(argv, env=environment(home, directory, **(extra or {})),
        cwd=directory, capture_output=True, text=True, timeout=timeout)
    (directory / "stdout.log").write_text(result.stdout)
    (directory / "stderr.log").write_text(result.stderr)
    value = {"command": argv, "return_code": result.returncode, "stdout": result.stdout,
        "stderr": result.stderr, "binary_sha256": mod_manifest.sha(binary), **events(directory)}
    mod_manifest.write(directory / "result.json", value)
    assert (result.returncode == 0) == good, value
    return value


def reject(home, *, metadata=False):
    args = ["cm", "--home", home, "doctor"] if metadata else ["exec", "--skip-git-repo-check", "must not start"]
    value = command(home, args, EVIDENCE / "reject", good=False)
    no_native(value)
    assert "sdk-a" in value["stderr"] or any("sdk-a" in json.dumps(row) for row in value["native"])
    return value


def decoded(directory, kind=16):
    return [{**row, "input": json.loads(bytes.fromhex(row["input_hex"]))}
            for row in events(directory)["mods"] if row["event"] == "dispatch" and row["kind"] == kind]


def settled(directory, *, pinned=False):
    value = events(directory)
    dispatch = {(row["owner"], row["request"]) for row in value["mods"] if row["event"] == "dispatch"}
    releases = [(row["owner"], row["request"]) for row in value["mods"] if row["event"] == "request-release"]
    assert len(releases) == len(set(releases)), "Request released twice"
    if pinned:
        assert dispatch - set(releases) and not any(row["event"] == "userdata-release" for row in value["mods"])
        assert not any(row["event"] == "dlclose" for row in value["native"])
    else:
        assert dispatch == set(releases), value
    return value


class Provider:
    def __init__(self, directory, *, tool=True, mode="normal", chunks=2):
        self.requests, self.emitted, self.errors = [], [], []
        self.tool, self.mode, self.chunks = tool, mode, chunks
        self.counter = directory / "original.log"
        self.closed = threading.Event()
        self.allow = threading.Event()
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    request = core.decode_request(self)
                    provider.requests.append(request)
                    ordinal = len(provider.requests)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()

                    def send(value):
                        provider.emitted.append({"request": ordinal, "event": value})
                        self.wfile.write(("data: " + json.dumps(value) + "\n\n").encode())
                        self.wfile.flush()

                    send({"type": "response.created", "response": {"id": "sdk-response-" + str(ordinal)}})
                    if provider.mode == "retry" and ordinal == 1:
                        self.close_connection = True
                        return
                    outputs = [item for item in request.get("input", []) if item.get("type") == "function_call_output"
                               and item.get("call_id") == "sdk-real-call"]
                    if outputs and provider.counter.exists():
                        assert len(outputs) == 1 and "CM_G06_ORIGINAL" in json.dumps(outputs), outputs
                    if provider.tool and not outputs:
                        args = json.dumps({"cmd": "printf 'original\\n' >> " + shlex.quote(str(provider.counter))
                            + "; printf 'CM_G06_ORIGINAL\\n'", "login": False, "yield_time_ms": 1000})
                        item = {"id": "sdk-item", "type": "function_call", "call_id": "sdk-real-call",
                                "name": "exec_command", "arguments": args}
                        send({"type": "response.output_item.added", "output_index": 0, "item": {**item, "arguments": ""}})
                        middle = len(args) // 2
                        for part in (args[:middle], args[middle:]):
                            send({"type": "response.function_call_arguments.delta", "item_id": "sdk-item",
                                  "call_id": "sdk-real-call", "output_index": 0, "delta": part})
                        send({"type": "response.output_item.done", "output_index": 0, "item": item})
                    else:
                        send({"type": "response.output_item.added", "output_index": 0, "item": {
                            "type": "message", "id": "sdk-message", "role": "assistant", "content": []}})
                        for _ in range(provider.chunks):
                            send({"type": "response.output_text.delta", "item_id": "sdk-message", "output_index": 0,
                                  "content_index": 0, "delta": "CM_G06_STREAM"})
                        send({"type": "response.output_item.done", "output_index": 0, "item": {
                            "type": "message", "id": "sdk-message", "role": "assistant",
                            "content": [{"type": "output_text", "text": "CM_G06_STREAM" * provider.chunks}]}})
                    if provider.mode == "hold":
                        assert provider.allow.wait(40), "Provider explicit release missing"
                    if provider.mode == "error":
                        send({"type": "response.failed", "response": {"id": "sdk-response-" + str(ordinal),
                            "error": {"code": "invalid_request_error", "message": "G06 deliberate provider failure"}}})
                    elif provider.mode != "unterminated":
                        send({"type": "response.completed", "response": {"id": "sdk-response-" + str(ordinal),
                              "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}})
                    self.close_connection = True
                except (BrokenPipeError, ConnectionResetError):
                    provider.closed.set()
                except Exception as error:
                    provider.errors.append(repr(error))
                finally:
                    provider.closed.set()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = "http://127.0.0.1:" + str(self.server.server_port)

    def close(self):
        self.allow.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def real(home, directory, *, mode="", tool=True, good=True, provider_mode="normal", chunks=2, on_wait=None):
    directory.mkdir(parents=True)
    provider = Provider(directory, tool=tool, mode=provider_mode, chunks=chunks)
    extra = {"CM_SEAMS_MODE": mode, "CM_SEAMS_MODE_KIND": "15" if tool else "16"}
    if on_wait:
        barrier = directory / "barrier"
        barrier.mkdir()
        extra.update(CM_SEAMS_BARRIER=str(barrier), CM_SEAMS_BARRIER_KIND="15" if tool else "16")
    argv = core.cli_arguments(BINARY, directory, provider.endpoint, sandboxed=True)
    try:
        with (directory / "stdout.log").open("w") as out, (directory / "stderr.log").open("w") as err:
            process = subprocess.Popen(argv, cwd=directory, env=environment(home, directory, **extra),
                stdout=out, stderr=err, start_new_session=True)
            try:
                if on_wait:
                    core.await_barrier(lambda: any(row["event"] == "waiting" for row in events(directory)["mods"]),
                        process, "native fixture explicit barrier")
                    on_wait(process, directory, provider)
                return_code = process.wait(timeout=100)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        value = {"command": argv, "return_code": return_code, "provider_requests": provider.requests,
            "provider_events": provider.emitted, "provider_errors": provider.errors,
            "original_count": len(provider.counter.read_text().splitlines()) if provider.counter.exists() else 0,
            "host_sha256": mod_manifest.sha(BINARY), **settled(directory, pinned=mode == "noncooperative")}
        mod_manifest.write(directory / "result.json", value)
        assert (return_code == 0) == good and not provider.errors, value
        if good:
            assert "CM_G06_STREAM" in (directory / "stdout.log").read_text(), value
        return value
    finally:
        provider.close()


def tool_run(*, variants=("a/v1",), mode="", expected=1, reverse=False, good=True, on_wait=None):
    home = install(PROFILE, variants, reverse=reverse)
    if len(variants) == 2 and variants == ("a/v1", "b/v1"):
        change(home, "sdk-a", ("contributions", 0, "order_before"), ["sdk-b::around"])
    value = real(home, EVIDENCE / "real", mode=mode, good=good, on_wait=on_wait)
    assert value["original_count"] == expected, value
    return value


def protocol(case):
    home = install(PROFILE, ("a/v1", "b/v1"))
    directory = EVIDENCE / "probe"
    barrier = directory / "barrier"
    barrier.mkdir(parents=True)
    mode = "cancel-before" if case in ("cancel-before", "cancel-queued") else case
    if case == "order-reentry":
        mode = "zero"
    extra = {"CM_SEAMS_PROFILE": str(home), "CM_SEAMS_PROBE_CASE": case,
        "CM_SEAMS_PROBE_REPORT": str(directory / "protocol.json"),
        "RUST_MIN_STACK": str(64 * 1024 * 1024), "CM_SEAMS_MODE": mode,
        "CM_SEAMS_MODE_KIND": "16" if case.startswith("stream-probe-") else "15"}
    if not case.startswith("tui-"):
        extra.update(CM_SEAMS_BARRIER=str(barrier), CM_SEAMS_BARRIER_KIND="16" if case.startswith("stream-probe-") else "15")
    if case == "stream-probe-late-ack":
        extra["CM_SEAMS_MODE"] = "late-complete"
    value = command(home, ["--ignored", "--exact", "thread_manager::tests::cm_sdk_seams_protocol", "--nocapture"],
        directory, binary=CORE_PROBE, extra=extra)
    assert "1 passed" in value["stdout"]
    proof = mod_manifest.read(directory / "protocol.json")
    assert proof["status"] == "pass" and proof["case"] == case
    value["protocol"] = proof
    settled(directory)
    return value


def release_native(process, directory, provider):
    for owner in ("sdk-a", "sdk-b"):
        (directory / "barrier" / owner).touch()


def cancel_native(process, directory, provider):
    os.killpg(process.pid, signal.SIGINT)


def preflight_change(field, value):
    home = install(PROFILE)
    change(home, "sdk-a", field, value)
    return reject(home)


def case_abi_contract():
    results = []
    for mode in ("valid", "major", "minor", "old-minor", "short-prefix", "short-tail", "huge",
            "null-host", "misaligned", "null-runtime", "runtime-short", "runtime-minor", "runtime-reserved",
            "null-complete", "null-state-get", "null-state-set", "null-next", "next-short", "next-minor",
            "next-reserved", "null-start", "null-poll", "null-cancel", "null-release"):
        directory = EVIDENCE / mode
        value = command(PROFILE, [INPUTS / "mods/g06/a/v1/payload.so", mode], directory,
                        binary=INPUTS / "probes/cm-sdk-c-abi")
        row = json.loads(value["stdout"])
        assert row["status"] == "pass" and row["caller_canaries"]
        assert (row["host_size"], row["services_size"], row["output_size"]) == (96, 48, 40)
        results.append({"mode": mode, "result": row, "command": value["command"]})
    return report(0, "c_consumer", results)


def case_abi_manifest():
    results = []
    for name, field, value in (
            ("major", ("compat", "abi_major"), 3), ("future", ("compat", "abi_minor_min"), 4),
            ("old-table", ("compat", "abi_minor_max"), 2), ("api", ("compat", "host_api_min"), "99.0.0"),
            ("undeclared-cap", ("compat", "required_capabilities"), []),
            ("reserved-route", ("commands", "entries", 0, "route"), 0),
            ("duplicate-route", ("commands", "entries", 1, "route"), 3),
            ("input-policy", ("commands", "entries", 0, "input"), "unbounded"),
            ("section", ("commands", "entries", 0, "section"), "core"),
            ("unknown-field", ("commands", "unexpected"), True)):
        home = install(PROFILE / name)
        change(home, "sdk-a", field, value)
        result = command(home, ["cm", "--home", home, "doctor"], EVIDENCE / name, good=False)
        no_native(result)
        results.append({"case": name, "result": result})
    return report(0, "manifest_rejections", results)


def case_abi_buffers():
    return report(0, "caller_buffer_capacity_and_canaries", protocol("poll-bound"))


def case_tool_base():
    return report(1, "base_real_handler", tool_run(variants=()))


def case_tool_next_once():
    value = tool_run()
    starts = [row for row in value["mods"] if row["event"] == "next-start"]
    assert len(starts) == 1
    return report(1, "one_saved_original", value)


def case_tool_next_twice():
    home = install(PROFILE)
    value = real(home, EVIDENCE / "real", mode="next-twice", good=False)
    assert value["original_count"] <= 1
    assert any(row["event"] == "repeat-next" and row["code"] == 7 for row in value["mods"])
    return report(1, "repeat_rejected", value)


def case_tool_zero_short():
    return report(1, "zero_next_short_circuit", tool_run(mode="zero", expected=0))


def case_tool_replacement():
    return report(1, "replacement_short_circuit", tool_run(variants=("a/replacement",), mode="replacement", expected=0))


def case_tool_duplicate_actual_name():
    home = install(PROFILE)
    change(home, "sdk-a", ("contributions", 0, "kind"), "tool")
    change(home, "sdk-a", ("contributions", 0, "capability"), "runtime.tool.v1")
    return report(1, "ordinary_tool_cannot_replace_builtin", reject(home))


def case_tool_reserved_name():
    return report(1, "reserved_command_name", preflight_change(("commands", "entries", 0, "name"), "help"))


def case_tool_missing_target():
    return report(1, "unsupported_original_target", preflight_change(("contributions", 0, "resource"), "missing_builtin"))


def case_tool_stale_token():
    return report(1, "stale_generation", protocol("tool-stale-token"))


def case_tool_foreign_owner():
    return report(1, "foreign_owner_does_not_cancel_owner", protocol("tool-foreign-owner"))


def case_cancel_before():
    return report(2, "cancel_before_consumption", protocol("cancel-before"))


def case_cancel_queued():
    return report(2, "cancel_before_native_worker_starts_saved_work", protocol("cancel-queued"))


def case_cancel_running():
    return report(2, "cancel_running_child", protocol("cancel-running"))


def case_cancel_after_complete():
    return report(2, "cancel_after_terminal_is_inert", protocol("cancel-after-complete"))


def case_late_complete():
    value = protocol("late-complete")
    assert any(row["event"] == "runtime-complete" and row["detail"]["code"] == 8 for row in value["native"])
    return report(2, "late_success_after_cancel_is_rejected", value)


def case_duplicate_complete():
    value = protocol("duplicate-complete")
    completions = [row["detail"]["code"] for row in value["native"] if row["event"] == "runtime-complete"]
    assert completions == [0, 7], completions
    return report(2, "duplicate_completion_delivered_once", value)


def case_drop_parent():
    return report(2, "drop_parent_future_cancels_child", protocol("drop-parent"))


def case_release_pending():
    return report(2, "released_handle_stale_before_physical_drain", protocol("release-pending"))


def case_noncooperative():
    home = install(PROFILE)
    value = command(home, ["cm", "--home", home, "run", "sdk-a__hello"], EVIDENCE / "pinned", good=False,
                    extra={"CM_SEAMS_MODE": "noncooperative", "CM_SEAMS_MODE_KIND": "17"}, timeout=100)
    settled(EVIDENCE / "pinned", pinned=True)
    assert any(row["event"] == "runtime-request-cancel" and row["detail"]["timeout"] for row in value["native"])
    assert any(row["event"] == "waiting" for row in value["mods"])
    return report(2, "noncooperative_library_retained_until_process_exit", value)


def case_exit_race():
    value = protocol("exit-race")
    regression = mod_manifest.read(Path("/fixture/g06-shutdown-regression.json"))
    assert regression["status"] == "pass" and len(regression["scenarios"]) == 6
    return report(2, "exit_race_and_original_six_cases", {"new_continuation": value, "original_regression": regression})


def ordered(reverse=False):
    value = tool_run(variants=("a/v1", "b/v1"), reverse=reverse)
    enters = [row["owner"] for row in value["mods"] if row["event"] == "dispatch" and row["kind"] == 15]
    exits = [row["owner"] for row in value["mods"] if row["event"] == "next-ready"]
    assert enters == ["sdk-a", "sdk-b"] and exits == ["sdk-b", "sdk-a"], value
    actual = [row["event"] for row in value["native"] if row["event"].startswith("runtime-original-tool-")]
    assert actual == ["runtime-original-tool-start", "runtime-original-tool-end"]
    return value


def case_order_ab():
    return report(3, "declared_dag_order", ordered())


def case_order_discovery_reversed():
    return report(3, "discovery_order_cannot_replace_plan_order", ordered(reverse=True))


def case_order_error():
    return report(3, "required_wrapper_error", tool_run(variants=("a/v1", "b/v1"), mode="mod-error", good=False))


def case_order_deadline():
    value = tool_run(variants=("a/v1", "b/v1"), mode="noncooperative", good=False)
    assert any(row["event"] == "runtime-request-cancel" and row["detail"]["timeout"] for row in value["native"])
    return report(3, "deadline_is_failure_and_retains_unquiet_workers", value)


def case_order_short():
    value = tool_run(variants=("a/v1", "b/v1"), mode="zero", expected=0)
    assert [row["owner"] for row in value["mods"] if row["event"] == "dispatch" and row["kind"] == 15] == ["sdk-a"]
    return report(3, "outer_short_circuit", value)


def case_order_reentry():
    value = protocol("order-reentry")
    rows = [row["detail"] for row in value["native"] if row["event"] == "runtime-native-reentry-probe"]
    assert rows and all(not row["callback_entered"] and row["error"] == "reentrant native callback rejected" for row in rows)
    return report(3, "ordinary_gate_reentry_rejected", value)


def case_order_cycle():
    home = install(PROFILE, ("a/v1", "b/v1"))
    change(home, "sdk-a", ("contributions", 0, "order_before"), ["sdk-b::around"])
    change(home, "sdk-b", ("contributions", 0, "order_before"), ["sdk-a::around"])
    return report(3, "cycle_preflight", reject(home))


def conflict(variants):
    home = install(PROFILE, variants)
    value = reject(home)
    assert "sdk-b" in value["stderr"] or any("sdk-b" in json.dumps(row) for row in value["native"])
    return value


def case_replacement_conflict():
    return report(3, "two_replacements_rejected_before_native", conflict(("a/replacement", "b/replacement")))


def case_replacement_mixed_conflict():
    return report(3, "unsupported_mixed_composition_rejected", conflict(("a/replacement", "b/v1")))


def stream_trace(value):
    streams = {}
    for row in value["mods"]:
        if row["event"] == "dispatch" and row["kind"] == 16:
            payload = json.loads(bytes.fromhex(row["input_hex"]))
            key = (row["owner"], payload["request_id"], payload["attempt"])
            streams.setdefault(key, []).append(payload)
            assert row["thread"] and row["turn"], "Stream inferred scope instead of using actual Core scope"
    assert streams
    for rows in streams.values():
        assert [row["sequence"] for row in rows] == list(range(1, len(rows) + 1))
        assert all(set(row) == {"version", "request_id", "attempt", "sequence", "event"} and row["version"] == 1 for row in rows)
    active = {}
    high_water = 0
    stream_handles = {(row["owner"], row["request"]) for row in value["mods"]
        if row["event"] == "dispatch" and row["kind"] == 16}
    for row in value["mods"]:
        key = (row["owner"], row["request"])
        if key not in stream_handles:
            continue
        if row["event"] == "dispatch":
            active[row["owner"]] = active.get(row["owner"], 0) + 1
            high_water = max(high_water, active[row["owner"]])
        elif row["event"] == "complete":
            active[row["owner"]] -= 1
    assert high_water == 1 and all(count == 0 for count in active.values())
    return {"streams": [{"owner": key[0], "request_id": key[1], "attempt": key[2], "metadata": rows}
        for key, rows in streams.items()], "max_in_flight_per_owner": high_water,
        "provider_events_sha256": runtime_cases.digest(value["provider_events"]), "execution": value}


def case_stream_order():
    home = install(PROFILE)
    value = real(home, EVIDENCE / "stream", tool=False)
    result = stream_trace(value)
    kinds = [row["event"]["kind"] for row in decoded(EVIDENCE / "stream") for row in [row["input"]]]
    assert kinds.index("created") < kinds.index("text_delta") < kinds.index("completed"), kinds
    return report(4, "ordered_unchanged_metadata_and_text", result)


def case_stream_tool_call():
    value = tool_run()
    result = stream_trace(value)
    kinds = [row["event"]["kind"] for row in decoded(EVIDENCE / "real") for row in [row["input"]]]
    assert kinds.index("tool_call_added") < kinds.index("tool_call_done")
    deltas = [row for row in value["provider_events"] if row["event"]["type"] == "response.function_call_arguments.delta"]
    assert len(deltas) == 2 and "tool_call_delta" not in kinds
    actual = [row for row in value["native"] if row["event"] == "runtime-original-tool-start"]
    assert len(actual) == 1 and actual[0]["detail"]["call_id"] == "sdk-real-call"
    return report(4, "generated_tool_boundary_and_actual_handler_are_distinct", result)


def case_stream_slow_mod():
    value = protocol("stream-probe-slow-mod")
    assert value["protocol"]["in_flight_limit"] == 1
    return report(4, "one_upstream_poll_while_ack_is_paused", value)


def case_stream_slow_consumer():
    value = protocol("stream-probe-slow-consumer")
    assert value["protocol"]["upstream_polls"] == 4
    return report(4, "no_prefetch_without_consumer_demand", value)


def case_stream_bound():
    home = install(PROFILE)
    value = real(home, EVIDENCE / "stream", tool=False, chunks=512)
    result = stream_trace(value)
    deltas = [row["event"]["bytes"] for row in decoded(EVIDENCE / "stream")
              for row in [row["input"]] if row["event"]["kind"] == "text_delta"]
    assert len(deltas) == 512 and set(deltas) == {len("CM_G06_STREAM")}
    assert all(len(json.dumps(row["input"]).encode()) < 4096 for row in decoded(EVIDENCE / "stream"))
    return report(4, "bounded_metadata_for_many_original_deltas", result)


def case_stream_mod_error():
    home = install(PROFILE)
    value = real(home, EVIDENCE / "stream", tool=False, mode="mod-error", good=False)
    assert any(row["event"] == "runtime-scope-failed" for row in value["native"])
    return report(4, "required_observer_failure_is_terminal", value)


def case_stream_drop():
    value = protocol("stream-probe-drop")
    assert value["protocol"]["upstream_dropped"] and value["protocol"]["upstream_polls"] == 1
    return report(4, "drop_cancels_native_and_drops_upstream", value)


def case_stream_turn_cancel():
    return report(4, "actual_scope_close_cancels_pending_ack", protocol("stream-probe-turn-cancel"))


def case_stream_late_ack():
    value = protocol("stream-probe-late-ack")
    assert any(row["event"] == "runtime-complete" and row["detail"]["code"] == 8 for row in value["native"])
    return report(4, "late_ack_does_not_revive_stream", value)


def case_stream_retry_scope():
    home = install(PROFILE)
    value = real(home, EVIDENCE / "stream", tool=False, provider_mode="retry")
    result = stream_trace(value)
    groups = result["streams"]
    assert len({row["request_id"] for row in groups}) == 1 and len({row["attempt"] for row in groups}) >= 2, groups
    assert len(value["provider_requests"]) >= 2
    return report(4, "logical_request_retained_across_transport_retry", result)


def case_cli_help():
    home = install(PROFILE)
    results = []
    for index, args in enumerate((["cm", "--home", home, "run", "--help"],
            ["cm", "--home", home, "run", "sdk-a__hello", "--help"],
            ["cm", "--home", home, "list"], ["cm", "--home", home, "doctor"], ["--help"])):
        value = command(home, args, EVIDENCE / str(index))
        no_native(value)
        if index < 2:
            assert "sdk-a__impossible_help_probe" in value["stdout"]
        results.append(value)
    return report(5, "metadata_help_and_existing_root_commands", results)


def case_cli_completion():
    home = install(PROFILE)
    results = {}
    for shell in ("bash", "zsh", "fish", "powershell", "elvish"):
        value = command(home, ["completion", shell], EVIDENCE / shell)
        no_native(value)
        assert "sdk-a__hello" in value["stdout"]
        results[shell] = value
    script = WORK / "completion.bash"
    script.write_text(results["bash"]["stdout"])
    argv = ["/bin/bash", "--noprofile", "--norc", "-c",
        'source "$1"; COMP_WORDS=(codex cm run sdk-a); COMP_CWORD=3; _codex codex sdk-a run; printf "%s\\n" "${COMPREPLY[@]}"; '
        'printf "CM_G06_CHILD\\n"; COMP_WORDS=(codex cm run sdk-a__hello --h); COMP_CWORD=4; _codex codex --h sdk-a__hello; printf "%s\\n" "${COMPREPLY[@]}"',
        "cm-completion-test", str(script)]
    run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=30,
                         env=environment(home, EVIDENCE / "bash-real"))
    assert "sdk-a__hello" in run.stdout.splitlines(), run.stdout
    assert run.stdout.split("CM_G06_CHILD\n")[1].splitlines() == ["--home", "--help"], run.stdout
    no_native(events(EVIDENCE / "bash-real"))
    return report(5, "generated_shells_and_actual_bash_completion", {"scripts": results, "bash": {"command": argv, "stdout": run.stdout}})


def case_cli_parse_dispatch():
    home = install(PROFILE)
    value = command(home, ["cm", "--home", home, "run", "sdk-a__hello", "one UTF-8 输入"], EVIDENCE / "cli")
    output = json.loads(value["stdout"])
    assert output["command"] == "sdk-a__hello" and "sdk-a author-v1" in output["text"]
    requests = decoded(EVIDENCE / "cli", kind=17)
    assert len(requests) == 1 and requests[0]["input"] == {"version": 1, "input": "one UTF-8 输入"}
    assert requests[0]["thread"] == requests[0]["turn"] == requests[0]["call"] == ""
    settled(EVIDENCE / "cli")
    return report(5, "real_clap_to_native_command", value)


def case_cli_unknown_args():
    home = install(PROFILE)
    results = []
    for index, args in enumerate((["missing"], ["sdk-a__hello", "one", "two"],
            ["sdk-a__hello", "--execute-anything"], ["sdk-a__hello", "x" * 8193])):
        value = command(home, ["cm", "--home", home, "run", *args], EVIDENCE / str(index), good=False)
        no_native(value)
        results.append(value)
    return report(5, "finite_argument_contract", results)


def case_cli_profile():
    home = install(PROFILE)
    mod_manifest.write_toml(home / "cm-runtime.toml", {"format_version": 2, "enabled": ["sdk-a"], "profiles": {"named": {"mods": {}}}})
    valid = command(home, ["--cm-profile", "named", "cm", "--home", home, "run", "sdk-a__hello"], EVIDENCE / "valid")
    bad = command(home, ["--cm-profile", "missing", "cm", "--home", home, "run", "--help"], EVIDENCE / "invalid", good=False)
    no_native(bad)
    return report(5, "same_profile_resolution_for_parse_and_execution", {"valid": valid, "invalid": bad})


def case_command_name_conflict():
    home = install(PROFILE, ("a/v1", "b/v1"))
    change(home, "sdk-a", ("commands", "entries", 0, "name"), "sdk-b__hello")
    return report(5, "foreign_namespace_cannot_hide_duplicate_command", reject(home))


def case_command_actual_drift():
    home = install(PROFILE)
    change(home, "sdk-a", ("commands", "entries", 0, "route"), 99)
    value = command(home, ["cm", "--home", home, "run", "sdk-a__hello"], EVIDENCE / "actual", good=False)
    assert any(row["event"] == "constructor" for row in value["mods"])
    assert not any(row["event"] in ("init", "dispatch") for row in value["mods"])
    return report(5, "actual_native_route_checked_before_init", value)


def tui_notice(*, reviewed):
    review = module("review-before-send/driver.py")
    PROFILE.mkdir(parents=True, exist_ok=True)
    home = PROFILE / "tui"
    installed = command(home, ["cm", "--home", home, "install", INPUTS / "mods/g06/a/v1"], EVIDENCE / "install-a")
    no_native(installed)
    if reviewed:
        installed = command(home, ["cm", "--home", home, "install", INPUTS / "mods/g02b/review-before-send"],
                            EVIDENCE / "install-b")
        no_native(installed)
    directory = EVIDENCE / "pty"
    terminal = review.Terminal("g06", "notice", home, reviewed=reviewed, directory=directory,
        extra_env={"CM_SEAMS_EVENTS": str(directory / "events.jsonl")})
    listener = None
    try:
        if reviewed:
            terminal.review("/sdk-a__notice")
            terminal.send(b"\r\t\r")
            terminal.quiet()
            assert not decoded(directory, kind=18)
            terminal.send("y")
        else:
            terminal.send("/sdk-a__notice")
            terminal.wait(lambda: terminal.managed.tui_text_visible(terminal.output, "/sdk-a__notice"), "slash input rendered")
            # Start the upstream paste window after the input is rendered.
            time.sleep(0.2)
            terminal.send(b"\r")
        terminal.wait(lambda: any(row["event"] == "tui-command-applied" for row in terminal.native()), "actual UI owner applied notice")
        terminal.wait(lambda: terminal.managed.tui_text_visible(terminal.output, "sdk-a UI notice-v1"), "bounded UI notice visible")
        assert len(decoded(directory, kind=18)) == 1
        assert not terminal.provider.requests, "A native notice must not send a model turn"
        listener = terminal.managed.tui_mcp_listener(terminal.process.pid)
        if reviewed:
            terminal.review("/quit")
            terminal.send("y")
        else:
            terminal.send("/quit")
            terminal.wait(lambda: terminal.managed.tui_text_visible(terminal.output, "/quit"), "quit input rendered")
            time.sleep(0.2)
            terminal.send(b"\r")
        terminal.process.wait(timeout=45)
        assert terminal.process.returncode == 0
        assert sum(row["event"] == "tui-command-applied" for row in terminal.native()) == 1
        value = {"production_cli_sha256": mod_manifest.sha(BINARY), "command": terminal.command,
            "return_code": terminal.process.returncode, "reviewed": reviewed, "model_requests": terminal.provider.requests,
            "applied_once": True, "tui_mcp_listener": listener, **settled(directory)}
        assert any(row["event"] == "stopped" for row in value["native"])
        return value
    finally:
        terminal.close(False)
        if listener is not None:
            record = json.loads((directory / "result.json").read_text())
            record["tui_mcp_listener"] = listener
            mod_manifest.write(directory / "result.json", record)


def case_tui_slash():
    return report(5, "actual_pty_slash_command", tui_notice(reviewed=False))


def case_tui_ui_owner():
    return report(5, "g02b_y_review_retained_for_sdk_command", {"pty": tui_notice(reviewed=True), "owner": protocol("tui-ui-owner")})


def case_tui_wrong_thread():
    return report(5, "wrong_thread_cannot_apply_or_consume_completion", protocol("tui-wrong-thread"))


def case_tui_stale_owner():
    return report(5, "replacement_owner_cannot_apply_previous_notice", protocol("tui-stale-owner"))


def case_tui_cancel():
    return report(5, "closed_owner_cannot_apply_pending_notice", protocol("tui-cancel"))


def case_independent_versions():
    frozen = mod_manifest.sha(BINARY)
    results = []
    for owner, version in (("a", "v1"), ("a", "v2"), ("b", "v1"), ("b", "v2")):
        home = install(PROFILE / (owner + version), (owner + "/" + version,))
        value = command(home, ["cm", "--home", home, "run", "sdk-" + owner + "__hello"],
            EVIDENCE / (owner + version))
        assert "author-" + version in json.loads(value["stdout"])["text"]
        assert mod_manifest.sha(BINARY) == frozen
        results.append(value)
    home = install(PROFILE / "mixed", ("a/v2", "b/v1"))
    for owner, version in (("a", "v2"), ("b", "v1")):
        value = command(home, ["cm", "--home", home, "run", "sdk-" + owner + "__hello"],
            EVIDENCE / ("mixed-" + owner))
        assert "author-" + version in json.loads(value["stdout"])["text"]
        results.append(value)
    producer = mod_manifest.read(Path("/fixture/g06-producer.json"))
    assert producer["host_sha256"] == frozen
    hashes = {key: value["payload_sha256"] for key, value in producer["authors"].items()}
    assert hashes["a/v1"] != hashes["a/v2"] and hashes["b/v1"] != hashes["b/v2"]
    return report(6, "independent_author_versions_on_one_frozen_host", {
        "host_sha256": frozen, "producer": producer, "runs": results, "installer_builds": 0})


def case_independent_disable_delete():
    home = install(PROFILE, ("a/v1", "b/v1"))
    before = command(home, ["cm", "--home", home, "run", "sdk-a__hello"], EVIDENCE / "before")
    mod_manifest.selection(home, ["sdk-b"])
    disabled = command(home, ["cm", "--home", home, "run", "sdk-b__hello"], EVIDENCE / "disabled")
    assert all(row["owner"] == "sdk-b" for row in disabled["mods"])
    shutil.rmtree(home / "mods/0-a-v1")
    deleted = command(home, ["cm", "--home", home, "run", "sdk-b__hello"], EVIDENCE / "deleted")
    assert all(row["owner"] == "sdk-b" for row in deleted["mods"])
    shutil.copytree(INPUTS / "mods/g06/a/v2", home / "mods/new-a")
    mod_manifest.selection(home, ["sdk-a", "sdk-b"])
    restarted = command(home, ["cm", "--home", home, "run", "sdk-a__hello"], EVIDENCE / "restarted")
    assert "author-v2" in json.loads(restarted["stdout"])["text"]
    assert len({row["binary_sha256"] for row in (before, disabled, deleted, restarted)}) == 1
    return report(6, "disable_delete_and_fresh_process_update", {
        "before": before, "disabled": disabled, "deleted": deleted, "restarted": restarted})


def case_legacy_abc():
    home = PROFILE / "old-ac"
    home.mkdir(parents=True)
    owners = ("org.example.turn-budget", "org.example.tool-concurrency")
    for owner, path in zip(owners, ("g02a/turn-budget", "g03/tool-concurrency")):
        shutil.copytree(INPUTS / "mods" / path, home / "mods" / owner)
        fields = tomllib.loads((home / "mods" / owner / "mod.toml").read_text())
        assert fields["compat"]["abi_minor_min"] == 2
    mod_manifest.selection(home, list(owners))
    ac = real(home, EVIDENCE / "old-ac")
    assert ac["original_count"] == 1
    kinds = {row["detail"]["event_kind"] for row in ac["native"] if row["event"] == "runtime-request"}
    assert {12, 14} <= kinds, kinds
    b = tui_notice(reviewed=True)
    return report(6, "old_2_2_a_b_c_individual_compatibility", {
        "a_and_c_core": ac, "b_reviewed_tui": b, "parent_integrated_abc_acceptance": False})


def case_old_host_reject():
    home = install(PROFILE)
    old = INPUTS / "upgrade-baseline/host/bin/codex"
    value = command(home, ["cm", "--home", home, "doctor"], EVIDENCE / "old", binary=old, good=False)
    no_native(value)
    return report(6, "older_frozen_host_rejects_new_2_3_metadata", value)


def case_capability_boundary():
    home = install(PROFILE)
    change(home, "sdk-a", ("compat", "required_capabilities"), ["core.unsupported_provider_rewrite.v1"])
    value = reject(home)
    return report(6, "unsupported_capability_is_not_silently_granted", value)


@ci_progress.case()
def matrix(case):
    runtime_cases.enter(globals(), "g06", case)
    EVIDENCE.mkdir(parents=True)
    WORK.mkdir(parents=True)
    value = globals()[runtime_cases.function(case, "g06")]()
    runtime_cases.finish("g06", case, value, REPORTS)


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "matrix"
    matrix(sys.argv[2])
