#!/usr/bin/env python3
"""Compiler-free G01 transactions; real CLI behavior and private probes stay distinct."""
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import tomllib

sys.path.insert(0, "/fixture/ci/scripts")
sys.path.insert(0, "/fixture/fixtures/native-loader")
import ci_progress
import core_acceptance as core
import mod_manifest
import runtime_cases
from runtime_hooks import REPORTS

INPUTS = Path("/inputs")
WORK = Path("/work")
PROFILE = Path("/profile")
EVIDENCE = Path("/evidence")
BINARY = INPUTS / "host/bin/codex"
PROBE = INPUTS / "probes/cm-hook-policy"


def report(index, key, value):
    rows = [{} for _ in REPORTS]
    rows[index] = {key: value}
    return rows


def producer():
    return mod_manifest.read(INPUTS / "producer.json")


def install(home, variants=("a/normal", "b/normal"), *, probe=False, reverse=False):
    home.mkdir(parents=True, exist_ok=True)
    selected = []
    for index, variant in enumerate(reversed(variants) if reverse else variants):
        package = home / "mods" / (str(index) + "-" + variant.replace("/", "-"))
        shutil.copytree(INPUTS / "mods/g01" / variant, package)
        fields = tomllib.loads((package / "mod.toml").read_text())
        # The reused composition payload requires a version marker in its config.
        fields["config"] = {"schema_version": 1,
            "schema": {"type": "object", "additionalProperties": False, "required": ["format_version"],
                "properties": {"format_version": {"type": "integer", "minimum": 3, "maximum": 3}}},
            "defaults": {"format_version": 3}}
        if probe:
            fields["compat"]["exact_host"]["executable_sha256"] = mod_manifest.sha(PROBE)
        mod_manifest.manifest(package, fields)
        selected.append(fields["id"])
    mod_manifest.selection(home, sorted(selected))
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
    return mod_manifest.mutate(home, owner, update)


def environment(home, directory, **extra):
    directory.mkdir(parents=True, exist_ok=True)
    user = directory / "home"
    user.mkdir(exist_ok=True)
    return {"PATH": "/usr/bin:/bin:/inputs/host/codex-path", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "TERM": "dumb", "HOME": str(user), "CODEX_HOME": str(home),
        "CM_NATIVE_TRACE": str(directory / "native.jsonl"),
        "CM_FIXTURE_EVENTS": str(directory / "events.jsonl"), **extra}


def events(directory):
    return {key: core.trace_rows(directory / name) for key, name in
            (("trace", "native.jsonl"), ("mod_events", "events.jsonl"))}


def no_native(value):
    assert not value["mod_events"], "Constructor/entry/init/callback/release executed before rejection"
    assert not any(row["event"] in ("dlopen-start", "entry-start", "init-start", "ready")
                   for row in value["trace"]), value


def reject(home, *, binary=BINARY, field=None, code=None):
    directory = EVIDENCE / "rejection"
    command = ([str(binary), "exec", "--skip-git-repo-check", "--json", "must never start"]
               if binary == BINARY else [str(binary), "cm", "--home", str(home), "doctor"])
    result = subprocess.run(command, env=environment(home, directory), capture_output=True, text=True, timeout=60)
    value = {"command": command, "return_code": result.returncode, **events(directory)}
    (directory / "stdout.log").write_text(result.stdout)
    (directory / "stderr.log").write_text(result.stderr)
    mod_manifest.write(directory / "result.json", value)
    errors = [row["detail"] for row in value["trace"] if row["event"] == "startup-failed"]
    if not errors:
        errors = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
    assert result.returncode != 0 and errors, result.stderr
    error = errors[-1]
    value["error"] = error
    mod_manifest.write(directory / "result.json", value)
    assert error["already_native_executed"] is False, value
    if field:
        assert error["field"] == field, error
    if code:
        assert error["code"] == code, error
    no_native(value)
    assert mod_manifest.sha(BINARY) == producer()["host"]["executable_sha256"]
    return value


def binding(field, value, *, expected=None):
    home = install(PROFILE, ("a/normal",))
    change(home, "compose-a", ("compat", "exact_host", field), value)
    return report(1, field, reject(home, field=expected or "compat.exact_host." + field))


def case_qualification_matrix():
    result = subprocess.run([str(BINARY), "cm-host-identity"], text=True, capture_output=True, check=True, timeout=30)
    identity = json.loads(result.stdout)
    frozen = producer()["host"]
    assert identity == frozen["host_identity"]
    assert mod_manifest.sha(BINARY) == frozen["executable_sha256"]
    assert runtime_cases.digest(identity["patch_map"]) == identity["patch_map_sha256"]
    descriptor = identity["patch_map"]["descriptor"]
    assert descriptor["backend"] == "prepared_slots" and descriptor["target"] == mod_manifest.TARGET
    assert [slot["id"] for slot in descriptor["slots"]] == ["core.tool_parallel_eligibility.v1"]
    assert identity["patch_map"]["build"]["flags"] == identity["inputs"]["flags"]
    prepared = mod_manifest.read(Path("/fixture/g01-producer.json"))
    assert prepared["original_query_count"] == prepared["bridge_count"] == 1
    return report(0, "embedded_identity", {"identity": identity, "executable_sha256": mod_manifest.sha(BINARY),
        "source_contract": prepared, "boundary": "source fingerprints and exact ELF; no detour machine-code proof"})


def case_binding_build_id():
    return binding("build_id", "sha256:" + "0" * 64)


def case_binding_executable():
    return binding("executable_sha256", "0" * 64)


def case_binding_map():
    return binding("patch_map_sha256", "0" * 64)


def case_binding_map_ordinary():
    home = install(PROFILE, ("a/normal",))
    change(home, "compose-a", ("kind",), "exact_host")
    valid = mod_manifest.metadata(BINARY, home, ["doctor"], evidence=EVIDENCE / "valid-map.json")
    assert valid["return_code"] == 0
    change(home, "compose-a", ("compat", "exact_host", "patch_map_sha256"), "0" * 64)
    return report(1, "ordinary_exact_host_map", {"valid": valid,
        "mismatch": reject(home, field="compat.exact_host.patch_map_sha256")})


def case_binding_map_missing():
    missing = binding("patch_map_sha256", None, expected="compat.exact_host")
    return report(1, "missing_patch_map_sha256", missing[1]["patch_map_sha256"])


def case_binding_other_host():
    home = install(PROFILE, ("a/normal",))
    prior = mod_manifest.read(Path("/fixture/g01-producer.json"))["previous_host"]
    binary = Path(prior["path"])
    assert binary.name == BINARY.name and mod_manifest.sha(binary) == prior["executable_sha256"]
    assert mod_manifest.sha(binary) != mod_manifest.sha(BINARY)
    return report(1, "actual_other_elf", {"previous": prior, "rejection": reject(home, binary=binary)})


def case_binding_abi():
    home = install(PROFILE, ("a/normal",))
    change(home, "compose-a", ("compat", "abi_major"), 1)
    change(home, "compose-a", ("binary", "entry"), "cm_mod_entry_v1")
    return report(1, "abi", reject(home))


def case_binding_target():
    from cm_platforms import foreign_linux_target
    home = install(PROFILE, ("a/normal",))
    change(home, "compose-a", ("binary", "target"), foreign_linux_target())
    return report(1, "wrong_target", reject(home))


def case_binding_slot():
    home = install(PROFILE, ("a/normal",))
    change(home, "compose-a", ("contributions", 0, "resource"), "core.tool_parallel_eligibility.v2")
    return report(1, "wrong_slot", reject(home, code="hook_unsupported"))


def case_binding_missing_target():
    home = install(PROFILE, ("a/normal",))
    change(home, "compose-a", ("compat", "required_capabilities"), ["core.missing_target.v1"])
    return report(1, "missing_target", reject(home, code="hook_unsupported"))


def read_line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(30), "Missing explicit child barrier"
        line = process.stdout.readline()
        assert line, "Child exited before barrier"
        return line


def case_binding_drift():
    home = install(PROFILE, probe=True)
    directory = EVIDENCE / "prepared"
    with (EVIDENCE / "stderr.log").open("w") as stderr:
        process = subprocess.Popen([str(PROBE), str(home)], text=True, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=stderr, env=environment(home, directory, CM_PROBE_ACTION="prepared"))
        try:
            plan = json.loads(read_line(process))
            no_native(events(directory))
            change(home, "compose-a", ("version",), "9.9.9")
            output, _ = process.communicate("commit\n", timeout=30)
            assert process.returncode != 0
            value = {"plan": plan, "return_code": process.returncode, "stdout": output,
                "stderr": (EVIDENCE / "stderr.log").read_text(),
                "separate_private_probe": True, **events(directory)}
            assert "input_drift" in value["stderr"], value
            no_native(value)
            mod_manifest.write(directory / "result.json", value)
            return report(1, "prepared_input_drift", value)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def case_binding_aslr():
    home = install(PROFILE)
    records = []

    def observe(process):
        executable = os.readlink("/proc/" + str(process.pid) + "/exe")
        maps = Path("/proc", str(process.pid), "maps").read_text().splitlines()
        selected = [line for line in maps if line.split()[-1] == executable]
        base = next(line.split("-", 1)[0] for line in selected if line.split()[2] == "00000000")
        assert Path(executable) == BINARY and mod_manifest.sha(Path(executable)) == producer()["host"]["executable_sha256"]
        records.append({"pid": process.pid, "base": base, "executable": executable, "maps": selected})
        mod_manifest.write(EVIDENCE / "aslr.json", records)

    for index in range(3):
        result = business("aslr-" + str(index), home, on_handler=observe)
        records[-1]["core_behavior"] = result
    mod_manifest.write(EVIDENCE / "aslr.json", records)
    assert len({row["base"] for row in records}) >= 2, "ASLR variation not observed; qualification is blocked"
    return report(1, "aslr", {"fresh_processes": records, "same_host_sha256": mod_manifest.sha(BINARY),
        "aslr_disabled": False})


def business(name, home, *, loaded=True, scenario="parallel", mode="", restrictive=True, on_handler=None):
    directory = EVIDENCE / name
    result = core.run_case(Path("/fixture"), directory, BINARY, home, loaded,
        scenario=scenario, restrictive=restrictive, expected_releases=2 if loaded else 0, sandboxed=True,
        extra_env={"CM_COMPOSE_MODE": mode}, on_handler=on_handler)
    trace = core.trace_rows(directory / "core-trace.jsonl")
    ready = next(row["detail"] for row in trace if row["event"] == "ready")
    frozen = producer()["host"]
    assert ready["plan"]["host"]["executable_sha256"] == frozen["executable_sha256"]
    assert ready["plan"]["host"]["patch_map_sha256"] == frozen["host_identity"]["patch_map_sha256"]
    assert ready["mod_count"] == (2 if loaded else 0)
    if scenario == "parallel":
        for call_id in ("cm-a", "cm-b"):
            assert sum(row["event"] == "policy-decision" and row["detail"]["call_id"] == call_id for row in trace) == 1
            assert sum(row["event"] == "handler-started" and row["detail"]["call_id"] == call_id for row in trace) == 1
            assert sum(row["event"] == "handler-finished" and row["detail"]["call_id"] == call_id for row in trace) == 1
    return {**result, "runtime_plan_sha256": ready["plan_sha256"], "runtime_plan": ready["plan"],
        "hook_trace": [row for row in trace if row["event"].startswith(("hook-", "around-", "policy-"))]}


def case_core_baseline():
    PROFILE.mkdir(parents=True)
    return report(2, "baseline", business("core-baseline", PROFILE, loaded=False, restrictive=False))


def case_core_around():
    home = install(PROFILE)
    value = business("core-around", home)
    for call_id in ("cm-a", "cm-b"):
        entered = [row["detail"]["mod"] for row in value["hook_trace"] if row["event"] == "hook-enter"
            and row["detail"]["phase"] == "around" and row["detail"]["call_id"] == call_id]
        assert entered == ["compose-a", "compose-b"], entered
    return report(2, "around", value)


def case_core_short():
    home = install(PROFILE, ("a/short", "b/normal"))
    value = business("core-short", home)
    assert not any(row["event"] == "hook-enter" and row["detail"]["phase"] == "around"
        and row["detail"]["mod"] == "compose-b" for row in value["hook_trace"])
    return report(2, "short_policy_only", value)


def case_core_error():
    home = install(PROFILE)
    return report(2, "error_no_fallback", business("core-error", home,
        scenario="callback-failure", mode="compose-a:before-fail"))


def policy_probe(name, *, action="policy", mode="", success=False):
    home = install(PROFILE / name, probe=True)
    directory = EVIDENCE / name
    command = [str(PROBE), str(home)]
    result = subprocess.run(command, env=environment(home, directory, CM_PROBE_ACTION=action,
        CM_COMPOSE_MODE=mode, CM_TOKEN_FILE=str(WORK / (name + ".token"))),
        text=True, capture_output=True, timeout=45)
    value = {"command": command, "return_code": result.returncode, "stdout": result.stdout,
        "stderr": result.stderr,
        "separate_private_probe": True, "binding_executable_sha256": mod_manifest.sha(PROBE), **events(directory)}
    mod_manifest.write(directory / "result.json", value)
    assert (result.returncode == 0) == success, result.stderr
    if not success:
        assert any(row["event"] == "policy-failed" for row in value["trace"]), value
    assert [row["mod"] for row in value["mod_events"] if row["event"] == "release"] == ["compose-b", "compose-a"]
    return value


def case_next_repeat():
    return report(2, "next_repeat", policy_probe("repeat", mode="compose-a:repeat"))


def case_next_stale_owner():
    return report(2, "next_stale_owner", [policy_probe("stale", action="twice", mode="compose-a:stale"),
        policy_probe("owner", mode="compose-b:cross-owner")])


def case_next_thread():
    return report(2, "next_thread", policy_probe("thread", mode="compose-a:wrong-thread"))


def case_ordinary_reentry():
    previous = mod_manifest.read(Path("/fixture/m02-native-probe.json"))
    value = previous["ordinary_reentry"]
    assert value["status"] == "pass" and value["private_instrumented_test_binary"]
    assert previous["cli_executable_sha256"] == producer()["host"]["executable_sha256"]
    trace = core.trace_rows(Path("/fixture/m02-native-trace.jsonl"))
    attempts = [row for row in trace if row["event"] == "runtime-native-reentry-probe"]
    assert len(attempts) == value["attempts"] > 0
    assert all(not row["detail"]["callback_entered"] for row in attempts)
    return report(2, "ordinary_entry_guard", {**value, "consumer_replayed": False,
        "original_producer": producer()["provenance"], "binary_sha256": previous["binary_sha256"]})


def conflict(mixed):
    home = install(PROFILE, ("a/replacement", "b/replacement"))
    if mixed:
        change(home, "compose-b", ("kind",), "sdk")
        change(home, "compose-b", ("compat", "exact_host"), None)
    result = reject(home, code="exclusive_conflict")
    assert set(result["error"]["related_contributions"]) == {"compose-a::terminal", "compose-b::terminal"}
    second = install(PROFILE / "reverse", ("a/replacement", "b/replacement"), reverse=True)
    if mixed:
        change(second, "compose-b", ("kind",), "sdk")
        change(second, "compose-b", ("compat", "exact_host"), None)
    for owner, priority in (("compose-a", -10), ("compose-b", 10)):
        change(second, owner, ("contributions", 0, "priority"), priority)
    reverse = mod_manifest.metadata(BINARY, second, ["doctor"], success=False, evidence=EVIDENCE / "reverse.json")
    assert reverse["output"]["code"] == "exclusive_conflict"
    assert set(reverse["output"]["related_contributions"]) == set(result["error"]["related_contributions"])
    return {"normal": result, "reverse_discovery": reverse}


def case_conflict_advanced():
    return report(3, "advanced_replacements", conflict(False))


def case_conflict_mixed():
    return report(3, "mixed_replacements", conflict(True))


def case_cancel_before():
    value = policy_probe("cancel-before", action="cancel-before", success=True)
    assert not any(row["event"] == "hook-enter" for row in value["trace"])
    return report(3, "cancel_before", value)


def case_cancel_during():
    return report(3, "cancel_waiting_core", business("cancel-during", install(PROFILE), scenario="cancel-waiting"))


def case_cancel_callback():
    home = install(PROFILE, probe=True)
    directory = EVIDENCE / "cancel-callback"
    directory.mkdir()
    path = directory / "callback.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(30)
        command = [str(PROBE), str(home)]
        with (directory / "stderr.log").open("w") as stderr:
            process = subprocess.Popen(command, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=stderr, env=environment(home, directory, CM_PROBE_ACTION="cancel-after",
                    CM_COMPOSE_MODE="compose-a:hold", CM_FIXTURE_SOCKET=str(path)))
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(30)
                    assert connection.recv(100) == b"callback-entered\n"
                    assert not any(row["event"] == "release" for row in events(directory)["mod_events"])
                    process.stdin.write("continue\n")
                    process.stdin.flush()
                    assert read_line(process).strip() == "cancel-recorded"
                    connection.sendall(b"x")
                output, _ = process.communicate(timeout=30)
                value = {"command": command, "return_code": process.returncode, "stdout": output,
                    "separate_private_probe": True, **events(directory)}
                mod_manifest.write(directory / "result.json", value)
                assert process.returncode == 0
                after = [row["detail"] for row in value["trace"] if row["event"] == "hook-enter" and row["detail"]["phase"] == "after"]
                assert len(after) == 2 and all(row["extra"]["outcome"] == 2 for row in after)
                assert sum(row["event"] == "release" for row in value["mod_events"]) == 2
                return report(3, "cancel_synchronous_callback", value)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def case_restart_disabled():
    home = install(PROFILE)
    before = business("enabled", home)
    mod_manifest.selection(home, [])
    disabled = business("disabled", home, loaded=False, restrictive=False)
    assert before["executable_sha256"] == disabled["executable_sha256"]
    return report(3, "disable_fresh_process", {"enabled": before, "disabled": disabled})


def unsupported(name):
    home = install(PROFILE, ("a/normal",))
    change(home, "compose-a", ("contributions", 0, "resource"), "unsupported." + name)
    return report(4, name, {"requested": name, "status": "unsupported",
        "rejection": reject(home, code="hook_unsupported"), "fallback": False})


def case_unsupported_detour():
    return unsupported("detour")


def case_unsupported_layout():
    return unsupported("rust_layout")


def case_unsupported_inline():
    return unsupported("inlined_function")


def case_unsupported_async():
    return unsupported("async_state_machine")


def case_unsupported_signature():
    return unsupported("signature_match")


@ci_progress.case()
def matrix(case):
    runtime_cases.enter(globals(), "g01", case)
    EVIDENCE.mkdir(parents=True)
    WORK.mkdir(parents=True)
    value = globals()[runtime_cases.function(case, "g01")]()
    runtime_cases.finish("g01", case, value, REPORTS)


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "matrix"
    matrix(sys.argv[2])
