#!/usr/bin/env python3
"""P02 producer/acceptance, only in the fixed independent Actions worker."""
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

import host
from linux_ci import TARGET, cargo_args, execute, load_config, source_file
from record_run import require_hosted_linux

CAPABILITY = "core.tool_parallel_eligibility.v1"
MOD = "fixtures/mods/serial-eligibility"
CHECKS = {
    "CM-P02-AC01": "native-loader-entry.json",
    "CM-P02-AC02": "internal-seam-proof.json",
    "CM-P02-AC03": "native-abi-contract.json",
    "CM-P02-AC04": "preload-rejection.json",
    "CM-P02-AC05": "loader-lifetime.json",
}


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.endswith("}")]


def install(home, library, changes=None):
    package = home / "mods" / "serial-fixture"
    package.mkdir(parents=True)
    payload = package / "payload.so"
    shutil.copyfile(library, payload)
    fields = {"format_version": 1, "id": "serial-fixture", "version": "0.1.0",
              "payload": "payload.so", "payload_size": payload.stat().st_size,
              "payload_sha256": host.sha(payload), "target": TARGET, "abi_major": 1, "abi_minor": 0,
              "required_capabilities": [CAPABILITY], "dependencies": [], "contribution": CAPABILITY}
    fields.update(changes or {})
    (package / "mod.toml").write_text("\n".join(key + " = " + json.dumps(value) for key, value in fields.items()) + "\n")
    return package


def build_fixtures(root, logs):
    cfg = load_config(root)
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    package = Path(os.environ["RUNNER_TEMP"]) / "cm-host-package"
    frozen = host.read(artifact / "evidence/host-baseline-build.json")
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    assert host.manifest_digest(host.manifest(package)) == frozen["package_manifest_sha256"]
    host_env = {**os.environ, "CARGO_TARGET_DIR": str(Path(os.environ["CARGO_TARGET_DIR"]) / "host")}
    adapter_unit = {**cfg["units"][0], "packages": ["codex-core", "codex-exec"]}
    execute(root, logs, "mod-adapter-fmt", ["cargo", "fmt", "--manifest-path", adapter_unit["manifest"],
            "--package", "codex-core", "--package", "codex-exec", "--", "--check"], host_env)
    execute(root, logs, "mod-adapter-clippy",
            cargo_args(adapter_unit, "clippy", cfg, cfg["clippy_profile"]) + ["--lib", "--", "-D", "warnings"], host_env)
    unit = {"id": "serial-mod", "manifest": MOD + "/Cargo.toml", "lockfile": MOD + "/Cargo.lock",
            "packages": ["cm-serial-eligibility-fixture"], "features": []}
    lock_before = host.sha(source_file(root, unit["lockfile"]))
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "mod-fixture"
    assert not target.exists(), "Independent author target must start empty"
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    for phase in ("fmt", "clippy", "test", "build"):
        if phase == "fmt":
            args = ["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"]
        else:
            args = cargo_args(unit, phase, cfg, cfg["build_profile"])
            if phase == "clippy":
                args += ["--all-targets", "--", "-D", "warnings"]
        execute(root, logs, "mod-" + phase, args, env)
    assert host.sha(source_file(root, unit["lockfile"])) == lock_before
    metadata_args = ["cargo", "metadata", "--locked", "--format-version", "1",
                     "--filter-platform", TARGET, "--manifest-path", str(root / unit["manifest"])]
    metadata = json.loads(subprocess.check_output(metadata_args, cwd=root / MOD, env=env, text=True))
    names = {value["name"] for value in metadata["packages"]}
    assert names == {"cm-abi", "cm-serial-eligibility-fixture"}, names
    host_inventory = host.read(package / "dependency-inventory.json")
    assert not any(value["name"] == "cm-serial-eligibility-fixture" for value in host_inventory["packages"])
    library = target / TARGET / cfg["build_profile"] / "libcm_serial_eligibility_fixture.so"
    execute(root, logs, "mod-exports", ["nm", "-D", "--defined-only", str(library)])
    assert any(line.split()[-1:] == ["cm_mod_entry_v1"] for line in (logs / "mod-exports.log").read_text().splitlines())
    published = install(artifact, library)
    shutil.copyfile(root / "crates/cm-abi/include/cm_mod_v1.h", published / "cm_mod_v1.h")
    shutil.copyfile(root / host.HOST / "LICENSE", published / "LICENSE")
    sources = host.manifest(root, [*source_file(root, MOD + "/Cargo.toml").parent.rglob("*"),
                                    *source_file(root, "crates/cm-abi/Cargo.toml").parent.rglob("*")])
    identity = {"source_manifest": sources, "lock_sha256": lock_before, "target": TARGET,
                "profile": cfg["build_profile"], "toolchain": frozen["host_identity"]["inputs"]["toolchain"],
                "flags": frozen["host_identity"]["inputs"]["flags"]}
    receipt = {"status": "pass", "mod_build_id": "sha256:" + host.digest(identity),
               "inputs": identity, "payload_sha256": host.sha(library), "payload": str(published / "payload.so"),
               "target_directory": str(target), "workspace": str(root / MOD), "dependencies": sorted(names),
               "metadata_command": metadata_args, "host_frozen_before_author_build": frozen["executable_sha256"],
               "host_dependency_graph_contains_mod": False}
    host.write(published / "mod-build.json", receipt)
    native = Path(os.environ["RUNNER_TEMP"]) / "cm-native-fixtures"
    native.mkdir()
    for name, flags in (("replacement", []), ("rpath", ["-Wl,-rpath,/tmp/cm-not-allowed"])):
        execute(root, logs, "mod-c-" + name, ["cc", "-shared", "-fPIC", "-march=x86-64", "-mtune=generic",
                str(source_file(root, "fixtures/native-loader/replacement.c")), *flags, "-o", str(native / (name + ".so"))])
    execute(root, logs, "mod-c-layout-build", ["cc", "-std=c11", str(source_file(root, "fixtures/native-loader/layout.c")),
                                             "-o", str(native / "layout")])
    execute(root, logs, "mod-c-layout", [str(native / "layout")])
    layout = json.loads((logs / "mod-c-layout.log").read_text())
    assert layout["mod"] == 72 and layout["policy_offset"] == 48
    assert "linux_x64_layout ... ok" in host.build_log(logs, "host-test").read_text()
    probe_unit = {**cfg["units"][0], "packages": ["cm-runtime"]}
    execute(root, logs, "mod-host-abi-probe-build",
            cargo_args(probe_unit, "build", cfg, cfg["build_profile"]) + ["--example", "native_probe"], host_env)
    snapshot_env = {**host_env, "CM_P02_FIXTURE_LIBRARY": str(library),
                    "CM_P02_REPLACEMENT_LIBRARY": str(native / "replacement.so"),
                    "CM_REPLACEMENT_SENTINEL": str(native / "snapshot-replacement-executed"),
                    "CM_FIXTURE_EVENTS": str(logs / "snapshot-mod-events.jsonl"), "CM_FIXTURE_MODE": ""}
    execute(root, logs, "mod-pinned-snapshot",
            cargo_args(probe_unit, "test", cfg, cfg["test_profile"]) + ["--lib",
                "replacement_and_in_place_edits_cannot_change_preflight_snapshot", "--", "--ignored", "--nocapture", "--test-threads=1"],
            snapshot_env)
    assert "1 passed; 0 failed" in (logs / "mod-pinned-snapshot.log").read_text()
    assert not Path(snapshot_env["CM_REPLACEMENT_SENTINEL"]).exists()
    assert [row["event"] for row in rows(Path(snapshot_env["CM_FIXTURE_EVENTS"]))].count("constructor") == 2
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    assert host.manifest_digest(host.manifest(package)) == frozen["package_manifest_sha256"]
    host.write(logs / "mod-build.json", receipt)


def child_case(directory, command, home, mode="", action="load", expected=0, extra=None):
    directory.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "CODEX_HOME": str(home), "CODEX_SQLITE_HOME": str(home),
           "HOME": str(directory / "home"), "CM_NATIVE_TRACE": str(directory / "trace.jsonl"),
           "CM_FIXTURE_MODE": mode, "CM_FIXTURE_EVENTS": str(directory / "mod-events.jsonl"),
           "CM_PROBE_ACTION": action, **(extra or {})}
    Path(env["HOME"]).mkdir()
    started = time.monotonic()
    with (directory / "stdout.log").open("w") as out, (directory / "stderr.log").open("w") as err:
        process = subprocess.Popen(command, cwd=directory, env=env, stdout=out, stderr=err,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            code = process.wait(timeout=30)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            host.write(directory / "result.json", {
                "command": command, "return_code": process.returncode, "mode": mode, "action": action,
                "elapsed_seconds": time.monotonic() - started,
                "trace": rows(directory / "trace.jsonl"), "mod_events": rows(directory / "mod-events.jsonl"),
            })
    result = {"command": command, "return_code": code, "mode": mode, "action": action,
              "elapsed_seconds": time.monotonic() - started,
              "trace": rows(directory / "trace.jsonl"), "mod_events": rows(directory / "mod-events.jsonl")}
    host.write(directory / "result.json", result)
    if expected == "nonzero":
        assert code != 0, command
    else:
        assert code == expected, (command, code, (directory / "stderr.log").read_text())
    return result


def startup_rejections(cases, binary, library, native):
    results = []
    for name, changes in (
        ("target", {"target": "aarch64-unknown-linux-gnu"}), ("hash", {"payload_sha256": "0" * 64}),
        ("size", {"payload_size": 1}), ("major", {"abi_major": 2}), ("minor", {"abi_minor": 1}),
        ("capability", {"required_capabilities": ["unpublished.capability"]}),
        ("duplicate-capability", {"required_capabilities": [CAPABILITY, CAPABILITY]}),
        ("dependency", {"dependencies": ["missing.mod"]}), ("contribution", {"contribution": "unpublished.seam"}),
        ("absolute", {"payload": "/tmp/payload.so"}), ("parent", {"payload": "../payload.so"}),
        ("oversize", {"payload_size": 64 * 1024 * 1024 + 1}),
    ):
        directory = cases / ("preflight-" + name)
        home = directory / "profile"
        install(home, library, changes)
        result = child_case(directory, [str(binary), "exec", "--skip-git-repo-check", "--json", "must never start"], home, expected="nonzero")
        assert not result["mod_events"], name
        assert not any(row["event"] in ("dlopen-start", "ready") for row in result["trace"])
        assert any(row["event"] == "startup-failed" and not row["detail"]["already_native_executed"] for row in result["trace"])
        assert "thread.started" not in (directory / "stdout.log").read_text()
        results.append({"case": directory.name, **result})
    for name in ("elf-architecture", "elf-truncated", "symlink", "extra-candidate", "rpath", "native-dependency",
                 "unknown-key", "duplicate-key", "manifest-symlink", "payload-hardlink", "root-symlink", "package-symlink"):
        directory = cases / ("preflight-" + name)
        home = directory / "profile"
        package = install(home, native / "rpath.so" if name == "rpath" else library)
        payload = package / "payload.so"
        if name == "elf-architecture":
            data = bytearray(payload.read_bytes())
            data[18:20] = (183).to_bytes(2, "little")
            payload.write_bytes(data)
        elif name == "elf-truncated":
            payload.write_bytes(b"\x7fELF")
        elif name == "symlink":
            payload.unlink()
            payload.symlink_to(library)
        elif name == "extra-candidate":
            (home / "mods/extra").mkdir()
        elif name in ("unknown-key", "duplicate-key"):
            with (package / "mod.toml").open("a") as manifest:
                manifest.write("unknown_field = 1\n" if name == "unknown-key" else "format_version = 1\n")
        elif name == "manifest-symlink":
            manifest = package / "mod.toml"
            manifest.rename(package / "actual.toml")
            manifest.symlink_to(package / "actual.toml")
        elif name == "payload-hardlink":
            os.link(payload, directory / "payload-second-link.so")
        elif name in ("root-symlink", "package-symlink"):
            original = home / "mods" if name == "root-symlink" else package
            actual = home / "actual"
            original.rename(actual)
            original.symlink_to(actual, target_is_directory=True)
        elif name == "native-dependency":
            data = payload.read_bytes()
            assert b"libc.so.6\0" in data
            payload.write_bytes(data.replace(b"libc.so.6\0", b"evil.so.6\0"))
        if name.startswith("elf-") or name == "native-dependency":
            text = (package / "mod.toml").read_text()
            import re
            text = re.sub(r"payload_size = \d+", "payload_size = " + str(payload.stat().st_size), text)
            text = re.sub(r'payload_sha256 = "[0-9a-f]+"', 'payload_sha256 = "' + host.sha(payload) + '"', text)
            (package / "mod.toml").write_text(text)
        sentinel = directory / "replacement-constructor"
        result = child_case(directory, [str(binary), "exec", "--skip-git-repo-check", "--json", "must never start"],
                            home, expected="nonzero", extra={"CM_REPLACEMENT_SENTINEL": str(sentinel)})
        assert not result["mod_events"] and not sentinel.exists()
        assert not any(row["event"] in ("dlopen-start", "ready") for row in result["trace"])
        assert any(row["event"] == "startup-failed" and not row["detail"]["already_native_executed"] for row in result["trace"])
        assert "thread.started" not in (directory / "stdout.log").read_text()
        results.append({"case": directory.name, **result})
    return results


def abi_rejections(cases, binary, probe, library, native):
    entry = []
    for mode in ("short-prefix", "short-table", "wrong-major", "wrong-minor", "null-policy", "null-init",
                 "declaration-drift", "null-view", "huge-view", "invalid-utf8", "reserved", "null-table",
                 "entry-fail", "entry-panic", "entry-status", "init-fail", "init-panic", "no-release"):
        directory = cases / ("abi-" + mode)
        home = directory / "profile"
        install(home, library)
        result = child_case(directory, [str(binary), "exec", "--skip-git-repo-check", "--json", "must never start"],
                            home, mode=mode, expected="nonzero")
        events = [row["event"] for row in result["mod_events"]]
        assert events.count("constructor") == 1, (mode, events)
        assert not any(row["event"] == "ready" for row in result["trace"])
        assert any(row["event"] == "startup-failed" and row["detail"]["already_native_executed"] for row in result["trace"])
        assert "thread.started" not in (directory / "stdout.log").read_text()
        if mode in ("init-fail", "init-panic"):
            assert events.count("release") == 1
        entry.append({"case": directory.name, **result})
    directory = cases / "abi-missing-entry"
    home = directory / "profile"
    install(home, native / "replacement.so")
    sentinel = directory / "missing-entry-constructor"
    result = child_case(directory, [str(binary), "exec", "--skip-git-repo-check", "--json", "must never start"],
                        home, expected="nonzero", extra={"CM_REPLACEMENT_SENTINEL": str(sentinel)})
    assert sentinel.is_file(), "Post-load rejection must admit constructor execution"
    assert any(row["event"] == "startup-failed" and row["detail"]["already_native_executed"] for row in result["trace"])
    entry.append({"case": directory.name, **result})
    callbacks = []
    for mode in ("callback-fail", "callback-panic", "bad-decision", "bad-status", "output-size",
                 "error-length", "error-null", "error-utf8", "error-canary", "output-canary"):
        directory = cases / ("callback-" + mode)
        home = directory / "profile"
        install(home, library)
        result = child_case(directory, [str(probe), str(home)], home, mode=mode, action="policy", expected="nonzero")
        assert any(row["event"] == "policy-failed" for row in result["trace"])
        assert [row["event"] for row in result["mod_events"]].count("release") == 1
        callbacks.append({"case": directory.name, **result})
    for mode in ("release-fail", "release-panic"):
        directory = cases / mode
        home = directory / "profile"
        install(home, library)
        result = child_case(directory, [str(probe), str(home)], home, mode=mode, expected="nonzero")
        assert [row["event"] for row in result["mod_events"]].count("release") == 1
        assert not any(row["event"] == "stopped" for row in result["trace"])
        callbacks.append({"case": directory.name, **result})
    for mode, code in (("abort", -signal.SIGABRT), ("segfault", -signal.SIGSEGV)):
        directory = cases / ("native-" + mode)
        home = directory / "profile"
        install(home, library)
        result = child_case(directory, [str(probe), str(home)], home, mode=mode, action="policy", expected=code)
        assert not any(row["event"] == "stopped" for row in result["trace"])
        callbacks.append({"case": directory.name, "classification": "native-process-failure-not-isolated", **result})
    return entry, callbacks


def lifetime(cases, probe, library):
    results = []
    directory = cases / "cancel-before"
    home = directory / "profile"
    install(home, library)
    result = child_case(directory, [str(probe), str(home)], home, action="cancel-before")
    assert "callback-enter" not in [row["event"] for row in result["mod_events"]]
    results.append(result)
    for action in ("drain", "cancel-after", "stuck"):
        directory = cases / ("lifetime-" + action)
        directory.mkdir(parents=True)
        home = directory / "profile"
        installed = install(home, library)
        listener = socket.socket(socket.AF_UNIX)
        path = directory / "callback.sock"
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(30)
        env = {**os.environ, "CM_NATIVE_TRACE": str(directory / "trace.jsonl"),
               "CM_FIXTURE_MODE": "stuck" if action == "stuck" else "hold",
               "CM_FIXTURE_EVENTS": str(directory / "mod-events.jsonl"), "CM_FIXTURE_SOCKET": str(path),
               "CM_PROBE_ACTION": "policy" if action == "stuck" else action}
        args = [str(probe), str(home)]
        with (directory / "stdout.log").open("w") as out, (directory / "stderr.log").open("w") as err:
            process = subprocess.Popen(args, env=env, stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True)
            watchdog = False
            try:
                with listener.accept()[0] as connection:
                    assert connection.recv(128) == b"callback-entered\n"
                    assert "release" not in [row["event"] for row in rows(directory / "mod-events.jsonl")]
                    # Directory removal changes the next process only; the in-flight callback owns its library.
                    shutil.rmtree(installed)
                    if action == "stuck":
                        try:
                            process.wait(timeout=2)
                            raise AssertionError("Stuck native callback unexpectedly returned")
                        except subprocess.TimeoutExpired:
                            watchdog = True
                            os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.stdin.write(b"continue\n")
                        process.stdin.flush()
                        deadline = time.monotonic() + 20
                        marker = "stopping-requested" if action == "drain" else "cancel-recorded"
                        while True:
                            observed = [row["event"] for row in rows(directory / "trace.jsonl")] if action == "drain" else (directory / "stdout.log").read_text()
                            if marker in observed:
                                break
                            if time.monotonic() > deadline or process.poll() is not None:
                                raise RuntimeError("Missing shutdown/cancellation request barrier")
                            threading.Event().wait(0.01)
                        assert "release" not in [row["event"] for row in rows(directory / "mod-events.jsonl")]
                        connection.sendall(b"R")
                    code = process.wait(timeout=30)
                    assert code == (-signal.SIGKILL if watchdog else 0), code
            finally:
                listener.close()
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        events = [row["event"] for row in rows(directory / "mod-events.jsonl")]
        if not watchdog:
            assert events.count("release") == 1
            native_events = rows(directory / "mod-events.jsonl")
            init_thread = next(row["os_thread"] for row in native_events if row["event"] == "init")
            callback_thread = next(row["os_thread"] for row in native_events if row["event"] == "callback-enter")
            assert init_thread != callback_thread, "Callbacks must not depend on init-thread TLS"
            assert next(row["os_thread"] for row in native_events if row["event"] == "release") == init_thread
            assert events.index("callback-returned-from-barrier") < events.index("release") < events.index("process-finalizer")
            assert any(row["event"] == "stopped" and row["detail"]["libraries_unloaded"] == 0 for row in rows(directory / "trace.jsonl"))
        else:
            assert "release" not in events
        result = {"action": action, "command": args, "return_code": code, "watchdog": watchdog,
                  "classification": "native-call-not-preemptible-process-killed" if watchdog else "drained",
                  "trace": rows(directory / "trace.jsonl"), "mod_events": rows(directory / "mod-events.jsonl")}
        host.write(directory / "result.json", result)
        results.append(result)
        next_directory = cases / ("next-empty-" + action)
        empty = child_case(next_directory, [str(probe), str(home)], home, action="policy")
        assert not empty["mod_events"]
        assert any(row["event"] == "policy-decision" and row["detail"]["final_parallel"] is True for row in empty["trace"])
        results.append(empty)
    return results


def acceptance(root, logs, report_name="acceptance.json"):
    cfg = load_config(root)
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    package, frozen = host.acceptance(root, logs, report_name="p01-baseline-acceptance.json")
    execute(root, logs, "native-mod-producer", ["python3", "-B", str(root / "ci/scripts/native_mod.py"), "build-fixtures"])
    mod = host.read(logs / "mod-build.json")
    library = Path(mod["payload"])
    native = Path(os.environ["RUNNER_TEMP"]) / "cm-native-fixtures"
    probe = Path(os.environ["CARGO_TARGET_DIR"]) / "host" / TARGET / cfg["build_profile"] / "examples/native_probe"
    binary = package / "bin/codex"
    cases = artifact / "evidence/native-cases"
    cases.mkdir()
    common = {"source_repository": os.environ["CM_SOURCE_REPOSITORY"], "source_sha": host.git(root, "rev-parse", "HEAD"),
              "workflow_repository": os.environ["GITHUB_REPOSITORY"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
              "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "job": os.environ["GITHUB_JOB"], "target": TARGET, "host": frozen, "mod": mod}
    valid_directory = cases / "native-positive-control"
    home = valid_directory / "profile"
    install(home, library)
    positive = child_case(valid_directory, [str(probe), str(home)], home, action="policy")
    assert [row["event"] for row in positive["mod_events"]].count("constructor") == 1
    assert [row["event"] for row in positive["mod_events"]].count("release") == 1
    restriction_cases = []
    for index, (original, tool, expected) in enumerate(((False, "exec_command", False),
            (True, "tool_é", True), (False, "tool_é", False))):
        directory = cases / ("native-restriction-" + str(index))
        home = directory / "profile"
        install(home, library)
        result = child_case(directory, [str(probe), str(home)], home, action="policy",
                            extra={"CM_PROBE_ORIGINAL": str(original).lower(), "CM_PROBE_TOOL": tool})
        decision = next(row["detail"] for row in result["trace"] if row["event"] == "policy-decision")
        assert decision["original_parallel"] is original and decision["final_parallel"] is expected
        assert decision["decision"] == (1 if tool == "exec_command" else 0)
        restriction_cases.append(result)
    preflight = startup_rejections(cases, binary, library, native)
    entry, callbacks = abi_rejections(cases, binary, probe, library, native)
    lifetimes = lifetime(cases, probe, library)
    sys.path.insert(0, str(root / "fixtures/native-loader"))
    from core_acceptance import run_case
    business_home = cases / "business-profile"
    business_home.mkdir()
    empty = run_case(root, cases / "core-empty", binary, business_home, False)
    installed = install(business_home, library)
    active = run_case(root, cases / "core-mod", binary, business_home, True)
    shutil.rmtree(installed)
    removed = run_case(root, cases / "core-removed", binary, business_home, False)
    install(business_home, library)
    policy_failure = run_case(root, cases / "core-callback-failure", binary, business_home, True,
                              scenario="callback-failure", mode="callback-fail")
    cancelled_wait = run_case(root, cases / "core-cancel-wait", binary, business_home, True, scenario="cancel-waiting")
    shutil.rmtree(business_home / "mods/serial-fixture")
    cancelled_exec = run_case(root, cases / "core-cancel-exec", binary, business_home, False, scenario="cancel-executing")
    for index, args in enumerate((["--version"], ["--help"], ["exec", "--help"], ["cm-host-identity"])):
        directory = cases / ("metadata-" + str(index))
        home = directory / "profile"
        install(home, library)
        result = child_case(directory, [str(binary), *args], home)
        assert not result["trace"] and not result["mod_events"], "Metadata executed Mod code"
    backend = cases / "wrong-backend"
    home = backend / "profile"
    install(home, library)
    rejected_backend = child_case(backend, [str(binary), "--remote", "ws://127.0.0.1:1"], home, expected="nonzero")
    assert not rejected_backend["mod_events"]
    assert any(row["event"] == "startup-failed" and row["detail"]["stage"] == "backend" for row in rejected_backend["trace"])
    assert host.sha(binary) == frozen["executable_sha256"]
    assert host.manifest_digest(host.manifest(package)) == frozen["package_manifest_sha256"]
    assert host.sha(library) == mod["payload_sha256"]
    assert host.read(logs / "host-identity.json")["inputs"] == host.identity_inputs(root, logs)
    host.verify_sources(root, logs)
    evidence = artifact / "evidence"
    reports = {
        "native-loader-entry.json": {"producer": mod, "positive_control": positive,
            "same_host_after_all_cases": frozen["executable_sha256"], "same_mod_payload": mod["payload_sha256"]},
        "internal-seam-proof.json": {"empty": empty, "with_mod": active, "removed": removed,
            "callback_failure_no_fallback": policy_failure, "cancel_wait": cancelled_wait, "cancel_execute": cancelled_exec,
            "seam": "ToolCallRuntime::handle_tool_call_with_source -> original per-runtime RWLock -> builtin exec_command"},
        "native-abi-contract.json": {"entry_cases": entry, "callback_cases": callbacks, "lifetime_cases": lifetimes,
            "restriction_and_utf8_cases": restriction_cases,
            "c_layout": json.loads((logs / "mod-c-layout.log").read_text()), "rust_layout": "host-test.log: linux_x64_layout",
            "native_memory_safety": "valid allocations only; abort/segfault are process failures, not recovered"},
        "preload-rejection.json": {"positive_control": positive, "rejections": preflight,
            "snapshot": "mod-pinned-snapshot.log: actual sealed-snapshot load after path replacement and in-place edit",
            "post_load_cases_separate": entry, "wrong_backend": rejected_backend},
        "loader-lifetime.json": {"lifetimes": lifetimes, "init_failures": [value for value in entry if value["mode"] in ("init-fail", "init-panic")],
            "callback_failure": policy_failure, "hot_unload": False},
    }
    for name, result in reports.items():
        assert common.keys().isdisjoint(result), "Report overwrites common provenance: " + name
        host.write(evidence / name, {"status": "pass", **common, **result})
    host.write(artifact / report_name, {
        "schema_version": 1, "task_id": "CM-P02", "status": "pass", "target": TARGET,
        "implementation_commit": common["source_sha"],
        "checks": [{"id": check, "status": "pass", "command": "python3 -B ci/scripts/native_mod.py acceptance",
                    "evidence": ["evidence/" + name]} for check, name in CHECKS.items()],
    })

    return package, frozen, mod, probe


def main():
    require_hosted_linux()
    if os.environ.get("GITHUB_REPOSITORY") != "DSLZL/CM-build-linux-x64":
        raise RuntimeError("P02 executes only in the independent Linux x64 builder")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = Path(os.environ["CM_SOURCE_DIR"]).resolve()
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    try:
        {"build-fixtures": build_fixtures, "acceptance": acceptance}[sys.argv[1]](root, logs)
    finally:
        evidence = Path(os.environ["CM_CI_ARTIFACT_DIR"]) / "evidence"
        for path in evidence.rglob("*"):
            relative = path.relative_to(evidence)
            if not path.is_file() or path.is_symlink() or path.suffix not in {".json", ".jsonl", ".log"}:
                continue
            if {"profile", "business-profile", "home"}.intersection(relative.parts):
                continue
            data = path.read_bytes()
            data.decode("utf-8")
            assert b"\0" not in data, "Binary data in lightweight evidence: " + str(relative)
            destination = logs / "acceptance-evidence" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        report = evidence.parent / "acceptance.json"
        if report.is_file():
            shutil.copyfile(report, logs / "acceptance.json")


if __name__ == "__main__":
    main()
