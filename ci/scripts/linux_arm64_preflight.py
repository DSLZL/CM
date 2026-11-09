#!/usr/bin/env python3
"""Small native mechanism gate; never builds or qualifies a production Host."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile

import ci_progress
import cm_platforms
import record_run

TARGET = "aarch64-unknown-linux-gnu"
NAMESPACES = ("user", "mnt", "pid", "ipc", "uts", "net")
STAGES = ("initial-mechanisms", "packaged-helper")


def elf(path):
    data = path.read_bytes()
    if (len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(data[16:18], "little") not in (2, 3)
            or int.from_bytes(data[18:20], "little") != 183):
        raise RuntimeError("Expected an actual ARM64 ELF64 input: " + str(path))
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "machine": 183}


def test_executables(text, target):
    found = {}
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") != "compiler-artifact" or not row.get("profile", {}).get("test"):
            continue
        name = row["target"]["name"]
        if name not in ("cm_abi", "cm_runtime") or not row.get("executable"):
            continue
        path = Path(row["executable"]).resolve()
        if not path.is_relative_to(target.resolve()) or name in found:
            raise RuntimeError("Ambiguous or escaping private test executable")
        found[name] = path
    if set(found) != {"cm_abi", "cm_runtime"}:
        raise RuntimeError("Missing the two private ABI/loader test executables")
    return found


def authority(policy, entry, env):
    expected = {"source_repository": "DSLZL/CM", "builder_repository": entry["repository"],
        "source_sha": env["CM_SOURCE_SHA"], "observed_source_default_sha": env["CM_SOURCE_SHA"],
        "workflow_sha": env["GITHUB_WORKFLOW_SHA"], "request_id": env["CM_REQUEST_ID"],
        "source_default_branch": "main", "worker_default_branch": "main", "platform": "linux-arm64",
        "target": TARGET, "cache_mode": "none", "execution_role": "platform_preflight",
        "build_kind": "qualification", "consumer_required": "false", "distribution_required": "false", "index_required": "false"}
    if (any(policy.get(key) != value for key, value in expected.items()) or entry["key"] != "linux-arm64"
            or env.get("CM_EXECUTION_ROLE") != "platform_preflight" or env.get("GITHUB_JOB") != "native-preflight"
            or env.get("GITHUB_REF") != "refs/heads/main" or env.get("CM_BUILD_KIND") != "qualification"
            or env.get("CM_HOST_ORIGIN", "") or env.get("CM_CACHE_MODE") != "none"
            or env.get("ACTIONS_CACHE_MODE") != "none" or env.get("GITHUB_WORKFLOW_REF") !=
                entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main"):
        raise RuntimeError("Mechanism gate differs from its trusted cache-none ARM64 preflight")


def helper_execution(executions, path):
    expected = r'\d+\s+execve\(' + re.escape(json.dumps(str(path))) + r', \[.*\], [^\n]*\) = 0'
    matches = [line for line in executions if re.match(r'\d+\s+execve\("[^"\n]*/bwrap", ', line)]
    if len(matches) != 1 or not re.fullmatch(expected, matches[0]):
        raise RuntimeError("Expected exactly one successful execution of the selected helper")
    return matches[0]


def isolation(root, logs, temp, run, helper, label="isolation"):
    import runtime_composition as observer
    from runtime_consumer import TRACE_SYSCALLS
    observer.check_network_audit()
    probe = temp / "native_probe"
    run(label + "-compile", ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        "-Wl,-z,relro,-z,now", str(root / "fixtures/native-loader/isolation.c"), "-o", str(probe)])
    dependencies = run(label + "-dependencies", ["ldd", str(probe)])
    filesystem = temp / "rootfs"
    filesystem.mkdir()
    files = {"/native_probe": probe}
    for line in dependencies.splitlines():
        if re.fullmatch(r"\s*linux-vdso[.]so[.]1 \(0x[0-9a-f]+\)\s*", line):
            continue
        match = re.fullmatch(r"\s*(?:[\w.+-]+ => )?(/[^\s]+) \(0x[0-9a-f]+\)\s*", line)
        if not match or Path(match[1]).name not in ("libc.so.6", "ld-linux-aarch64.so.1"):
            raise RuntimeError("Unexpected trusted C-probe dependency: " + line)
        files[match[1]] = Path(match[1]).resolve(strict=True)
    assert len(files) == 3, "Expected only the native probe, libc and ARM64 loader"
    inventory = []
    for destination, source in files.items():
        target = filesystem / destination.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755)
        inventory.append({"path": destination, **elf(target)})
    for name in ("input", "work", "proc", "dev", "tmp"):
        (filesystem / name).mkdir()
    marker = filesystem / "input/marker"
    marker.write_bytes(b"immutable")
    marker.chmod(0o666)
    inventory.append({"path": "/input/marker", "sha256": hashlib.sha256(b"immutable").hexdigest(), "size": 9, "mode": "0666"})
    outside = temp / "outside-marker"
    outside.write_bytes(b"outside")
    cargo_marker = Path(os.environ["CARGO_HOME"]) / "private-marker"
    cargo_marker.write_bytes(b"cargo-private")
    work = temp / "work"
    work.mkdir()
    traces = logs / (label + "-traces")
    traces.mkdir()
    helper = helper.resolve(strict=True)
    helper_input = {"path": str(helper), **elf(helper)}
    (logs / (label + "-inputs.json")).write_text(json.dumps({"rootfs": inventory, "helper": helper_input,
        "trace_syscalls": TRACE_SYSCALLS}, indent=2) + "\n", encoding="utf-8")
    with socket.socket() as canary:
        canary.bind(("127.0.0.1", 0))
        canary.listen()
        canary.settimeout(0.2)
        port = canary.getsockname()[1]
        args = ["strace", "-ff", "-qq", "-yy", "--pidns-translation", "-s", "1024", "-e", TRACE_SYSCALLS,
            "-o", str(traces / "syscalls"), "--", str(helper), "--unshare-user", "--unshare-pid",
            "--unshare-ipc", "--unshare-uts", "--unshare-net", "--uid", "1000", "--gid", "1000",
            "--cap-drop", "ALL", "--new-session", "--die-with-parent", "--ro-bind", str(filesystem), "/",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(work), "/work",
            "--chdir", "/work", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--", "/native_probe", str(port),
            *(os.readlink("/proc/self/ns/" + name) for name in NAMESPACES), str(outside),
            str(root / ".github/cm-ci.json"), str(cargo_marker)]
        result = json.loads(run(label + "-native", args, 60))
        try:
            connection, _ = canary.accept()
        except socket.timeout:
            pass
        else:
            connection.close()
            raise RuntimeError("The isolated probe reached the outer canary")
    assert result["status"] == "pass" and result["namespace_checks"] == 24
    assert marker.read_bytes() == b"immutable" and outside.read_bytes() == b"outside" and cargo_marker.read_bytes() == b"cargo-private"
    calls = []
    for path in sorted(traces.glob("syscalls.*")):
        assert path.suffix[1:].isdigit()
        safe = observer.redact_syscalls("".join(path.suffix[1:] + " " + line + "\n" for line in path.read_text().splitlines()))
        path.write_text(safe, encoding="utf-8")
        calls.extend(observer.complete_syscalls(safe.splitlines()))
    executions = [line for line in calls if re.match(r"\d+\s+execve(?:at)?\(", line)]
    selected_execution = helper_execution(executions, helper)
    assert elf(helper) == {key: value for key, value in helper_input.items() if key != "path"}
    denied = [line for line in executions if re.fullmatch(
        r'\d+\s+execve\("(/usr/bin/(?:cc|cargo))", \["\1", "--version"\], [^\n]*\) = -1 ENOENT \(No such file or directory\)', line)]
    assert len(denied) == 2 and all(sum('"/usr/bin/' + name + '"' in line for line in denied) == 1 for name in ("cc", "cargo"))
    observer.audit_executions([line for line in executions if line not in denied], native_probes=("/native_probe",))
    ports = {str(port), str(result["internal_port"])}
    network = [line for line in calls if re.match(r"\d+\s+(?:connect|sendto|socketpair)\(", line)]
    observer.audit_network(network, Path("/work"), ports, observer.kernel_route_sockets(calls),
        observer.provider_tcp_connections(calls, ports))
    return {**result, "helper": helper_input, "helper_execution": selected_execution,
        "rootfs": inventory, "inputs_unchanged": True, "outer_canary_hits": 0,
        "trace_syscalls": TRACE_SYSCALLS, "trace_files": len(list(traces.glob("syscalls.*"))),
        "expected_denied_compiler_executions": denied, "execution_audit": "pass", "network_audit": "pass"}


def main(stage="initial-mechanisms"):
    if stage not in STAGES:
        raise RuntimeError("Unknown ARM64 preflight stage: " + stage)
    entry = record_run.require_hosted_worker(enabled=False)
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    policy = json.loads(Path(os.environ["RUNNER_TEMP"], "cm-worker-preflight.json").read_text())
    authority(policy, entry, os.environ)
    root = Path(os.environ["CM_SOURCE_DIR"]).resolve()
    assert root == Path(__file__).resolve().parents[2]
    record_run.record(logs)
    shutil.copyfile(Path(os.environ["RUNNER_TEMP"], "cm-worker-preflight.json"), logs / "worker-preflight.json")
    scope = "initial-native-mechanisms" if stage == "initial-mechanisms" else "packaged-helper-mechanisms"
    report = {"schema_version": 1, "scope": "linux-arm64-" + scope, "stage": stage, "status": "running",
        "provenance": policy, "platform_enabled": entry["enabled"], "cache_mode": "none", "cache_writes": 0,
        "production_host": "not_built", "v01": "partial", "qualification": "not_run", "release_ready": False,
        "not_run": ["packaged-helper", "complete-V01", "V02-V08", "production-Host", "full-runtime-qualification"], "gates": {}}
    if stage == "packaged-helper":
        report["not_run"][0] = "ABI-and-loader-probes-in-this-run"
    report_path = logs / "linux-arm64-preflight.json"

    def write():
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def run(label, command, timeout=300):
        command = [str(part) for part in command]
        cwd = Path.cwd()
        if command[0] == "cargo" and "--manifest-path" in command:
            cwd = Path(command[command.index("--manifest-path") + 1]).resolve(strict=True).parent
        with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"stage": label, "command": command, "cwd": str(cwd), "timeout_seconds": timeout}) + "\n")
        with contextlib.chdir(cwd):
            result = ci_progress.run(logs, label, command, timeout)
        if result.returncode:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return (logs / (label + ".log")).read_text(encoding="utf-8")

    write()
    try:
        with tempfile.TemporaryDirectory(prefix="cm-arm64-preflight-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory)
            cargo_home = temp / "cargo-home"
            cargo_home.mkdir()
            for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CFLAGS", "CXXFLAGS", "RUSTC_WORKSPACE_WRAPPER"):
                os.environ.pop(key, None)
            os.environ.update(CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(temp / "runtime-target"),
                CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2", RUSTC_WRAPPER="", RUSTUP_TOOLCHAIN="1.95.0")
            with contextlib.chdir(root):
                rust = run("rust-toolchain", ["rustc", "-vV"])
                assert "host: " + TARGET in rust
                cc = run("native-c-target", ["cc", "-dumpmachine"]).strip()
                assert cc == "aarch64-linux-gnu", cc
                report["gates"]["native-tools"] = {"rust": rust, "cc_target": cc,
                    "cc_version": run("native-c-version", ["cc", "--version"]),
                    "python_version": sys.version, "python_machine": platform.machine(), "python_system": platform.system(),
                    "python_elf": elf(Path(sys.executable).resolve(strict=True)),
                    "cc_elf": elf(Path(shutil.which("cc")).resolve(strict=True)),
                    "strace": run("strace-version", ["strace", "--version"])}
                system_isolation = isolation(root, logs, temp, run, Path("/usr/bin/bwrap"))
                report["gates"]["isolation"] = {**system_isolation,
                    "system_bwrap_sha256": system_isolation["helper"]["sha256"], "packaged_helper": "not_run"}
                write()
                import host
                with ci_progress.stage("prepare-pinned-source-only"):
                    host.prepare(root, logs)
                workspace = root / host.HOST / "codex-rs/Cargo.toml"
                if stage == "packaged-helper":
                    host.reject_native_overrides()
                    helper_target = temp / "helper-target"
                    runtime_target = os.environ["CARGO_TARGET_DIR"]
                    os.environ["CARGO_TARGET_DIR"] = str(helper_target)
                    try:
                        for phase, command in host.helper_commands(workspace, TARGET, "dev-small").items():
                            run("packaged-helper-" + phase, command, 900)
                    finally:
                        os.environ["CARGO_TARGET_DIR"] = runtime_target
                    binary = helper_target / TARGET / "dev-small/bwrap"
                    helper_gate = {"status": "running", "package": "codex-bwrap", "target": TARGET,
                        "profile": "dev-small", "elf": elf(binary),
                        "libcap_version": run("libcap-version", ["pkg-config", "--modversion", "libcap"]).strip(),
                        "libcap_flags": run("libcap-flags", ["pkg-config", "--cflags", "--libs", "libcap"]).strip(),
                        "dependencies": run("packaged-helper-dependencies", ["ldd", binary])}
                    report["gates"]["packaged-helper"] = helper_gate
                    write()
                    version = run("packaged-helper-version", [binary, "--version"]).strip()
                    assert version == "bubblewrap built for Codex", version
                    helper_gate["version"] = version
                    helper_temp = temp / "packaged-helper-isolation"
                    helper_temp.mkdir()
                    helper_gate["isolation"] = isolation(root, logs, helper_temp, run, binary, "packaged-helper-isolation")
                    assert helper_gate["elf"]["sha256"] == helper_gate["isolation"]["helper"]["sha256"]
                    helper_gate["status"] = report["status"] = "pass"
                    return
                identity = temp / "private-probe-identity.json"
                identity.write_text(json.dumps({"domain": "cm.native-mechanism-probe.v1", "target": TARGET,
                    "host_build_id": "sha256:" + hashlib.sha256((policy["source_sha"] + TARGET).encode()).hexdigest(),
                    "production_host": False}), encoding="utf-8")
                os.environ["CM_HOST_IDENTITY_JSON"] = str(identity)
                run("loader-fmt", ["cargo", "fmt", "--manifest-path", workspace, "-p", "cm-abi", "-p", "cm-runtime", "--", "--check"])
                cargo = ["--manifest-path", workspace, "--locked", "--target", TARGET, "--profile", "dev-small", "-p", "cm-abi", "-p", "cm-runtime", "--lib"]
                run("loader-clippy", ["cargo", "clippy", *cargo, "--", "-D", "warnings"], 900)
                artifacts = run("loader-test-build", ["cargo", "test", *cargo, "--no-run", "--message-format=json-render-diagnostics"], 900)
                tests = test_executables(artifacts, temp / "runtime-target")
                report["private_test_identity"] = json.loads(identity.read_text())
                report["private_test_executables"] = {name: elf(path) for name, path in tests.items()}
                for name, arguments in (("cm_abi", []), ("cm_runtime", ["loader::"])):
                    output = run(name + "-tests", [tests[name], *arguments, "--test-threads=1"])
                    assert re.search(r"test result: ok[.] [1-9][0-9]* passed; 0 failed;", output), output
                report["gates"]["rust-abi-and-loader"] = {"status": "pass", "scope": "cm-abi all units; cm-runtime loader units"}
                for name in ("serial-eligibility", "sdk-seams-a"):
                    manifest = root / "fixtures/mods" / name / "Cargo.toml"
                    run(name + "-fmt", ["cargo", "fmt", "--manifest-path", manifest, "--", "--check"])
                    run(name + "-build", ["cargo", "build", "--manifest-path", manifest, "--locked", "--target", TARGET,
                        "--profile", "dev-small", "--target-dir", temp / name], 600)
                serial = temp / "serial-eligibility" / TARGET / "dev-small/libcm_serial_eligibility_fixture.so"
                replacement = temp / "replacement.so"
                run("replacement-compile", ["cc", "-shared", "-fPIC", root / "fixtures/native-loader/replacement.c", "-o", replacement])
                report["fixture_elf"] = {"serial": elf(serial), "replacement": elf(replacement)}
                sentinel, events = temp / "replacement-sentinel", temp / "fixture-events.jsonl"
                os.environ.update(CM_P02_FIXTURE_LIBRARY=str(serial), CM_P02_REPLACEMENT_LIBRARY=str(replacement),
                    CM_REPLACEMENT_SENTINEL=str(sentinel), CM_FIXTURE_EVENTS=str(events), CM_FIXTURE_MODE="")
                output = run("sealed-native-load", [tests["cm_runtime"],
                    "loader::tests::replacement_and_in_place_edits_cannot_change_preflight_snapshot", "--exact", "--ignored", "--nocapture", "--test-threads=1"])
                assert "test result: ok. 1 passed; 0 failed;" in output and not sentinel.exists()
                rows = [json.loads(line) for line in events.read_text().splitlines()]
                assert sum(row["event"] == "constructor" for row in rows) == 2
                report["gates"]["sealed-native-load"] = {"status": "pass", "original_payload": elf(serial),
                    "replacement_payload": elf(replacement), "constructor_count": 2, "replacement_constructor": False,
                    "scope": "real loader; path replacement and in-place writes after preflight"}
                for key in ("CM_FIXTURE_EVENTS", "CM_P02_FIXTURE_LIBRARY", "CM_P02_REPLACEMENT_LIBRARY", "CM_REPLACEMENT_SENTINEL"):
                    os.environ.pop(key, None)
                abi = {"status": "running", "layouts": {}, "cases": [], "abi_2_3": "experimental"}
                report["gates"]["c-abi"] = abi
                for name in ("native-loader", "runtime-composition", "runtime-sdk"):
                    executable = temp / (name + "-layout")
                    run(name + "-layout-build", ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", root / "crates/cm-abi/include",
                        root / "fixtures" / name / "layout.c", "-o", executable])
                    abi["layouts"][name] = {"elf": elf(executable), "output": run(name + "-layout", [executable])}
                library = temp / "sdk-seams-a" / TARGET / "dev-small/libcm_sdk_seams_a.so"
                executable = temp / "sdk-abi"
                run("sdk-abi-build", ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", root / "crates/cm-abi/include",
                    root / "fixtures/sdk-seams/abi.c", "-ldl", "-o", executable])
                abi.update(sdk_library=elf(library), sdk_probe=elf(executable))
                modes = ("valid", "major", "minor", "old-minor", "short-prefix", "short-tail", "huge", "null-host", "misaligned",
                    "null-runtime", "runtime-short", "runtime-minor", "runtime-reserved", "null-complete", "null-state-get", "null-state-set",
                    "null-next", "next-short", "next-minor", "next-reserved", "null-start", "null-poll", "null-cancel", "null-release")
                for mode in modes:
                    row = json.loads(run("sdk-abi-" + mode, [executable, library, mode]))
                    assert row["status"] == "pass" and row["caller_canaries"]
                    abi["cases"].append(row)
                abi["status"] = "pass"
        report["status"] = "pass"
    except Exception as error:
        report.update(status="failed", error=repr(error))
        raise
    finally:
        write()


def self_check():
    import host
    host.reject_native_overrides({})
    for key in ("V8_FROM_SOURCE", "RUSTY_V8_ARCHIVE", "RUSTY_V8_SRC_BINDING_PATH", "CODEX_SKIP_BWRAP_BUILD",
            "CODEX_BWRAP_SOURCE_DIR", "CODEX_BWRAP_SHA256", "PKG_CONFIG_PATH", "PKG_CONFIG_SYSROOT_DIR"):
        for value in ("", "override"):
            try:
                host.reject_native_overrides({key: value})
            except RuntimeError:
                pass
            else:
                raise AssertionError("Native override accepted: " + key)
    manifest, profile, legacy_target = "/source/Cargo.toml", "dev-small", "x86_64-unknown-linux-gnu"
    legacy = {
        "fmt": ["cargo", "fmt", "--manifest-path", manifest, "-p", "codex-bwrap", "--", "--check"],
        "clippy": ["cargo", "clippy", "--locked", "--manifest-path", manifest, "--target", legacy_target,
            "--profile", profile, "-p", "codex-bwrap", "--all-targets", "--", "-D", "warnings"],
        "test": ["cargo", "test", "--locked", "--manifest-path", manifest, "--target", legacy_target,
            "--profile", profile, "-p", "codex-bwrap"],
        "build": ["cargo", "build", "--locked", "--manifest-path", manifest, "--target", legacy_target,
            "--profile", profile, "-p", "codex-bwrap"],
    }
    commands = host.helper_commands(manifest, legacy_target, profile)
    assert commands == legacy and list(commands) == list(legacy)
    assert host.helper_commands(Path(manifest), TARGET, profile) == {
        phase: [TARGET if part == legacy_target else part for part in command] for phase, command in legacy.items()}
    selected = '123 execve("/private/helper/bwrap", ["/private/helper/bwrap", "--unshare-user"], 0x0 /* 0 vars */) = 0'
    assert helper_execution([selected], Path("/private/helper/bwrap")) == selected
    for lines in ([], [selected, selected], [selected.replace("/private/helper", "/usr/bin")],
            [selected, selected.replace("/private/helper", "/usr/bin")],
            [selected.replace(" = 0", " = -1 ENOENT (No such file or directory)")]):
        try:
            helper_execution(lines, Path("/private/helper/bwrap"))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Unbound helper execution accepted")
    try:
        main("unknown-stage")
    except RuntimeError as error:
        assert "Unknown ARM64 preflight stage" in str(error)
    else:
        raise AssertionError("Unknown preflight stage accepted")
    entry = cm_platforms.select("linux-arm64")
    env = {"CM_SOURCE_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "b" * 40, "CM_REQUEST_ID": "mechanism-check",
        "CM_EXECUTION_ROLE": "platform_preflight", "GITHUB_JOB": "native-preflight", "GITHUB_REF": "refs/heads/main",
        "CM_BUILD_KIND": "qualification", "CM_CACHE_MODE": "none", "ACTIONS_CACHE_MODE": "none",
        "GITHUB_WORKFLOW_REF": entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main"}
    policy = {"source_repository": "DSLZL/CM", "builder_repository": entry["repository"], "source_sha": "a" * 40,
        "observed_source_default_sha": "a" * 40, "workflow_sha": "b" * 40, "request_id": "mechanism-check",
        "source_default_branch": "main", "worker_default_branch": "main", "platform": "linux-arm64", "target": TARGET,
        "cache_mode": "none", "execution_role": "platform_preflight", "build_kind": "qualification",
        "consumer_required": "false", "distribution_required": "false", "index_required": "false"}
    authority(policy, entry, env)
    for key in policy:
        try:
            authority({**policy, key: "wrong"}, entry, env)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Mismatched preflight field accepted: " + key)
    for changes in ({"GITHUB_JOB": "build-write"}, {"CM_EXECUTION_ROLE": "platform_builder"}, {"ACTIONS_CACHE_MODE": "write"},
            {"CM_CACHE_MODE": "read"}, {"GITHUB_REF": "refs/heads/other"}, {"CM_HOST_ORIGIN": "{}"}, {"CM_BUILD_KIND": "program"},
            {"GITHUB_WORKFLOW_REF": "other"}):
        try:
            authority(policy, entry, {**env, **changes})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid preflight context accepted")
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory)
        data = bytearray(64)
        data[:7], data[16:20] = b"\x7fELF\x02\x01\x01", bytes((3, 0, 183, 0))
        paths = {name: target / name for name in ("cm_abi", "cm_runtime")}
        for path in paths.values():
            path.write_bytes(data)
            assert elf(path)["machine"] == 183
        rows = [{"reason": "compiler-artifact", "target": {"name": name}, "profile": {"test": True}, "executable": str(path)}
            for name, path in paths.items()]
        assert test_executables("\n".join(json.dumps(row) for row in rows), target) == paths
        for offset, value in ((4, 1), (5, 2), (18, 62)):
            invalid = data.copy()
            invalid[offset] = value
            paths["cm_abi"].write_bytes(invalid)
            try:
                elf(paths["cm_abi"])
            except RuntimeError:
                pass
            else:
                raise AssertionError("Invalid ELF accepted")
        for changed in (rows[:1], [*rows, rows[0]], [{**row, "executable": str(target.parent / row["target"]["name"])} for row in rows]):
            try:
                test_executables("\n".join(json.dumps(row) for row in changed), target)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Invalid test executable identity accepted")
    print("ARM64 mechanism infrastructure self-check passed; no native execution")


if __name__ == "__main__":
    if sys.argv[1:] == ["self-check"]:
        self_check()
    elif not sys.argv[1:]:
        main()
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        raise SystemExit("Expected initial-mechanisms, packaged-helper or self-check")
