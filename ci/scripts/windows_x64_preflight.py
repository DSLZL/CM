"""Bounded Windows fixture loading/ConPTY controls; never product qualification."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import shutil
import struct
import subprocess
import tempfile
import threading

import ci_progress
import record_run

KEY, TARGET = "windows-x64", "x86_64-pc-windows-msvc"


def authority(policy, entry, env):
    expected = {"source_repository": "DSLZL/CM", "source_sha": env.get("CM_SOURCE_SHA"),
        "observed_source_default_sha": env.get("CM_SOURCE_SHA"), "source_default_branch": "main",
        "builder_repository": entry["repository"], "workflow_sha": env.get("GITHUB_WORKFLOW_SHA"),
        "worker_default_branch": "main", "request_id": env.get("CM_REQUEST_ID"),
        "platform": KEY, "target": TARGET, "cache_mode": "none", "execution_role": "platform_preflight",
        "build_kind": "qualification", "consumer_required": "false",
        "distribution_required": "false", "index_required": "false"}
    if (entry["key"] != KEY or any(policy.get(key) != value for key, value in expected.items())
            or env.get("CM_EXECUTION_ROLE") != "platform_preflight"
            or env.get("GITHUB_JOB") != "native-preflight" or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("CM_BUILD_KIND") != "qualification" or env.get("CM_HOST_ORIGIN")
            or any(env.get(key) != "none" for key in ("CM_CACHE_MODE", "ACTIONS_CACHE_MODE"))
            or env.get("GITHUB_WORKFLOW_REF") != entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main"):
        raise RuntimeError("Windows probe differs from its exact cache-none native preflight authority")


def pe_fixture(data, dll):
    if not 128 <= len(data) <= 32 * 1024 * 1024 or data[:2] != b"MZ":
        raise RuntimeError("Expected bounded native PE fixture")
    header = struct.unpack_from("<I", data, 60)[0]
    if not 64 <= header <= len(data) - 264 or data[header:header + 4] != b"PE\0\0":
        raise RuntimeError("Invalid PE fixture header")
    machine, count = struct.unpack_from("<HH", data, header + 4)
    optional, flags = struct.unpack_from("<HH", data, header + 20)
    if (machine != 0x8664 or not 1 <= count <= 32 or optional != 240
            or not flags & 2 or bool(flags & 0x2000) != dll
            or struct.unpack_from("<H", data, header + 24)[0] != 0x20B):
        raise RuntimeError("Wrong PE fixture architecture/kind")
    sections = header + 24 + optional
    if sections + count * 40 > len(data):
        raise RuntimeError("Truncated PE fixture section table")
    for offset in range(sections, sections + count * 40, 40):
        size, raw = struct.unpack_from("<II", data, offset + 16)
        attributes = struct.unpack_from("<I", data, offset + 36)[0]
        if (size and (raw < sections + count * 40 or raw > len(data) or size > len(data) - raw)
                or attributes & 0x20000000 and attributes & 0x80000000):
            raise RuntimeError("Invalid PE fixture section range/permissions")
    return {"format": "pe32+", "machine": machine, "dll": dll, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "scope": "fixture-header-and-section-bounds",
        "full_dependency_qualification": "not_run"}


def exact_record(text, expected):
    if len(text) > 8192:
        raise RuntimeError("Oversized native fixture record")
    value = json.loads(text)
    if (not isinstance(value, dict) or value != expected or set(value) != set(expected)
            or any(type(value[key]) is not type(item) for key, item in expected.items())):
        raise RuntimeError("Native fixture record differs from the required observation")
    return value


def terminal_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized ConPTY fixture record")
    value = json.loads(text)
    if not isinstance(value, dict) or type(value.get("output_bytes")) is not int or not 1 <= value["output_bytes"] < 65536:
        raise RuntimeError("Missing bounded ConPTY output")
    return exact_record(text, {"status": "pass", "gate": "ConPTY-control", "initial_columns": 96,
        "initial_rows": 28, "resized_columns": 120, "resized_rows": 40, "input": "Y",
        "child_exit_code": 0, "drain_error": 109, "output_bytes": value["output_bytes"], "full_host_tui": "not_run"})


def mutation_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized mutation fixture record")
    value = json.loads(text)
    errors = ("write_error", "delete_error", "replace_error", "rename_error", "parent_rename_error")
    if (not isinstance(value, dict) or any(type(value.get(key)) is not int
            or value[key] not in (5, 32) for key in errors) or value.get("write_error") != 32):
        raise RuntimeError("External mutation was not denied by the native pin")
    return exact_record(text, {**{key: value[key] for key in errors}, "native_executed": False})


def lpac_network_record(text):
    return exact_record(text, {"status": "pass", "gate": "lpac-internal-provider-network-control",
        "outside_token_checks": 3, "capability_count": 0, "ordinary_file_positive": True,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "lpac_opt_out_file_denied": True, "private_file_positive": True, "provider_http_positive": True,
        "outside_listener_positive": True, "outside_connect_error": 10013, "outside_unexpected_accepts": 0,
        "profile_deleted": True, "full_isolation": "not_run", "product": "not_run"})


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    authority(json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text()), entry, os.environ)
    mechanism = os.environ.get("CM_PREFLIGHT_STAGE", "loader-terminal")
    if mechanism not in ("loader-terminal", "lpac-network"):
        raise RuntimeError("Unknown Windows native mechanism stage")
    lpac = mechanism == "lpac-network"
    if Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Mechanism source must be the exact recorded source checkout")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Fixture text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running",
        "scope": "V01c-lpac-network-fixture-only" if lpac else "V01a-loader-terminal-fixtures-only",
        "platform": KEY, "target": TARGET, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": os.environ["CM_REQUEST_ID"],
        "cache_mode": "none", "cache_writes": 0, "product_build": "not_run", "qualification": "not_run",
        "isolation": "not_run", "rust_v8_protoc": "not_run", "dependency_search_attacks": "not_run",
        "platform_enabled": False, "release_ready": False, "controls": {}}

    def command(label, args):
        values = [str(value) for value in args]
        with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"stage": label, "command": values}) + "\n")
        return values

    def run(label, args, timeout=30, codes=(0,)):
        result = ci_progress.run(logs, label, command(label, args), timeout)
        text = (logs / (label + ".log")).read_text(encoding="utf-8", errors="replace")
        if result.returncode not in codes:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return result.returncode, text.strip()

    @contextmanager
    def interactive(label, args):
        with ci_progress.stage(label), (logs / (label + ".log")).open("w", encoding="utf-8") as stream:
            process = subprocess.Popen(command(label, args), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="strict")
            lines = queue.Queue()

            def read():
                try:
                    for line in process.stdout:
                        stream.write(line)
                        stream.flush()
                        lines.put(line)
                finally:
                    lines.put(None)

            reader = threading.Thread(target=read, daemon=True)
            reader.start()

            def receive():
                try:
                    value = lines.get(timeout=10)
                except queue.Empty as error:
                    raise RuntimeError(label + " native barrier timed out") from error
                if value is None:
                    raise RuntimeError(label + " ended before its native barrier")
                return value.strip()

            try:
                yield process, receive
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
                reader.join(timeout=5)
                if reader.is_alive():
                    raise RuntimeError(label + " native text reader failed to drain")
                process.stdin.close()
                process.stdout.close()

    try:
        with tempfile.TemporaryDirectory(prefix="cm-wx-mechanisms-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory).resolve()
            cl = Path(shutil.which("cl.exe") or "")
            if not cl.is_absolute() or not cl.is_file() or tuple(part.lower() for part in cl.parts[-3:]) != ("hostx64", "x64", "cl.exe"):
                raise RuntimeError("Missing exact native x64 MSVC compiler")
            sdk = {key: os.environ.get(key) for key in ("VCToolsVersion", "WindowsSDKVersion", "WindowsSdkDir", "VCToolsInstallDir")}
            if not all(sdk.values()) or not os.environ.get("ImageOS") or not os.environ.get("ImageVersion"):
                raise RuntimeError("Missing MSVC/SDK/hosted image identity")
            report["environment"] = {"os": platform.platform(), "python": platform.python_version(),
                "cl": str(cl), **sdk, "image_os": os.environ["ImageOS"], "image_version": os.environ["ImageVersion"]}
            source = root / "fixtures/native-loader" / ("windows-lpac-network.c" if lpac else "windows-preflight.c")
            probe, payload = temp / "native-probe.exe", temp / "sentinel.dll"
            flags = ["/nologo", "/Bv", "/std:c11", "/W4", "/WX", "/O2", "/MT", "/utf-8", "/TC"]
            libraries = ["bcrypt.lib", *(["userenv.lib", "advapi32.lib", "ws2_32.lib"] if lpac else [])]
            run("compile-native-probe", [cl, *flags, source, "/Fo" + str(temp / "probe.obj"),
                "/Fe" + str(probe), "/link", *libraries, "/INCREMENTAL:NO"], 120)
            if lpac:
                report["inputs"] = {"probe": pe_fixture(probe.read_bytes(), False)}
                run("probe-dependencies", [cl.with_name("dumpbin.exe"), "/nologo", "/dependents", probe])
                _, text = run("lpac-internal-provider-network-control", [probe, "run"], 120)
                report["controls"]["lpac_network"] = lpac_network_record(text)
                report["status"] = "passed_bounded_network_controls_only"
                return
            run("compile-sentinel-dll", [cl, *flags, "/DCM_PAYLOAD", "/LD", source,
                "/Fo" + str(temp / "payload.obj"), "/Fe" + str(payload), "/link",
                "/IMPLIB:" + str(temp / "sentinel.lib"), "/INCREMENTAL:NO"], 120)
            report["inputs"] = {"probe": pe_fixture(probe.read_bytes(), False), "payload": pe_fixture(payload.read_bytes(), True)}
            for name, path in (("probe", probe), ("payload", payload)):
                run(name + "-dependencies", [cl.with_name("dumpbin.exe"), "/nologo", "/dependents", path])
            digest = report["inputs"]["payload"]["sha256"]
            marker = temp / "constructor.marker"
            os.environ["CM_CONSTRUCTOR_MARKER"] = str(marker)
            for mode in ("writer", "mapping"):
                candidate = temp / ("retained-" + mode + ".dll")
                shutil.copyfile(payload, candidate)
                _, text = run("baseline-pin-" + mode, [probe, "pin-only", candidate])
                baseline = exact_record(text, {"status": "accepted", "gate": "pin", "native_executed": False})
                with interactive("retained-" + mode, [probe, "hold", mode, candidate]) as (holder, receive):
                    exact_record(receive(), {"status": "held", "native_executed": False})
                    with interactive("pin-with-retained-" + mode, [probe, "pin-held", candidate]) as (locker, locked):
                        text = locked()
                        pin_result = json.loads(text)
                        accepted = pin_result == {"status": "accepted", "gate": "pin", "native_executed": False}
                        holder.stdin.write("W"); holder.stdin.flush()
                        mutated = exact_record(receive(), {"status": "mutated", "written": 1, "native_executed": False})
                        if holder.wait(timeout=10) != 0:
                            raise RuntimeError("Retained writer/mapping control failed")
                        changed = hashlib.sha256(candidate.read_bytes()).hexdigest() != digest
                        if accepted:
                            locker.stdin.write("Q"); locker.stdin.flush()
                        code = locker.wait(timeout=10)
                report["controls"]["retained_" + mode] = {"pin_return_code": code, "pin_result": pin_result,
                    "baseline_pin": baseline, "writer_result": mutated, "backing_object_changed": changed,
                    "pin_held_during_mutation_if_accepted": accepted, "modified_native_executed": False}
                if not changed or marker.exists() or code != 2:
                    raise RuntimeError("Retained " + mode + " counterexample prevents fixed-handle qualification")
                exact_record(text, {"status": "rejected", "gate": "pin-file", "error": 32, "native_executed": False})
            baseline = temp / "unpinned"
            baseline.mkdir()
            baseline_file = baseline / "candidate.dll"
            shutil.copyfile(payload, baseline_file)
            (baseline / "candidate.dll.replacement").write_bytes(b"unlocked replacement control")
            _, text = run("unlocked-mutation-controls", [probe, "attack", baseline_file, baseline], codes=(2,))
            report["controls"]["unlocked_mutation"] = exact_record(text,
                {"write_error": 0, "delete_error": 0, "replace_error": 0, "rename_error": 0,
                 "parent_rename_error": 0, "native_executed": False})
            if marker.exists():
                raise RuntimeError("Unlocked mutation control executed a constructor")
            stage = temp / "pinned"
            stage.mkdir()
            candidate = stage / "candidate.dll"
            shutil.copyfile(payload, candidate)
            (stage / "candidate.dll.replacement").write_bytes(b"replacement must never be loaded")
            wrong = ("1" if digest[0] != "1" else "2") + digest[1:]
            _, text = run("wrong-hash-before-constructor", [probe, "load", candidate, wrong], codes=(2,))
            report["controls"]["wrong_hash"] = exact_record(text,
                {"status": "rejected", "gate": "payload-hash", "error": 13, "native_executed": False})
            if marker.exists():
                raise RuntimeError("Wrong hash executed a constructor")
            with interactive("verified-pin-and-load", [probe, "load", candidate, digest]) as (loader, receive):
                exact_record(receive(), {"status": "ready", "gate": "verified-pin", "native_executed": False})
                _, text = run("independent-write-delete-rename", [probe, "attack", candidate, stage])
                report["controls"]["external_mutation"] = mutation_record(text)
                if marker.exists() or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                    raise RuntimeError("Pinned fixture changed or executed before the load barrier")
                loader.stdin.write("L"); loader.stdin.flush()
                report["controls"]["pinned_load"] = exact_record(receive(), {"status": "pass",
                    "gate": "pinned-system-loader-control", "constructor_value": 41, "native_executed": True})
                if loader.wait(timeout=10) != 0 or marker.read_bytes() != b"constructor41":
                    raise RuntimeError("Missing actual constructor control")
            moved = temp / "unpinned-after-exit"
            stage.rename(moved)
            if hashlib.sha256((moved / candidate.name).read_bytes()).hexdigest() != digest:
                raise RuntimeError("Post-exit parent rename control changed its object")
            (moved / candidate.name).unlink()
            report["controls"]["rename_delete_after_loader_exit"] = "pass"
            _, text = run("conpty-input-resize-drain", [probe, "conpty"], 45)
            report["controls"]["conpty"] = terminal_record(text)
            if hashlib.sha256(payload.read_bytes()).hexdigest() != digest:
                raise RuntimeError("Original payload changed during controls")
            report["status"] = "passed_bounded_controls_only"
    except BaseException:
        report["status"] = "failed"
        raise
    finally:
        name = "windows-x64-lpac-network.json" if lpac else "windows-x64-mechanisms.json"
        (logs / name).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Windows V01a fixture controls passed; isolation, full dependency closure and product qualification remain NOT_RUN", flush=True)


def self_check():
    from unittest.mock import patch
    import cm_platforms
    entry = cm_platforms.select(KEY)
    env = {"CM_SOURCE_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "b" * 40, "CM_REQUEST_ID": "windows-controls",
        "CM_EXECUTION_ROLE": "platform_preflight", "GITHUB_JOB": "native-preflight", "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main",
        "CM_BUILD_KIND": "qualification", "CM_CACHE_MODE": "none", "ACTIONS_CACHE_MODE": "none"}
    policy = {"source_repository": "DSLZL/CM", "source_sha": "a" * 40, "observed_source_default_sha": "a" * 40,
        "source_default_branch": "main", "builder_repository": entry["repository"], "workflow_sha": "b" * 40,
        "worker_default_branch": "main", "request_id": "windows-controls", "platform": KEY, "target": TARGET,
        "cache_mode": "none", "execution_role": "platform_preflight", "build_kind": "qualification",
        "consumer_required": "false", "distribution_required": "false", "index_required": "false"}
    authority(policy, entry, env)
    for changes in ({"GITHUB_JOB": "build-write"}, {"CM_CACHE_MODE": "write"}, {"ACTIONS_CACHE_MODE": "read"},
            {"GITHUB_REF": "refs/heads/other"}, {"CM_BUILD_KIND": "program"}, {"CM_HOST_ORIGIN": "{}"}):
        try:
            authority(policy, entry, {**env, **changes})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid Windows authority accepted")
    for field in policy:
        try:
            authority({**policy, field: "wrong"}, entry, env)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Changed Windows preflight identity accepted: " + field)
    for key in set(cm_platforms.load()["platforms"]) - {KEY}:
        try:
            authority(policy, cm_platforms.select(key), env)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Cross-platform native authority accepted")
    data = bytearray(1024)
    data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HH", data, 132, 0x8664, 1)
    struct.pack_into("<HHH", data, 148, 240, 0x2002, 0x20B)
    struct.pack_into("<II", data, 408, 512, 512)
    struct.pack_into("<I", data, 428, 0x60000020)
    assert pe_fixture(bytes(data), True)["machine"] == 0x8664
    for offset, format_string, value in ((60, "<I", 0xFFFFFFF0), (132, "<H", 0xAA64),
            (134, "<H", 99), (148, "<H", 239), (150, "<H", 2), (152, "<H", 0x10B),
            (408, "<I", 0xFFFFFF00), (412, "<I", 100), (428, "<I", 0xE0000020)):
        changed = bytearray(data); struct.pack_into(format_string, changed, offset, value)
        try:
            pe_fixture(bytes(changed), True)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Malformed PE fixture accepted")
    expected = {"status": "ready", "gate": "verified-pin", "native_executed": False}
    assert exact_record(json.dumps(expected), expected) == expected
    for changed in ({**expected, "native_executed": 0}, {**expected, "status": "pass"}, {**expected, "extra": True}):
        try:
            exact_record(json.dumps(changed), expected)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Forged native fixture record accepted")
    mutations = {key: 32 for key in ("write_error", "delete_error", "replace_error", "rename_error", "parent_rename_error")}
    mutations["native_executed"] = False
    assert mutation_record(json.dumps(mutations)) == mutations
    for changed in ({**mutations, "write_error": 0}, {**mutations, "replace_error": 2},
            {**mutations, "parent_rename_error": False}):
        try:
            mutation_record(json.dumps(changed))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Unproven external mutation rejection accepted")
    # Windows-only fixture inputs must not rebuild either qualified Linux Host.
    import retry
    module = Path(cm_platforms.__file__).read_text()
    recipe = "    env:\n      CM_TARGET: x86_64-unknown-linux-gnu\n    steps:\n"
    rows = b"100644 blob aaaa\tci/scripts/cm_platforms.py\x00"
    additions = b"".join(b"100644 blob bbbb\t" + path.encode() + b"\x00" for path in (
        "ci/worker-files-windows-x64.json", "ci/scripts/windows_x64_preflight.py",
        "fixtures/native-loader/windows-preflight.c", "ci/scripts/windows_isolation_preflight.py",
        "fixtures/native-loader/windows-isolation-probe.rs", "fixtures/native-loader/windows-lpac-network.c"))
    with patch.object(retry, "source", side_effect=lambda root, revision, path:
            module if path == "ci/scripts/cm_platforms.py" else recipe):
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            with patch.dict(os.environ, {"CM_TARGET": target}), patch.object(retry, "git", return_value=rows):
                baseline = retry.product_inputs(Path("."), "HEAD")
                with patch.object(retry, "git", return_value=rows + additions):
                    assert retry.product_inputs(Path("."), "HEAD") == baseline
                with patch.object(retry, "git", return_value=rows + additions + b"100644 blob cccc\tcrates/cm/src/lib.rs\x00"):
                    assert retry.product_inputs(Path("."), "HEAD") != baseline
    terminal = {"status": "pass", "gate": "ConPTY-control", "initial_columns": 96, "initial_rows": 28,
        "resized_columns": 120, "resized_rows": 40, "input": "Y", "child_exit_code": 0,
        "drain_error": 109, "output_bytes": 100, "full_host_tui": "not_run"}
    assert terminal_record(json.dumps(terminal)) == terminal
    for changed in ({**terminal, "output_bytes": True}, {**terminal, "child_exit_code": 1},
            {**terminal, "drain_error": 0}, {**terminal, "resized_rows": 28}, {**terminal, "full_host_tui": "pass"}):
        try:
            terminal_record(json.dumps(changed))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Incomplete ConPTY observation accepted")
    lpac = {"status": "pass", "gate": "lpac-internal-provider-network-control", "outside_token_checks": 3,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "capability_count": 0, "ordinary_file_positive": True, "lpac_opt_out_file_denied": True,
        "private_file_positive": True, "provider_http_positive": True, "outside_listener_positive": True,
        "outside_connect_error": 10013, "outside_unexpected_accepts": 0, "profile_deleted": True,
        "full_isolation": "not_run", "product": "not_run"}
    assert lpac_network_record(json.dumps(lpac)) == lpac
    changed = [{**lpac, key: value} for key, value in (("outside_token_checks", True), ("capability_count", 1),
        ("environment_allowlist_count", True), ("environment_allowlist_count", 0), ("environment_allowlist_count", 7),
        ("outside_connect_error", 10061), ("outside_connect_error", 10060), ("outside_unexpected_accepts", 1),
        ("profile_deleted", False), ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
    changed += [{**lpac, key: False} for key, value in lpac.items() if type(value) is bool]
    changed += [{key: value for key, value in lpac.items() if key != "provider_http_positive"}]
    for raw in [json.dumps(value) for value in changed] + ["[]", " " * 8193]:
        try:
            lpac_network_record(raw)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError("Incomplete or overclaimed LPAC network observation accepted")
    print("Windows preflight authority, PE fixture and bounded native records self-check passed", flush=True)


if __name__ == "__main__":
    main()
