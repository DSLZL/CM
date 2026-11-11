"""Hosted-only Darwin mechanism counterexamples; never builds the Codex CLI."""
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile

import ci_progress
import cm_platforms
import record_run

KEY = "macos-arm64"
TARGET = "aarch64-apple-darwin"


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
        raise RuntimeError("Darwin probe differs from its exact cache-none native preflight authority")


def macho(data, kind):
    if len(data) < 32:
        raise RuntimeError("Truncated native Mach-O")
    magic, cpu, subtype, filetype, count, command_bytes, flags, reserved = struct.unpack_from("<8I", data)
    if (magic != 0xfeedfacf or cpu != 0x100000c or filetype != kind or not count
            or command_bytes > len(data) - 32 or count > command_bytes // 8):
        raise RuntimeError("Probe must be a bounded thin native ARM64 Mach-O of the expected kind")
    offset, dependencies = 32, []
    for _ in range(count):
        if offset + 8 > 32 + command_bytes:
            raise RuntimeError("Truncated Mach-O load command")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or size % 8 or offset + size > 32 + command_bytes:
            raise RuntimeError("Invalid Mach-O load command")
        if command in (0xc, 0x18 | 0x80000000, 0x1f | 0x80000000, 0x23 | 0x80000000):
            if size < 24:
                raise RuntimeError("Truncated dylib load command")
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if name_offset < 24 or name_offset >= size:
                raise RuntimeError("Invalid dylib name offset")
            raw = data[offset + name_offset:offset + size]
            if b"\0" not in raw:
                raise RuntimeError("Unterminated dylib dependency")
            name = raw.split(b"\0", 1)[0].decode("utf-8")
            if not name.startswith(("/usr/lib/", "/System/Library/")) or ".." in name.split("/"):
                raise RuntimeError("Probe depends on a non-system dylib")
            dependencies.append(name)
        offset += size
    if offset != 32 + command_bytes:
        raise RuntimeError("Mach-O command inventory is incomplete")
    return {"format": "macho64", "cpu": cpu, "subtype": subtype, "filetype": filetype,
        "dependencies": dependencies, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def snapshot_result(text):
    value = json.loads(text)
    if (not isinstance(value, dict) or value.get("status") != "failed" or value.get("gate") != "same-byte-snapshot"
            or value.get("retained_writer_control") != "pass"
            or value.get("frozen_loading_qualified") is not False or value.get("native_executed") is not False
            or type(value.get("post_rmdir_create")) is not bool
            or type(value.get("adversarial_directory_reopen")) is not bool
            or any(type(value.get(key)) is not int or value[key] < 0 for key in ("create_errno", "reopen_errno"))):
        raise RuntimeError("Snapshot diagnostic cannot be presented as qualified frozen loading")
    if not value["post_rmdir_create"] and (not value["create_errno"] or value["adversarial_directory_reopen"]):
        raise RuntimeError("Inconsistent anonymous directory result")
    return value


def seatbelt(probe, marker, work, port):
    literal = lambda value: "(literal " + json.dumps(str(value)) + ")"
    return "\n".join(["(version 1)", "(deny default)",
        "(allow process-exec " + literal(probe) + ")",
        "(allow process-fork)", "(allow signal (target same-sandbox))",
        "(allow file-read-metadata)",
        "(allow file-read* file-map-executable (subpath \"/usr/lib\") (subpath \"/System/Library\"))",
        "(allow file-read* file-map-executable " + literal(probe) + ")",
        "(allow file-read-data " + literal(marker) + ")",
        "(allow file-read* file-write* (subpath " + json.dumps(str(work)) + "))",
        "(allow file-read* file-write-data (literal \"/dev/null\"))",
        "(allow file-read* file-write-data (literal \"/dev/fd/0\") (literal \"/dev/fd/1\") (literal \"/dev/fd/2\"))",
        '(allow network-outbound (remote ip "localhost:' + str(port) + '"))', ""])


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    policy = json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text())
    authority(policy, entry, os.environ)
    if Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Mechanism source must be the exact recorded source checkout")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Probe text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running", "platform": KEY, "target": TARGET,
        "source_sha": os.environ["CM_SOURCE_SHA"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "request_id": os.environ["CM_REQUEST_ID"], "cache_mode": "none", "cache_writes": 0,
        "product_build": "not_run", "rust_v8_terminal": "not_run", "qualification": "not_run",
        "release_ready": False, "same_byte": {"status": "not_run"}, "isolation": {"status": "not_run"}}

    def run(label, command, timeout=60, codes=(0,)):
        command = [str(value) for value in command]
        with (logs / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps({"stage": label, "command": command, "timeout_seconds": timeout}) + "\n")
        result = ci_progress.run(logs, label, command, timeout)
        if result.returncode not in codes:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return (logs / (label + ".log")).read_text(errors="replace")

    try:
        with tempfile.TemporaryDirectory(prefix="cm-ma-mechanisms-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory).resolve()
            clang = run("native-clang-path", ["/usr/bin/xcrun", "--find", "clang"]).strip()
            if not Path(clang).is_absolute() or not Path(clang).is_file():
                raise RuntimeError("Missing native Apple clang")
            report["environment"] = {"sdk": run("native-sdk", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"]).strip(),
                "sdk_path": run("native-sdk-path", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"]).strip(),
                "os": run("native-os", ["/usr/bin/sw_vers", "-productVersion"]).strip(),
                "arm64": run("native-cpu", ["/usr/sbin/sysctl", "-n", "hw.optional.arm64"]).strip(),
                "clang": run("native-clang", [clang, "--version"]).strip(),
                "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion")}
            if report["environment"]["arm64"] != "1":
                raise RuntimeError("Missing real ARM64 CPU")
            if (report["environment"]["os"].split(".")[0] != "26"
                    or not report["environment"]["image_os"] or not report["environment"]["image_version"]):
                raise RuntimeError("Missing exact macOS 26 hosted image identity")
            source = root / "fixtures/native-loader/macos-preflight.c"
            probe, payload = temp / "native-probe", temp / "sentinel.dylib"
            compile_flags = ["-arch", "arm64", "-mmacosx-version-min=26.0", "-std=c11", "-Wall",
                "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-D_DARWIN_C_SOURCE", "-O2"]
            run("compile-native-probe", [clang, *compile_flags, source, "-o", probe], 120)
            run("compile-sentinel-dylib", [clang, *compile_flags, "-DCM_PAYLOAD", "-dynamiclib",
                source, "-o", payload], 120)
            report["inputs"] = {"probe": macho(probe.read_bytes(), 2), "payload": macho(payload.read_bytes(), 6)}
            for name, path in (("probe", probe), ("payload", payload)):
                run(name + "-dependencies", ["/usr/bin/otool", "-L", path])
                run(name + "-signature", ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", path])
                run(name + "-signature-details", ["/usr/bin/codesign", "-d", "--verbose=2", path])
            clean = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=" + str(temp), probe]
            try:
                bad_marker, marker = temp / "wrong-hash-marker", temp / "verified-marker"
                wrong = json.loads(run("wrong-hash-before-constructor",
                    [*clean, "load", payload, "0" * 64, bad_marker], codes=(3,)))
                if wrong != {"status": "rejected", "gate": "payload-hash", "native_executed": False} or bad_marker.exists():
                    raise RuntimeError("Wrong hash reached native constructor")
                positive = json.loads(run("ordinary-dlopen-control",
                    [*clean, "load", payload, report["inputs"]["payload"]["sha256"], marker]))
                if (positive.get("status") != "pass" or positive.get("constructor_value") != 41
                        or positive.get("native_executed") is not True
                        or positive.get("frozen_loading_qualified") is not False
                        or marker.read_bytes() != b"verified-constructor\n"):
                    raise RuntimeError("Dylib/constructor positive control failed")
                report["same_byte"] = snapshot_result(run("anonymous-directory-and-retained-writer",
                    [*clean, "snapshot", temp], codes=(2,)))
                report["same_byte"]["controls"] = {"wrong_hash": wrong, "ordinary_dlopen": positive}
            except Exception as exc:
                report["same_byte"] = {"status": "failed", "error": str(exc), "frozen_loading_qualified": False}
            try:
                marker, work = temp / "input", temp / "work"
                marker.write_bytes(b"immutable")
                marker.chmod(0o666)
                work.mkdir()
                denied_files = [temp / "outside", root / ".github/cm-ci.json", temp / "private-cache"]
                denied_files[0].write_bytes(b"outside")
                denied_files[2].write_bytes(b"private-cache")
                before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [marker, *denied_files]}
                alias = work / "compiler-link"
                alias.symlink_to(clang)
                run("compiler-link-control", [alias, "--version"])
                with socket.socket() as provider, socket.socket() as outside, \
                        socket.socket(type=socket.SOCK_DGRAM) as udp:
                    for connection in (provider, outside):
                        connection.bind(("127.0.0.1", 0))
                        connection.listen(8)
                        connection.settimeout(0.2)
                    udp.bind(("127.0.0.1", outside.getsockname()[1]))
                    udp.settimeout(0.2)
                    profile = temp / "profile.sb"
                    text = seatbelt(probe, marker, work, provider.getsockname()[1])
                    profile.write_text(text)
                    (logs / "seatbelt-profile.sb.txt").write_text(text)
                    result = json.loads(run("seatbelt-native-parent-and-child", ["/usr/bin/env", "-i",
                        "PATH=/usr/bin:/bin", "HOME=" + str(work), "/usr/bin/sandbox-exec", "-f", profile,
                        probe, "isolation", marker, work, *denied_files, clang, alias,
                        provider.getsockname()[1], outside.getsockname()[1]]))
                    hits = []
                    for connection in (provider, outside):
                        count = 0
                        while True:
                            try:
                                accepted, _ = connection.accept()
                            except socket.timeout:
                                break
                            accepted.close()
                            count += 1
                        hits.append(count)
                    if result != {"status": "pass", "gate": "seatbelt-controls", "parent_checks": 12, "child_checks": 12} or hits != [2, 0]:
                        raise RuntimeError("Missing positive provider controls or external canary denial")
                    try:
                        udp.recvfrom(64)
                    except socket.timeout:
                        pass
                    else:
                        raise RuntimeError("Isolated probe reached the external UDP canary")
                if before != {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [marker, *denied_files]}:
                    raise RuntimeError("Isolated probe changed protected inputs")
                report["isolation"] = {**result, "provider_hits": 2, "outside_hits": 0, "outside_udp_hits": 0,
                    "protected_inputs_unchanged": True, "full_consumer_audit": "not_run"}
            except Exception as exc:
                report["isolation"] = {"status": "failed", "error": str(exc)}
            report["status"] = "failed"
    except Exception as exc:
        report["status"], report["error"] = "failed", str(exc)
    finally:
        (logs / "macos-arm64-mechanisms.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "same_byte": report["same_byte"]["status"],
        "isolation": report["isolation"]["status"], "qualification": "not_run", "product_build": "not_run"}), flush=True)
    raise RuntimeError("Frozen Darwin loading remains unqualified; no full CLI build is permitted by this preflight")


def self_check():
    from copy import deepcopy
    from unittest.mock import patch
    entry = cm_platforms.select(KEY)
    env = {"CM_EXECUTION_ROLE": "platform_preflight", "GITHUB_JOB": "native-preflight",
        "GITHUB_REF": "refs/heads/main", "CM_BUILD_KIND": "qualification", "CM_HOST_ORIGIN": "",
        "CM_CACHE_MODE": "none", "ACTIONS_CACHE_MODE": "none", "CM_SOURCE_SHA": "a" * 40,
        "GITHUB_WORKFLOW_SHA": "b" * 40, "CM_REQUEST_ID": "check",
        "GITHUB_WORKFLOW_REF": entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main"}
    policy = {"source_repository": "DSLZL/CM", "source_sha": "a" * 40, "observed_source_default_sha": "a" * 40,
        "source_default_branch": "main", "builder_repository": entry["repository"], "workflow_sha": "b" * 40,
        "worker_default_branch": "main", "request_id": "check", "platform": KEY, "target": TARGET,
        "cache_mode": "none", "execution_role": "platform_preflight", "build_kind": "qualification",
        "consumer_required": "false", "distribution_required": "false", "index_required": "false"}
    authority(policy, entry, env)
    for field, value in (("cache_mode", "write"), ("source_sha", "c" * 40), ("target", "x86_64-apple-darwin"),
            ("builder_repository", "DSLZL/CM"), ("index_required", "true"), ("workflow_sha", "c" * 40)):
        try:
            authority({**policy, field: value}, entry, env)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Darwin mechanism authority accepted " + field)
    for field, value in (("GITHUB_JOB", "build-write"), ("GITHUB_REF", "refs/heads/other"),
            ("CM_CACHE_MODE", "write"), ("ACTIONS_CACHE_MODE", "read"), ("CM_HOST_ORIGIN", "{}"),
            ("GITHUB_WORKFLOW_REF", "other"), ("CM_EXECUTION_ROLE", "platform_builder")):
        try:
            authority(policy, entry, {**env, field: value})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Darwin mechanism environment accepted " + field)
    thin = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 6, 1, 24, 0, 0) + struct.pack("<6I", 0x1b, 24, 0, 0, 0, 0)
    assert macho(thin, 6)["cpu"] == 0x100000c
    dependency = b"/tmp/foreign.dylib\0"
    command_size = (24 + len(dependency) + 7) & ~7
    command = (struct.pack("<6I", 0xc, command_size, 24, 0, 0, 0) + dependency).ljust(command_size, b"\0")
    external = thin[:20] + struct.pack("<I", command_size) + thin[24:32] + command
    for data in (thin[:31], b"\0" * len(thin), thin[:4] + struct.pack("<I", 0x1000007) + thin[8:],
            thin[:36] + struct.pack("<I", 32) + thin[40:], thin[:-1], external):
        try:
            macho(data, 6)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid or foreign Mach-O accepted")
    result = {"status": "failed", "gate": "same-byte-snapshot", "retained_writer_control": "pass",
        "frozen_loading_qualified": False, "native_executed": False, "post_rmdir_create": False,
        "create_errno": errno.ENOENT, "adversarial_directory_reopen": False, "reopen_errno": 0}
    assert snapshot_result(json.dumps(result)) == result
    for changes in ({"status": "pass"}, {"frozen_loading_qualified": True}, {"native_executed": True},
            {"retained_writer_control": "not_run"}, {"adversarial_directory_reopen": True}, {"create_errno": 0}):
        try:
            snapshot_result(json.dumps({**deepcopy(result), **changes}))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Diagnostic evidence was misrepresented as frozen loading")
    for value in (None, [], "pass"):
        try:
            snapshot_result(json.dumps(value))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Malformed mechanism evidence was accepted")
    # Darwin-only probe inputs must not rebuild either qualified Linux Host.
    import retry
    module = Path(cm_platforms.__file__).read_text()
    recipe = "    env:\n      CM_TARGET: x86_64-unknown-linux-gnu\n    steps:\n"
    rows = b"100644 blob aaaa\tci/scripts/cm_platforms.py\x00"
    additions = b"".join(b"100644 blob bbbb\t" + path.encode() + b"\x00" for path in (
        "ci/worker-files-macos-arm64.json", "ci/scripts/macos_arm64_preflight.py",
        "fixtures/native-loader/macos-preflight.c"))
    with patch.object(retry, "source", side_effect=lambda root, revision, path:
            module if path == "ci/scripts/cm_platforms.py" else recipe):
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            with patch.dict(os.environ, {"CM_TARGET": target}), patch.object(retry, "git", return_value=rows):
                baseline = retry.product_inputs(Path("unused"), "baseline")
                with patch.object(retry, "git", return_value=rows + additions):
                    assert retry.product_inputs(Path("unused"), "darwin-probe-only") == baseline
                with patch.object(retry, "git", return_value=rows + additions + b"100644 blob cccc\tcrates/cm/src/lib.rs\x00"):
                    assert retry.product_inputs(Path("unused"), "real-product-change") != baseline
    print("Darwin preflight authority, native format and counterexample evidence self-check passed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, KeyError, ValueError) as exc:
        print("CM Darwin mechanism error: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
