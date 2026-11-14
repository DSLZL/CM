"""Fixed native build inputs and existing ABI layouts; no product build."""
import gzip
import csv
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import tomllib
import urllib.request

import ci_progress
import record_run
from windows_x64_preflight import authority, exact_record, pe_fixture

KEY = "windows-arm64"
TARGET = "aarch64-pc-windows-msvc"
REVISION = "e4568a3538c9cab6627d64ff8cdfc7d98b79b7db"
SOURCE_HASHES = {
    "scripts/codex_package/v8.py": "a6ec2a955af2e99e8823aeaf8ea079aa8af170f7758fd639dfec7cc7bf91f238",
    "scripts/codex_package/targets.py": "aa0b4f6652b27b512ffe759c9e2609909e90ea076716625b5a941e52f38ff2ed",
    "codex-rs/Cargo.lock": "319fbf5f0e3f1217f09e3bdeeae5bbd6b9da208e30495d7f5eb3102a76474812",
    "third_party/v8/rusty_v8_152_2_0_release_manifests.sha256": "1dd7c7f7d3d91af7f06a2846bddc6a1da7725acc67ecd7ab2c7dfc980dd8c6d4",
    "codex-rs/code-mode-protocol/build.rs": "92171dbc25135066d8a17dbdab947566f56e44d8ff39629de67842fa01856658",
    "codex-rs/code-mode-protocol/Cargo.toml": "2ac9af96867f5babb423d9865e1e1277329e6e1fb10a069d0cb9e380beef2b70",
}
LAYOUTS = {
    "native-loader": {"header": 8, "bytes": 16, "error": 24, "host": 32, "mod": 72,
        "input": 96, "output": 16, "alignment": 8, "policy_offset": 48, "original_offset": 88},
    "runtime-composition": {"v1_preserved": True, "v2_all_sizes_alignments_offsets": True},
    "runtime-consumer": {"v21_all_sizes_alignments_offsets": True},
    "runtime-sdk": {"v22_all_sizes_alignments_offsets": True, "unchanged_v21_prefix": True},
}
RUST_TESTS = {
    "tests::linux_x64_layout", "v2::tests::linux_x64_composition_layout",
    "v21::tests::linux_x64_additive_layout", "v22::tests::linux_x64_layout_and_unchanged_prefixes",
    "v23::tests::additive_layout_keeps_the_legacy_prefix",
}


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url, path, expected, limit):
    if path.exists() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("Fresh pinned download required")
    size = 0
    with ci_progress.stage("download-" + path.name), urllib.request.urlopen(url, timeout=120) as source, path.open("xb") as output:
        while data := source.read(1024 * 1024):
            size += len(data)
            if size > limit:
                raise RuntimeError("Pinned input download exceeds its bound")
            output.write(data)
    if not size or sha(path) != expected:
        raise RuntimeError("Pinned input download digest differs: " + path.name)
    return {"url": url, "bytes": size, "sha256": expected}


def coff_members(path, evidence):
    # Only inspect member machines here; product linking and dependency checks remain separate gates.
    size = path.stat().st_size
    if not 68 <= size <= 1024 * 1024 * 1024:
        raise RuntimeError("V8 library size is outside the bounded preflight")
    objects, special, rows = 0, {"/": 0, "//": 0}, []
    with path.open("rb") as source:
        if source.read(8) != b"!<arch>\n":
            raise RuntimeError("Expected COFF archive signature")
        while source.tell() < size:
            offset = source.tell()
            header = source.read(60)
            if len(header) != 60 or header[58:] != b"`\n" or not re.fullmatch(rb"[0-9]+ *", header[48:58]):
                raise RuntimeError("Invalid or truncated COFF archive member")
            length = int(header[48:58])
            end = source.tell() + length
            name = header[:16].decode("ascii", errors="strict").rstrip(" ")
            if end > size or not name or any(ord(char) < 32 for char in name):
                raise RuntimeError("Invalid COFF member name/range")
            if name in special:
                special[name] += 1
                if objects or special["/"] > 2 or special["//"] > 1:
                    raise RuntimeError("Unexpected COFF archive metadata member")
            else:
                data = source.read(min(length, 56))
                if len(data) < 20:
                    raise RuntimeError("Truncated COFF object header")
                machine, sections = struct.unpack_from("<HH", data)
                header_size = 20
                if (machine, sections) == (0, 0xFFFF):
                    if (len(data) < 56 or struct.unpack_from("<H", data, 4)[0] != 2
                            or data[12:28] != bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8")):
                        raise RuntimeError("Unsupported nonstandard COFF object")
                    machine = struct.unpack_from("<H", data, 6)[0]
                    sections = struct.unpack_from("<I", data, 44)[0]
                    header_size = 56
                elif struct.unpack_from("<H", data, 16)[0] != 0:
                    raise RuntimeError("Expected COFF object without an image optional header")
                if machine != 0xAA64 or not 1 <= sections <= (length - header_size) // 40:
                    raise RuntimeError("Non-ARM64 or truncated V8 COFF object at " + str(offset))
                objects += 1
                rows.append((offset, length, machine, name))
                if objects > 20000:
                    raise RuntimeError("V8 member count exceeds preflight bound")
            source.seek(end)
            if length % 2 and source.read(1) != b"\n":
                raise RuntimeError("Invalid COFF archive alignment byte")
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows([("offset", "bytes", "machine", "header_name"), *rows])
    text = output.getvalue()
    if not objects or not special["/"] or len(text.encode("ascii")) > 900000:
        raise RuntimeError("Missing or oversized complete V8 member evidence")
    evidence.write_text(text, encoding="ascii")
    return {"scope": "all-coff-object-member-machines", "machine": 0xAA64, "objects": objects,
        "metadata_members": special, "bytes": size, "sha256": sha(path),
        "members_file": evidence.name, "members_sha256": sha(evidence), "link_test": "not_run"}


def crate_file(archive, name, limit):
    with tarfile.open(archive, "r:gz") as source:
        matches = [row for row in source.getmembers() if row.name == name]
        if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= limit:
            raise RuntimeError("Missing unique bounded regular crate input: " + name)
        with source.extractfile(matches[0]) as stream:
            data = stream.read(limit + 1)
        if len(data) != matches[0].size:
            raise RuntimeError("Crate input length differs")
        return data


def rust_results(text):
    names = re.findall(r"^test (\S+) \.\.\. ok$", text, re.MULTILINE)
    if set(names) != RUST_TESTS or len(names) != len(RUST_TESTS) or not re.search(
            r"^test result: ok\. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", text, re.MULTILINE):
        raise RuntimeError("All five unfiltered existing Rust ABI tests must pass")
    return {"tests": sorted(names), "passed": 5, "failed": 0, "filtered": 0,
        "historical_test_names": True, "experimental_abi_2_3_separate": True}


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    authority(json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text()), entry, os.environ, key=KEY)
    if os.environ.get("CM_PREFLIGHT_STAGE") != "native-inputs" or Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Native input preflight requires its exact reviewed stage/source")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Native input text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running", "scope": "V01g-native-inputs-and-abi-only",
        "platform": KEY, "target": TARGET, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "request_id": os.environ["CM_REQUEST_ID"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "cache_mode": "none", "cache_writes": 0, "cache_deletes": 0, "product_build": "not_run",
        "qualification": "not_run", "platform_enabled": False, "release_ready": False,
        "loader_port": "not_run", "dependency_search_attacks": "not_run", "full_isolation": "not_run"}

    def run(label, args, timeout=30):
        values = [str(value) for value in args]
        with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"stage": label, "command": values, "cwd": str(Path.cwd())}) + "\n")
        result = ci_progress.run(logs, label, values, timeout)
        text = (logs / (label + ".log")).read_text(encoding="utf-8", errors="strict").strip()
        if result.returncode:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return text

    try:
        cfg = json.loads((root / ".github/cm-ci.json").read_text(encoding="utf-8"))
        if cfg["upstream"]["commit"] != REVISION or cfg["rust_toolchain"] != "1.95.0":
            raise RuntimeError("Native input pins changed and require review")
        cl = Path(shutil.which("cl.exe") or "")
        if not cl.is_absolute() or tuple(part.lower() for part in cl.parts[-3:]) != ("hostarm64", "arm64", "cl.exe"):
            raise RuntimeError("Missing installed native Hostarm64/arm64 MSVC")
        report["environment"] = {name: os.environ[name] for name in (
            "ImageOS", "ImageVersion", "VCToolsVersion", "WindowsSDKVersion", "VCToolsInstallDir", "WindowsSdkDir")}
        report["tools"] = {"cl": {"path": str(cl), **pe_fixture(cl.read_bytes(), False, expected_machine=0xAA64)}}
        with tempfile.TemporaryDirectory(prefix="cm-windows-arm64-native-inputs-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory)
            toolchain = cfg["rust_toolchain"] + "-" + TARGET
            run("native-toolchain", ["rustup", "toolchain", "install", toolchain, "--profile", "minimal"], 180)
            for name in ("rustc", "cargo"):
                tool = Path(run("native-" + name + "-path", ["rustup", "which", "--toolchain", toolchain, name]))
                report["tools"][name] = {"path": str(tool), **pe_fixture(tool.read_bytes(), False, expected_machine=0xAA64)}
                report[name] = run("native-" + name + "-version", [tool, "-Vv"])
                if "host: " + TARGET not in report[name].splitlines():
                    raise RuntimeError(name + " is not the fixed native ARM64 host")
            inputs = sorted([*root.glob("crates/cm-abi/src/*.rs"), *root.glob("crates/cm-abi/include/*.h"),
                *(root / "fixtures" / name / "layout.c" for name in LAYOUTS)])
            report["abi_source_sha256"] = {str(path.relative_to(root)).replace("\\", "/"): sha(path) for path in inputs}
            report["c_abi"] = {}
            for name, expected in LAYOUTS.items():
                binary = temp / (name + ".exe")
                run("compile-" + name, [cl, "/nologo", "/Bv", "/std:c11", "/W4", "/WX", "/O2", "/MT", "/utf-8", "/TC",
                    root / "fixtures" / name / "layout.c", "/Fo" + str(temp / (name + ".obj")),
                    "/Fe" + str(binary), "/link", "/INCREMENTAL:NO"], 120)
                identity = pe_fixture(binary.read_bytes(), False, expected_machine=0xAA64)
                report["c_abi"][name] = {"binary": identity, "layout": exact_record(run("run-" + name, [binary]), expected)}
            tests = temp / "cm-abi-tests.exe"
            run("compile-rust-abi", [report["tools"]["rustc"]["path"], "--edition=2021", "--test",
                "--target", TARGET, root / "crates/cm-abi/src/lib.rs", "-o", tests], 120)
            report["rust_abi"] = {"binary": pe_fixture(tests.read_bytes(), False, expected_machine=0xAA64),
                **rust_results(run("run-rust-abi", [tests, "--test-threads=1"]))}
            upstream = temp / "fixed-upstream-inputs"
            report["upstream"] = {"repository": "openai/codex", "commit": REVISION, "scope": "six-fixed-files-only", "files": {}}
            for relative, expected in SOURCE_HASHES.items():
                path = upstream / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                report["upstream"]["files"][relative] = download(
                    "https://raw.githubusercontent.com/openai/codex/" + REVISION + "/" + relative, path, expected, 524288)
            packages = tomllib.loads((upstream / "codex-rs/Cargo.lock").read_text())["package"]
            report["protoc"] = {"native": False, "executed": False, "crates": {}}
            for name, member, limit in (("protoc-bin-vendored", "src/lib.rs", 65536),
                    ("protoc-bin-vendored-win32", "bin/protoc.exe", 32 * 1024 * 1024)):
                matches = [row for row in packages if row["name"] == name]
                if len(matches) != 1 or matches[0]["version"] != "3.2.0":
                    raise RuntimeError("Pinned protoc crate version differs")
                archive = temp / (name + ".crate")
                report["protoc"]["crates"][name] = download("https://static.crates.io/crates/" + name + "/" + name + "-3.2.0.crate",
                    archive, matches[0]["checksum"], 16 * 1024 * 1024)
                data = crate_file(archive, name + "-3.2.0/" + member, limit)
                if member.endswith(".rs"):
                    (logs / "pinned-protoc-selection.rs.txt").write_text(data.decode("utf-8", errors="strict"), encoding="utf-8")
                else:
                    protoc = temp / "protoc.exe"
                    protoc.write_bytes(data)
                    report["protoc"].update(bytes=len(data), sha256=sha(protoc))
                    try:
                        report["protoc"]["binary"] = pe_fixture(data, False, expected_machine=0xAA64)
                    except RuntimeError as error:
                        report["protoc"]["rejection"] = str(error)
                        if len(data) >= 64 and data[:2] == b"MZ":
                            offset = struct.unpack_from("<I", data, 60)[0]
                            if offset + 6 <= len(data) and data[offset:offset + 4] == b"PE\0\0":
                                report["protoc"]["observed_machine"] = struct.unpack_from("<H", data, offset + 4)[0]
                    else:
                        report["protoc"].update(native=True, executed=True, version=run("native-protoc-version", [protoc, "--version"]))
                        if not re.fullmatch(r"libprotoc [0-9]+\.[0-9]+(?:\.[0-9]+)?", report["protoc"]["version"]):
                            raise RuntimeError("Unexpected native protoc version record")
                        proto, descriptor = temp / "smoke.proto", temp / "smoke.pb"
                        proto.write_text('syntax = "proto3"; package cm.preflight; message Probe { uint64 value = 1; }\n', encoding="utf-8")
                        run("native-protoc-descriptor", [protoc, "--proto_path=" + str(temp), "--descriptor_set_out=" + str(descriptor), proto])
                        if not descriptor.is_file() or not 0 < descriptor.stat().st_size <= 4096:
                            raise RuntimeError("Missing bounded native protoc descriptor")
                        report["protoc"]["descriptor_sha256"] = sha(descriptor)
            if any(os.environ.get(name) for name in ("V8_FROM_SOURCE", "RUSTY_V8_ARCHIVE", "RUSTY_V8_SRC_BINDING_PATH")):
                raise RuntimeError("V8 overrides are not native input evidence")
            os.environ["CODEX_REPO_ROOT"] = str(upstream)
            sys.path.insert(0, str(upstream / "scripts"))
            with ci_progress.stage("fixed-native-v8-inputs"):
                specs = importlib.import_module("codex_package.targets").TARGET_SPECS
                resolver = importlib.import_module("codex_package.v8")
                values = resolver.resolve_codex_v8_cargo_env(specs[TARGET], environ={}, cache_root=temp / "v8-inputs")
                if set(values) != {"RUSTY_V8_ARCHIVE", "RUSTY_V8_SRC_BINDING_PATH"} or resolver.resolved_v8_crate_version() != "152.2.0":
                    raise RuntimeError("Fixed V8 resolver/version differs")
                archive, binding = (Path(values[name]) for name in ("RUSTY_V8_ARCHIVE", "RUSTY_V8_SRC_BINDING_PATH"))
                library = temp / "rusty_v8.lib"
                with gzip.open(archive, "rb") as source, library.open("xb") as output:
                    size = 0
                    while data := source.read(1024 * 1024):
                        size += len(data)
                        if size > 1024 * 1024 * 1024:
                            raise RuntimeError("Uncompressed V8 library exceeds preflight bound")
                        output.write(data)
                report["v8"] = {"version": "152.2.0", "profile": resolver.V8_ARTIFACT_PROFILE,
                    "archive_sha256": sha(archive), "archive_bytes": archive.stat().st_size,
                    "binding_sha256": sha(binding), "binding_bytes": binding.stat().st_size,
                    "manifest_sha256": sha(archive.with_suffix("").with_suffix(".sha256")),
                    **coff_members(library, logs / "v8-members.csv")}
            if any(sha(upstream / relative) != expected for relative, expected in SOURCE_HASHES.items()) or any(
                    sha(root / relative) != expected for relative, expected in report["abi_source_sha256"].items()):
                raise RuntimeError("Native input preflight changed its source inputs")
            run("source-pristine", ["git", "-C", root, "diff", "--exit-code"])
            if not report["protoc"]["native"]:
                report["blocked_at"] = "non-native-vendored-protoc"
                raise RuntimeError("Pinned vendored protoc is not ARM64; it was not executed and no CLI build was started")
            report["status"] = "observed_native_inputs_and_abi_only"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        (logs / "windows-native-inputs.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def self_check():
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        def member(name, data):
            header = name.encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6) * 2 + b"0".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n"
            return header + data + (b"\n" if len(data) % 2 else b"")
        normal = struct.pack("<HHIIIHH", 0xAA64, 1, 0, 0, 0, 0, 0) + bytes(40)
        big = struct.pack("<HHHHI", 0, 0xFFFF, 2, 0xAA64, 0) + bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8") + bytes(16) + struct.pack("<III", 1, 0, 0) + bytes(40)
        path, evidence = temp / "input.lib", temp / "members.csv"
        valid = b"!<arch>\n" + member("/", b"index") + member("normal.obj/", normal) + member("big.obj/", big)
        path.write_bytes(valid)
        assert coff_members(path, evidence)["objects"] == 2
        for invalid in (b"", valid[:-1], valid + b"x", valid.replace(b"!<arch>", b"!<thin>"),
                valid.replace(b"\x64\xaa", b"\x64\x86", 1), valid.replace(b"normal.obj/", b"//        ", 1),
                b"!<arch>\n" + member("normal.obj/", normal),
                b"!<arch>\n" + member("/", b"index") + member("bad.obj/", b"\x00\x00\xff\xff" + bytes(56)),
                valid.replace(b"`\n", b"??", 1), valid.replace(b"index\n", b"indexX", 1)):
            path.write_bytes(invalid)
            try:
                coff_members(path, evidence)
            except (RuntimeError, UnicodeError):
                pass
            else:
                raise AssertionError("Invalid V8 archive accepted")
        good = "\n".join("test " + name + " ... ok" for name in sorted(RUST_TESTS)) + "\ntest result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
        assert rust_results(good)["passed"] == 5
        for invalid in (good.replace("5 passed", "4 passed"), good.replace("0 ignored", "1 ignored"),
                good.replace("0 filtered out", "1 filtered out"), good + "test extra ... ok\n", good.replace("... ok", "... FAILED", 1)):
            try:
                rust_results(invalid)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Incomplete Rust ABI test run accepted")
        archive = temp / "crate.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            row = tarfile.TarInfo("expected"); row.size = 4
            output.addfile(row, io.BytesIO(b"test"))
        assert crate_file(archive, "expected", 4) == b"test"
        for name, limit in (("missing", 4), ("expected", 3)):
            try:
                crate_file(archive, name, limit)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Unbounded or missing crate input accepted")
        for kind in ("duplicate", "symlink"):
            with tarfile.open(archive, "w:gz") as output:
                row = tarfile.TarInfo("expected")
                if kind == "duplicate":
                    row.size = 4
                    output.addfile(row, io.BytesIO(b"test"))
                    output.addfile(row, io.BytesIO(b"test"))
                else:
                    row.type = tarfile.SYMTYPE; row.linkname = "outside"
                    output.addfile(row)
            try:
                crate_file(archive, "expected", 4)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Duplicate or linked crate input accepted")
        expected = hashlib.sha256(b"test").hexdigest()
        for index, (digest, limit) in enumerate(((expected, 4), ("0" * 64, 4), (expected, 3))):
            destination = temp / ("download-" + str(index))
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b"test")):
                try:
                    value = download("https://example.invalid/fixed", destination, digest, limit)
                except RuntimeError:
                    assert index != 0
                else:
                    assert index == 0 and value["bytes"] == 4 and sha(destination) == expected
        with patch("urllib.request.urlopen") as fetch:
            try:
                download("https://example.invalid/fixed", temp / "download-0", expected, 4)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Existing pinned input overwritten")
            fetch.assert_not_called()
        root = Path(__file__).resolve().parents[2]
        for changes in ({"CM_PREFLIGHT_STAGE": "isolation-inputs"}, {"CM_SOURCE_DIR": str(temp)}):
            env = {"RUNNER_TEMP": str(temp), "CM_SOURCE_DIR": str(root), "CM_PREFLIGHT_STAGE": "native-inputs", **changes}
            (temp / "cm-worker-preflight.json").write_text("{}", encoding="utf-8")
            with patch.dict(os.environ, env, clear=True), patch.object(record_run, "require_hosted_worker", return_value={}), \
                    patch(__name__ + ".authority"), patch("shutil.which") as tool, patch("urllib.request.urlopen") as fetch:
                try:
                    main()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Wrong native input stage/source accepted")
                tool.assert_not_called(); fetch.assert_not_called()
    print("Windows native inputs self-check passed; no native tool or product execution", flush=True)


if __name__ == "__main__":
    main()
