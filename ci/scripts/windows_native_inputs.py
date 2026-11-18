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
import zipfile

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
V8_TESTS = {
    "tests::exposes_expected_bazel_target", "tests::exposes_embedded_v8_version",
    "tests::sandbox_feature_matches_linked_v8", "tests::evaluates_integer_addition",
    "tests::evaluates_string_concatenation", "tests::parses_crdtp_dispatchable_messages",
}
V8_SOURCE_HASHES = {
    "codex-rs/Cargo.toml": "05c9740164aa212e1719bae3ad2ec50320b14480ac4171e11cc4ba77782c4f9c",
    "codex-rs/.cargo/config.toml": "b8ae1cea341beb2d4a3c8fb81f97a96f4aee1fd53f769c57f140dfe949806a80",
    "codex-rs/v8-poc/Cargo.toml": "e98d307ee1683087debb02cf5fba46cc1a23177a25cd6b03f74f1539239312c9",
    "codex-rs/v8-poc/src/lib.rs": "7121f241941ebc18758bbc9dbfb0848a9ea25a93a65eecd34c890fc86ccecfcc",
}


PROTOC_SOURCES = (
    ("protobuf", "protocolbuffers/protobuf", "74211c0dfc2777318ab53c2cd2c317a2ef9012de"),
    ("absl", "abseil/abseil-cpp", "9ac7062b1860d895fb5a8cbf58c3e9ef8f674b5f"),
)


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


def rust_results(text, *, tests=RUST_TESTS):
    names = re.findall(r"^test (\S+) \.\.\. ok$", text, re.MULTILINE)
    if set(names) != tests or len(names) != len(tests) or not re.search(
            rf"^test result: ok\. {len(tests)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", text, re.MULTILINE):
        raise RuntimeError("All expected unfiltered Rust tests must pass")
    return {"tests": sorted(names), "passed": len(tests), "failed": 0, "filtered": 0}


def ninja_file(path):
    limit = 4 * 1024 * 1024
    with zipfile.ZipFile(path) as source:
        rows = source.infolist()
        if len(rows) != 1 or rows[0].filename != "ninja.exe" or rows[0].is_dir() or not 0 < rows[0].file_size <= limit or (
                rows[0].external_attr >> 16) & 0o170000 not in (0, 0o100000):
            raise RuntimeError("Expected one bounded regular native Ninja executable")
        with source.open(rows[0]) as stream:
            data = stream.read(limit + 1)
        if len(data) != rows[0].file_size:
            raise RuntimeError("Native Ninja input length differs")
    return data


def protoc_tools(temp, tools, report, run):
    archive, ninja = temp / "ninja-winarm64.zip", temp / "ninja.exe"
    report["native_ninja_input"] = download("https://github.com/ninja-build/ninja/releases/download/v1.13.1/ninja-winarm64.zip",
        archive, "fb959b674970e36a7c9a23191524b80fb5298fc71fc98bfa42456bcc0a8dfb2f", 1024 * 1024)
    ninja.write_bytes(ninja_file(archive))
    cmake_root = Path(os.environ["VSINSTALLDIR"]) / "Common7/IDE/CommonExtensions/Microsoft/CMake"
    sdk_bin = Path(os.environ["WindowsSdkDir"]) / "bin" / os.environ["WindowsSDKVersion"].strip("\\/") / "arm64"
    paths = {"cmake": cmake_root / "CMake/bin/cmake.exe", "ninja": ninja,
        **{name: Path(tools["cl"]["path"]).with_name(name + ".exe") for name in ("link", "lib")},
        **{name: sdk_bin / (name + ".exe") for name in ("rc", "mt")}}
    for name, path in paths.items():
        tools[name] = {"path": str(path), **pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)}
    return paths


def native_protoc(temp, tools, report, run):
    paths = protoc_tools(temp, tools, report, run)
    result = report["protoc_replacement"] = {"version_expected": "libprotoc 31.1", "native": False,
        "executed": False, "build_scope": "protoc-only", "sources": {}, "host_build_integration": "not_run"}
    result["cmake_version"] = run("native-cmake-version", [paths["cmake"], "--version"])
    result["ninja_version"] = run("native-ninja-version", [paths["ninja"], "--version"])
    for name, repository, revision in PROTOC_SOURCES:
        source = temp / name
        run("protoc-" + name + "-init", ["git", "init", source])
        run("protoc-" + name + "-fetch", ["git", "-C", source, "fetch", "--depth=1", "--no-tags",
            "https://github.com/" + repository + ".git", revision], 180)
        run("protoc-" + name + "-checkout", ["git", "-c", "core.hooksPath=NUL", "-C", source, "checkout", "--detach", revision], 180)
        if run("protoc-" + name + "-identity", ["git", "-C", source, "rev-parse", "HEAD"]) != revision:
            raise RuntimeError("Native protoc source checkout differs: " + name)
        result["sources"][name] = {"repository": repository, "commit": revision}
    build = temp / "protoc-build"
    cl = Path(tools["cl"]["path"]).as_posix()
    configured = run("native-protoc-configure", [paths["cmake"], "-S", temp / "protobuf", "-B", build, "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_CXX_STANDARD=17", "-DCMAKE_CXX_STANDARD_REQUIRED=ON",
        "-DCMAKE_C_COMPILER=" + cl,
        "-DCMAKE_CXX_COMPILER=" + cl, "-DCMAKE_LINKER=" + paths["link"].as_posix(),
        "-DCMAKE_AR=" + paths["lib"].as_posix(), "-DCMAKE_MAKE_PROGRAM=" + paths["ninja"].as_posix(),
        "-DCMAKE_RC_COMPILER=" + paths["rc"].as_posix(), "-DCMAKE_MT=" + paths["mt"].as_posix(),
        "-Dprotobuf_BUILD_TESTS=OFF", "-Dprotobuf_BUILD_CONFORMANCE=OFF", "-Dprotobuf_BUILD_EXAMPLES=OFF",
        "-Dprotobuf_BUILD_SHARED_LIBS=OFF", "-Dprotobuf_MSVC_STATIC_RUNTIME=ON",
        "-Dprotobuf_WITH_ZLIB=OFF", "-Dprotobuf_INSTALL=OFF", "-Dprotobuf_FORCE_FETCH_DEPENDENCIES=ON",
        "-DFETCHCONTENT_SOURCE_DIR_ABSL=" + (temp / "absl").as_posix(), "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"], 180)
    if "-- Performing Test ABSL_INTERNAL_AT_LEAST_CXX17 - Success" not in configured.splitlines():
        raise RuntimeError("Native protoc requires one C++17 ABI for Abseil and protobuf")
    result["cxx_standard"] = 17
    # Check the bootstrap include path before building the compiler's other objects.
    run("native-protoc-upb-input", [paths["cmake"], "--build", build, "--target",
        "CMakeFiles/libprotoc.dir/upb_generator/common.cc.obj", "--parallel", "2"], 120)
    run("native-protoc-build", [paths["cmake"], "--build", build, "--target", "protoc", "--parallel", "2"], 720)
    protoc = build / "protoc.exe"
    result["binary"] = pe_fixture(protoc.read_bytes(), False, expected_machine=0xAA64)
    result["native"] = True
    result["executed"] = True
    result["version"] = run("native-built-protoc-version", [protoc, "--version"])
    if result["version"] != result["version_expected"]:
        raise RuntimeError("Native protoc version differs from the fixed vendored version")
    proto, descriptor = temp / "native-smoke.proto", temp / "native-smoke.pb"
    proto.write_text('syntax = "proto3"; package cm.preflight; message Probe { uint64 value = 1; }\n', encoding="utf-8")
    run("native-built-protoc-descriptor", [protoc, "--proto_path=" + str(temp), "--descriptor_set_out=" + str(descriptor), proto])
    if not descriptor.is_file() or not 0 < descriptor.stat().st_size <= 4096:
        raise RuntimeError("Missing bounded native protoc descriptor")
    result["descriptor_sha256"] = sha(descriptor)
    for name, _, _ in PROTOC_SOURCES:
        if run("protoc-" + name + "-pristine", ["git", "-C", temp / name, "status", "--porcelain", "--untracked-files=all"]):
            raise RuntimeError("Native protoc source changed during build: " + name)


def v8_executable(text, target, source):
    if len(text) > 1024 * 1024:
        raise RuntimeError("Oversized V8 Cargo evidence")
    found = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or row.get("reason") != "compiler-artifact":
            continue
        item, profile = row.get("target"), row.get("profile")
        if not isinstance(item, dict) or not isinstance(profile, dict):
            raise RuntimeError("Malformed V8 compiler artifact")
        if item.get("name") != "codex_v8_poc" or profile.get("test") is not True:
            continue
        if not isinstance(item.get("src_path"), str) or not isinstance(row.get("executable"), str):
            raise RuntimeError("Missing V8 test source/executable path")
        if Path(item["src_path"]).resolve() != source.resolve() or not row["executable"]:
            raise RuntimeError("V8 test artifact differs from the fixed proof of concept")
        path = Path(row["executable"]).resolve()
        if not path.is_relative_to(target.resolve()) or path.suffix.lower() != ".exe":
            raise RuntimeError("V8 test executable escapes its private native target")
        found.append(path)
    if len(found) != 1:
        raise RuntimeError("Expected exactly one native V8 test executable")
    return found[0]


def v8_link(temp, tools, values, report, run):
    if any(os.environ.get(name) for name in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "V8_FROM_SOURCE")):
        raise RuntimeError("V8 proof of concept requires the fixed native compiler without overrides")
    checkout = temp / "v8-upstream"
    run("v8-source-init", ["git", "init", checkout])
    run("v8-source-fetch", ["git", "-C", checkout, "fetch", "--depth=1", "--no-tags",
        "https://github.com/openai/codex.git", REVISION], 180)
    run("v8-source-checkout", ["git", "-c", "core.hooksPath=NUL", "-c", "core.autocrlf=false", "-C", checkout,
        "checkout", "--detach", REVISION], 180)
    if run("v8-source-identity", ["git", "-C", checkout, "rev-parse", "HEAD"]) != REVISION:
        raise RuntimeError("V8 proof of concept checkout differs")
    expected = {**SOURCE_HASHES, **V8_SOURCE_HASHES}
    if any(sha(checkout / path) != digest for path, digest in expected.items()):
        raise RuntimeError("V8 proof of concept source inputs differ")
    target, cargo_home = temp / "v8-target", temp / "v8-cargo"
    target.mkdir()
    cargo_home.mkdir()
    linker = Path(tools["cl"]["path"]).with_name("link.exe")
    tools["link"] = {"path": str(linker), **pe_fixture(linker.read_bytes(), False, expected_machine=0xAA64)}
    result = report["v8_runtime"] = {"scope": "fixed-upstream-proof-of-concept-only", "builds": 0,
        "executed": False, "source_sha256": expected, "cli_builds": 0, "native_protoc_builds": 0,
        "host_integration": "not_run"}
    os.environ.update({**values, "CARGO_HOME": str(cargo_home), "CARGO_TARGET_DIR": str(target),
        "CARGO_INCREMENTAL": "0", "RUSTC": tools["rustc"]["path"], "RUSTUP_TOOLCHAIN": "1.95.0-" + TARGET,
        "CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER": str(linker)})
    previous = Path.cwd()
    try:
        os.chdir(checkout / "codex-rs")
        result["builds"] = 1
        output = run("native-v8-build", [tools["cargo"]["path"], "test", "--locked", "--target", TARGET,
            "-p", "codex-v8-poc", "--features", "sandbox", "--lib", "--no-run",
            "--message-format=json-render-diagnostics", "-j", "2"], 1080)
        binary = v8_executable(output, target, checkout / "codex-rs/v8-poc/src/lib.rs")
        result["binary_bytes"] = binary.stat().st_size
        if result["binary_bytes"] > 256 * 1024 * 1024:
            raise RuntimeError("Oversized native V8 test executable")
        result["binary"] = pe_fixture(binary.read_bytes(), False, expected_machine=0xAA64,
            maximum_bytes=256 * 1024 * 1024)
        if any(sha(checkout / path) != digest for path, digest in expected.items()) or any(
                sha(Path(values[name])) != report["v8"][digest] for name, digest in (
                    ("RUSTY_V8_ARCHIVE", "archive_sha256"), ("RUSTY_V8_SRC_BINDING_PATH", "binding_sha256"))):
            raise RuntimeError("V8 source/archive/binding changed during compilation")
        if run("v8-source-pristine-before-run", ["git", "-C", checkout, "status", "--porcelain", "--untracked-files=all"]):
            raise RuntimeError("V8 source checkout changed before execution")
        result["executed"] = True
        result.update(rust_results(run("native-v8-tests", [binary, "--test-threads=1"], 120), tests=V8_TESTS))
        if sha(binary) != result["binary"]["sha256"] or any(sha(checkout / path) != digest for path, digest in expected.items()):
            raise RuntimeError("V8 test executable or source changed during execution")
        if run("v8-source-pristine-after-run", ["git", "-C", checkout, "status", "--porcelain", "--untracked-files=all"]):
            raise RuntimeError("V8 source checkout changed during execution")
        report["v8"]["link_test"] = "pass"
    finally:
        os.chdir(previous)


def verified_protoc(temp, report):
    tool = temp / "protoc-build/protoc.exe"
    inputs = report.get("protoc_replacement", {})
    if (not tool.is_file() or tool.is_symlink() or not tool.resolve().is_relative_to(temp.resolve())
            or not 128 <= tool.stat().st_size <= 32 * 1024 * 1024 or inputs.get("native") is not True
            or inputs.get("executed") is not True or inputs.get("version") != "libprotoc 31.1"
            or inputs.get("cxx_standard") != 17 or any(inputs.get("sources", {}).get(name, {}).get("commit") != revision
                for name, _, revision in PROTOC_SOURCES)):
        raise RuntimeError("Verified native protoc is required before protocol compilation")
    if sha(tool) != inputs.get("binary", {}).get("sha256") or pe_fixture(
            tool.read_bytes(), False, expected_machine=0xAA64) != inputs["binary"]:
        raise RuntimeError("Native protoc changed before protocol compilation")
    return tool


def native_protocol(root, temp, tools, report, run):
    if any(os.environ.get(name) for name in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "V8_FROM_SOURCE", "CM_NATIVE_PROTOC")):
        raise RuntimeError("Protocol compilation requires the verified native tool without overrides")
    overlay_name = "adapters/codex-e4568a3/native-protoc-build.rs"
    build_name = "codex-rs/code-mode-protocol/build.rs"
    pin = json.loads((root / "adapters/codex-e4568a3/source.json").read_text(encoding="utf-8"))
    overlay = root / overlay_name
    if (pin["commit"] != REVISION or pin.get("target_overlay", {}).get(TARGET, {}).get(overlay_name) != build_name
            or overlay_name not in (root / "ci/source-files.txt").read_text().splitlines()
            or overlay.is_symlink() or not overlay.is_file() or not 0 < overlay.stat().st_size <= 4096):
        raise RuntimeError("Protocol requires its reviewed target overlay")
    overlay_hash = sha(overlay)
    checkout = temp / "protocol-upstream"
    git = ["git", "-c", "core.hooksPath=NUL", "-c", "core.autocrlf=false", "-c", "core.longpaths=true", "-C", checkout]
    run("protocol-source-init", ["git", "init", checkout])
    run("protocol-source-fetch", [*git, "fetch", "--depth=1", "--no-tags",
        "https://github.com/openai/codex.git", REVISION], 180)
    run("protocol-source-checkout", [*git, "checkout", "--detach", REVISION], 180)
    if run("protocol-source-identity", [*git, "rev-parse", "HEAD"]) != REVISION:
        raise RuntimeError("Protocol source checkout differs")
    expected = {**SOURCE_HASHES, **{path: V8_SOURCE_HASHES[path] for path in (
        "codex-rs/Cargo.toml", "codex-rs/.cargo/config.toml")}}
    if any(sha(checkout / path) != value for path, value in expected.items()) or run(
            "protocol-source-pristine", [*git, "status", "--porcelain", "--untracked-files=all"]):
        raise RuntimeError("Protocol source inputs differ before compilation")
    proto = checkout / "codex-rs/code-mode-protocol/src/grpc/codex.code_mode.v1.proto"
    expected[proto.relative_to(checkout).as_posix()] = sha(proto)
    shutil.copyfile(overlay, checkout / build_name)
    expected[build_name] = overlay_hash
    target, cargo_home = temp / "protocol-target", temp / "c"
    target.mkdir()
    cargo_home.mkdir()
    result = report["protocol_integration"] = {"scope": "fixed-upstream-protocol-library-only", "builds": 0,
        "source_sha256": expected, "overlay": {"path": overlay_name, "sha256": overlay_hash},
        "cli_builds": 0, "v8_builds": 0, "host_integration": "not_run", "cache_identity": "probe-inputs-only",
        "cargo_home": str(cargo_home), "dependency_preparation": "not_run"}
    run("protocol-native-components", ["rustup", "component", "add", "clippy", "rustfmt",
        "--toolchain", "1.95.0-" + TARGET], 180)
    for name in ("rustfmt", "cargo-clippy", "clippy-driver"):
        path = Path(run("protocol-" + name + "-path", ["rustup", "which", "--toolchain", "1.95.0-" + TARGET, name]))
        tools[name] = {"path": str(path), **pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)}
    run("protocol-overlay-fmt", [tools["rustfmt"]["path"], "--edition", "2024", "--check", overlay], 30)
    if run("protocol-preparation-delta", [*git, "diff", "HEAD", "--name-only"]) != build_name or run(
            "protocol-preparation-untracked", [*git, "ls-files", "--others", "--exclude-standard"]):
        raise RuntimeError("Protocol checkout changed before compilation")
    os.environ.update({"CARGO_HOME": str(cargo_home), "CARGO_TARGET_DIR": str(target), "CARGO_INCREMENTAL": "0",
        "RUSTC": tools["rustc"]["path"], "RUSTUP_TOOLCHAIN": "1.95.0-" + TARGET})
    previous = Path.cwd()
    try:
        os.chdir(checkout / "codex-rs")
        run("protocol-dependencies", [tools["cargo"]["path"], "tree", "--locked", "--target", TARGET,
            "-p", "codex-code-mode-protocol", "--edges", "normal,build", "--depth", "1"], 180)
        if any(sha(checkout / path) != value for path, value in expected.items()) or sha(overlay) != overlay_hash:
            raise RuntimeError("Protocol source or overlay changed during dependency preparation")
        if run("protocol-dependency-delta", [*git, "diff", "HEAD", "--name-only"]) != build_name or run(
                "protocol-dependency-untracked", [*git, "ls-files", "--others", "--exclude-standard"]):
            raise RuntimeError("Protocol checkout changed during dependency preparation")
        result["dependency_preparation"] = "pass"
        native_protoc(temp, tools, report, run)
        protoc = verified_protoc(temp, report)
        result["protoc_sha256"] = report["protoc_replacement"]["binary"]["sha256"]
        os.environ.update({"CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER": tools["link"]["path"],
            "CM_NATIVE_PROTOC": str(protoc)})
        verified_protoc(temp, report)
        if any(sha(checkout / path) != value for path, value in expected.items()) or sha(overlay) != overlay_hash:
            raise RuntimeError("Protocol source or overlay changed before compilation")
        if run("protocol-source-delta-before", [*git, "diff", "HEAD", "--name-only"]) != build_name or run(
                "protocol-source-untracked-before", [*git, "ls-files", "--others", "--exclude-standard"]):
            raise RuntimeError("Protocol checkout changed before compilation")
        result["builds"] = 1
        run("native-protocol-clippy", [tools["cargo"]["path"], "clippy", "--locked", "--target", TARGET,
            "-p", "codex-code-mode-protocol", "--lib", "--message-format=short", "-j", "2", "--", "-D", "warnings"], 1080)
        generated = list((target / TARGET / "debug/build").glob("codex-code-mode-protocol-*/out/codex.code_mode.v1.rs"))
        metadata = list((target / TARGET / "debug/deps").glob("libcodex_code_mode_protocol-*.rmeta"))
        if len(generated) != 1 or len(metadata) != 1 or any(path.is_symlink() or not path.is_file() or
                not 0 < path.stat().st_size <= limit for path, limit in (
                    (generated[0], 1024 * 1024), (metadata[0], 32 * 1024 * 1024))):
            raise RuntimeError("Missing unique bounded actual protocol bindings and library metadata")
        output = generated[0].parent.parent / "output"
        if output.is_symlink() or not output.is_file() or not 0 < output.stat().st_size <= 65536:
            raise RuntimeError("Missing bounded actual protocol build script output")
        text = output.read_text(encoding="utf-8")
        if "cargo:rerun-if-env-changed=CM_NATIVE_PROTOC" not in text.splitlines():
            raise RuntimeError("Actual protocol build script did not record its native tool input")
        logs = Path(os.environ["CM_CI_LOG_DIR"])
        shutil.copyfile(generated[0], logs / "protocol-generated.rs.txt")
        shutil.copyfile(output, logs / "protocol-build-script.txt")
        result["generated"] = {"bytes": generated[0].stat().st_size, "sha256": sha(generated[0])}
        result["library_metadata"] = {"bytes": metadata[0].stat().st_size, "sha256": sha(metadata[0])}
        if any(sha(checkout / path) != value for path, value in expected.items()) or sha(overlay) != overlay_hash:
            raise RuntimeError("Protocol source or overlay changed during compilation")
        verified_protoc(temp, report)
        if any(sha(Path(tool["path"])) != tool["sha256"] for tool in tools.values()):
            raise RuntimeError("Protocol native tool changed during compilation")
        if run("protocol-source-delta", [*git, "diff", "HEAD", "--name-only"]) != build_name or run(
                "protocol-source-untracked", [*git, "ls-files", "--others", "--exclude-standard"]):
            raise RuntimeError("Protocol checkout changed outside its reviewed build script")
        result["status"] = "pass"
    finally:
        os.chdir(previous)


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    authority(json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text()), entry, os.environ, key=KEY)
    stage = os.environ.get("CM_PREFLIGHT_STAGE")
    if stage not in ("native-inputs", "v8-link", "native-protocol") or Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Native input preflight requires its exact reviewed stage/source")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Native input text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running", "stage": stage,
        "scope": {"v8-link": "V01h-native-v8-runtime-only", "native-protocol": "V01i-native-protocol-library-only",
            "native-inputs": "V01g-native-inputs-and-abi-only"}[stage],
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
                **rust_results(run("run-rust-abi", [tests, "--test-threads=1"])),
                "historical_test_names": True, "experimental_abi_2_3_separate": True}
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
            if stage == "v8-link":
                v8_link(temp, report["tools"], values, report, run)
                run("source-pristine-after-v8", ["git", "-C", root, "diff", "--exit-code"])
            else:
                if not report["protoc"]["native"] and (report["protoc"].get("observed_machine") != 0x14C
                        or report["protoc"]["executed"]):
                    raise RuntimeError("Unexpected vendored protoc input; native replacement requires the reviewed I386 original")
                if stage == "native-protocol":
                    native_protocol(root, temp, report["tools"], report, run)
                    run("source-pristine-after-protocol", ["git", "-C", root, "diff", "--exit-code"])
                elif not report["protoc"]["native"]:
                    native_protoc(temp, report["tools"], report, run)
            report["status"] = {"v8-link": "observed_native_v8_runtime_only",
                "native-protocol": "observed_native_protocol_library_only",
                "native-inputs": "observed_native_inputs_and_abi_only"}[stage]
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        (logs / "windows-native-inputs.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def self_check():
    from unittest.mock import Mock, patch

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        ninja_zip = temp / "ninja.zip"
        with zipfile.ZipFile(ninja_zip, "w") as source:
            source.writestr("ninja.exe", b"test")
        assert ninja_file(ninja_zip) == b"test"
        for case in ("missing", "extra", "symlink", "oversized", "empty"):
            with zipfile.ZipFile(ninja_zip, "w") as source:
                member = zipfile.ZipInfo("other.exe" if case == "missing" else "ninja.exe")
                member.external_attr = (0o120777 if case == "symlink" else 0o100600) << 16
                source.writestr(member, bytes(4 * 1024 * 1024 + 1) if case == "oversized" else b"" if case == "empty" else b"test")
                if case == "extra":
                    source.writestr("extra.exe", b"test")
            try:
                ninja_file(ninja_zip)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Invalid native Ninja ZIP accepted")
        env = {"VSINSTALLDIR": str(temp), "WindowsSdkDir": str(temp), "WindowsSDKVersion": "1"}
        for case in ("foreign-tool", "wrong-source", "cxx-standard", "upb-input"):
            def invoke(label, args, *_):
                if case in ("cxx-standard", "upb-input"):
                    if label == "native-protoc-configure":
                        assert "-DCMAKE_CXX_STANDARD=17" in args and "-DCMAKE_CXX_STANDARD_REQUIRED=ON" in args
                        return "-- Performing Test ABSL_INTERNAL_AT_LEAST_CXX17 - " + (
                            "Failed" if case == "cxx-standard" else "Success")
                    if label == "native-protoc-upb-input":
                        raise RuntimeError("upb-input")
                    for name, _, revision in PROTOC_SOURCES:
                        if label == "protoc-" + name + "-identity":
                            return revision
                return "wrong-commit"
            command = Mock(side_effect=invoke)
            with patch.dict(os.environ, env), patch.object(Path, "read_bytes", return_value=b"foreign"), \
                    patch(__name__ + ".download", return_value={}), patch(__name__ + ".ninja_file", return_value=b"foreign"), \
                    patch(__name__ + ".pe_fixture", return_value={}, side_effect=RuntimeError("foreign") if case == "foreign-tool" else None):
                try:
                    native_protoc(temp, {"cl": {"path": str(temp / "cl.exe")}}, {}, command)
                except RuntimeError as error:
                    assert str(error) == {"foreign-tool": "foreign", "wrong-source":
                        "Native protoc source checkout differs: protobuf", "cxx-standard":
                        "Native protoc requires one C++17 ABI for Abseil and protobuf", "upb-input": "upb-input"}[case]
                else:
                    raise AssertionError("Invalid native protoc input accepted")
            if case == "foreign-tool":
                command.assert_not_called()
            elif case == "wrong-source":
                assert not any(call.args[0] == "native-protoc-configure" for call in command.call_args_list)
            else:
                labels = [call.args[0] for call in command.call_args_list]
                assert labels[-1] == ("native-protoc-configure" if case == "cxx-standard" else "native-protoc-upb-input")
                assert "native-protoc-build" not in labels
                if case == "cxx-standard":
                    assert "native-protoc-upb-input" not in labels
        root = Path(__file__).resolve().parents[2]
        protoc = temp / "protoc-build/protoc.exe"
        protoc.parent.mkdir()
        protoc.write_bytes(bytes(128))
        binary = {"machine": 0xAA64, "size": 128, "sha256": sha(protoc)}
        replacement = {"native": True, "executed": True, "version": "libprotoc 31.1", "cxx_standard": 17,
            "sources": {name: {"commit": revision} for name, _, revision in PROTOC_SOURCES}, "binary": binary}
        with patch(__name__ + ".pe_fixture", return_value=binary):
            assert verified_protoc(temp, {"protoc_replacement": replacement}) == protoc
            for changed in ({}, {**replacement, "native": False}, {**replacement, "executed": False},
                    {**replacement, "version": "libprotoc 30.0"}, {**replacement, "cxx_standard": 14},
                    {**replacement, "sources": {}}, {**replacement, "binary": {**binary, "sha256": "0" * 64}}):
                try:
                    verified_protoc(temp, {"protoc_replacement": changed})
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Unverified or changed native protoc reached protocol compilation")
        with patch(__name__ + ".pe_fixture", side_effect=RuntimeError("foreign")):
            try:
                verified_protoc(temp, {"protoc_replacement": replacement})
            except RuntimeError as error:
                assert str(error) == "foreign"
            else:
                raise AssertionError("Foreign native protoc accepted")
        protoc.unlink()
        try:
            verified_protoc(temp, {"protoc_replacement": replacement})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Missing native protoc accepted")
        for variable in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                "V8_FROM_SOURCE", "CM_NATIVE_PROTOC"):
            command = Mock()
            with patch.dict(os.environ, {variable: "untrusted"}, clear=True):
                try:
                    native_protocol(root, temp, {}, {}, command)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Protocol compiler or tool override accepted")
            command.assert_not_called()
        pin = json.loads((root / "adapters/codex-e4568a3/source.json").read_text(encoding="utf-8"))
        for case in ("overlay", "commit", "hash"):
            changed = {**pin, "target_overlay": {}} if case == "overlay" else pin
            command = Mock(return_value="wrong-source" if case == "commit" else REVISION)
            with patch.dict(os.environ, {}, clear=True), patch(__name__ + ".native_protoc") as bootstrap, \
                    patch("json.loads", return_value=changed), patch(__name__ + ".sha", return_value="0" * 64):
                try:
                    native_protocol(root, temp, {}, {}, command)
                except RuntimeError as error:
                    assert str(error) == {"overlay": "Protocol requires its reviewed target overlay",
                        "commit": "Protocol source checkout differs",
                        "hash": "Protocol source inputs differ before compilation"}[case]
                else:
                    raise AssertionError("Changed protocol source or target overlay reached Cargo")
            assert not any(call.args[0] == "native-protocol-clippy" for call in command.call_args_list)
            bootstrap.assert_not_called()
            if case == "overlay":
                command.assert_not_called()
        for case in ("pristine", "format", "dependencies", "dependency-source", "dependency-delta", "prepared"):
            with tempfile.TemporaryDirectory() as directory:
                private = Path(directory)
                (private / "protocol-upstream/codex-rs").mkdir(parents=True)
                compiler = private / "native-tool.exe"
                compiler.write_bytes(bytes(128))
                expected = {**SOURCE_HASHES, **{path: V8_SOURCE_HASHES[path] for path in (
                    "codex-rs/Cargo.toml", "codex-rs/.cargo/config.toml")}}

                def source_hash(path):
                    labels = [call.args[0] for call in command.call_args_list]
                    if path == root / "adapters/codex-e4568a3/native-protoc-build.rs" or path.suffix == ".proto":
                        return "e" * 64
                    if path.name == "build.rs" and "protocol-overlay-fmt" in labels:
                        return "e" * 64
                    if case == "dependency-source" and path.name == "Cargo.lock" and "protocol-dependencies" in labels:
                        return "0" * 64
                    return expected[path.relative_to(private / "protocol-upstream").as_posix()]

                def prepare(label, args, timeout=30):
                    if label.startswith(("protocol-source-", "protocol-preparation-", "protocol-dependency-")) and label != "protocol-source-init":
                        assert "core.longpaths=true" in args and "core.autocrlf=false" in args and "core.hooksPath=NUL" in args
                    if label == "protocol-source-identity":
                        return REVISION
                    if label == "protocol-source-pristine" and case == "pristine":
                        return " D missing-long-snapshot.snap"
                    if label.endswith("-path"):
                        return str(compiler)
                    if label == "protocol-overlay-fmt" and case == "format":
                        raise RuntimeError("format-error")
                    if label == "protocol-dependencies":
                        assert args == [str(compiler), "tree", "--locked", "--target", TARGET, "-p",
                            "codex-code-mode-protocol", "--edges", "normal,build", "--depth", "1"]
                        assert Path(os.environ["CARGO_HOME"]) == private / "c"
                        assert Path(os.environ["CARGO_TARGET_DIR"]) == private / "protocol-target"
                        assert os.environ["RUSTC"] == str(compiler) and os.environ["RUSTUP_TOOLCHAIN"] == "1.95.0-" + TARGET
                        assert "CM_NATIVE_PROTOC" not in os.environ
                        if case == "dependencies":
                            raise RuntimeError("dependency-error")
                    if label in ("protocol-preparation-delta", "protocol-dependency-delta"):
                        return "unexpected.rs" if label == "protocol-dependency-delta" and case == "dependency-delta" else "codex-rs/code-mode-protocol/build.rs"
                    return ""

                command = Mock(side_effect=prepare)
                previous = Path.cwd()
                with patch.dict(os.environ, {}, clear=True), \
                        patch(__name__ + ".native_protoc", side_effect=RuntimeError("bootstrap-boundary")) as bootstrap, \
                        patch(__name__ + ".verified_protoc") as verify, patch(__name__ + ".sha", side_effect=source_hash), \
                        patch(__name__ + ".pe_fixture", return_value=binary), patch("shutil.copyfile"):
                    try:
                        tools = {name: {"path": str(compiler)} for name in ("rustc", "cargo")}
                        native_protocol(root, private, tools, {}, command)
                    except RuntimeError as error:
                        assert str(error) == {"pristine": "Protocol source inputs differ before compilation",
                            "format": "format-error", "dependencies": "dependency-error", "dependency-source":
                            "Protocol source or overlay changed during dependency preparation", "dependency-delta":
                            "Protocol checkout changed during dependency preparation", "prepared": "bootstrap-boundary"}[case]
                    else:
                        raise AssertionError("Invalid protocol preparation reached the native build")
                assert Path.cwd() == previous
                assert bootstrap.call_count == (1 if case == "prepared" else 0)
                verify.assert_not_called()
                assert not any(call.args[0] == "native-protocol-clippy" for call in command.call_args_list)
        import host
        overlay_name = "adapters/codex-e4568a3/native-protoc-build.rs"
        old_pin = {**pin, "target_overlay": {key: value for key, value in pin["target_overlay"].items() if key != TARGET}}
        read = host.read
        changed_manifest = [{**row, "sha256": "0" * 64} if row["path"] == overlay_name else row
            for row in host.cm_manifest(root)]
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            with patch.object(host, "TARGET", target):
                with patch.object(host, "read", side_effect=lambda path: old_pin if path.name == "source.json" else read(path)):
                    before = host.product_manifest(root)
                assert host.product_manifest(root) == before
                with patch.object(host, "cm_manifest", return_value=changed_manifest):
                    assert host.product_manifest(root) == before
        assert all(overlay_name not in {**pin["overlay"], **pin["target_overlay"].get(target, {})} for target in (
            "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "x86_64-apple-darwin", "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc"))
        poc_source, poc_target = temp / "poc/lib.rs", temp / "private-target"
        artifact = {"reason": "compiler-artifact", "target": {"name": "codex_v8_poc", "src_path": str(poc_source)},
            "profile": {"test": True}, "executable": str(poc_target / "v8-tests.exe")}
        assert v8_executable("progress\n" + json.dumps(artifact), poc_target, poc_source) == Path(artifact["executable"]).resolve()
        for text in ("", "[]", json.dumps(artifact) + "\n" + json.dumps(artifact),
                json.dumps({**artifact, "target": []}), json.dumps({**artifact, "executable": 1}),
                json.dumps({**artifact, "executable": str(temp / "outside.exe")}),
                json.dumps({**artifact, "executable": str(poc_target / "wrong.dll")}),
                json.dumps({**artifact, "target": {**artifact["target"], "src_path": str(temp / "other.rs")}}),
                json.dumps({**artifact, "profile": {"test": False}}), "x" * (1024 * 1024 + 1)):
            try:
                v8_executable(text, poc_target, poc_source)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Missing, ambiguous or escaping V8 test executable accepted")
        for variable in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "V8_FROM_SOURCE"):
            command = Mock()
            with patch.dict(os.environ, {variable: "untrusted"}, clear=True):
                try:
                    v8_link(temp, {}, {}, {}, command)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("V8 compiler override accepted")
            command.assert_not_called()
        for wrong_source in ("commit", "hash"):
            command = Mock(return_value="wrong-source" if wrong_source == "commit" else REVISION)
            with patch.dict(os.environ, {}, clear=True), patch(__name__ + ".sha", return_value="0" * 64):
                try:
                    v8_link(temp, {}, {}, {}, command)
                except RuntimeError as error:
                    assert str(error) == ("V8 proof of concept checkout differs" if wrong_source == "commit" else
                        "V8 proof of concept source inputs differ")
                else:
                    raise AssertionError("Changed V8 source reached Cargo")
            assert not any(call.args[0].startswith("native-v8") for call in command.call_args_list)
        poc = "\n".join("test " + name + " ... ok" for name in sorted(V8_TESTS)) + (
            "\ntest result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n")
        assert rust_results(poc, tests=V8_TESTS)["passed"] == 6
        for invalid in (poc.replace("6 passed", "5 passed"), poc.replace("0 ignored", "1 ignored"),
                poc.replace("0 filtered out", "1 filtered out"), poc + "test extra ... ok\n"):
            try:
                rust_results(invalid, tests=V8_TESTS)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Incomplete V8 proof of concept tests accepted")

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
