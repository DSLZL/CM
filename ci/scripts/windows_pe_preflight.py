"""Native PE parser and dependency search evidence, without a Codex CLI build."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tarfile
import tempfile
import tomllib
from unittest.mock import patch

import ci_progress
import record_run
from windows_native_inputs import KEY, TARGET, REVISION, crate_file, sha
from windows_x64_preflight import authority, pe_fixture

INPUTS = (
    "crates/cm/src/loader/pe.rs", "fixtures/native-loader/windows-pe.c",
    "fixtures/native-loader/windows-preflight.c",
    "fixtures/native-loader/windows-pe/Cargo.toml", "fixtures/native-loader/windows-pe/Cargo.lock",
    "fixtures/native-loader/windows-pe/src/main.rs", "fixtures/native-loader/windows-pe/src/payload.rs",
    "ci/scripts/windows_pe_preflight.py",
    "crates/cm/src/loader/windows.rs", "crates/cm/native/windows-loader.c", "crates/cm/native/windows-loader.h",
    "crates/cm/build.rs", "crates/cm/Cargo.toml",
    "crates/cm/src/loader/input.rs", "crates/cm/src/loader/input/windows.rs",
    "crates/cm/src/profile/directory.rs",
)
LOCKED = {
    "block-buffer": ("0.10.4", "3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71"),
    "cc": ("1.2.55", "47b26a0954ae34af09b50f0de26458fa95369a0d478d8236d3f93082b219bd29"),
    "cfg-if": ("1.0.4", "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"),
    "cpufeatures": ("0.2.17", "59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280"),
    "crypto-common": ("0.1.7", "78c8292055d1c1df0cce5d180393dc8cce0abec0a7102adb6c7b1eef6016d60a"),
    "digest": ("0.10.7", "9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292"),
    "find-msvc-tools": ("0.1.9", "5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582"),
    "generic-array": ("0.14.7", "85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a"),
    "libc": ("0.2.186", "68ab91017fe16c622486840e4c83c9a37afeff978bd239b5293d61ece587de66"),
    "libloading": ("0.8.9", "d7c4b02199fee7c5d21a5ae7d8cfa79a6ef5bb2fc834d6e9058e89c825efdc55"),
    "object": ("0.37.3", "ff76201f031d8863c38aa7f905eca4f53abbfa15f609db4277d44cd8938f33fe"),
    "memchr": ("2.8.1", "6b947ae49db0d222b1dbc6b113ce7248a3fc3a6ca21b696717bfc000ba4484d8"),
    "shlex": ("1.3.0", "0fda2ff0d084019ba4d7c6f371c95d8fd75ce3524c3cb8fb653a3023f6323e64"),
    "sha2": ("0.10.9", "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283"),
    "typenum": ("1.20.0", "40ce102ab67701b8526c123c1bab5cbe42d7040ccfd0f64af1a385808d2f43de"),
    "version_check": ("0.9.5", "0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a"),
    "windows-link": ("0.2.1", "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5"),
}
INPUT_CHECKS = ["bounded-read", "empty-read", "read-bounds", "unchanged-pin", "changed-bytes",
    "same-bytes-replacement", "invalid-paths", "preheld-writer", "preheld-mapping",
    "retained-file", "retained-ancestors", "hardlinks", "reparse-points", "post-close-usable"]
PRIVATE_CHECKS = ["descriptor-owner-mismatch", "owner-directory", "owner-file", "owner-read-only",
    "foreign-file-ace", "foreign-directory-ace", "null-dacl", "empty-dacl", "unprotected-dacl",
    "unsupported-ace", "inherited-ace", "held-dacl-drift", "restored-dacl",
    "created-private-file", "created-empty-file", "created-chunked-file", "existing-file-preserved",
    "file-directory-collision", "create-invalid-paths", "unsafe-parent-no-write", "created-ancestor-pin",
    "lock-open-create", "lock-exclusive", "lock-clone-lifetime", "lock-shared",
    "lock-content-preserved", "lock-unsafe-file", "lock-parent-drift",
    "directory-flush", "created-private-directory", "existing-private-directory", "directory-collisions",
    "directory-invalid-paths", "directory-parent-drift", "directory-ancestor-pin",
    "published-private-file", "publish-collisions", "published-private-directory",
    "publish-retained-pins", "publish-unsafe-source", "publish-invalid-paths", "publish-parent-drift",
    "staging-create-only", "remove-full-identity", "remove-entry-kinds", "remove-retained-pins",
    "discard-private-tree", "discard-replacement-preserved", "remove-invalid-parent"]


def private_record(text):
    if text.splitlines() != ["cm_private passed=" + name for name in PRIVATE_CHECKS]:
        raise RuntimeError("Actual private owner/DACL controls differ")
    return {"status": "pass", "checks": PRIVATE_CHECKS, "actual_directory_module": INPUTS[15],
        "actual_handle_module": INPUTS[14], "foreign_owner_control": "descriptor-only", "foreign_owned_file": "not_run"}


def inventory(metadata):
    packages = metadata.get("packages", [])
    if sorted(row["name"] for row in packages) != sorted(["cm-windows-pe-fixture", *LOCKED]):
        raise RuntimeError("PE fixture dependency closure changed")
    for row in packages:
        if row["name"] in LOCKED:
            if row["version"] != LOCKED[row["name"]][0] or row["source"] != "registry+https://github.com/rust-lang/crates.io-index":
                raise RuntimeError("PE fixture dependency identity changed")
            if not row.get("license"):
                raise RuntimeError("PE fixture dependency license declaration missing")
    nodes = metadata.get("resolve", {}).get("nodes", [])
    object_ids = {row["id"] for row in packages if row["name"] == "object"}
    features = [set(row["features"]) for row in nodes if row["id"] in object_ids]
    if features != [{"coff", "pe", "read_core", "std"}]:
        raise RuntimeError("PE fixture parser features changed")


def audit_record(text):
    matches = re.findall(r"^cm_pe dependencies=([a-z0-9.,-]*) imports=([0-9]+) ordinals=([0-9]+) entry=([0-9]+)$", text, re.M)
    if len(matches) != 1:
        raise RuntimeError("Missing unique native PE audit record")
    dependencies, imports, ordinals, entry = matches[0]
    names = dependencies.split(",") if dependencies else []
    if names != sorted(set(names)) or len(names) > 32 or not 0 <= int(ordinals) <= int(imports) <= 4096 or not 0 < int(entry) < 256 * 1024 * 1024:
        raise RuntimeError("Native PE audit record exceeds its bounds")
    return {"dependencies": names, "imports": int(imports), "ordinal_imports": int(ordinals), "entry_rva": int(entry)}


def offsets(data):
    if len(data) < 64 or data[:2] != b"MZ":
        raise RuntimeError("Expected real compiled PE control")
    nt = struct.unpack_from("<I", data, 60)[0]
    if nt + 264 > len(data) or data[nt:nt + 4] != b"PE\0\0" or struct.unpack_from("<H", data, nt + 24)[0] != 0x20B:
        raise RuntimeError("Expected compiled PE32+ control")
    optional = nt + 24
    sections = optional + struct.unpack_from("<H", data, nt + 20)[0]
    return nt, optional, sections, optional + 112


def file_offset(data, rva):
    nt, _, sections, _ = offsets(data)
    for index in range(struct.unpack_from("<H", data, nt + 6)[0]):
        at = sections + index * 40
        size, start, raw_size, raw = struct.unpack_from("<IIII", data, at + 8)
        if start <= rva < start + min(max(size, raw_size), raw_size) and raw + rva - start < len(data):
            return raw + rva - start
    raise RuntimeError("Fixture RVA has no file-backed control")


def string_at(data, offset):
    end = data.find(b"\0", offset, offset + 513)
    if end < offset:
        raise RuntimeError("Fixture string control missing")
    return data[offset:end]


def export_slot(data, name):
    _, _, _, directories = offsets(data)
    table = file_offset(data, struct.unpack_from("<I", data, directories)[0])
    ordinal_base, functions, count, function_rva, name_rva, ordinal_rva = struct.unpack_from("<IIIIII", data, table + 16)
    if not 0 < count <= 4096 or not 0 < functions <= 4096:
        raise RuntimeError("Fixture export controls exceed bounds")
    names, ordinals, addresses = (file_offset(data, rva) for rva in (name_rva, ordinal_rva, function_rva))
    for index in range(count):
        pointer = names + 4 * index
        name_offset = file_offset(data, struct.unpack_from("<I", data, pointer)[0])
        if string_at(data, name_offset) == name:
            ordinal = struct.unpack_from("<H", data, ordinals + 2 * index)[0]
            if ordinal >= functions:
                raise RuntimeError("Fixture export ordinal control")
            return {"table": table, "name_pointer": pointer, "name_offset": name_offset,
                "ordinal_offset": ordinals + 2 * index, "function_offset": addresses + 4 * ordinal,
                "ordinal": ordinal_base + ordinal}
    raise RuntimeError("Missing named fixture export control")


def version_import(data):
    _, _, _, directories = offsets(data)
    rva, size = struct.unpack_from("<II", data, directories + 8)
    start = file_offset(data, rva)
    for index in range(min(size // 20, 33)):
        at = start + index * 20
        lookup, _, _, name, iat = struct.unpack_from("<IIIII", data, at)
        if not any((lookup, name, iat)):
            break
        name_offset = file_offset(data, name)
        if string_at(data, name_offset).lower() == b"version.dll":
            return {"descriptor": at, "name": name_offset, "lookup": file_offset(data, lookup or iat),
                "iat": file_offset(data, iat), "start": start, "size": size}
    raise RuntimeError("Missing actual version.dll import control")


def mutations(data):
    nt, optional, sections, directories = offsets(data)
    entry = export_slot(data, b"cm_mod_entry_v1")
    imported = version_import(data)
    specs = [
        ("dos-magic", 0, b"NZ"), ("nt-offset", 60, struct.pack("<I", 0xFFFFFFF0)),
        ("signature", nt, b"PX\0\0"), ("wrong-machine", nt + 4, struct.pack("<H", 0x8664)),
        ("arm64ec-machine", nt + 4, struct.pack("<H", 0xA641)),
        ("arm64x-machine", nt + 4, struct.pack("<H", 0xA64E)),
        ("pe32-kind", optional, struct.pack("<H", 0x10B)),
        ("not-dll", nt + 22, struct.pack("<H", struct.unpack_from("<H", data, nt + 22)[0] & ~0x2000)),
        ("section-count", nt + 6, struct.pack("<H", 97)),
        ("optional-size", nt + 20, struct.pack("<H", 239)),
        ("directory-count", optional + 108, struct.pack("<I", 17)),
        ("section-overflow", sections + 12, struct.pack("<I", 0xFFFFFF00)),
        ("raw-outside-file", sections + 20, struct.pack("<I", len(data) + 512)),
        ("section-overlap", sections + 40 + 12, data[sections + 12:sections + 16]),
        ("raw-overlap", sections + 40 + 20, data[sections + 20:sections + 24]),
        ("writable-code", sections + 36, struct.pack("<I", struct.unpack_from("<I", data, sections + 36)[0] | 0x80000000)),
        ("directory-zero-rva", directories + 8, b"\0" * 4),
        ("directory-overflow", directories, struct.pack("<I", 0xFFFFFF00)),
        ("bound-directory", directories + 11 * 8, data[directories + 8:directories + 12] + struct.pack("<I", 8)),
        ("delay-rva-directory", directories + 13 * 8, data[directories + 8:directories + 12] + struct.pack("<I", 32)),
        ("managed-directory", directories + 14 * 8, data[directories + 8:directories + 12] + struct.pack("<I", 20)),
        ("dependency-unknown", imported["name"], b"evilbin.dll"),
        ("dependency-path", imported["name"], b"..\\evil.dll"),
        ("dependency-name-rva", imported["descriptor"] + 12, struct.pack("<I", 0xFFFFFF00)),
        ("missing-null-descriptor", directories + 12, struct.pack("<I", imported["size"] - 20)),
        ("iat-mismatch", imported["iat"], struct.pack("<Q", struct.unpack_from("<Q", data, imported["iat"])[0] ^ 1)),
        ("missing-required-entry", entry["name_offset"], b"cm_mod_entry_v0"),
        ("export-ordinal", entry["ordinal_offset"], struct.pack("<H", 65535)),
        ("export-forwarder", entry["function_offset"], data[directories:directories + 4]),
        ("export-entry-data", entry["function_offset"], data[sections + 40 + 12:sections + 40 + 16]),
        ("export-null-entry", entry["function_offset"], b"\0" * 4),
        ("export-count", entry["table"] + 20, struct.pack("<I", 0xFFFFFFFF)),
    ]
    for label, at, replacement in specs:
        changed = bytearray(data)
        changed[at:at + len(replacement)] = replacement
        if changed == data:
            raise RuntimeError("Ineffective PE negative control: " + label)
        yield label, bytes(changed)
    for label, raw in (("zero-ordinal", 1 << 63), ("ordinal-extra-bits", (1 << 63) | 0x10001),
            ("named-import-high-bits", (1 << 32) | struct.unpack_from("<Q", data, imported["lookup"])[0])):
        changed = bytearray(data)
        for at in {imported["lookup"], imported["iat"]}:
            struct.pack_into("<Q", changed, at, raw)
        yield label, bytes(changed)
    yield "truncated-image", data[:len(data) // 2]
    yield "oversized-image", data + bytes(max(0, 32 * 1024 * 1024 + 1 - len(data)))


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    authority(json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text()), entry, os.environ, key=KEY)
    if os.environ.get("CM_PREFLIGHT_STAGE") != "native-pe" or Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("PE preflight requires its exact reviewed stage and source")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("PE text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running", "stage": "native-pe", "scope": "V01j-native-pe-and-search-only",
        "platform": KEY, "target": TARGET, "source_sha": os.environ["CM_SOURCE_SHA"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": os.environ["CM_REQUEST_ID"],
        "cache_mode": "none", "cache_writes": 0, "cache_deletes": 0, "cli_builds": 0, "v8_builds": 0, "protoc_builds": 0,
        "platform_enabled": False, "full_qualification": "not_run", "product_loader_integration": "not_run",
        "full_dependency_closure": "not_run", "instruction_set_proof": "native machine and controlled build only", "cases": {}}

    def run(label, args, timeout=30, *, codes=(0,), cwd=None, environ=None):
        values = [str(value) for value in args]
        previous = Path.cwd()
        try:
            if cwd is not None:
                os.chdir(cwd)
            with patch.dict(os.environ, environ or {}):
                with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"stage": label, "command": values, "cwd": str(Path.cwd())}) + "\n")
                result = ci_progress.run(logs, label, values, timeout)
        finally:
            os.chdir(previous)
        text = (logs / (label + ".log")).read_text(encoding="utf-8", errors="strict").strip()
        if result.returncode not in codes:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return result.returncode, text

    try:
        if any(os.environ.get(name) for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER", "CFLAGS", "CXXFLAGS", "CL", "_CL_", "CC", "AR",
                "CC_aarch64_pc_windows_msvc", "AR_aarch64_pc_windows_msvc",
                "CFLAGS_aarch64_pc_windows_msvc", "CRATE_CC_NO_DEFAULTS", "CC_FORCE_DISABLE")):
            raise RuntimeError("PE fixture requires native baseline compilers without overrides")
        cfg = json.loads((root / ".github/cm-ci.json").read_text())
        if cfg["upstream"]["commit"] != REVISION or cfg["rust_toolchain"] != "1.95.0":
            raise RuntimeError("PE fixture toolchain/source pins changed")
        report["source_sha256"] = {name: sha(root / name) for name in INPUTS}
        report["environment"] = {name: os.environ[name] for name in (
            "ImageOS", "ImageVersion", "VCToolsVersion", "WindowsSDKVersion", "VCToolsInstallDir", "WindowsSdkDir")}
        cl = Path(shutil.which("cl.exe") or "")
        if not cl.is_absolute() or tuple(part.lower() for part in cl.parts[-3:]) != ("hostarm64", "arm64", "cl.exe"):
            raise RuntimeError("PE fixture requires installed native ARM64 MSVC")
        tools = report["tools"] = {"cl": {"path": str(cl), **pe_fixture(cl.read_bytes(), False, expected_machine=0xAA64)}}
        link = Path(shutil.which("link.exe") or "")
        if not link.is_absolute() or link.parent != cl.parent:
            raise RuntimeError("PE fixture requires the matching installed native ARM64 linker")
        tools["link"] = {"path": str(link), **pe_fixture(link.read_bytes(), False, expected_machine=0xAA64)}
        dumpbin = cl.with_name("dumpbin.exe")
        tools["dumpbin"] = {"path": str(dumpbin), **pe_fixture(dumpbin.read_bytes(), False, expected_machine=0xAA64)}
        librarian = cl.with_name("lib.exe")
        tools["lib"] = {"path": str(librarian), **pe_fixture(librarian.read_bytes(), False, expected_machine=0xAA64)}
        fixture = root / "fixtures/native-loader/windows-pe"
        lock = tomllib.loads((fixture / "Cargo.lock").read_text())
        if {row["name"]: (row["version"], row.get("checksum")) for row in lock["package"]} != {
                "cm-windows-pe-fixture": ("0.1.0", None), **LOCKED}:
            raise RuntimeError("PE fixture lock differs")
        with tempfile.TemporaryDirectory(prefix="cm-arm64-pe-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory)
            toolchain = "1.95.0-" + TARGET
            run("pe-native-toolchain", ["rustup", "toolchain", "install", toolchain, "--profile", "minimal"], 180)
            run("pe-native-components", ["rustup", "component", "add", "rustfmt", "clippy", "--toolchain", toolchain], 180)
            for name in ("rustc", "cargo", "rustfmt", "cargo-clippy", "clippy-driver"):
                _, text = run("pe-" + name + "-path", ["rustup", "which", "--toolchain", toolchain, name])
                path = Path(text)
                tools[name] = {"path": str(path), **pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)}
            _, version = run("pe-rustc-version", [tools["rustc"]["path"], "-Vv"])
            if "host: " + TARGET not in version.splitlines():
                raise RuntimeError("PE fixture Rust compiler is not native ARM64")
            formatted = {"parser": INPUTS[0], "main": INPUTS[5], "payload": INPUTS[6],
                "snapshot": INPUTS[8], "product-build": INPUTS[11], "input": INPUTS[13], "input-windows": INPUTS[14],
                "directory": INPUTS[15]}
            for name, relative in formatted.items():
                run("pe-format-" + name, [tools["rustfmt"]["path"], "--edition", "2024", "--emit", "stdout", root / relative])
            run("pe-format-check", [tools["rustfmt"]["path"], "--edition", "2024", "--check",
                *(root / relative for relative in formatted.values())])
            report["rustflags"] = "-Ctarget-feature=+crt-static"
            os.environ.update({"CARGO_HOME": str(temp / "c"), "CARGO_TARGET_DIR": str(temp / "t"), "CARGO_INCREMENTAL": "0",
                "RUSTUP_TOOLCHAIN": toolchain, "RUSTC": tools["rustc"]["path"], "RUSTFLAGS": report["rustflags"],
                "CC": str(cl), "AR": str(librarian),
                "CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER": tools["link"]["path"]})
            cargo = [tools["cargo"]["path"]]
            _, text = run("pe-cargo-metadata", [*cargo, "metadata", "--format-version", "1", "--locked"], 180, cwd=fixture)
            records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
            if len(records) != 1:
                raise RuntimeError("Missing unique Cargo metadata JSON record")
            metadata = records[0]
            inventory(metadata)
            fixture_package = next(row for row in metadata["packages"] if row["name"] == "cm-windows-pe-fixture")
            build_scripts = [row for row in fixture_package["targets"] if row["kind"] == ["custom-build"]]
            if len(build_scripts) != 1 or Path(build_scripts[0]["src_path"]).resolve() != root / "crates/cm/build.rs":
                raise RuntimeError("PE fixture must compile the actual product build script")
            report["dependencies"] = [{"name": row["name"], "version": row["version"], "license": row["license"]}
                for row in metadata["packages"] if row["name"] in LOCKED]
            report["licenses"] = {}
            for name, (version, checksum) in LOCKED.items():
                matches = list((temp / "c/registry/cache").glob("*/" + name + "-" + version + ".crate"))
                if len(matches) != 1 or sha(matches[0]) != checksum:
                    raise RuntimeError("Missing exact PE fixture registry source archive")
                with tarfile.open(matches[0], "r:gz") as archive:
                    members = [row for row in archive.getmembers() if row.isfile() and Path(row.name).name.upper() in (
                        "LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "LICENSE-APACHE-2.0", "COPYING", "UNLICENSE")]
                if not 1 <= len(members) <= 8:
                    raise RuntimeError("Missing bounded upstream dependency license files")
                for member in members:
                    data = crate_file(matches[0], member.name, 32768)
                    evidence = "pe-license-" + name + "-" + Path(member.name).name + ".txt"
                    data.decode("utf-8", errors="strict")
                    (logs / evidence).write_bytes(data)
                    report["licenses"][evidence] = {"crate_sha256": checksum, "member": member.name,
                        "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            run("pe-clippy", [*cargo, "clippy", "--locked", "--target", TARGET, "--all-targets", "-j", "2",
                "--", "-D", "warnings"], 300, cwd=fixture)
            run("pe-build", [*cargo, "build", "--locked", "--target", TARGET, "--bins", "--lib", "-j", "2"], 300, cwd=fixture)
            run("pe-input-identity-test", [*cargo, "test", "--locked", "--target", TARGET, "--bin", "cm-pe",
                "input::tests::revalidation_compares_the_complete_file_identity", "--", "--exact", "--nocapture"], 120, cwd=fixture)
            validator = temp / "t" / TARGET / "debug/cm-pe.exe"
            rust_payload = temp / "t" / TARGET / "debug/cm_pe_rust_payload.dll"
            run("pe-rust-dependencies", [tools["dumpbin"]["path"], "/nologo", "/dependents", rust_payload])
            probe = temp / "pe-probe.exe"
            source = root / INPUTS[1]
            common = [cl, "/nologo", "/Bv", "/std:c11", "/W4", "/WX", "/O2", "/MT", "/utf-8", "/TC", source]
            run("pe-compile-control", [*common, "/Fo" + str(temp / "control.obj"), "/Fe" + str(probe),
                "/link", "/INCREMENTAL:NO", "bcrypt.lib"], 120)
            poison = temp / "version.dll"
            definition = temp / "poison.def"
            definition.write_text("LIBRARY version\nEXPORTS\n GetFileVersionInfoSizeW=cm_pe_fake_version\n")
            payloads = {}
            for name, defines, extra in (
                    ("ordinary", ["/DCM_PE_PAYLOAD"], ["version.lib"]),
                    ("delayed", ["/DCM_PE_PAYLOAD"], ["version.lib", "delayimp.lib", "/DELAYLOAD:version.dll"]),
                    ("forwarded", ["/DCM_PE_PAYLOAD", "/DCM_PE_FORWARD"], []),
                    ("poison", ["/DCM_PE_POISON"], ["/DEF:" + str(definition)])):
                binary = poison if name == "poison" else temp / (name + ".dll")
                if name == "forwarded":
                    forward = temp / "forward.def"
                    forward.write_text("EXPORTS\n cm_mod_entry_v1=KERNEL32.GetLastError\n")
                    extra = ["/DEF:" + str(forward)]
                run("pe-compile-" + name, [*common, *defines, "/LD", "/Fo" + str(temp / (name + ".obj")),
                    "/Fe" + str(binary), "/link", "/INCREMENTAL:NO", *extra], 120)
                payloads[name] = binary
            report["binaries"] = {name: pe_fixture(path.read_bytes(), dll, expected_machine=0xAA64) for name, path, dll in (
                ("validator", validator, False), ("control", probe, False), ("rust", rust_payload, True),
                *((name, path, True) for name, path in payloads.items()))}
            input_root = temp / "input-controls"
            input_root.mkdir()
            _, text = run("pe-case-inputs", [validator, "input", input_root])
            checks = re.findall(r"^cm_input passed=([a-z-]+)$", text, re.M)
            if checks != INPUT_CHECKS:
                raise RuntimeError("Actual input module controls differ")
            report["input_controls"] = {"status": "pass", "checks": checks, "identity_bytes": 24,
                "full_file_id_mutation_test": "pass", "actual_product_module": INPUTS[13]}
            private_root = temp / "private-controls"
            private_root.mkdir()
            _, text = run("pe-case-private", [validator, "private", private_root, probe])
            report["private_controls"] = private_record(text)

            def observe(label, data, *, abi="cm_mod_entry_v1", expected_code=0, mode="guarded",
                    expected_value=41, constructor=True, poison_marker=False, location=None):
                case = temp / label
                case.mkdir()
                dll = case / "payload.dll"
                dll.write_bytes(data)
                poison_path = case / "version.dll"
                if location == "adjacent":
                    shutil.copyfile(poison, poison_path)
                cwd = case
                env = {"CM_CONSTRUCTOR_MARKER": str(case / "payload.marker"), "CM_PE_POISON_MARKER": str(case / "poison.marker")}
                if location in ("cwd", "path"):
                    other = case / "other"
                    other.mkdir()
                    shutil.copyfile(poison, other / "version.dll")
                    if location == "cwd":
                        cwd = other
                    else:
                        env["PATH"] = str(other)
                code, text = run("pe-case-" + label, [validator, "load", dll, abi, probe, sha(dll), mode, poison],
                    codes=(0, 2, 3), cwd=cwd, environ=env)
                payload_seen = (case / "payload.marker").exists()
                poison_seen = (case / "poison.marker").exists()
                if code != expected_code or payload_seen != constructor or poison_seen != poison_marker:
                    raise RuntimeError("PE case result or constructor differs: " + label)
                if payload_seen and (case / "payload.marker").read_bytes() != b"constructor41":
                    raise RuntimeError("PE payload constructor marker differs")
                if poison_seen and (case / "poison.marker").read_bytes() != b"poison77":
                    raise RuntimeError("PE poison constructor marker differs")
                row = {"return_code": code, "payload_sha256": sha(dll), "payload_constructor": payload_seen,
                    "poison_constructor": poison_seen, "mode": mode, "poison_location": location}
                if code == 3:
                    if not re.fullmatch(r"cm_pe_rejected: PE [A-Za-z0-9 ,/-]+", text):
                        raise RuntimeError("PE negative did not reject at the parser")
                    row["rejection"] = text
                else:
                    row["audit"] = audit_record(text)
                    records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
                    if code == 0:
                        if not records or records[-1].get("status") != "loaded" or records[-1].get("entry_value") != expected_value:
                            raise RuntimeError("PE native entry control differs")
                        if mode == "trusted-release" and records[:-1] != [{"status": "retained",
                                "caller_reference_released": True, "payload_executed": False}]:
                            raise RuntimeError("System dependency lost its owned reference after caller release")
                    elif not records or records[-1] != {"status": "rejected", "gate": "system-dependency-identity",
                            "preload_executed": True, "payload_executed": False}:
                        raise RuntimeError("PE preloaded foreign dependency rejection differs")
                    row["native"] = records
                report["cases"][label] = row
                return row

            original = payloads["ordinary"].read_bytes()
            for abi in ("cm_mod_entry_v1", "cm_mod_entry_v2"):
                observe("c-" + abi, original, abi=abi)
            for label, changed in mutations(original):
                row = observe(label, changed, expected_code=3, constructor=False)
                if label == "missing-required-entry" and row["rejection"] != "cm_pe_rejected: PE missing required entry":
                    raise RuntimeError("Missing-entry control rejected for an unrelated reason")
            for label in ("delayed", "forwarded"):
                observe("compiled-" + label, payloads[label].read_bytes(), expected_code=3, constructor=False)
            system = ctypes.create_unicode_buffer(4096)
            get_system = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
            get_system.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
            get_system.restype = ctypes.c_uint
            length = get_system(system, len(system))
            if not 0 < length < len(system):
                raise RuntimeError("Native System32 path unavailable")
            version_file = Path(system.value) / "version.dll"
            version_data = version_file.read_bytes()
            ordinal = export_slot(version_data, b"GetFileVersionInfoSizeW")["ordinal"]
            if not 0 < ordinal <= 65535:
                raise RuntimeError("Actual system export ordinal exceeds PE import encoding")
            ordinal_data = bytearray(original)
            imported = version_import(original)
            for at in {imported["lookup"], imported["iat"]}:
                struct.pack_into("<Q", ordinal_data, at, (1 << 63) | ordinal)
            row = observe("actual-system-ordinal", bytes(ordinal_data))
            if row["audit"]["ordinal_imports"] != 1:
                raise RuntimeError("Actual ordinal import was skipped")
            report["system_ordinal_control"] = {"path": str(version_file), "sha256": sha(version_file), "ordinal": ordinal}
            observe("adjacent-unsafe", original, mode="unsafe", expected_value=77, poison_marker=True, location="adjacent")
            for location in ("adjacent", "cwd", "path"):
                observe(location + "-system32", original, mode="system32", location=location)
                observe(location + "-guarded", original, location=location)
            observe("preloaded-unchecked", original, mode="unchecked-preloaded", expected_value=77, poison_marker=True)
            observe("preloaded-guarded", original, mode="guarded-preloaded", expected_code=2, constructor=False, poison_marker=True)
            observe("trusted-system-reference", original, mode="trusted-release")
            for abi in ("cm_mod_entry_v1", "cm_mod_entry_v2"):
                observe("rust-" + abi, rust_payload.read_bytes(), abi=abi, constructor=False)
                observe("snapshot-" + abi, original, abi=abi, mode="snapshot")
            if any(sha(root / name) != expected for name, expected in report["source_sha256"].items()) or any(
                    sha(Path(tool["path"])) != tool["sha256"] for tool in tools.values()):
                raise RuntimeError("PE fixture source or native tool changed")
            run("pe-source-pristine", ["git", "-C", root, "diff", "--exit-code"])
            report["status"] = "observed_native_pe_and_search_only"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        (logs / "windows-native-pe.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def self_check():
    root = Path(__file__).resolve().parents[2]
    import host
    production = {row["path"] for row in host.product_manifest(root)}
    shared = {"crates/cm/Cargo.toml", "crates/cm/src/loader/input.rs", "crates/cm/src/profile/directory.rs"}
    assert not ((set(INPUTS) - shared) & production), "Windows-only loader/fixture must stay outside Linux H"
    assert shared <= production, "Shared crate build inputs must change the Linux H identity"
    import retry
    pin_name = "adapters/codex-e4568a3/source.json"
    pin = json.loads((root / pin_name).read_text())
    rows = b"100644 blob aaaa\t" + pin_name.encode() + b"\x00"
    additions = b"".join(b"100644 blob bbbb\t" + name.encode() + b"\x00" for name in set(INPUTS) - shared)
    recipe = "    env:\n      CM_TARGET: x86_64-unknown-linux-gnu\n    steps:\n"
    with patch.object(retry, "source", side_effect=lambda root, revision, path:
            json.dumps(pin) if path == pin_name else recipe):
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            with patch.dict(os.environ, {"CM_TARGET": target}), patch.object(retry, "git", return_value=rows):
                baseline = retry.product_inputs(root, "HEAD")
                with patch.object(retry, "git", return_value=rows + additions):
                    assert retry.product_inputs(root, "HEAD") == baseline
                for name in shared:
                    with patch.object(retry, "git", return_value=rows + additions + b"100644 blob cccc\t" + name.encode() + b"\x00"):
                        assert retry.product_inputs(root, "HEAD") != baseline
    private_text = "\n".join("cm_private passed=" + name for name in PRIVATE_CHECKS)
    assert private_record(private_text)["checks"] == PRIVATE_CHECKS
    for text in (private_text + "\n" + private_text, private_text.replace("owner-file", "unknown"),
            private_text.split("\n", 1)[1], private_text + "\nnoise"):
        try:
            private_record(text)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Incomplete or unrelated private-control evidence accepted")
    record = "cm_pe dependencies=kernel32.dll,version.dll imports=2 ordinals=1 entry=4096"
    assert audit_record(record)["ordinal_imports"] == 1
    for text in (record + "\n" + record, record.replace("ordinals=1", "ordinals=3"),
            record.replace("entry=4096", "entry=0"), record.replace("kernel32.dll,version.dll", "version.dll,kernel32.dll")):
        try:
            audit_record(text)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Bad native PE evidence accepted")
    lock = tomllib.loads((root / "fixtures/native-loader/windows-pe/Cargo.lock").read_text())
    assert {row["name"]: (row["version"], row.get("checksum")) for row in lock["package"]} == {
        "cm-windows-pe-fixture": ("0.1.0", None), **LOCKED}
    metadata = {"packages": [{"name": "cm-windows-pe-fixture", "id": "fixture"},
        *({"name": name, "id": name, "version": values[0], "source": "registry+https://github.com/rust-lang/crates.io-index",
            "license": "test declaration"} for name, values in LOCKED.items())],
        "resolve": {"nodes": [{"id": "object", "features": ["coff", "pe", "read_core", "std"]}]}}
    inventory(metadata)
    metadata["resolve"]["nodes"][0]["features"].append("compression")
    try:
        inventory(metadata)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Unused PE dependency features accepted")


if __name__ == "__main__":
    main()
