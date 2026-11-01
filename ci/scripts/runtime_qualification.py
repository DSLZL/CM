"""G04 static binary qualification and reports; never loads a Mod to inspect it."""
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tomllib

from mod_manifest import TARGET, read, sha, write
from runtime_cases import digest

REPORTS = ("linux-binary-contract.json", "compiler-free-runtime.json", "linux-runtime-support.json",
           "prebuilt-package-inventory.json", "runtime-qualification-failures.json")
MODS = ("m01-a", "m01-b", "m02/lifecycle-audit/normal", "m02/example-tool/normal",
        "g02a/turn-budget", "g02b/review-before-send", "g03/tool-concurrency")
HELPERS = ("bin/codex", "bin/codex-code-mode-host", "codex-resources/bwrap", "codex-path/rg")


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60,
        env=os.environ | {"LC_ALL": "C", "LANGUAGE": "C"})
    assert result.returncode == 0 and len(result.stdout) <= 8 * 1024 * 1024, (args, result.stderr)
    assert not result.stderr.strip(), (args, result.stderr)
    return result.stdout


def parse_elf(data, text):
    assert len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "Expected ELF64 little-endian v1"
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    assert kind in (2, 3) and machine == 62 and version == 1 and data[7] in (0, 3) and data[8] == 0, "Unsupported ELF ABI/architecture"
    offset = struct.unpack_from("<Q", data, 32)[0]
    header, stride, count = struct.unpack_from("<HHH", data, 52)
    assert header == 64 and stride == 56 and 0 < count <= 1024 and offset >= 64
    assert offset + count * stride <= len(data), "Truncated ELF program headers"
    for index in range(count):
        segment = struct.unpack_from("<IIQQQQQQ", data, offset + index * stride)
        assert segment[2] <= len(data) and segment[5] <= len(data) - segment[2], "Truncated ELF segment"
    assert not re.search(r"\((?:RPATH|RUNPATH)\)", text), "Forbidden ELF search path"
    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", text)
    soname = re.findall(r"\(SONAME\).*\[([^\]]+)\]", text)
    assert len(needed) == len(set(needed)) and len(soname) <= 1
    assert all(re.fullmatch(r"[A-Za-z0-9_+.-]+", value) and value not in (".", "..") for value in needed + soname)
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)", text)
    assert len(interpreters) <= 1
    # Version definitions describe exports, not the binary's minimum requirement.
    needs = text.split("Version needs section", 1)[1] if "Version needs section" in text else ""
    versions = sorted(set(re.findall(r"\bName: (\S+)", needs)))
    glibc = [tuple(map(int, item[6:].split("."))) for item in versions if re.fullmatch(r"GLIBC_[0-9]+(?:\.[0-9]+)+", item)]
    isa = re.findall(r"x86 ISA needed: ([^\n]+)", text)
    assert all(part.strip() == "x86-64-baseline" for row in isa for part in row.split(",")), "Mandatory ISA above x86-64 baseline"
    return {"class": 64, "endian": "little", "machine": machine, "type": kind,
        "osabi": data[7], "abi_version": data[8], "interpreter": interpreters,
        "needed": needed, "soname": soname, "rpath": [], "runpath": [], "version_requirements": versions,
        "glibc_symbol_min": ".".join(map(str, max(glibc))) if glibc else None,
        "gnu_notes": text.split("Displaying notes found in:", 1)[1] if "Displaying notes found in:" in text else "",
        "mandatory_isa_notes": isa}


def elf(path):
    text = command("readelf", "-W", "-h", "-l", "-d", "-V", "-n", str(path))
    return {**parse_elf(path.read_bytes(), text), "sha256": sha(path), "size": path.stat().st_size,
            "mode": path.stat().st_mode & 0o777, "readelf": text, "readelf_sha256": digest(text)}


def system_path(value):
    path = Path(value)
    assert path.is_absolute() and ".." not in path.parts and path.is_file(), "Missing/unsafe runtime library: " + value
    canonical = path.resolve(strict=True)
    assert str(path).startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"))
    assert str(canonical).startswith(("/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/")), "Library escapes system directories"
    return path


def resolve_library(name, cache):
    assert re.fullmatch(r"[A-Za-z0-9_+.-]+", name) and name not in (".", ".."), "Unsafe DT_NEEDED"
    matches = re.findall(r"^\s*" + re.escape(name) + r" .*x86-64.* => (/\S+)$", cache, re.MULTILINE)
    paths = [system_path(value) for value in matches]
    assert paths and len({path.resolve() for path in paths}) == 1, "Missing/ambiguous runtime library: " + name
    return str(paths[0])


def package_inventory(host):
    from runtime_consumer import inventory
    return [entry for entry in inventory(host) if not entry["path"].startswith(("g02a-legacy/", "review-legacy/"))]


def audit(inputs, frozen):
    import host as host_module
    from runtime_consumer import system_package_owners
    host = inputs / "host"
    assert sha(host / "bin/codex") == frozen["executable_sha256"]
    manifest = read(host / "cm-runtime-files.json")
    canonical = [entry for entry in host_module.manifest(host)
                 if not entry["path"].startswith(("g02a-legacy/", "review-legacy/"))]
    assert [entry for entry in canonical if entry["path"] != "cm-runtime-files.json"] == manifest["files"]
    assert host_module.manifest_digest(canonical) == frozen["package_manifest_sha256"]
    selected = {"host/" + name for name in HELPERS}
    for entry in canonical:
        if entry["mode"] != "120000":
            with (host / entry["path"]).open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    selected.add("host/" + entry["path"])
    mods = {}
    for name in MODS:
        package = inputs / "mods" / name
        fields = tomllib.loads((package / "mod.toml").read_text())
        payload = package / fields["binary"]["path"]
        assert payload.resolve().is_relative_to(package.resolve()) and not payload.is_symlink()
        assert sha(payload) == fields["binary"]["sha256"] and payload.stat().st_size == fields["binary"]["size"]
        relative = payload.relative_to(inputs).as_posix()
        selected.add(relative)
        mods[name] = {"path": relative, "binary": fields["binary"], "compat": fields["compat"],
                      "manifest_sha256": sha(package / "mod.toml")}
    binaries, libraries, edges, pending, canonical_libraries = {}, {}, [], [], {}
    cache = command("ldconfig", "-p")
    for name in sorted(selected):
        path = inputs / name
        assert not path.is_symlink() and path.is_file()
        binaries[name] = elf(path)
        pending.append((name, binaries[name]))
    while pending:
        owner, binary = pending.pop()
        dependencies = [(name, resolve_library(name, cache)) for name in binary["needed"]]
        dependencies += [("PT_INTERP", str(system_path(name))) for name in binary["interpreter"]]
        for name, resolved in dependencies:
            edges.append({"binary": owner, "name": name, "resolved": resolved})
            if resolved in libraries:
                continue
            assert len(libraries) < 256, "Runtime dependency closure exceeds bound"
            path = Path(resolved)
            canonical = str(path.resolve())
            if canonical in canonical_libraries:
                libraries[resolved] = canonical_libraries[canonical]
                continue
            owners = system_package_owners(path)
            libraries[resolved] = {**elf(path), "canonical": canonical,
                "packages": {package: command("dpkg-query", "-W", "-f=${Version}", package) for package in owners}}
            canonical_libraries[canonical] = libraries[resolved]
            pending.append((resolved, libraries[resolved]))
    names = {}
    for name, binary in {**binaries, **libraries}.items():
        for soname in binary["soname"]:
            previous = names.setdefault(soname, binary["sha256"])
            assert previous == binary["sha256"], "Conflicting runtime SONAME: " + soname
    running_glibc = tuple(map(int, command("getconf", "GNU_LIBC_VERSION").split()[1].split(".")))
    for name, record in mods.items():
        binary = binaries[record["path"]]
        assert binary["type"] == 3 and not binary["interpreter"], name
        assert record["binary"]["target"] == TARGET and record["binary"]["cpu"] == "x86-64"
        minimum = binary["glibc_symbol_min"]
        assert minimum is None or tuple(map(int, minimum.split("."))) <= tuple(map(int, record["binary"]["glibc_min"].split(".")))
        assert tuple(map(int, record["binary"]["glibc_min"].split("."))) <= running_glibc, "Declared glibc exceeds actual producer"
    return {"status": "pass", "binaries": binaries, "libraries": libraries, "dependency_edges": edges,
        "mods": mods, "package_inventory": manifest, "package_files": package_inventory(host),
        "host_executable_sha256": frozen["executable_sha256"],
        "producer_backends": {"Cargo": "used", "Bazel": "deferred_not_implemented"},
        "baseline_intent": frozen["host_identity"]["inputs"]["flags"],
        "isa_boundary": "ELF notes and build flags do not prove every instruction or untested older CPUs"}


def prepare(inputs, frozen):
    root = Path(os.environ["CM_SOURCE_DIR"])
    for name in ("ci/scripts/runtime_qualification.py", "fixtures/runtime-qualification/driver.py"):
        path = inputs / "fixture" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, path)
    write(inputs / "fixture/g04-producer.json", audit(inputs, frozen))


def reports(inputs, root, closure, evidence, audit_result, steps, checkpoint_index):
    static = read(inputs / "fixture/g04-producer.json")
    assert static["status"] == "pass" and audit_result["status"] == "pass"
    assert static["package_files"] == package_inventory(root / "inputs/host")
    for name, binary in static["binaries"].items():
        assert sha(root / "inputs" / name) == binary["sha256"]
    for name, binary in static["libraries"].items():
        assert sha(root / name.lstrip("/")) == binary["sha256"], "Consumer library differs from audited producer"
    environment = {"runner": {key: os.environ[key] for key in
        ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")}, "kernel": platform.release(),
        "cpuinfo": Path("/proc/cpuinfo").read_text(), "glibc": command("getconf", "GNU_LIBC_VERSION").strip(),
        "os_release": Path("/etc/os-release").read_text(), "packages": closure["packages"],
        "rootfs_content_sha256": closure["sha256"], "rootfs_kind": closure["kind"]}
    actual = read(evidence / "g04/missing-library/baseline.json")["runtime_environment"]
    assert actual["glibc"] == environment["glibc"] and actual["machine"] == "x86_64"
    verified = {**actual, "runner_image": environment["runner"],
        "native_inputs_sha256": checkpoint_index["steps"]["g04-missing-library"]["inputs"]["native"],
        "execution_origin": steps["g04-missing-library"]["origin"], "execution_kind": steps["g04-missing-library"]["kind"]}
    assert environment["runner"]["RUNNER_OS"] == "Linux" and environment["runner"]["RUNNER_ARCH"] == "X64"
    # Existing business cases remain evidence with their own current/reused origin.
    required = ("m02-embedded", "m02-stdio", "m03-process", "m03-terminal", "m03-rejections",
                "m03-backends", "concurrency-value-flow", "consumer-missing-library", "consumer-library-recovery")
    assert all(steps[name]["status"] == "pass" for name in required)
    cases = read(evidence / "g04/suite.json")
    assert cases["status"] == "pass"
    failures = read(evidence / REPORTS[4])
    rejected = read(evidence / "atomic-mod-installation.json")["rejections"]
    assert {row["case"] for row in rejected} >= {"elf-architecture", "runpath", "actual-glibc", "actual-cpu-property"}
    failure_fields = {**failures, "native_preflight": rejected,
        "backend_rejections": read(evidence / "prebuilt-backend-selection.json"),
        "missing_library": read(evidence / "missing-library.json"),
        "library_recovery": read(evidence / "actual-missing-library-recovery.json")}
    values = (static,
        {"business_steps": {name: {key: value for key, value in steps[name].items() if key != "audit"} for name in required},
         "isolation": read(evidence / "isolation-probes.json"), "runtime_inventory_checked": True,
         "compiler_linker_jit_build_service_calls": audit_result["compiler_linker_jit_build_service_calls"],
         "python": "audited fixture driver, not a product dependency"},
        {"verified": [verified], "current_validation_environment": environment,
         "deferred": ["other distributions", "older glibc", "other CPUs", "Windows", "macOS", "ARM64", "musl"],
         "native_mod_trust": "shares Host process permissions; not a native-code sandbox"},
        {"files": static["package_files"], "runtime_inventory": static["package_inventory"],
         "variants": {"codex_package": "exercised", "codex_app_server_subcommand": "exercised by m02-stdio",
             "Embedded_InProcess": "exercised by m03-terminal", "standalone_codex_app_server_package": "deferred_not_shipped"},
         "actual_helpers": {name: static["binaries"]["host/" + name] for name in HELPERS}}, failure_fields)
    for name, value in zip(REPORTS, values):
        write(evidence / name, {**value, "status": "behavior_pass"})


def self_check():
    from record_run import require_hosted_linux
    from unittest.mock import patch
    import tempfile
    require_hosted_linux()
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, 62, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    text = "(NEEDED) Shared library: [libc.so.6]\nVersion definition section\nName: GLIBC_99.0\nVersion needs section\nName: GLIBC_2.34\n"
    parsed = parse_elf(data, text)
    assert parsed["glibc_symbol_min"] == "2.34" and parsed["needed"] == ["libc.so.6"]
    wrong = bytearray(data)
    struct.pack_into("<H", wrong, 18, 183)
    for payload, output in ((data[:63], text), (data[:-1], text), (wrong, text), (data, text + "(RUNPATH) [tmp]"),
                            (data, "(NEEDED) [../bad.so]"), (data, "x86 ISA needed: x86-64-v3\n")):
        try:
            parse_elf(payload, output)
        except AssertionError:
            pass
        else:
            raise AssertionError("Invalid binary metadata accepted")
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "library"
        path.touch()
        with patch.object(sys.modules[__name__], "system_path", side_effect=lambda value: Path(value)):
            cache = " libc.so.6 (libc6,x86-64) => " + str(path) + "\n"
            assert resolve_library("libc.so.6", cache) == str(path)
            for name, index in (("libc.so.6", ""), ("../bad", cache),
                                ("libc.so.6", cache + cache.replace(str(path), str(path) + "-other"))):
                try:
                    resolve_library(name, index)
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Missing/unsafe/ambiguous dependency accepted")
    assert elf(Path("/usr/bin/env"))["machine"] == 62
    for value in ("/etc/hosts", "/usr/lib/../../etc/hosts", "/usr/lib/cm-g04-missing-library"):
        try:
            system_path(value)
        except AssertionError:
            pass
        else:
            raise AssertionError("Non-system/missing runtime library accepted")
    from retry import test_inputs, source
    root = Path(os.environ["CM_SOURCE_DIR"])
    before = test_inputs(root, "HEAD")
    path = "fixtures/runtime-qualification/driver.py"
    original_source = source
    changed = source(root, "HEAD", path).replace("def case_abi():\n", "def case_abi():\n    assert False\n")
    import retry
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            changed if name == path else original_source(directory, revision, name)):
        after = test_inputs(root, "HEAD")
    assert {name for name in before if before[name] != after[name]} == {"g04-abi"}
    from retry import Checkpoints, native_key
    import runtime_cases
    checkpoints = object.__new__(Checkpoints)
    checkpoints.reports = {"g04-" + case: ["g04/" + case + "/reports.json"] for case in runtime_cases.GROUPS["g04"]}
    for case in runtime_cases.GROUPS["g04"]:
        label = "g04-" + case
        assert checkpoints.owns(label, Path("g04") / case / "protection.json")
        assert all(not checkpoints.owns(label, Path("g04") / other / "protection.json")
                   for other in runtime_cases.GROUPS["g04"] if other != case)
    labels = ["g04-" + case for case in runtime_cases.GROUPS["g04"]]
    closure = {"packages": {}, "files": [
        {"path": "inputs/mods/constructor-sentinel/payload.so", "sha256": "one"},
        {"path": "inputs/mods/m02/example-tool/normal/payload.so", "sha256": "one"}]}
    before = {label: native_key(closure, label) for label in labels}
    closure["files"][0]["sha256"] = "two"
    assert {label for label in labels if native_key(closure, label) != before[label]} == {"g04-abi"}
    before = {label: native_key(closure, label) for label in labels}
    closure["files"][1]["sha256"] = "two"
    assert all(native_key(closure, label) != before[label] for label in labels)
    print("CM G04 ELF/dependency and independent checkpoint checks passed", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "self-check":
        self_check()
    else:
        assert sys.argv[1] == "produce"
        from runtime_consumer import produce
        produce()
