#!/usr/bin/env python3
"""Sealed native Windows Host build candidate; product qualification stays separate."""
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile

import ci_progress
import host
import record_run
import windows_native_inputs as native
import worker_policy
from windows_runtime_preflight import GIT_CONFIG
from windows_x64_preflight import authority, pe_fixture

KEY, TARGET = native.KEY, native.TARGET
BINS = ("codex.exe", "codex-code-mode-host.exe", "codex-command-runner.exe", "codex-windows-sandbox-setup.exe")
PACKAGES = ("codex-cli", "codex-code-mode-host", "cm-abi", "cm-runtime", "cm-sdk", "cm-host-adapter")
NATIVE_FILES = ("protoc.exe", "sccache.exe", "ninja.exe", "v8.gz", "v8.rs", "gh.exe")
MAXIMUM = 2 * 1024 ** 3
SCCACHE_SHA = "205d613fa74a9a0525e41a5ace77b1c71907d5bd4a5e668bad79111776829290"


def recipes():
    common = ["--locked", "--target", TARGET, "--profile", "dev-small", "-j", "2"]
    packages = [arg for name in sorted(PACKAGES) for arg in ("-p", name)]
    extra = [arg for name in ("codex-app-server", "codex-core", "codex-tui") for arg in ("-p", name)]
    return {
        "host-fmt": ["cargo", "fmt", *packages, *extra, "-p", "codex-windows-sandbox", "--", "--check"],
        "host-clippy": ["cargo", "clippy", *common, *packages, *extra, "--all-targets", "--", "-D", "warnings"],
        "host-test": ["cargo", "test", *common, *packages, "--", "--test-threads=1"],
        "host-build": ["cargo", "build", *common, *packages],
        "helper-clippy": ["cargo", "clippy", *common, "-p", "codex-windows-sandbox", "--bins", "--", "-D", "warnings"],
        "helper-build": ["cargo", "build", *common, "-p", "codex-windows-sandbox",
            "--bin", "codex-command-runner", "--bin", "codex-windows-sandbox-setup"],
    }


def files(directory):
    result = []
    for path in sorted(directory.rglob("*")):
        attributes = path.lstat()
        if stat.S_ISDIR(attributes.st_mode) and not getattr(attributes, "st_file_attributes", 0) & 0x400:
            continue
        if not stat.S_ISREG(attributes.st_mode) or getattr(attributes, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("Host build material must be a regular non-reparse file: " + str(path))
        result.append({"path": path.relative_to(directory).as_posix(), "size": attributes.st_size, "sha256": host.sha(path)})
    return result


def archive_path(name):
    path = PurePosixPath(name)
    reserved = {"CON", "PRN", "AUX", "NUL", *(prefix + str(n) for prefix in ("COM", "LPT") for n in range(1, 10))}
    if (not name or path.is_absolute() or path.as_posix() != name or len(name) > 240
            or any(not part or part in (".", "..") or part != part.rstrip(" .")
                or any(char in part for char in '\\:*?"<>|') or any(ord(char) < 32 for char in part)
                or part.split(".")[0].upper() in reserved for part in path.parts)
            or (name != "build.json" and path.parts[0] not in ("bin", "native", "quality", "materials"))):
        raise RuntimeError("Invalid Windows Host archive path: " + repr(name))
    return path


def extract(archive, destination):
    if destination.exists():
        raise RuntimeError("Host restore destination must be fresh")
    members, seen, total = archive.infolist(), set(), 0
    if not 1 <= len(members) <= 8192:
        raise RuntimeError("Host archive inventory exceeds its bound")
    for row in members:
        name = row.filename.removesuffix("/") if row.is_dir() else row.filename
        archive_path(name)
        key = name.casefold()
        kind = (row.external_attr >> 16) & 0o170000
        if key in seen or kind not in ((0, 0o040000) if row.is_dir() else (0, 0o100000)):
            raise RuntimeError("Duplicate, aliased or special Host archive member")
        seen.add(key)
        total += row.file_size
        limit = 512 * 1024 ** 2 if name.startswith(("bin/", "native/")) else 16 * 1024 ** 2
        if not 0 <= row.file_size <= limit or total > MAXIMUM:
            raise RuntimeError("Host archive bytes exceed their bound")
    destination.mkdir()
    for row in members:
        path = destination.joinpath(*PurePosixPath(row.filename).parts)
        if row.is_dir():
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(row) as source, path.open("xb") as output:
                shutil.copyfileobj(source, output)
            if path.stat().st_size != row.file_size:
                raise RuntimeError("Host archive extraction length differs")


def read_origin(raw):
    if not raw:
        return None
    if len(raw) > 4096:
        raise RuntimeError("Oversized explicit Host build origin")
    value = json.loads(raw)
    required = {"run_id", "run_attempt", "source_sha", "workflow_sha", "artifact_id", "artifact_sha256"}
    if (not isinstance(value, dict) or set(value) != required
            or any(type(value[key]) is not int or not 0 < value[key] < 2 ** 63 for key in ("run_id", "run_attempt", "artifact_id"))
            or any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{40}", value[key])
                for key in ("source_sha", "workflow_sha"))
            or not isinstance(value["artifact_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["artifact_sha256"])):
        raise RuntimeError("Incomplete or invalid explicit Host build origin")
    return value


def restore(origin, temp):
    repo = "DSLZL/CM-build-" + KEY
    run = worker_policy.api(f"repos/{repo}/actions/runs/{origin['run_id']}")
    jobs = worker_policy.api(f"repos/{repo}/actions/runs/{origin['run_id']}/attempts/{origin['run_attempt']}/jobs?per_page=100")
    if (run.get("id") != origin["run_id"] or run.get("run_attempt") != origin["run_attempt"]
            or run.get("head_sha") != origin["workflow_sha"] or run.get("head_branch") != "main"
            or run.get("event") != "workflow_dispatch" or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("path") != ".github/workflows/native-preflight.yml"
            or jobs.get("total_count") != 1 or len(jobs.get("jobs", [])) != 1):
        raise RuntimeError("Explicit Host producer is not one complete successful exact native run")
    job = worker_policy.successful_job(jobs["jobs"], "native-preflight")
    comparison = worker_policy.api(f"repos/{repo}/compare/{origin['workflow_sha']}...{os.environ['GITHUB_WORKFLOW_SHA']}")
    if comparison.get("status") not in ("ahead", "identical"):
        raise RuntimeError("Host producer worker is not a trusted current ancestor")
    artifact = worker_policy.api(f"repos/{repo}/actions/artifacts/{origin['artifact_id']}")
    worker_policy.artifact_binding(artifact, origin["artifact_id"],
        f"cm-{KEY}-host-build-{origin['run_id']}-{origin['run_attempt']}", origin["artifact_sha256"], origin["run_id"])
    destination = temp / "restored-host"
    with worker_policy.download_origin_archive(repo, artifact, temp / "host-origin.zip", maximum=MAXIMUM) as archive:
        extract(archive, destination)
    receipt = host.read(destination / "build.json")
    expected = {"source_sha": origin["source_sha"], "workflow_sha": origin["workflow_sha"],
        "run_id": origin["run_id"], "run_attempt": origin["run_attempt"], "job": "native-preflight",
        "repository": repo, "source_repository": "DSLZL/CM", "target": TARGET}
    if (receipt.get("schema_version") != 1 or receipt.get("domain") != "cm.windows-host-build.v1"
            or receipt.get("origin") != expected or receipt.get("files") != [row for row in files(destination) if row["path"] != "build.json"]):
        raise RuntimeError("Host producer receipt or complete file inventory differs")
    required = ({"bin/" + name for name in BINS} | {"native/" + name for name in NATIVE_FILES}
        | {"native/inputs.json", "native/verifier.json"} | {"quality/" + name + ".log" for name in recipes()})
    actual = {row["path"] for row in receipt["files"]}
    if not required <= actual or any(name not in required and not name.startswith("materials/") for name in actual):
        raise RuntimeError("Host origin has missing or unexpected build inputs")
    checked_quality(receipt, destination)
    return destination, receipt, job


def sdk_inventory():
    result, seen, total = [], set(), 0
    for variable in ("INCLUDE", "LIB"):
        roots = os.environ[variable].split(";")
        for index, name in enumerate(roots):
            if not name:
                continue
            root = Path(name).resolve()
            if not root.is_dir() or getattr(root.lstat(), "st_file_attributes", 0) & 0x400:
                raise RuntimeError("SDK input root must be a non-reparse directory")
            for directory, dirs, names in os.walk(root, followlinks=False):
                for entry in dirs + names:
                    path = Path(directory) / entry
                    data = path.lstat()
                    if getattr(data, "st_file_attributes", 0) & 0x400 or not (stat.S_ISDIR(data.st_mode) or stat.S_ISREG(data.st_mode)):
                        raise RuntimeError("Unsupported native SDK input: " + str(path))
                for entry in sorted(names):
                    path = Path(directory) / entry
                    key = str(path).casefold()
                    if key in seen:
                        continue
                    seen.add(key)
                    total += path.stat().st_size
                    if len(seen) > 100000 or total > 16 * 1024 ** 3:
                        raise RuntimeError("Native SDK input inventory exceeds its bound")
                    result.append({"path": str(path), "link": None, "sha256": host.sha(path),
                        "input": f"{variable}/{index}/" + path.relative_to(root).as_posix()})
    if not result:
        raise RuntimeError("Native SDK input inventory is empty")
    return sorted(result, key=lambda row: row["input"])


def sccache_tool(temp, run):
    archive = temp / "sccache.zip"
    native.download("https://github.com/mozilla/sccache/releases/download/v0.18.0/"
        "sccache-v0.18.0-aarch64-pc-windows-msvc.zip", archive, SCCACHE_SHA, 16 * 1024 ** 2)
    import zipfile
    with zipfile.ZipFile(archive) as stream:
        members = stream.infolist()
        selected = [row for row in members if PurePosixPath(row.filename).name == "sccache.exe"]
        if (not 0 < len(members) <= 64 or sum(row.file_size for row in members) > 64 * 1024 ** 2
                or len(selected) != 1 or selected[0].is_dir()
                or (selected[0].external_attr >> 16) & 0o170000 not in (0, 0o100000)
                or not 0 < selected[0].file_size <= 32 * 1024 ** 2):
            raise RuntimeError("Expected one bounded native sccache executable")
        data = stream.read(selected[0])
    path = temp / "sccache.exe"
    path.write_bytes(data)
    identity = {"path": str(path), **pe_fixture(data, False, expected_machine=0xAA64)}
    if run("host-sccache-version", [path, "--version"]).strip() != "sccache 0.18.0":
        raise RuntimeError("Native sccache version differs")
    return identity


def checked_quality(receipt, directory):
    commands = recipes()
    quality = receipt.get("quality")
    if not isinstance(quality, dict) or set(quality) != set(commands):
        raise RuntimeError("Host lacks its complete original successful quality checks")
    for name, command in commands.items():
        row = quality[name]
        if (row.get("command") != command or row.get("return_code") != 0
                or row.get("log_sha256") != host.sha(directory / "quality" / (name + ".log"))):
            raise RuntimeError("Original Host recipe, result or log differs: " + name)


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    authority(host.read(Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json"), entry, os.environ, key=KEY)
    if os.environ.get("CM_PREFLIGHT_STAGE") != "native-host" or Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Host candidate requires its exact reviewed native stage and source")
    if any(os.environ.get(name) != value for name, value in GIT_CONFIG.items()):
        raise RuntimeError("Host source preparation requires the fixed per-process Git configuration")
    if any(os.environ.get(name) for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTDOC",
            "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CC", "CXX", "AR", "CFLAGS", "CXXFLAGS", "CL", "_CL_",
            "CM_NATIVE_PROTOC", "CM_DISTRIBUTION_GH_SHA256", "CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER")):
        raise RuntimeError("Host candidate forbids unregistered compiler/native overrides")
    host.reject_native_overrides()
    origin = read_origin(os.environ.get("CM_PREFLIGHT_HOST_ORIGIN", ""))
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Host evidence must remain in runner temporary storage")
    output = Path(os.environ["RUNNER_TEMP"]) / "cm-windows-arm64-host-build"
    if output.exists():
        raise RuntimeError("Host build export must start empty")
    report = {"schema_version": 1, "status": "running", "stage": "native-host", "platform": KEY, "target": TARGET,
        "source_sha": os.environ["CM_SOURCE_SHA"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "cache_mode": "none", "cache_writes": 0, "cache_deletes": 0, "platform_enabled": False,
        "full_qualification": "not_run", "product_consumer": "not_run", "actual_host_tui": "not_run",
        "helper_setup_execution": "not_run", "cli_builds": 0, "quality": {}, "host_build_origin": origin}
    tools, started = {}, False

    def run(label, args, timeout=60, *, cwd=root):
        previous = Path.cwd()
        values = [str(value) for value in args]
        try:
            os.chdir(cwd)
            with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"stage": label, "command": values, "cwd": str(cwd)}) + "\n")
            result = ci_progress.run(logs, label, values, timeout)
        finally:
            os.chdir(previous)
        if result.returncode:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return (logs / (label + ".log")).read_text(encoding="utf-8", errors="strict").strip()

    try:
        cfg = host.read(root / ".github/cm-ci.json")
        pin = host.read(root / host.ADAPTER / "source.json")
        if cfg["rust_toolchain"] != "1.95.0" or cfg["upstream"]["commit"] != native.REVISION or host.TARGET != TARGET:
            raise RuntimeError("Host toolchain, target or upstream pins differ")
        report["source_sha256"] = {row["path"]: row["sha256"] for row in host.cm_manifest(root)}
        report["environment"] = {name: os.environ[name] for name in (
            "ImageOS", "ImageVersion", "VCToolsVersion", "WindowsSDKVersion", "VCToolsInstallDir", "WindowsSdkDir")}
        cl = Path(shutil.which("cl.exe") or "")
        if not cl.is_absolute() or tuple(part.lower() for part in cl.parts[-3:]) != ("hostarm64", "arm64", "cl.exe"):
            raise RuntimeError("Host requires installed native ARM64 MSVC")
        for name, path in (("cl", cl), ("link", cl.with_name("link.exe")), ("lib", cl.with_name("lib.exe")),
                ("go", Path(shutil.which("go.exe") or ""))):
            tools[name] = {"path": str(path), **pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)}

        with tempfile.TemporaryDirectory(prefix="cm-host-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory).resolve()
            try:
                toolchain = cfg["rust_toolchain"] + "-" + TARGET
                run("host-native-toolchain", ["rustup", "toolchain", "install", toolchain, "--profile", "minimal"], 180)
                run("host-native-components", ["rustup", "component", "add", "rustfmt", "clippy", "--toolchain", toolchain], 180)
                for name in ("rustc", "cargo", "rustfmt", "cargo-clippy", "clippy-driver"):
                    path = Path(run("host-" + name + "-path", ["rustup", "which", "--toolchain", toolchain, name]))
                    tools[name] = {"path": str(path), **pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)}
                rust_tools = {name: {"sha256": tools[name]["sha256"],
                    "version": run("host-" + name + "-version", [tools[name]["path"], "-Vv"])} for name in ("rustc", "cargo")}
                if any("host: " + TARGET not in row["version"].splitlines() for row in rust_tools.values()):
                    raise RuntimeError("Host requires native ARM64 Rust compiler and Cargo")
                tools["sccache"] = sccache_tool(temp, run)
                os.environ.update({"TEMP": str(temp), "TMP": str(temp), "CARGO_HOME": str(temp / "cargo"),
                    "CARGO_TARGET_DIR": str(temp / "target"), "CM_HOST_PRISTINE": str(temp / "pristine"),
                    "RUSTUP_TOOLCHAIN": toolchain, "PATH": str(Path(tools["cargo"]["path"]).parent) + os.pathsep + os.environ["PATH"]})
                with ci_progress.stage("host-fixed-source-prepare"):
                    host.prepare(root, logs)
                provenance = host.verify_sources(root, logs)
                tree = root / host.HOST
                with ci_progress.stage("host-native-sdk-inventory"):
                    sdk = sdk_inventory()
                host.write(logs / "native-files.json", sdk)
                if origin:
                    restored, receipt, original_job = restore(origin, temp)
                    native.protoc_tools(temp, tools, report, run)
                    (temp / "protoc-build").mkdir()
                    shutil.copyfile(restored / "native/protoc.exe", temp / "protoc-build/protoc.exe")
                    native_inputs = host.read(restored / "native/inputs.json")
                    report["protoc_replacement"] = native_inputs["protoc"]
                    verifier_dir = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-verifier"
                    verifier_dir.mkdir()
                    shutil.copyfile(restored / "native/gh.exe", verifier_dir / "gh.exe")
                    shutil.copyfile(restored / "native/verifier.json", verifier_dir / "verifier.json")
                    shutil.copytree(restored / "materials", verifier_dir / "licenses")
                    verifier = host.read(verifier_dir / "verifier.json")
                    v8 = {"RUSTY_V8_ARCHIVE": str(restored / "native/v8.gz"),
                        "RUSTY_V8_SRC_BINDING_PATH": str(restored / "native/v8.rs")}
                    report["original_job"] = original_job
                else:
                    native.native_protoc(temp, tools, report, run)
                    v8 = host.resolve_v8(root, TARGET)
                    import distribution_provenance
                    with ci_progress.stage("host-native-distribution-verifier"):
                        verifier = distribution_provenance.verifier(root, logs)
                protoc = native.verified_protoc(temp, report)
                policy = host.read(root / "crates/cm/src/distribution-policy-windows-arm64.json")
                if (verifier["pin"] != policy["verifier"]
                        or verifier["policy_sha256"] != host.sha(root / "crates/cm/src/distribution-policy-windows-arm64.json")
                        or verifier["root_sha256"] != host.sha(root / "crates/cm/src/distribution-root.jsonl")):
                    raise RuntimeError("Host verifier policy or trust root differs")
                verifier_path = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-verifier/gh.exe"
                if pe_fixture(verifier_path.read_bytes(), False, expected_machine=0xAA64, maximum_bytes=128 * 1024 ** 2)["sha256"] != verifier["sha256"]:
                    raise RuntimeError("Native verifier executable differs")
                proto = report["protoc_replacement"]
                native_identity = {"rust_tools": rust_tools, "distribution_verifier": verifier,
                    "v8": {name: {"name": "v8.gz" if name == "RUSTY_V8_ARCHIVE" else "v8.rs", "sha256": host.sha(Path(path))}
                        for name, path in v8.items()},
                    "sdk_sha256": host.digest([{key: row[key] for key in ("input", "sha256")} for row in sdk]),
                    "protoc": {name: proto[name] for name in ("sources", "version", "cxx_standard", "binary")},
                    "protoc_recipe": host.digest(inspect.getsource(native.native_protoc) + inspect.getsource(native.protoc_tools))}

                os.environ.update({**v8, "CM_NATIVE_PROTOC": str(protoc), "CM_DISTRIBUTION_GH_SHA256": verifier["sha256"],
                    "CARGO_INCREMENTAL": "0", "RUSTC": tools["rustc"]["path"], "RUSTC_WRAPPER": tools["sccache"]["path"],
                    "RUSTFLAGS": "-Ctarget-feature=+crt-static", "CC": tools["cl"]["path"], "CXX": tools["cl"]["path"],
                    "AR": tools["lib"]["path"], "CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER": tools["link"]["path"],
                    "SCCACHE_DIR": str(temp / "sccache"), "SCCACHE_GHA_ENABLED": "false", "SCCACHE_CACHE_SIZE": "2G",
                    "SCCACHE_IDLE_TIMEOUT": "0", "SCCACHE_BASEDIRS": str(root), "CODEX_HOME": str(temp / "codex-home")})
                host.write(root / host.ADAPTER / "inputs/native.json", native_identity)
                profiles = {name: "dev-small" for name in ("build_profile", "test_profile", "clippy_profile")}
                compile_tools = {name: {key: value for key, value in tools[name].items() if key != "path"}
                    for name in ("cl", "link", "lib", "rc", "mt", "rustc", "cargo", "sccache")}
                inputs = {"source": provenance["host_manifest_sha256"], "cm_inputs": host.manifest_digest(host.product_manifest(root)),
                    "lock": provenance["host_lock_sha256"], "target": TARGET,
                    "toolchain": {"declared": cfg["rust_toolchain"], **{name: row["version"] for name, row in rust_tools.items()}},
                    "profiles": profiles, "units": [{"id": "host", "packages": list(PACKAGES)}, {"id": "windows-helper",
                        "packages": ["codex-windows-sandbox"], "binaries": list(BINS[2:])}],
                    "flags": {"RUSTFLAGS": os.environ["RUSTFLAGS"], "CARGO_INCREMENTAL": "0", "RUSTC_WRAPPER": "sccache"},
                    "cargo_configuration": {".cargo/config.toml": host.sha(tree / "codex-rs/.cargo/config.toml")},
                    "native_tools": compile_tools, "native": native_identity,
                    "helper": {"package": "codex-windows-sandbox", "binaries": list(BINS[2:]), "build": "same sealed source/target",
                        "commands": recipes()}}
                inputs["runtime_hooks"] = host.hook_map(root, inputs)
                protocol = host.manifest_digest(host.manifest(tree / pin["protocol_source"]))
                identity = host.build_identity(pin, inputs, protocol)
                host.write(logs / "host-identity.json", identity)
                os.environ["CM_HOST_IDENTITY_JSON"] = str(logs / "host-identity.json")
                os.environ.pop("CM_POLICY_TOKEN", None)
                binaries = Path(os.environ["CARGO_TARGET_DIR"]) / TARGET / "dev-small"
                if origin:
                    checked_quality(receipt, restored)
                    if receipt.get("identity") != identity:
                        raise RuntimeError("Explicit Host origin differs from current sealed production/native/compiler inputs")
                    binaries.mkdir(parents=True)
                    for name in BINS:
                        shutil.copyfile(restored / "bin" / name, binaries / name)
                    report["quality"] = receipt["quality"]
                    report["host_compilation"] = "reused_original"
                else:
                    started = True
                    run("host-sccache-zero", [tools["sccache"]["path"], "--zero-stats"])
                    for name in ("host-fmt", "helper-clippy", "helper-build", "host-clippy", "host-test", "host-build"):
                        command = recipes()[name]
                        run(name, command, 5400, cwd=tree / "codex-rs")
                        report["quality"][name] = {"command": command, "return_code": 0, "log_sha256": host.sha(logs / (name + ".log"))}
                    report["cli_builds"] = 1
                    report["host_compilation"] = "executed_current"
                    run("host-sccache-stats", [tools["sccache"]["path"], "--show-stats", "--stats-format=json"])
                report["binaries"] = {name: pe_fixture((binaries / name).read_bytes(), False,
                    expected_machine=0xAA64, maximum_bytes=512 * 1024 ** 2) for name in BINS}
                host.verify_binary(binaries / "codex.exe", identity)
                run("host-cli-version", [binaries / "codex.exe", "--version"])
                host.verify_sources(root, logs)
                if any(host.sha(Path(row["path"])) != row["sha256"] for row in tools.values()):
                    raise RuntimeError("Native Host tools changed during construction")
                report["host_identity"] = identity["host_build_id"]

                if not origin:
                    for name in ("bin", "native", "quality"):
                        (output / name).mkdir(parents=True)
                    for name in BINS:
                        shutil.copyfile(binaries / name, output / "bin" / name)
                    native_paths = {"protoc.exe": protoc, "sccache.exe": Path(tools["sccache"]["path"]),
                        "ninja.exe": Path(tools["ninja"]["path"]), "v8.gz": Path(v8["RUSTY_V8_ARCHIVE"]),
                        "v8.rs": Path(v8["RUSTY_V8_SRC_BINDING_PATH"]), "gh.exe": verifier_path}
                    for name, path in native_paths.items():
                        shutil.copyfile(path, output / "native" / name)
                    host.write(output / "native/inputs.json", {"protoc": proto})
                    host.write(output / "native/verifier.json", verifier)
                    shutil.copytree(verifier_path.parent / "licenses", output / "materials")
                    for name in recipes():
                        shutil.copyfile(logs / (name + ".log"), output / "quality" / (name + ".log"))
                    receipt = {"schema_version": 1, "domain": "cm.windows-host-build.v1", "identity": identity,
                        "quality": report["quality"], "files": files(output),
                        "origin": {"source_sha": report["source_sha"], "workflow_sha": report["workflow_sha"],
                            "run_id": report["run_id"], "run_attempt": report["run_attempt"], "job": "native-preflight",
                            "repository": "DSLZL/CM-build-" + KEY, "source_repository": "DSLZL/CM", "target": TARGET}}
                    host.write(output / "build.json", receipt)
                    checked_quality(receipt, output)
                report.update(status="pass", source_inputs_unchanged=True, tools_unchanged=True)
                report["tools"] = tools
                report["artifact_name"] = f"cm-{KEY}-host-build-{report['run_id']}-{report['run_attempt']}" if not origin else (
                    f"cm-{KEY}-host-build-{origin['run_id']}-{origin['run_attempt']}")
                worker_policy.output({"host_reused": "true" if origin else "false",
                    "host_build_artifact_id": origin["artifact_id"] if origin else "",
                    "host_build_artifact_sha256": origin["artifact_sha256"] if origin else ""})
            finally:
                if started:
                    run("host-sccache-stop", [tools["sccache"]["path"], "--stop-server"])
    except BaseException as error:
        report.update(status="failed", error=repr(error))
        raise
    finally:
        host.write(logs / "windows-host-build.json", report)


def self_check():
    record_run.require_hosted_linux()
    import io
    import zipfile
    from unittest.mock import patch

    assert read_origin("") is None
    valid = {"run_id": 1, "run_attempt": 1, "source_sha": "a" * 40, "workflow_sha": "b" * 40,
        "artifact_id": 2, "artifact_sha256": "c" * 64}
    assert read_origin(json.dumps(valid)) == valid
    for bad in ([], {}, {**valid, "extra": 1}, {**valid, "run_id": True}, {**valid, "run_attempt": 0},
            {**valid, "source_sha": "main"}, {**valid, "artifact_sha256": "c" * 63}):
        try:
            read_origin(json.dumps(bad))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid Host build origin accepted")
    for name in ("bin/codex.exe", "native/gh.exe", "quality/host-build.log", "materials/gh/LICENSE", "build.json"):
        assert archive_path(name).as_posix() == name
    for name in ("../outside", "/bin/codex.exe", "bin/../codex.exe", "bin\\codex.exe", "bin/CON.exe",
            "bin/name:stream", "bin/name.", "bin/name ", "bin//name", "unknown/file", "bin/\x00"):
        try:
            archive_path(name)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid Windows Host path accepted")

    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
        temp = Path(directory)
        fixture = temp / "fixture"
        for name in BINS:
            (fixture / "bin").mkdir(parents=True, exist_ok=True)
            (fixture / "bin" / name).write_bytes(b"native-fixture")
        for name in (*NATIVE_FILES, "inputs.json", "verifier.json"):
            (fixture / "native").mkdir(parents=True, exist_ok=True)
            (fixture / "native" / name).write_bytes(b"input-fixture")
        quality = {}
        (fixture / "quality").mkdir()
        for name, command in recipes().items():
            log = fixture / "quality" / (name + ".log")
            log.write_text("original successful check\n", encoding="utf-8")
            quality[name] = {"command": command, "return_code": 0, "log_sha256": host.sha(log)}
        checked_quality({"quality": quality}, fixture)
        for changed in ("command", "return_code", "log_sha256"):
            bad = json.loads(json.dumps(quality))
            bad["host-build"][changed] = [] if changed == "command" else 1
            try:
                checked_quality({"quality": bad}, fixture)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Changed original Host quality was reused")
        repo = "DSLZL/CM-build-" + KEY
        receipt = {"schema_version": 1, "domain": "cm.windows-host-build.v1", "quality": quality,
            "identity": {"host_build_id": "fixture"}, "files": files(fixture),
            "origin": {"source_sha": valid["source_sha"], "workflow_sha": valid["workflow_sha"],
                "run_id": 1, "run_attempt": 1, "job": "native-preflight", "repository": repo,
                "source_repository": "DSLZL/CM", "target": TARGET}}
        host.write(fixture / "build.json", receipt)
        archive = temp / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            for row in files(fixture):
                stream.write(fixture / row["path"], row["path"])
        run = {"id": 1, "run_attempt": 1, "head_sha": valid["workflow_sha"], "head_branch": "main",
            "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
            "path": ".github/workflows/native-preflight.yml"}
        job = {"name": "native-preflight", "id": 3, "status": "completed", "conclusion": "success"}
        artifact = {"id": 2, "name": f"cm-{KEY}-host-build-1-1", "expired": False,
            "digest": "sha256:" + valid["artifact_sha256"], "workflow_run": {"id": 1}}
        def api(path):
            if "/attempts/" in path:
                return {"total_count": 1, "jobs": [job]}
            if "/compare/" in path:
                return {"status": "ahead"}
            return artifact if "/artifacts/" in path else run
        with patch.object(worker_policy, "api", side_effect=api), patch.object(worker_policy,
                "download_origin_archive", side_effect=lambda *args, **kwargs: zipfile.ZipFile(archive)):
            restored, actual, original_job = restore(valid, temp)
            assert actual == receipt and original_job == {"job": "native-preflight", "job_id": 3,
                "job_conclusion": "success"} and files(restored) == files(fixture)
        with zipfile.ZipFile(archive, "a") as stream:
            stream.writestr("bin/unexpected.exe", b"unregistered")
        (temp / "changed").mkdir()
        with patch.object(worker_policy, "api", side_effect=api), patch.object(worker_policy,
                "download_origin_archive", side_effect=lambda *args, **kwargs: zipfile.ZipFile(archive)):
            try:
                restore(valid, temp / "changed")
            except RuntimeError:
                pass
            else:
                raise AssertionError("Changed Host archive reused")
        for names, mode in ((("bin/name", "bin/NAME"), 0o100644), (("../outside",), 0o100644),
                (("bin/link",), 0o120777)):
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as stream:
                for name in names:
                    row = zipfile.ZipInfo(name)
                    row.external_attr = mode << 16
                    stream.writestr(row, b"fixture")
            data.seek(0)
            with zipfile.ZipFile(data) as stream:
                try:
                    extract(stream, temp / "invalid")
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Unsafe Host archive accepted")
            assert not (temp / "invalid").exists()


if __name__ == "__main__":
    main()
