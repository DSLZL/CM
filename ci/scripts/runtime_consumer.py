"""P04 producer and trusted outer consumer. Never copied into the runtime root."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import threading
import time
import types

import ci_progress
from cm_platforms import linux_native

TARGET = linux_native()["target"]
TRACE_SYSCALLS = ("trace=execve,execveat,socket,getsockname,accept,accept4,connect,sendto,recvfrom,socketpair,"
                  "symlink,symlinkat,open,openat,openat2,close,close_range,dup,dup2,dup3,fcntl,readlink,"
                  "mmap,mprotect,memfd_create,clone,clone3,fork,vfork,getpid,gettid")
CAPABILITY = "core.exec_output_limit.v1"
CONSUMER_ENV_PREFIX = ("/usr/bin/env", "-u", "PWD")
ENTRY_INVALID = ("short-prefix", "short-tail", "future-minor", "stride", "count", "null-array",
                 "misaligned-array", "reserved", "descriptor-size", "descriptor-minor",
                 "descriptor-reserved", "null-callback", "null-view", "huge-view", "utf8")
CALL_INVALID = ("callback-fail", "status", "cancelled", "increase", "zero", "keep-nonzero",
                "decision", "output-header", "output-reserved", "output-canary", "error-length",
                "error-null", "error-utf8", "error-canary")


def parallel_matrices(logs, commands, run=None):
    # These suites share read-only inputs and use separate profile/work/evidence paths.
    with ThreadPoolExecutor(max_workers=3) as pool:
        pending = {label: pool.submit(run or ci_progress.run, logs, label, command, timeout)
                   for label, command, timeout in commands}
        return {label: future.result() for label, future in pending.items()}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inventory(root):
    result = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            result.append({"path": relative, "mode": mode, "link": os.readlink(path)})
        else:
            assert path.is_file(), "Special input: " + relative
            result.append({"path": relative, "mode": mode, "sha256": sha(path), "size": path.stat().st_size})
    return result


@ci_progress.case()
def validate_inputs(inputs):
    manifest = read(inputs / "input-manifest.json")
    entries = [entry for entry in inventory(inputs) if entry["path"] != "input-manifest.json"]
    assert manifest["files"] == entries and manifest["sha256"] == digest(entries), "Producer inputs changed"
    return manifest


def validate_runtime_inventory(root, entries):
    forbidden = re.compile(r'^(?:cargo|rustc|rustdoc|gcc(?:-\d+)?|g\+\+|cc|c\+\+|clang.*|ld(?:\..*)?|as|ar|make|cmake|ninja|sccache|ssh|curl|wget|git|docker|podman|apt(?:-get|-cache)?|pip(?:[0-9.]+)?)$')
    for entry in entries:
        path = Path(entry["path"])
        assert not forbidden.fullmatch(path.name), path
        assert path.name not in ("Cargo.toml", "Cargo.lock", "Makefile", "CMakeLists.txt")
        assert path.suffix not in (".rs", ".c", ".h", ".a") or path.as_posix() in (
            "inputs/mods/s01/a/build.rs", "inputs/mods/s01/b/build.rs",
            "inputs/mods/s01/a/proc-macro.rs", "inputs/mods/s01/b/proc-macro.rs"), path
        if "link" in entry:
            target = Path(entry["link"])
            assert not target.is_absolute() and (root / path).resolve().is_relative_to(root), path


def provenance():
    return {key: os.environ[key] for key in ("CM_SOURCE_REPOSITORY", "CM_SOURCE_SHA", "GITHUB_REPOSITORY",
            "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "CM_REQUEST_ID")}


def hosted():
    from record_run import require_hosted_worker
    entry = require_hosted_worker()
    assert entry["runner_os"] == "Linux" and entry["target"] == TARGET


def relocate_profile_links(profile, original, copied):
    original = original.resolve(strict=True)
    copied = copied.resolve(strict=True)
    executable_sha256 = sha(original)
    if sha(copied) != executable_sha256:
        raise RuntimeError("Official fixture copy differs from its original executable")
    relocated = []
    for path in sorted(profile.rglob("*")):
        if not path.is_symlink():
            continue
        if path.resolve(strict=True) != original:
            raise RuntimeError("Unexpected official profile alias: " + str(path))
        previous = os.readlink(path)
        link = os.path.relpath(copied, path.parent)
        path.unlink()
        path.symlink_to(link)
        relocated.append({"path": path.relative_to(profile).as_posix(), "original_link": previous,
                          "link": link, "executable_sha256": executable_sha256})
    return relocated


def runtime_observer_source(composition):
    # The early check and handoff must use the same runtime-only module.
    return "import json\nimport re\nfrom pathlib import Path\n\n" + "\n\n".join(inspect.getsource(getattr(composition, name))
        for name in ("redact_syscalls", "complete_syscalls", "kernel_route_sockets", "provider_tcp_connections", "audit_network", "sandbox_path", "bound_sandbox_aliases", "bound_bwrap_executions", "audit_executions", "check_network_audit"))


def produce():
    import host
    import runtime_composition as composition
    from linux_ci import cargo_args, execute, load_config
    from worker_policy import archive_members

    hosted()
    root = Path(os.environ["CM_SOURCE_DIR"])
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    # Runs current-source P01, P02 and P03, retaining each report under its own name.
    composition.main()
    shutil.move(artifact / "acceptance.json", artifact / "p03-baseline-acceptance.json")
    for task in ("p01", "p02", "p03"):
        assert read(artifact / (task + "-baseline-acceptance.json"))["status"] == "pass"
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    inputs.mkdir(parents=True)
    package = Path(os.environ["RUNNER_TEMP"]) / "cm-host-package"
    frozen = read(artifact / "evidence/host-baseline-build.json")
    assert sha(package / "bin/codex") == frozen["executable_sha256"]
    shutil.copytree(package, inputs / "host", copy_function=os.link, symlinks=True)
    shutil.copytree(Path(read(logs / "mod-build.json")["payload"]).parent,
                    inputs / "mods/a", ignore=shutil.ignore_patterns("*.h"))
    cfg = load_config(root)
    unit = {"manifest": "fixtures/mods/output-limit/Cargo.toml", "lockfile": "fixtures/mods/output-limit/Cargo.lock",
            "packages": ["cm-output-limit-fixture"], "features": []}
    lock = sha(root / unit["lockfile"])
    authors = {"a": read(logs / "mod-build.json")}
    for variant in ("normal", "two-limiters", "init-fail", *ENTRY_INVALID, *CALL_INVALID,
                    *(("config",) if cfg["task_id"] in ("CM-M01", "CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03") else ())):
        target = Path(os.environ["CARGO_TARGET_DIR"]) / ("output-limit-" + variant)
        assert not target.exists(), "Independent author target must start empty"
        env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CM_LIMIT_VARIANT": variant}
        for phase in (("fmt", "clippy", "test", "build") if variant == "normal" else ("build",)):
            command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"] if phase == "fmt"
                       else cargo_args(unit, phase, cfg, cfg["build_profile"]))
            if phase == "clippy":
                command += ["--all-targets", "--", "-D", "warnings"]
            execute(root, logs, "output-limit-" + variant + "-" + phase, command, env)
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
            "--manifest-path", str(root / unit["manifest"])], env=env, text=True))
        dependencies = sorted(item["name"] for item in metadata["packages"])
        assert dependencies == ["cm-abi", "cm-output-limit-fixture"]
        assert not any(item["name"] == "cm-output-limit-fixture" for item in read(package / "dependency-inventory.json")["packages"])
        assert sha(root / unit["lockfile"]) == lock
        destination = inputs / "mods/b" / variant
        destination.mkdir(parents=True)
        shutil.copyfile(target / TARGET / cfg["build_profile"] / "libcm_output_limit_fixture.so", destination / "payload.so")
        identity = {"source_manifest": host.manifest(root, [root / unit["manifest"], root / unit["lockfile"],
            root / "fixtures/mods/output-limit/src/lib.rs", *list((root / "crates/cm-abi").rglob("*"))]),
            "variant": variant, "lock_sha256": lock, "dependencies": dependencies,
            "toolchain": frozen["host_identity"]["inputs"]["toolchain"], "flags": frozen["host_identity"]["inputs"]["flags"]}
        fields = {"format_version": 2, "id": "output-fixture", "version": "0.1.0", "payload": "payload.so",
            "payload_size": (destination / "payload.so").stat().st_size, "payload_sha256": sha(destination / "payload.so"),
            "target": TARGET, "abi_major": 2, "abi_minor": 1, "required_capabilities": [CAPABILITY], "dependencies": [],
            "contributions": [{"id": "limit", "capability": CAPABILITY, "resource": CAPABILITY, "kind": "output_limit"}]}
        if variant == "two-limiters":
            fields["contributions"].append({"id": "a-smaller", "capability": CAPABILITY, "resource": CAPABILITY, "kind": "output_limit"})
        composition.write_manifest(destination, fields)
        authors["b/" + variant] = {"mod_build_id": "sha256:" + digest(identity), "inputs": identity,
            "payload_sha256": sha(destination / "payload.so"), "initial_target_empty": True,
            "host_frozen_before_author_build": frozen["executable_sha256"]}
    native = Path(os.environ["RUNNER_TEMP"]) / "cm-p04-layout"
    execute(root, logs, "output-limit-c-layout-build", ["cc", "-std=c11", str(root / "fixtures/runtime-consumer/layout.c"), "-o", str(native)])
    execute(root, logs, "output-limit-c-layout", [str(native)])
    assert read(logs / "output-limit-c-layout.log")["v21_all_sizes_alignments_offsets"]
    assert "linux_x64_additive_layout ... ok" in host.build_log(logs, "host-test").read_text()
    for relative in ("fixtures/runtime-consumer/driver.py", "fixtures/native-loader/core_acceptance.py", "fixtures/native-loader/tool_barrier.py",
                     "ci/scripts/mod_manifest.py", "ci/scripts/cm_platforms.py", "ci/scripts/ci_progress.py"):
        destination = inputs / "fixture" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    metadata_audit = None
    binary_packages = None
    if cfg["task_id"] in ("CM-M01", "CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import mod_manifest
        legacy = read(artifact / "evidence/runtime-plan-determinism.json")["mods"]["a/normal"]
        composition.install(inputs, legacy, directory="m01-legacy-v2")
        authors["legacy-v2"] = legacy
        binary_packages = mod_manifest.prepare_binary_packages(inputs)
        try:
            mod_manifest.producer_audit(inputs, package, artifact / "evidence/m01-producer")
        finally:
            copy_evidence(artifact / "evidence/m01-producer", logs / "acceptance-evidence/m01-producer")
        metadata_audit = read(artifact / "evidence/m01-producer/metadata-source-attachments.json")
    (inputs / "observer.py").write_text(runtime_observer_source(composition), encoding="utf-8")
    shutil.copyfile(Path(__file__), inputs / "runtime_consumer.py")
    shutil.copyfile(root / "ci/scripts/ci_progress.py", inputs / "ci_progress.py")
    shutil.copyfile(root / "ci/scripts/cm_platforms.py", inputs / "cm_platforms.py")
    official_root = Path(os.environ["RUNNER_TEMP"]) / "cm-p04-official"
    official_root.mkdir()
    installation, official = host.official_fixture(root, official_root)
    profile = official_root / "profile"
    profile.mkdir()
    subprocess.run([str(official), "--version"], env={"PATH": "/usr/bin:/bin", "HOME": str(profile), "CODEX_HOME": str(profile)}, check=True)
    shutil.copytree(installation, inputs / "official/install", symlinks=True)
    shutil.copytree(profile, inputs / "official/profile", symlinks=True)
    original_profile = inventory(profile)
    # Startup aliases use current_exe; relocate only the fixture copy before freezing it.
    relocations = relocate_profile_links(inputs / "official/profile", official,
        inputs / "official/install" / official.relative_to(installation))
    assert inventory(profile) == original_profile
    official_setup = {"original_profile": original_profile, "relocations": relocations,
                      "prepared_profile": inventory(inputs / "official/profile")}
    write(logs / "official-profile-setup.json", official_setup)
    runtime_sdk = None
    if cfg["task_id"] in ("CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        from runtime_sdk import prepare
        runtime_sdk = prepare(inputs, package, authors)
    if cfg["task_id"] in ("CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import managed_package
        managed_package.prepare(inputs, package, frozen, logs)
    if cfg["task_id"] in ("CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_state
        runtime_state.prepare(inputs, package, frozen, logs, authors)
    m05 = None
    if cfg["task_id"] in ("CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import mod_author
        m05 = mod_author.prepare(inputs, package, frozen, logs)
    g02a = None
    if cfg["task_id"] in ("CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import turn_budget
        g02a = turn_budget.prepare(inputs, package, frozen, logs, authors, runtime_sdk)
    review = None
    if cfg["task_id"] in ("CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import review_before_send
        review = review_before_send.prepare(inputs, package, frozen, logs, authors, runtime_sdk)
    concurrency = None
    if cfg["task_id"] in ("CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import tool_concurrency
        concurrency = tool_concurrency.prepare(inputs, package, frozen, logs, authors, runtime_sdk)
    if cfg["task_id"] in ("CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_qualification
        runtime_qualification.prepare(inputs, frozen)
    hooks = None
    if cfg["task_id"] in ("CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_hooks
        hooks = runtime_hooks.prepare(inputs, frozen, logs, authors)
    upgrade = None
    from runtime_cases import historical_hosts
    if historical_hosts() and cfg["task_id"] in ("CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_upgrade
        upgrade = runtime_upgrade.prepare(inputs, frozen)
    seams = None
    if cfg["task_id"] in ("CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import sdk_seams
        seams = sdk_seams.prepare(root, inputs, package, frozen, logs, authors)
    distribution = None
    if cfg["task_id"] in ("CM-S01", "CM-S02", "CM-S03"):
        import distribution_provenance
        distribution = distribution_provenance.prepare(root, inputs, frozen, logs, authors)
    if cfg["task_id"] == "CM-S03":
        import binary_index
        binary_index.prepare_transport(inputs)
    write(inputs / "producer.json", {"schema_version": 1, "task_id": cfg["task_id"], "target": TARGET,
        "provenance": provenance(), "producer_job": os.environ["GITHUB_JOB"], "host": frozen, "authors": authors,
        "entry_invalid": ENTRY_INVALID, "call_invalid": CALL_INVALID,
        "regressions": {task: read(artifact / (task + "-baseline-acceptance.json")) for task in ("p01", "p02", "p03")},
        "maintained_source": read(logs / "host-source-provenance.json"), "official": host.manifest(inputs / "official"),
        "official_profile_setup": official_setup, "c_layout": read(logs / "output-limit-c-layout.log"),
        "metadata_source_attachment_audit": metadata_audit, "binary_packages": binary_packages,
        "runtime_sdk": runtime_sdk, "m05": m05, "g02a": g02a, "review": review, "concurrency": concurrency,
        "hooks": hooks, "upgrade": upgrade, "sdk_seams": seams, "distribution": distribution})
    entries = inventory(inputs)
    write(inputs / "input-manifest.json", {"files": entries, "sha256": digest(entries)})
    write(logs / "consumer-input-links.json", [entry for entry in entries if "link" in entry])
    transfer = Path(os.environ["CM_CONSUMER_TRANSFER_DIR"])
    transfer.mkdir()
    with tarfile.open(transfer / "runtime-inputs.tar", "w") as archive:
        archive.add(inputs, arcname="runtime-inputs")
    with tarfile.open(transfer / "runtime-inputs.tar", "r:") as archive:
        archive_members(archive.getmembers(), "runtime-inputs")
    assert host.manifest_digest(host.manifest(package)) == frozen["package_manifest_sha256"]
    write(artifact / "producer-inputs.json", {"status": "pass", "task_id": cfg["task_id"], "input_manifest_sha256": digest(entries),
        "provenance": provenance(), "consumer_acceptance": "not_run"})


def elf_dependencies(path):
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic != b"\x7fELF":
        return []
    header = subprocess.check_output(["readelf", "-l", "-d", str(path)], text=True)
    assert not re.search(r'\((?:RPATH|RUNPATH)\)', header), "Unregistered ELF search path: " + str(path)
    result = re.findall(r'Requesting program interpreter: ([^\]]+)', header)
    needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', header)
    cache = subprocess.check_output(["ldconfig", "-p"], text=True)
    for library in needed:
        matches = re.findall(r'^\s*' + re.escape(library) + r' .*' +
            re.escape(linux_native()["ldconfig_arch"]) + r'.* => (/\S+)$', cache, re.MULTILINE)
        assert matches, "Unresolved ELF dependency: " + library
        assert len({str(Path(name).resolve(strict=True)) for name in matches}) == 1, "Ambiguous ELF dependency: " + library
        result.append(matches[0])
    return result


def dpkg_owners(output, path):
    owners = set()
    for line in output.splitlines():
        names, separator, filename = line.partition(": ")
        candidates = names.split(", ")
        if separator and filename == str(path) and all(
            re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?", name) for name in candidates
        ):
            owners.update(candidates)
    return sorted(owners)


def system_package_owners(path):
    for candidate in dict.fromkeys((str(path), str(path.resolve()), str(path.resolve()).removeprefix("/usr"))):
        query = subprocess.run(["dpkg-query", "-S", candidate], capture_output=True, text=True,
                               env=os.environ | {"LC_ALL": "C.UTF-8", "LANGUAGE": "C"})
        if query.returncode == 0:
            owners = dpkg_owners(query.stdout, candidate)
            if owners:
                return owners
    raise RuntimeError("Unowned runtime input: " + str(path) + " -> " + str(path.resolve()))


def copy_runtime_tree(source, destination):
    # Managed package readers require independent, single-link regular files.
    shutil.copytree(source, destination, symlinks=True)
    for path in destination.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert path.stat().st_nlink == 1, "Hard-linked runtime input: " + str(path)


@ci_progress.case()
def rootfs(inputs, root, *, upgrade_baseline=True):
    root.mkdir()
    packages = {}
    copied = set()

    def system(name):
        path = Path(name)
        assert path.is_absolute() and path.is_file() and str(path).startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/bin/", "/bin/")), name
        destination = root / path.relative_to("/")
        if str(path) in copied:
            return
        copied.add(str(path))
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Dereference package-owned symlinks; no rootfs link can escape its root.
        shutil.copyfile(path, destination)
        destination.chmod(stat.S_IMODE(path.stat().st_mode))
        for owner in system_package_owners(path):
            packages[owner] = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", owner], text=True)
        for dependency in elf_dependencies(path):
            system(dependency)

    for name in ("python3.12", "bash", "env", "uname", "id", "tty", "stty", "getent", "ps", "readlink", "getconf"):
        path = shutil.which(name)
        assert path, "Required runtime helper missing: " + name
        system(str(Path(path)))
    for alias, target in (("/bin/sh", "/usr/bin/bash"), ("/bin/bash", "/usr/bin/bash"),
                          ("/usr/bin/python3", "/usr/bin/python3.12"), ("/bin/env", "/usr/bin/env")):
        destination = root / alias.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copyfile(root / target.lstrip("/"), destination)
            destination.chmod(0o755)
    stdlib = Path(sysconfig.get_path("stdlib"))
    assert str(stdlib) == "/usr/lib/python3.12", "Use the OS Python, not a hosted-toolcache distribution"
    excluded = {"test", "tests", "__pycache__", "ensurepip", "venv", "idlelib", "tkinter", "site-packages", "dist-packages"}
    for path in stdlib.rglob("*"):
        if not path.is_file() or excluded.intersection(path.relative_to(stdlib).parts) or "config-" in str(path):
            continue
        if path.suffix not in (".py", ".so"):
            continue
        destination = root / path.relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        destination.chmod(0o644)
        for dependency in elf_dependencies(path):
            system(dependency)
    for name in ("host", "mods", "official"):
        copy_runtime_tree(inputs / name, root / "inputs" / name)
    if (inputs / "distribution").is_dir():
        copy_runtime_tree(inputs / "distribution", root / "inputs/distribution")
    if upgrade_baseline and read(inputs / "producer.json").get("upgrade"):
        import runtime_upgrade
        runtime_upgrade.mount_reference(inputs, root, system)
    if (inputs / "probes").exists():
        copy_runtime_tree(inputs / "probes", root / "inputs/probes")
    shutil.copytree(inputs / "fixture", root / "fixture")
    import retry
    effective = retry.effective_producer(inputs)
    write(root / "inputs/producer.json", effective)
    for key, name in (("g02a", "g02a-producer.json"), ("review", "review-producer.json"),
                      ("concurrency", "concurrency-producer.json")):
        if key in effective:
            write(root / "fixture" / name, effective[key])
    for path in (root / "inputs").rglob("*"):
        if path.is_file():
            for dependency in elf_dependencies(path):
                system(dependency)
    for directory in ("proc", "dev", "tmp", "profile", "work", "evidence", "etc", "home/fixture"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "etc/passwd").write_text("fixture:x:1000:1000::/home/fixture:/bin/bash\n")
    (root / "etc/group").write_text("fixture:x:1000:\n")
    (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files\n")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n")
    entries = inventory(root)
    validate_runtime_inventory(root, entries)
    return {"files": entries, "sha256": digest(entries), "packages": packages, "system_paths": sorted(copied),
            "kind": "canonical runtime rootfs content, not an OCI digest"}


@ci_progress.case()
def copy_evidence(source, destination):
    import mod_manifest
    for path in source.rglob("*"):
        if not stat.S_ISREG(path.lstat().st_mode) or not (path.suffix in {".json", ".jsonl", ".log"} or path.name.startswith("syscalls.")):
            continue
        data = path.read_bytes()
        data.decode("utf-8")
        assert b"\0" not in data and len(data) <= 16 * 1024 * 1024, path
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(mod_manifest.redact(data.decode("utf-8")), encoding="utf-8")


def report_audit(audit, evidence):
    # Keep the complete per-case audit once, rather than embedding it in every report.
    return {**{key: value for key, value in audit.items() if key not in ("steps", "executions")},
        "step_count": len(audit["steps"]), "execution_count": len(audit["executions"]),
        "evidence": {"path": "outer-runtime-audit.json", "sha256": sha(evidence / "outer-runtime-audit.json")}}


def report_audit_self_check():
    with tempfile.TemporaryDirectory() as directory:
        evidence, exported = Path(directory) / "source", Path(directory) / "exported"
        for status in ("pass", "failed"):
            audit = {"status": status, "compiler_linker_jit_build_service_calls": 0 if status == "pass" else None,
                "steps": {"case": {"executions": ["trace" * 10000]}}, "executions": ["trace" * 10000]}
            write(evidence / "outer-runtime-audit.json", audit)
            summary = report_audit(audit, evidence)
            assert summary["status"] == status
            assert summary["compiler_linker_jit_build_service_calls"] == audit["compiler_linker_jit_build_service_calls"]
            assert summary["step_count"] == summary["execution_count"] == 1
            assert len(json.dumps(summary)) < 1024, "Report repeated the complete audit"
            copy_evidence(evidence, exported)
            assert sha(exported / summary["evidence"]["path"]) == summary["evidence"]["sha256"]


@ci_progress.case()
def check_evidence_redaction(paths):
    import mod_manifest
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert all(secret not in text for secret in mod_manifest.CANARIES), "Configuration value leaked into evidence"


def self_check():
    from unittest.mock import patch
    ci_progress.self_check()
    report_audit_self_check()
    for raises in (False, True):
        barrier = threading.Barrier(3)
        finished = []

        def simulated(logs, label, command, timeout):
            try:
                barrier.wait(timeout=5)
                if raises and label == "m01":
                    raise RuntimeError("matrix self-check")
                return types.SimpleNamespace(returncode=int(label == "m02"))
            finally:
                finished.append(label)

        with patch.object(ci_progress, "run", side_effect=simulated):
            try:
                results = parallel_matrices(None, [(label, [], 5) for label in ("p04", "m01", "m02")])
                assert not raises and results["m02"].returncode == 1
            except RuntimeError as error:
                assert raises and str(error) == "matrix self-check"
        assert set(finished) == {"p04", "m01", "m02"}, "Audit started before all matrices exited"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(__file__).resolve().parents[2]
        for relative in ("fixtures/runtime-consumer/driver.py", "fixtures/runtime-sdk/driver.py",
                         "fixtures/managed-package/driver.py"):
            subprocess.run([sys.executable, "-I", "-B", "-c",
                "import runpy,sys; runpy.run_path(sys.argv[1])", str(root / relative)], cwd=directory, check=True)
    import mod_manifest
    mod_manifest.self_check()
    with tempfile.TemporaryDirectory() as directory:
        evidence = Path(directory)
        nested = evidence / "missing-dependency-inventory.json"
        nested.mkdir()
        for name in ("report.json", "events.jsonl", "details.log"):
            path = nested / name
            path.write_text("safe evidence", encoding="utf-8")
            paths = [nested, path]
            check_evidence_redaction(paths)
            path.write_text(mod_manifest.CANARIES[0], encoding="utf-8")
            try:
                check_evidence_redaction(paths)
            except AssertionError as error:
                assert str(error) == "Configuration value leaked into evidence"
            else:
                raise AssertionError("Evidence canary was not detected")
            path.write_text("safe evidence", encoding="utf-8")
    import runtime_sdk
    runtime_sdk.self_check()
    import managed_package
    managed_package.self_check()
    import runtime_state
    runtime_state.self_check()
    import mod_author
    mod_author.self_check()
    import turn_budget
    turn_budget.self_check()
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        source = base / "source"
        source.mkdir()
        payload = source / "payload"
        payload.write_bytes(b"runtime input")
        payload.chmod(0o755)
        os.link(payload, source / "alias")
        (source / "relative-link").symlink_to("payload")
        copied, cloned = base / "rootfs", base / "missing-library-root"
        copy_runtime_tree(source, copied)
        copy_runtime_tree(copied, cloned)
        assert payload.stat().st_nlink == 2
        assert stat.S_IMODE((copied / "payload").stat().st_mode) == 0o755
        assert os.readlink(cloned / "relative-link") == "payload"
        (copied / "payload").write_bytes(b"changed")
        assert all(path.read_bytes() == b"runtime input" for path in
                   (payload, copied / "alias", cloned / "payload"))
    import runtime_composition as composition
    observer_text = runtime_observer_source(composition)
    observer = types.ModuleType("observer")
    exec(observer_text, observer.__dict__)
    unicode_host = "/work/m03/process/独立 Host/bin/codex"
    encoded = "".join("\\%03o" % byte if byte >= 128 else chr(byte) for byte in unicode_host.encode())
    sample = '1 execve("' + encoded + '", ["codex"], 0x1) = 0'
    assert trace_paths(sample) == '1 execve("' + unicode_host + '", ["codex"], 0x1) = 0'
    assert trace_paths("1 openat(3<" + encoded + ">, \"payload\", O_RDONLY) = -1") == \
        "1 openat(3<" + unicode_host + ">, \"payload\", O_RDONLY) = -1"
    for invalid in (r'1 execve("/work/\377/codex", [], 0x1) = 0',
                    r'1 execve("/work/\000/codex", [], 0x1) = 0',
                    r'1 execve("/work/\q/codex", [], 0x1) = 0'):
        try:
            trace_paths(invalid)
        except (AssertionError, UnicodeDecodeError):
            continue
        raise AssertionError("Invalid trace path encoding accepted")
    alias = "/profile/m03/用户 数据/tmp/arg0-linux/codex-arg0ABC/codex-linux-sandbox"
    creation = '1 symlink("' + unicode_host + '", "' + alias + '") = 0'
    assert observer.bound_sandbox_aliases([creation], (unicode_host,)) == {alias}
    assert not observer.bound_sandbox_aliases([creation], (unicode_host + "-other",))
    for invalid in (alias.replace("/profile/", "/profile-extra/"), alias.replace("/m03/", "/m03/../"),
                    alias.replace("/m03/", "/m03//")):
        assert not observer.sandbox_path(invalid, "codex-linux-sandbox")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        primary = root / "rootfs/inputs/host/bin/codex"
        primary.parent.mkdir(parents=True)
        build_id = "sha256:" + "a" * 64
        data = b"frozen Host " + build_id.encode()
        primary.write_bytes(data)
        write(root / "rootfs/inputs/producer.json", {"host": {
            "executable_sha256": sha(primary), "host_identity": {"host_build_id": build_id}}})
        copies = {
            "/inputs/host/bin/codex": data,
            "/work/m03/process/独立 Host/bin/codex": data,
            "/work/m01/lock/integrity/changed-host/codex": data + b"different executable identity",
            "/work/m01/lock/integrity/changed-host-build-id/codex": data.replace(build_id.encode(), b"sha256:" + b"0" * 64),
        }
        for name, content in copies.items():
            actual = root / ("rootfs" + name if name.startswith("/inputs/") else name.lstrip("/"))
            actual.parent.mkdir(parents=True, exist_ok=True)
            actual.write_bytes(content)
        calls = ['1 execve("' + name + '", ["codex"], 0x1) = 0' for name in copies]
        bound = bind_host_executables(calls, root)
        assert bound == {name: hashlib.sha256(content).hexdigest() for name, content in copies.items()}
        with patch.object(sys.modules[__name__], "sha", wraps=sha) as hashes:
            assert bind_host_executables(calls * 3, root) == bound
            assert hashes.call_count == len(copies) + 1, "Repeated executions rehashed identical final paths"
        legacy = "/inputs/host/g02a-legacy/codex"
        old = root / ("rootfs" + legacy)
        old.parent.mkdir(parents=True)
        old.write_bytes(b"previous qualified Host")
        metadata = read(root / "rootfs/inputs/producer.json")
        metadata["g02a"] = {"legacy_host": {"path": legacy, "host": {"executable_sha256": sha(old)}}}
        write(root / "rootfs/inputs/producer.json", metadata)
        legacy_call = '1 execve("' + legacy + '", ["' + legacy + '", "cm", "--home", "/profile/legacy", "install", "/inputs/mod.cmod"], 0x1) = 0'
        assert bind_host_executables([legacy_call], root) == {legacy: sha(old)}
        doctor_call = '1 execve("' + legacy + '", ["' + legacy + '", "cm", "--home", "/profile/g01/binding-other-host", "doctor"], 0x1) = 0'
        for invalid in (legacy_call.replace('"install"', '"launch"'),
                        legacy_call.replace(legacy, "/inputs/host/unbound/codex"), doctor_call):
            try:
                bind_host_executables([invalid], root)
            except AssertionError:
                pass
            else:
                raise AssertionError("Legacy reference escaped its byte/metadata binding")
        hook = "/inputs/probes/cm-hook-policy"
        hook_file = root / ("rootfs" + hook)
        hook_file.parent.mkdir(parents=True)
        hook_file.write_bytes(b"separate policy probe")
        metadata["hooks"] = {"probe": {"path": hook, "sha256": sha(hook_file), "separate_from_cli": True}}
        write(root / "rootfs/inputs/producer.json", metadata)
        assert bind_host_executables([doctor_call], root) == {legacy: sha(old)}
        hook_call = '1 execve("' + hook + '", ["' + hook + '", "/profile/g01/binding-drift"], 0x1) = 0'
        assert bind_hook_probes([hook_call], root) == [hook]
        for invalid in (hook_call.replace("binding-drift", "core-around"),
                        hook_call.replace('binding-drift"]', 'binding-drift", "extra"]')):
            try:
                bind_hook_probes([invalid], root)
            except AssertionError:
                pass
            else:
                raise AssertionError("Policy probe escaped its declared fixture invocation")
        hook_file.write_bytes(b"changed policy probe")
        try:
            bind_hook_probes([hook_call], root)
        except AssertionError:
            pass
        else:
            raise AssertionError("Policy probe byte drift accepted")
        for invalid in (doctor_call.replace("binding-other-host", "core-around"),
                        doctor_call.replace('"doctor"', '"launch"'),
                        doctor_call.replace('"doctor"]', '"doctor", "exec"]')):
            try:
                bind_host_executables([invalid], root)
            except AssertionError:
                pass
            else:
                raise AssertionError("G01 previous Host escaped its read-only binding check")
        del metadata["hooks"]
        write(root / "rootfs/inputs/producer.json", metadata)
        old.write_bytes(b"changed legacy Host")
        try:
            bind_host_executables([legacy_call], root)
        except AssertionError:
            pass
        else:
            raise AssertionError("Legacy Host byte drift accepted")
        trusted, evidence = root / "trusted", root / "evidence"
        trusted.mkdir()
        evidence.mkdir()
        (trusted / "syscalls.100").write_text("\n".join([
            *(line.split(" ", 1)[1] for line in calls), creation.split(" ", 1)[1],
            'openat(AT_FDCWD, "/inputs/host/codex-resources/bwrap", O_RDONLY|O_CLOEXEC) = 3</inputs/host/codex-resources/bwrap>',
            'execve("/proc/self/fd/3", ["bwrap", "--version"], 0x1) = 0',
            'execve("/inputs/host/codex-path/rg", ["rg"], 0x1) = 0']) + "\n")
        (trusted / "syscalls.101").write_text('openat(AT_FDCWD, "/inputs/host/bin/codex", O_RDONLY) = 4\n')
        (trusted / "syscalls.102").write_text("")
        with patch.dict(sys.modules, observer=observer):
            report = observe(trusted, evidence)
        assert report["status"] == "pass" and report["trace_files"] == ["syscalls.100", "syscalls.101", "syscalls.102"]
        assert (trusted / "syscalls.102").read_text() == ""
        assert report["bound_host_executables"] == bound and report["file_load_count"] == 2
        assert report["sandbox_aliases"] == [{"path": alias, "target": unicode_host}]
        tui = {"command": ["/inputs/host/bin/codex", "cm", "--home", "/profile/m03/terminal/tui", "launch", "--"],
            "tui": True, "empty_launch_argv": True,
            "identity": {"proc_exe": "/inputs/host/bin/codex", "executable_sha256": bound["/inputs/host/bin/codex"]},
            "provider_requests": [{"tools": [{"name": "mcp__codex_worktrees"}]}],
            "tui_mcp_listener": {"inode": "81", "port": 8080}}
        metadata = [
            '4 accept4(6<TCP:[81]>, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("127.0.0.1")}, [128 => 16], SOCK_CLOEXEC|SOCK_NONBLOCK) = 5<TCP:[71]>',
            '3 getsockname(6<TCP:[81]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, [128 => 16]) = 0']
        assert bind_tui_mcp_listener(tui, metadata, bound, observer) == {
            "port": "8080", "listener_inode": "81", "accepted_socket_inodes": ["71"]}
        m04_tui = tui | {"command": [*tui["command"][:3], "/profile/m04/terminal/tui", "launch", "--"]}
        assert bind_tui_mcp_listener(m04_tui, metadata, bound, observer) == bind_tui_mcp_listener(tui, metadata, bound, observer)
        for case in ("tui-slash", "tui-ui-owner", "legacy-abc"):
            sdk_tui = tui | {"command": [*tui["command"][:3], "/profile/g06/" + case + "/tui", "launch", "--"],
                "provider_requests": []}
            assert bind_tui_mcp_listener(sdk_tui, metadata, bound, observer) == bind_tui_mcp_listener(tui, metadata, bound, observer)
            for change in ({"provider_requests": tui["provider_requests"]},
                           {"command": [*sdk_tui["command"][:3], "/profile/g06/unbound/tui", "launch", "--"]},
                           {"identity": {**tui["identity"], "executable_sha256": "0" * 64}},
                           {"tui_mcp_listener": {"inode": "82", "port": 8080}},
                           {"tui_mcp_listener": {"inode": "81", "port": 8081}}):
                try:
                    bind_tui_mcp_listener(sdk_tui | change, metadata, bound, observer)
                except AssertionError:
                    continue
                raise AssertionError("Unbound notice-only TUI listener accepted: " + repr(change))
        image_tui = tui | {"command": [*tui["command"][:3], "/profile/review/entry-coverage/cli-image", "launch", "--",
            "--image", "/profile/review/entry-coverage/probe-0/review.png", "--", "CM_M02_cli-image"], "empty_launch_argv": False}
        assert bind_tui_mcp_listener(image_tui, metadata, bound, observer) == bind_tui_mcp_listener(tui, metadata, bound, observer)
        for change in ({"empty_launch_argv": True}, {"command": [*image_tui["command"][:-1], "other-prompt"]},
                       {"command": [*image_tui["command"][:7], "/profile/other.png", *image_tui["command"][8:]]}):
            try:
                bind_tui_mcp_listener(image_tui | change, metadata, bound, observer)
            except AssertionError:
                continue
            raise AssertionError("Unbound initial image arguments accepted: " + repr(change))
        for change in ({"tui": False}, {"empty_launch_argv": False},
                       {"command": [*tui["command"], "exec"]}, {"provider_requests": []},
                       {"command": [*tui["command"][:3], "/profile/m04/other", "launch", "--"]},
                       {"identity": {**tui["identity"], "proc_exe": "/work/other/codex"}},
                       {"identity": {**tui["identity"], "executable_sha256": "0" * 64}},
                       {"tui_mcp_listener": {"inode": "82", "port": 8080}},
                       {"tui_mcp_listener": {"inode": "81", "port": 8081}}):
            try:
                bind_tui_mcp_listener(tui | change, metadata, bound, observer)
            except AssertionError:
                continue
            raise AssertionError("Unbound TUI MCP listener accepted: " + repr(change))
        for invalid in (metadata[:1], metadata[1:], [line.replace('127.0.0.1', '198.51.100.1') for line in metadata]):
            try:
                bind_tui_mcp_listener(tui, invalid, bound, observer)
            except AssertionError:
                continue
            raise AssertionError("Unobserved TUI MCP listener accepted: " + repr(invalid))
        for name in ("/work/m03/process/独立 Host/bin/codex", "/work/m01/lock/integrity/changed-host/codex",
                     "/work/m01/lock/integrity/changed-host-build-id/codex", "/work/m01/lock/integrity/changed-host-extra/codex"):
            actual = root / name.lstrip("/")
            actual.parent.mkdir(parents=True, exist_ok=True)
            actual.write_bytes(b"unexpected executable")
            try:
                bind_host_executables(['1 execve("' + name + '", ["codex"], 0x1) = 0'], root)
            except AssertionError:
                pass
            else:
                raise AssertionError("Unpinned Host bytes accepted: " + name)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        probe = "/inputs/probes/cm-sdk-c-abi"
        actual = root / ("rootfs" + probe)
        actual.parent.mkdir(parents=True)
        actual.write_bytes(b"independent SDK ABI probe")
        producer = {"sdk_seams": {"c_probe_sha256": sha(actual),
            "private_core_probe": "/inputs/probes/cm-concurrency-core"}, "concurrency": {}}
        for key, name in (("probe", "cm-concurrency-core"), ("backend_probe", "cm-concurrency-backend")):
            binary = actual.with_name(name)
            binary.write_bytes(name.encode())
            producer["concurrency"][key] = {"path": "/inputs/probes/" + name,
                "sha256": sha(binary), "separate_from_cli": True, "names": ["existing_protocol"]}
        write(root / "rootfs/inputs/producer.json", producer)
        call = '1 execve("' + probe + '", ["' + probe + '", "/inputs/mods/g06/a/v1/payload.so", "valid"], 0x1) = 0'
        assert bind_sdk_probes([call], root) == [probe]
        for invalid in (call.replace('"valid"', '"unbound"'),
                        call.replace('/a/v1/', '/b/v1/'), call.replace('"valid"]', '"valid", "extra"]')):
            try:
                bind_sdk_probes([invalid], root)
            except AssertionError:
                continue
            raise AssertionError("SDK ABI probe escaped its exact invocation")
        core_call = '1 execve("/inputs/probes/cm-concurrency-core", ["/inputs/probes/cm-concurrency-core", "--ignored", "--exact", "thread_manager::tests::cm_sdk_seams_protocol", "--nocapture"], 0x1) = 0'
        assert bind_concurrency_probes([core_call], root) == [
            "/inputs/probes/cm-concurrency-core", "/inputs/probes/cm-concurrency-backend"]
        del producer["sdk_seams"]
        write(root / "rootfs/inputs/producer.json", producer)
        try:
            bind_concurrency_probes([core_call], root)
        except AssertionError:
            pass
        else:
            raise AssertionError("SDK Core probe accepted without SDK producer metadata")
        producer["sdk_seams"] = {"c_probe_sha256": "0" * 64}
        write(root / "rootfs/inputs/producer.json", producer)
        try:
            bind_sdk_probes([call], root)
        except AssertionError:
            pass
        else:
            raise AssertionError("SDK ABI probe byte drift accepted")
    observer.audit_network([
        '1 socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, [7<UNIX-STREAM:[161700->161701]>, 8<UNIX-STREAM:[161701->161700]>]) = 0'
    ], Path("/metadata"), ())
    for secret in mod_manifest.CANARIES:
        assert secret not in redact_trace('1 execve("/codex", ["--cm-set", "' + secret + '"], []) = 0\n', observer)
    assert {"host", "native_mod", "linux_ci"}.isdisjoint(observer.__dict__)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fixtures/native-loader"))
    from core_acceptance import Tools, await_barrier, cli_arguments, trace_rows
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fixtures/runtime-consumer"))
    from driver import check_mounts

    for sandboxed in (False, True):
        command = cli_arguments(Path("/host/codex"), Path("/work"), "http://127.0.0.1:8080", sandboxed=sandboxed)
        split = command.index("exec")
        assert "-c" not in command[split:]
        settings = [command[index + 1] for index in range(1, split) if command[index] == "-c"]
        assert 'model_provider="cm_fixture"' in settings
        assert 'model_providers.cm_fixture.base_url="http://127.0.0.1:8080/v1"' in settings
        assert ("--sandbox" in command) is sandboxed
        assert ('approval_policy="never"' in settings) is sandboxed
    print(json.dumps({"consumer_cli_overrides": "pass"}))

    prefix = "/home/runner/work/_temp/cm-runtime-consumer"
    binds = {point: prefix + "/" + name for point, name in
             (("/", "rootfs"), ("/profile", "profile"), ("/work", "work"), ("/evidence", "evidence"))}
    mounts = [f"1 0 259:1 {source} {point} {'ro' if point == '/' else 'rw'},nosuid - ext4 /dev/root rw"
              for point, source in binds.items()]
    mounts += [f"2 1 0:1 / {point} rw,nosuid - {kind} {kind} rw"
               for point, kind in (("/proc", "proc"), ("/dev", "tmpfs"), ("/tmp", "tmpfs"))]
    mounts += ["3 2 0:6 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw"]
    check_mounts(mounts, binds)
    escaped = {point: source.replace("/work/", "/work space/") for point, source in binds.items()}
    check_mounts([line.replace("/work/", r"/work\040space/") for line in mounts], escaped)
    for invalid in ([mounts[0].replace("ro,nosuid", "rw,nosuid"), *mounts[1:]],
                    [mounts[0], mounts[1].replace(binds["/profile"], "/home/runner"), *mounts[2:]],
                    [*mounts, "4 1 259:1 /home/runner /source ro - ext4 /dev/root rw"],
                    [*mounts, "4 1 0:6 /docker.sock /dev/docker.sock rw - devtmpfs devtmpfs rw"],
                    [*mounts, mounts[0]], mounts[1:],
                    [line.replace("/profile rw,", "/profile ro,") for line in mounts],
                    [line.replace("- tmpfs tmpfs", "- ext4 /dev/root") for line in mounts]):
        try:
            check_mounts(invalid, binds)
        except AssertionError:
            continue
        raise AssertionError("Unexpected runtime mount was accepted: " + repr(invalid))
    print(json.dumps({"consumer_mount_validation": "pass"}))

    loader = linux_native()["interpreter"]
    arch = linux_native()["dpkg_arch"]
    libc = "libc6:" + arch
    diversions = "diversion by libc6 from: " + loader + "\ndiversion by libc6 to: " + loader + ".usr-is-merged\n"
    assert dpkg_owners(diversions + libc + ": " + loader + "\n", loader) == [libc]
    assert dpkg_owners(libc + ", libc6-compat:" + arch + ": " + loader, loader) == ["libc6-compat:" + arch, libc]
    assert dpkg_owners("bash: /bin/bash\n", "/bin/bash") == ["bash"]
    for invalid in (diversions, "not a package: " + loader, "-invalid: " + loader,
                    libc + ": " + loader + ".other", ""):
        assert dpkg_owners(invalid, loader) == []
    actual_owners = system_package_owners(Path(loader))
    assert libc in actual_owners, actual_owners
    for owner in actual_owners:
        assert subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", owner], text=True).strip()
    print(json.dumps({"dpkg_query_loader_owners": actual_owners}))

    expected_env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "CM_ENV_SENTINEL": "retained"}
    cleaned_env = json.loads(subprocess.check_output([*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B", "-c",
        "import json, os; print(json.dumps(dict(os.environ)))"], env={**expected_env, "PWD": "/must-not-pass"}, text=True))
    assert cleaned_env == expected_env, sorted(cleaned_env)
    print(json.dumps({"consumer_pwd_cleanup": "pass"}))

    observer.check_network_audit()
    write(Path(os.environ["CM_CI_LOG_DIR"]) / "consumer-observer-self-check.json",
          {"status": "pass", "source_sha256": hashlib.sha256(observer_text.encode()).hexdigest(),
           "module": "same runtime-only source as consumer handoff"})
    helper = read(Path(os.environ["CM_CI_LOG_DIR"]) / "host-helper.json")
    binary = Path(os.environ["CARGO_TARGET_DIR"]) / "helper" / TARGET / helper["profile"] / "bwrap"
    assert sha(binary) == helper["sha256"]
    with tempfile.TemporaryDirectory() as directory:
        trace = Path(directory) / "helper-syscalls.log"
        result = subprocess.run(["strace", "-f", "-qq", "-yy", "-s", "1024", "-e",
            "trace=socket,getsockname,accept,accept4,connect,sendto,recvfrom,execve,open,openat,openat2,close,close_range,dup,dup2,dup3,fcntl",
            "-o", str(trace), "--", "/usr/bin/python3", "-B", "-c",
            "import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_CLOEXEC); os.execv('/proc/self/fd/'+str(fd), ['bwrap', *sys.argv[2:]])",
            str(binary), "--unshare-user", "--unshare-net", "--cap-drop", "ALL",
            "--ro-bind", "/", "/", "--clearenv", "--", "/usr/bin/python3", "-B", "-c",
            "import socket,json; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); port=s.getsockname()[1]; "
            "c=socket.socket(); c.connect(('127.0.0.1',port)); p,_=s.accept(); c.sendall(b'ping'); "
            "assert p.recv(4)==b'ping'; p.sendall(b'pong'); assert c.recv(4)==b'pong'; "
            "p.close(); c.close(); s.close(); print(json.dumps({'port':port}))"],
            check=True, stdout=subprocess.PIPE, text=True, close_fds=True, timeout=30)
        sanitized = observer.redact_syscalls(trace.read_text())
        (Path(os.environ["CM_CI_LOG_DIR"]) / "consumer-helper-syscalls.log").write_text(sanitized, encoding="utf-8")
        calls = observer.complete_syscalls(sanitized.splitlines())
        routes = observer.kernel_route_sockets(calls)
        packets = [line for line in calls if re.match(r'\d+\s+sendto\(', line)]
        assert routes and packets, "Actual sandbox loopback setup was not observed"
        ports = {str(json.loads(result.stdout)["port"])}
        connections = observer.provider_tcp_connections(calls, ports)
        assert connections, "Actual provider listener/accept inode binding was not observed"
        network = [line for line in calls if re.match(r'\d+\s+(?:connect|sendto)\(', line)]
        observer.audit_network(network, Path(directory), ports, routes, connections)
        fd_executions = observer.bound_bwrap_executions(calls, str(binary))
        assert len(fd_executions) == 1, "Actual packaged helper FD launch was not observed"
        observer.audit_executions(fd_executions, bwrap_executions=fd_executions)
        print(json.dumps({"actual_helper_fd_execution": "pass"}))
        print(json.dumps({"actual_helper_kernel_route_audit": "pass", "socket_count": len(routes), "packet_count": len(packets)}))
        print(json.dumps({"actual_provider_tcp_inode_audit": "pass", "connection_count": len(connections)}))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        tools = Tools(root / "tool-barriers")
        command = [str(binary), "--unshare-user", "--unshare-net", "--cap-drop", "ALL", "--ro-bind", "/", "/",
            "--bind", str(root), str(root), "--chdir", str(root), "--clearenv", "--", "/usr/bin/python3", "-B",
            str(Path(__file__).resolve().parents[2] / "fixtures/native-loader/tool_barrier.py"), str(tools.path)]
        processes = {}
        try:
            for label in ("A", "B"):
                processes[label] = subprocess.Popen([*command, label], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, close_fds=True)
            for label, process in processes.items():
                await_barrier(lambda label=label: tools.has(label + ":entered"), process, label)
                assert not (tools.path / (label + ".exiting")).exists()
            for label in ("B", "A"):
                tools.release(label)
                stdout, stderr = processes[label].communicate(timeout=10)
                assert processes[label].returncode == 0 and "cm-real-tool-" + label + "-ok" in stdout, stderr
            assert tools.error is None
            (tools.path / "invalid").touch()
            with tools.condition:
                assert tools.condition.wait_for(lambda: tools.error is not None, timeout=2)
            print(json.dumps({"actual_helper_file_barriers": "pass"}))
        finally:
            for process in processes.values():
                if process.poll() is None:
                    process.kill()
                    process.wait()
            tools.close()
    for source in ('1 recvfrom(4<UNIX-STREAM:[1->2]>, "observer-secret", 15, 0, NULL, NULL) = 15',
                   '1 <... recvfrom resumed>"observer-secret", 15, 0, NULL, NULL) = 15'):
        sanitized = observer.redact_syscalls(source)
        assert "observer-secret" not in sanitized and "payload redacted" in sanitized
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "result.json").write_text('{"status":"pass"}\n')
        (evidence / "syscalls.123").write_text("redacted syscall\n")
        (evidence / "syscalls.directory.0.123").write_text(mod_manifest.CANARIES[0] + "\n")
        (evidence / "payload.so").write_bytes(b"\x7fELF\0")
        (evidence / "linked.json").symlink_to(evidence / "result.json")
        os.mkfifo(evidence / "pipe.log")
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(evidence / "tools.log"))
            copy_evidence(evidence, root / "copied")
        assert sorted(path.name for path in (root / "copied").iterdir()) == ["result.json", "syscalls.123", "syscalls.directory.0.123"]
        assert (root / "copied/syscalls.directory.0.123").read_text() == "<configuration redacted>\n"
        for invalid in (b"\xff", b"text\0"):
            (evidence / "invalid.log").write_bytes(invalid)
            try:
                copy_evidence(evidence, root / "invalid-copy")
            except (AssertionError, UnicodeError):
                continue
            raise AssertionError("Non-text evidence accepted")
        (evidence / "invalid.log").unlink()
        print(json.dumps({"consumer_text_evidence": "pass"}))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        trace = root / "trace.jsonl"
        row = {"event": "ready", "detail": {"text": "\u00e9"}}
        record = json.dumps(row, ensure_ascii=False).encode() + b"\n"
        assert trace_rows(trace, waiting=True) == []
        for boundary in range(len(record)):
            trace.write_bytes(record[:boundary])
            assert trace_rows(trace, waiting=True) == []
        trace.write_bytes(record)
        assert trace_rows(trace) == [row]
        trace.write_bytes(record + record[:-1])
        assert trace_rows(trace, waiting=True) == [row]
        trace.write_bytes(record + record)
        assert trace_rows(trace) == [row, row]
        for data, waiting in ((record[:-1], False), (b'{"event":}\n', False),
                              (b'{"event":}\n', True), (b'{"event":"\xff"}\n', True)):
            trace.write_bytes(data)
            try:
                trace_rows(trace, waiting=waiting)
            except ValueError:
                continue
            raise AssertionError("Malformed or truncated trace record was accepted")
        trace.unlink()
        payload = root / "cli"
        payload.write_bytes(b"frozen")
        payload.chmod(0o755)
        entries = inventory(root)
        write(root / "input-manifest.json", {"files": entries, "sha256": digest(entries)})
        assert validate_inputs(root)["files"] == entries
        validate_runtime_inventory(root, [{"path": "usr/lib/python3.12/pipes.py", "mode": 0o644}])
        for mutation in (lambda: payload.write_bytes(b"changed"), lambda: payload.chmod(0o644)):
            payload.write_bytes(b"frozen")
            payload.chmod(0o755)
            mutation()
            try:
                validate_inputs(root)
            except AssertionError:
                continue
            raise AssertionError("Changed runtime input was accepted")
        for path in ("usr/bin/cargo", "usr/bin/ld", "inputs/source/lib.rs", "inputs/Cargo.lock"):
            try:
                validate_runtime_inventory(root, [{"path": path, "mode": 0o755}])
            except AssertionError:
                continue
            raise AssertionError("Build material accepted in runtime root: " + path)
        (root / "escape").symlink_to("../outside")
        try:
            validate_runtime_inventory(root, [{"path": "escape", "link": "../outside"}])
        except AssertionError:
            pass
        else:
            raise AssertionError("Escaping runtime link was accepted")
        original_profile = root / "official-profile"
        original_profile.mkdir()
        (original_profile / "apply_patch").symlink_to(payload.resolve())
        copied = root / "official-install/codex"
        copied.parent.mkdir()
        shutil.copyfile(payload, copied)
        prepared = root / "prepared-profile"
        shutil.copytree(original_profile, prepared, symlinks=True)
        relocated = relocate_profile_links(prepared, payload, copied)
        assert len(relocated) == 1 and not Path(relocated[0]["link"]).is_absolute()
        assert (prepared / "apply_patch").resolve(strict=True) == copied.resolve()
        assert os.readlink(original_profile / "apply_patch") == str(payload.resolve())
        unexpected = root / "unexpected-official-target"
        unexpected.write_bytes(payload.read_bytes())
        invalid_profile = root / "invalid-profile"
        invalid_profile.mkdir()
        (invalid_profile / "apply_patch").symlink_to(unexpected)
        try:
            relocate_profile_links(invalid_profile, payload, copied)
        except RuntimeError as error:
            assert "Unexpected official profile alias" in str(error)
        else:
            raise AssertionError("Unknown official alias target was accepted")
        copied.write_bytes(b"changed")
        try:
            relocate_profile_links(prepared, payload, copied)
        except RuntimeError as error:
            assert "Official fixture copy differs" in str(error)
        else:
            raise AssertionError("Changed official executable copy was accepted")


def trace_paths(text):
    def decode(value):
        result = bytearray()
        position = 0
        while position < len(value):
            if value[position] != "\\":
                result.extend(value[position].encode("utf-8"))
                position += 1
            elif value[position + 1:position + 2] in ('"', "\\"):
                result.extend(value[position + 1].encode())
                position += 2
            else:
                octal = value[position + 1:position + 4]
                assert len(octal) == 3 and all(c in "01234567" for c in octal), "Unknown trace path escape"
                number = int(octal, 8)
                assert number <= 255
                result.append(number)
                position += 4
        path = result.decode("utf-8", errors="strict")
        assert len(result) <= 4096 and not any(ord(c) < 32 for c in path), "Invalid trace path"
        return path

    text = re.sub(r'"(/(?:[^"\\]|\\.)*)"', lambda match: json.dumps(decode(match[1]), ensure_ascii=False), text)
    return re.sub(r'<(/[^>\n]*)>', lambda match: "<" + decode(match[1]) + ">", text)


def redact_trace(text, observer):
    import mod_manifest
    return trace_paths(mod_manifest.redact(observer.redact_syscalls(text)))


def bind_host_executables(executions, root):
    primary = root / "rootfs/inputs/host/bin/codex"
    expected = sha(primary)
    producer = read(root / "rootfs/inputs/producer.json")
    host = producer["host"]
    assert expected == host["executable_sha256"], "Frozen Host differs from the producer"
    before = host["host_identity"]["host_build_id"].encode()
    data = primary.read_bytes()
    assert re.fullmatch(rb"sha256:[0-9a-f]{64}", before) and before in data
    after = b"sha256:" + (b"0" if before != b"sha256:" + b"0" * 64 else b"1") * 64
    # The M01 rejection matrix executes exactly these two deterministic mutations.
    rejected = {
        "/work/m01/lock/integrity/changed-host/codex": hashlib.sha256(data + b"different executable identity").hexdigest(),
        "/work/m01/lock/integrity/changed-host-build-id/codex": hashlib.sha256(data.replace(before, after)).hexdigest(),
    }
    if producer.get("g02a"):
        legacy = producer["g02a"]["legacy_host"]
        assert legacy["path"] == "/inputs/host/g02a-legacy/codex"
        rejected[legacy["path"]] = legacy["host"]["executable_sha256"]
    if producer.get("review"):
        rejected["/inputs/host/review-legacy/codex"] = producer["review"]["reference"]["host"]["executable_sha256"]
    if producer.get("upgrade"):
        rejected["/inputs/upgrade-baseline/host/bin/codex"] = producer["upgrade"]["baseline"]["pin"]["executable_sha256"]
    del data
    bound = {}
    for line in executions:
        match = re.search(r'execve\("([^"]+)"', line)
        if not match or Path(match[1]).name != "codex":
            continue
        path = Path(match[1])
        if str(path) in ("/inputs/host/g02a-legacy/codex", "/inputs/host/review-legacy/codex"):
            install = re.search(r', \["[^"]+", "cm", "--home", "[^"]+", "install"(?:,|\])', line)
            hook_binding = (producer.get("hooks") and str(path) == "/inputs/host/g02a-legacy/codex"
                and re.search(r', \["[^"]+", "cm", "--home", "/profile/g01/binding-other-host", "doctor"\]', line))
            assert install or hook_binding, "Legacy Host is metadata-only"
        if str(path) in bound:
            continue
        if path.is_relative_to("/inputs/host") or str(path) == "/inputs/upgrade-baseline/host/bin/codex":
            actual = root / "rootfs" / path.relative_to("/")
        elif path.is_relative_to("/work") or path.is_relative_to("/profile"):
            actual = root / path.relative_to("/")
        else:
            raise AssertionError("Unbound Host executable: " + str(path))
        wanted = rejected.get(str(path), expected)
        assert ".." not in path.parts and actual.is_file() and sha(actual) == wanted, "Host bytes differ: " + str(path)
        bound[str(path)] = wanted
    return bound


def bind_benchmark_tui_pid(record, own, calls):
    edges, identities, executions = {}, {}, {}
    for line in calls:
        pid = line.split()[0]
        child = re.search(r'\b(?:clone3?|fork|vfork)\(.*\)\s+=\s+(\d+)(?: /\* (\d+) in strace\x27s PID NS \*/)?$', line)
        if child and int(child[1]) > 0:
            outer = child[2] or child[1]
            assert outer not in edges, "Ambiguous benchmark process lineage"
            edges[outer] = (pid, child[1], "CLONE_THREAD" in line)
        identity = re.search(r'\bgetpid\(\)\s+=\s+(\d+)(?: /\* \d+ in strace\x27s PID NS \*/)?$', line)
        if identity:
            identities[pid] = identity[1]
        execution = re.search(r'execve\("([^"]+)", (\[.*?\]), .*\)\s+=\s+0$', line)
        if execution:
            executions.setdefault(pid, []).append((execution[1], json.loads(execution[2])))

    def process(pid):
        seen = set()
        while pid in edges and edges[pid][2]:
            assert pid not in seen, "Cyclic benchmark thread lineage"
            seen.add(pid)
            pid = edges[pid][0]
        return pid

    launch = (record["command"][0], record["command"])
    reentry = (record["command"][0], [record["command"][0], *record["command"][6:]])
    # cm launch re-enters the same sealed executable without replacing its PID.
    hosts = [pid for pid, chain in executions.items() if chain in ([launch], [launch, reentry])]
    owned = {process(line.split()[0]) for line in own}
    assert len(owned) == 1 and owned <= set(hosts), "TUI listener is not owned by the observed Host process"
    host = next(iter(owned))
    inner = {value for pid, value in identities.items() if process(pid) == host}
    if host in edges:
        inner.add(edges[host][1])
    assert inner == {str(record["identity"]["pid"])}, "Benchmark TUI PID differs from the outer trace"
    return {"outer_host_pid": host, "inner_host_pid": next(iter(inner))}


def benchmark_tui_binding_self_check():
    command = ["/inputs/host/bin/codex", "cm", "--home", "/profile/s04/block-1", "launch", "--"]
    record = {"command": command, "identity": {"pid": 7}}
    calls = ['10 clone(child_stack=NULL, flags=SIGCHLD) = 7 /* 20 in strace\'s PID NS */',
        '20 execve("' + command[0] + '", ' + json.dumps(command) + ', 0x1) = 0',
        '20 clone3({flags=CLONE_VM|CLONE_THREAD}, 88) = 8 /* 21 in strace\'s PID NS */', '21 getpid() = 7']
    own = ['21 getsockname(3<TCP:[123]>, {}) = 0']
    assert bind_benchmark_tui_pid(record, own, calls)["inner_host_pid"] == "7"
    reentry = calls + ['20 execve("' + command[0] + '", ' + json.dumps([command[0]]) + ', 0x1) = 0']
    assert bind_benchmark_tui_pid(record, own, reentry)["outer_host_pid"] == "20"
    forwarded = [*command, "--tool-concurrency", "2"]
    concurrent = [line.replace(json.dumps(command), json.dumps(forwarded)) for line in reentry]
    concurrent[-1] = concurrent[-1].replace(json.dumps([command[0]]), json.dumps([command[0], *forwarded[6:]]))
    assert bind_benchmark_tui_pid({**record, "command": forwarded}, own, concurrent)["outer_host_pid"] == "20"
    for invalid_record, invalid_own, invalid_calls in (
        ({**record, "identity": {"pid": 9}}, own, calls),
        (record, [own[0].replace("21 ", "22 ")], calls),
        (record, own, [line.replace("block-1", "block-1-lookalike") for line in calls]),
        (record, own, [line.replace("/inputs/host/bin/codex", "/work/codex") for line in calls]),
        (record, own, [*reentry[:-1], reentry[-1].replace('execve("' + command[0] + '"', 'execve("/work/codex"')]),
        ({**record, "command": forwarded}, own, [*concurrent[:-1], concurrent[-1].replace('"2"', '"3"')]),
        (record, own, [*reentry[:-1], reentry[-1].replace(json.dumps([command[0]]), json.dumps([command[0], "--unexpected"]))])):
        try:
            bind_benchmark_tui_pid(invalid_record, invalid_own, invalid_calls)
        except AssertionError:
            pass
        else:
            raise AssertionError("Benchmark TUI binding accepted an unrelated process")


def bind_tui_mcp_listener(record, metadata, bound_hosts, observer, *, process_calls=()):
    command = record["command"]
    assert len(command) >= 6 and command[0] in bound_hosts and command[1:3] == ["cm", "--home"]
    upgrade = re.fullmatch(r"/profile/g05/reuse-(?:b|ab)-(h[01])/(old|candidate)", command[3])
    if upgrade:
        expected_host, expected_home = (("/inputs/upgrade-baseline/host/bin/codex", "old")
            if upgrade[1] == "h0" else ("/inputs/host/bin/codex", "candidate"))
        assert command[0] == expected_host and upgrade[2] == expected_home
    else:
        assert command[0] == "/inputs/host/bin/codex"
    initial_image = command[3] == "/profile/review/entry-coverage/cli-image"
    concurrency = command[3] == "/profile/concurrency/value-flow/tui"
    benchmark = re.fullmatch(r"/profile/s04/block-[123]", command[3])
    benchmark_concurrency = benchmark and command[4:] == ["launch", "--", "--tool-concurrency", "2"]
    sdk_notice = re.fullmatch(r"/profile/g06/(?:tui-slash|tui-ui-owner|legacy-abc)/tui", command[3])
    expected = (["launch", "--", "--tool-concurrency", "2"] if concurrency or benchmark_concurrency else
        ["launch", "--", "--image", "/profile/review/entry-coverage/probe-0/review.png", "--", "CM_M02_cli-image"]
        if initial_image else ["launch", "--"])
    assert command[4:] == expected
    assert upgrade or concurrency or sdk_notice or benchmark or command[3] in (
        "/profile/m03/terminal/tui", "/profile/m04/terminal/tui", "/profile/s02/abc") or re.fullmatch(
        r"/profile/review/(?:nondestructive|invalidation|key-events|entry-coverage|queue-lifecycle|plug-and-play)/[a-z0-9-]+", command[3]), "Unregistered TUI MCP profile: " + command[3]
    assert record["tui"] and record["empty_launch_argv"] is (not (initial_image or concurrency or benchmark_concurrency))
    assert record["identity"]["proc_exe"] == command[0]
    assert record["identity"]["executable_sha256"] == bound_hosts[command[0]]
    if sdk_notice:
        assert not record["provider_requests"], "SDK notice unexpectedly sent a model turn"
    else:
        assert any(item.get("name") == "mcp__codex_worktrees" for request in record["provider_requests"] for item in request["tools"])
    listener = record["tui_mcp_listener"]
    inode, port = listener["inode"], str(listener["port"])
    assert re.fullmatch(r"[1-9][0-9]*", inode) and 0 < int(port) < 65536
    # Bind the live TUI's /proc fd ownership to the outer kernel trace, not an arbitrary loopback port.
    own = [line for line in metadata if "<TCP:[" + inode + "]>" in line]
    assert any(re.fullmatch(r'\d+\s+getsockname\(\d+<TCP:\[' + inode +
        r'\]>, \{sa_family=AF_INET, sin_port=htons\(' + port +
        r'\), sin_addr=inet_addr\("127\.0\.0\.1"\)\}, \[\d+(?: => \d+)?\]\) = 0', line) for line in own)
    connections = observer.provider_tcp_connections(own, {port})
    assert connections, "TUI MCP listener has no matching successful loopback accept"
    binding = bind_benchmark_tui_pid(record, own, process_calls) if benchmark else {}
    return {"port": port, "listener_inode": inode, "accepted_socket_inodes": sorted(connections), **binding}


@ci_progress.case()
def check_distribution_verifier_binding(source):
    import distribution_provenance
    policy_path = distribution_provenance.POLICY_PATH
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary) / "rootfs"
        paths = ("fixture/s01-producer.json", "fixture/" + policy_path,
            "fixture/s01-bootstrap/identity.json", "inputs/host/cm-host.json")
        policy = read(source / policy_path)
        helper = b"audit parser fixture, not a cryptographic verifier"
        identity = hashlib.sha256(helper).hexdigest()
        values = ({}, policy, {"binary_sha256": identity},
            {"inputs": {"native": {"distribution_verifier": {"sha256": identity}}}})
        for path, value in zip(paths, values):
            write(root / path, value)
        for path in ("fixture/s01-bootstrap/gh", "inputs/host/codex-resources/gh"):
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_bytes(helper)
        arguments = ["/proc/2/fd/5", "attestation", "verify", "/proc/2/fd/6", "--bundle", "/proc/2/fd/10/bundle.jsonl",
            "--custom-trusted-root", "/proc/2/fd/9", "--repo", policy["builder_repository"],
            "--cert-identity", "https://github.com/" + policy["builder_repository"] + "/" + policy["workflow"] + "@" + policy["ref"],
            "--cert-oidc-issuer", policy["issuer"], "--source-ref", policy["ref"],
            "--source-digest", "a" * 40, "--signer-digest", "a" * 40, "--deny-self-hosted-runners", "--format", "json"]
        calls = ['10 getpid() = 2',
            '10 memfd_create("cm-distribution-verifier", MFD_CLOEXEC|MFD_ALLOW_SEALING) = 4',
            '10 fcntl(4, F_ADD_SEALS, F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE) = 0',
            '10 openat(AT_FDCWD, "/proc/self/fd/4", O_RDONLY|O_CLOEXEC) = 5</memfd:cm-distribution-verifier (deleted)>',
            '10 memfd_create("cm-distribution-bundle", MFD_CLOEXEC|MFD_ALLOW_SEALING) = 7',
            '10 fcntl(7, F_ADD_SEALS, F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE) = 0',
            '10 openat(AT_FDCWD, "/proc/self/fd/7", O_RDONLY|O_CLOEXEC) = 8</memfd:cm-distribution-bundle (deleted)>',
            '10 symlink("/proc/2/fd/8", "/proc/2/fd/10/bundle.jsonl") = 0']
        execution = '11 execve("/proc/2/fd/5", ' + json.dumps(arguments) + ', 0x1) = 0'
        assert bind_distribution_verifiers([*calls, execution], Path(temporary)) == {execution}
        actual = [line.replace('getpid() =', 'getpid()                                =')
            .replace('fcntl(4,', 'fcntl(4</memfd:cm-distribution-verifier>(deleted),')
            .replace('fcntl(7,', 'fcntl(7</memfd:cm-distribution-bundle>(deleted),')
            .replace(' (deleted)>', '>(deleted)') for line in calls]
        assert bind_distribution_verifiers([*actual, execution], Path(temporary)) == {execution}
        lineage = ['11 clone3({flags=CLONE_VM|CLONE_THREAD}, 88) = 12',
            '12 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 13']
        missing = '13 execve("/memfd:cm-distribution-verifier", ["/memfd:cm-distribution-verifier", "send-telemetry"], 0x1) = -1 ENOENT (No such file or directory)'
        assert bind_distribution_verifiers([*calls, execution, *lineage, missing], Path(temporary)) == {execution, missing}
        assert not bind_distribution_verifiers([*calls, *lineage, missing], Path(temporary))
        for invalid in (missing.replace('13 execve', '14 execve'),
            missing.replace('"send-telemetry"', '"attestation"'),
            missing.replace(' = -1 ENOENT (No such file or directory)', ' = 0'),
            missing.replace('ENOENT (No such file or directory)', 'EACCES (Permission denied)'),
            missing.replace('/memfd:cm-distribution-verifier', '/work/cm-distribution-verifier')):
            assert bind_distribution_verifiers([*calls, execution, *lineage, invalid], Path(temporary)) == {execution}
        for invalid in ([*calls[:2], calls[3], execution], [*calls, execution.replace('"--repo"', '"--unknown"')],
            [*calls, execution.replace(policy["workflow"], ".github/workflows/other.yml")],
            [*calls, execution.replace(policy["ref"], "refs/heads/other")],
            [*calls, execution.replace(policy["issuer"], "https://issuer.invalid")],
            [*calls, execution.replace('"--deny-self-hosted-runners", ', "")],
            [*calls, execution.replace('"--cert-identity"', '"--signer-workflow"')],
            [*calls, execution.replace('"/proc/2/fd/10/bundle.jsonl"', '"/work/unbound-bundle"')],
            [*calls[:5], *calls[6:], execution],
            [*calls[:-1], calls[-1].replace('/proc/2/fd/8', '/proc/2/fd/9'), execution],
            [*calls[:-1], calls[-1].replace('/proc/2/fd/8', '/proc/3/fd/8'), execution]):
            try:
                bind_distribution_verifiers(invalid, Path(temporary))
            except AssertionError:
                pass
            else:
                raise AssertionError("Unbound verifier execution escaped the outer audit")
        route = '10 sendto(5<NETLINK:[25061]>, "<payload redacted>", 40, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 40'
        audited = {"status": "pass", "distribution_verifier_executions": [execution],
            "network": [route], "kernel_route_sockets": [("10", "5", "NETLINK:[25061]")]}
        audit_offline_bootstrap(audited)
        audit_offline_bootstrap(audited | {"network": []})
        for invalid in (audited | {"distribution_verifier_executions": []},
            audited | {"network": [route.replace("25061", "25062")]},
            audited | {"network": [route.replace("10 sendto", "11 sendto")]},
            audited | {"network": ['10 connect(5<TCP:[25061]>, {sa_family=AF_INET}, 16) = 0']},
            audited | {"network": ['10 socketpair(AF_UNIX, SOCK_STREAM, 0, [5, 6]) = 0']}):
            try:
                audit_offline_bootstrap(invalid)
            except AssertionError:
                pass
            else:
                raise AssertionError("Unexpected offline bootstrap network accepted")


def bind_distribution_verifiers(calls, consumer_root):
    """Attribute only pinned gh attestation verification, including sealed Host snapshots."""
    root = consumer_root / "rootfs"
    if not (root / "fixture/s01-producer.json").is_file():
        return set()
    import distribution_provenance
    policy = read(root / "fixture" / distribution_provenance.POLICY_PATH)
    bootstrap = read(root / "fixture/s01-bootstrap/identity.json")
    helper = root / "inputs/host/codex-resources/gh"
    identity = read(root / "inputs/host/cm-host.json")
    expected = identity["inputs"]["native"]["distribution_verifier"]["sha256"]
    assert sha(helper) == expected == bootstrap["binary_sha256"]
    assert sha(root / "fixture/s01-bootstrap/gh") == expected
    inner, created, sealed, readonly = {}, {}, set(), {}
    for line in calls:
        pid = line.split(None, 1)[0]
        own = re.search(r'getpid\(\)\s+=\s+(\d+)', line)
        if own:
            inner[pid] = own[1]
        allocation = re.search(r'memfd_create\("cm-distribution-(verifier|bundle)", MFD_CLOEXEC\|MFD_ALLOW_SEALING\) = (\d+)', line)
        if allocation:
            created[pid, allocation[2]] = allocation[1]
        seal = re.search(r'fcntl\((\d+)(?:<[^>]+>(?:\(deleted\))?)?, F_ADD_SEALS, ([A-Z_|]+)\) = 0', line)
        if seal and (pid, seal[1]) in created:
            assert set(seal[2].split("|")) == {"F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"}
            sealed.add((pid, seal[1]))
        opened = re.search(r'openat\(AT_FDCWD(?:<[^>]*>)?, "/proc/self/fd/(\d+)", O_RDONLY\|O_CLOEXEC\) = (\d+)</memfd:cm-distribution-(verifier|bundle)(?: \(deleted\)>|>\(deleted\))', line)
        if opened and (pid, opened[1]) in sealed and created[pid, opened[1]] == opened[3]:
            readonly[pid, opened[2]] = opened[3]
    descriptors = {kind: {(inner.get(pid, pid), fd) for (pid, fd), name in readonly.items() if name == kind}
        for kind in ("verifier", "bundle")}
    aliases = set()
    for line in calls:
        alias = re.search(r'symlink\("/proc/(\d+)/fd/(\d+)", "(/proc/\d+/fd/\d+/bundle[.]jsonl)"\) = 0', line)
        if alias and (alias[1], alias[2]) in descriptors["bundle"]:
            pid = line.split(None, 1)[0]
            assert inner.get(pid, pid) == alias[1]
            assert alias[3].startswith("/proc/" + alias[1] + "/fd/")
            aliases.add(alias[3])
    accepted = set()
    for line in calls:
        execution = re.search(r'execve\("([^"]+)", (\[[^\n]*?\]), ', line)
        if not execution:
            continue
        path = execution[1]
        descriptor = re.fullmatch(r"/proc/(\d+)/fd/(\d+)", path)
        direct = path == "/fixture/s01-bootstrap/gh"
        if not direct and not descriptor:
            continue
        arguments = json.loads(execution[2])
        if arguments[1:3] != ["attestation", "verify"]:
            continue
        assert line.endswith(" = 0"), "Unsuccessful verifier exec"
        if descriptor:
            assert (descriptor[1], descriptor[2]) in descriptors["verifier"], "Unbound sealed verifier executable"
            assert re.fullmatch(r"/proc/" + descriptor[1] + r"/fd/\d+", arguments[3])
        else:
            assert re.fullmatch(r"/fixture/s01-proofs/subjects/(?:cm-host|sdk-a|sdk-b)\.json", arguments[3]) or re.fullmatch(
                r"/fixture/(?:s01-proofs/index/(?:negative-subjects|subjects)|s03-qualified/index/(?:qualifications|qualified))/[a-z0-9-]+\.json", arguments[3])
        options, position = {}, 4
        while position < len(arguments):
            key = arguments[position]
            assert key not in options
            if key == "--deny-self-hosted-runners":
                options[key] = True
                position += 1
            else:
                assert position + 1 < len(arguments)
                options[key] = arguments[position + 1]
                position += 2
        required = {"--repo": policy["builder_repository"],
            "--cert-identity": "https://github.com/" + policy["builder_repository"] + "/" + policy["workflow"] + "@" + policy["ref"],
            "--cert-oidc-issuer": policy["issuer"], "--source-ref": policy["ref"],
            "--deny-self-hosted-runners": True, "--format": "json"}
        assert set(options) == {*required, "--bundle", "--custom-trusted-root", "--source-digest", "--signer-digest"}
        assert all(options[key] == value for key, value in required.items())
        assert re.fullmatch(r"[0-9a-f]{40}", options["--source-digest"])
        assert options["--source-digest"] == options["--signer-digest"]
        if descriptor:
            assert options["--bundle"] in aliases
            assert options["--bundle"].startswith("/proc/" + descriptor[1] + "/fd/")
            assert re.fullmatch(r"/proc/" + descriptor[1] + r"/fd/\d+", options["--custom-trusted-root"])
        else:
            subject = Path(arguments[3])
            bundle = {"negative-subjects": "negative-bundle.jsonl", "subjects": "index-bundle.jsonl",
                "qualifications": "qualification-bundle.jsonl", "qualified": "qualified-index-bundle.jsonl"}
            expected_bundle = (subject.parent.parent / bundle[subject.parent.name]
                if "/index/" in arguments[3] else Path("/fixture/s01-proofs/bundle.jsonl"))
            assert options["--bundle"] == str(expected_bundle)
            assert options["--custom-trusted-root"] == "/fixture/s01-bootstrap/distribution-root.jsonl" or re.fullmatch(
                r"/work/s01/bootstrap/roots\.jsonl", options["--custom-trusted-root"])
        accepted.add(line)
    parents = {}
    for line in calls:
        spawned = re.search(r'\b(clone3?|vfork|fork)\(.*\)\s+=\s+(\d+)(?: /\* (\d+) in strace\x27s PID NS \*/)?$', line)
        if spawned:
            child = spawned[3] or spawned[2]
            assert child not in parents, "Ambiguous verifier process lineage"
            parents[child] = line.split()[0]
    verified = {line.split()[0] for line in accepted}
    for line in calls:
        missing = re.search(r'execve\("(/memfd:cm-distribution-verifier)", (\[[^\n]*?\]), ', line)
        if (not missing or json.loads(missing[2]) != [missing[1], "send-telemetry"]
                or not line.endswith(" = -1 ENOENT (No such file or directory)")):
            continue
        # The pinned Go verifier may try its vanished memfd path; no program was started.
        pid, seen = line.split()[0], set()
        while pid in parents and pid not in verified:
            assert pid not in seen, "Cyclic verifier process lineage"
            seen.add(pid)
            pid = parents[pid]
        if pid in verified:
            accepted.add(line)
    return accepted


def audit_offline_bootstrap(audit):
    assert audit["status"] == "pass" and audit["distribution_verifier_executions"]
    routes = {tuple(row) for row in audit["kernel_route_sockets"]}
    for line in audit["network"]:
        # observe() already validates destinations; only its bound kernel route messages are offline.
        match = re.match(r"(\d+)\s+sendto\((\d+)<(NETLINK:\[[^\]]+\])>, ", line)
        assert match and match.groups() in routes, "Unexpected offline bootstrap network: " + line


def bind_index_http_origin(record, metadata, hosts, observer):
    arguments = record["command"]
    assert arguments[0] == "/inputs/host/bin/codex" and arguments[0] in hosts
    assert record["host_sha256"] == hosts[arguments[0]] and arguments[1:3] == ["cm", "--home"]
    assert re.fullmatch(r"/profile/s03/(?:read-only|missing-target|http-size|http-redirect|http-timeout|http-tls)", arguments[3])
    assert arguments[4:6] in (["index", "list"], ["index", "plan"])
    assert arguments.count("--source") == 1
    endpoint = arguments[arguments.index("--source") + 1]
    match = re.fullmatch(r"https?://127[.]0[.]0[.]1:([1-9][0-9]{0,4})/current[.]json", endpoint)
    assert match and int(match[1]) < 65536
    port = match[1]
    assert observer.provider_tcp_connections(metadata, {port}), "HTTP fixture has no observed listener/accept pair"
    return port


@ci_progress.case()
def observe(directory, evidence, *, consumer_root=None, result_paths=None):
    import observer
    observer.check_network_audit()
    scripts = ("fixtures/native-loader/tool_barrier.py", "fixtures/runtime-consumer/driver.py",
               "ci/scripts/mod_manifest.py", "ci/scripts/runtime_sdk.py", "ci/scripts/managed_package.py",
               "ci/scripts/runtime_state.py", "ci/scripts/mod_author.py", "fixtures/turn-budget/driver.py",
               "fixtures/review-before-send/driver.py", "fixtures/tool-concurrency/driver.py",
               "fixtures/runtime-qualification/driver.py", "fixtures/runtime-hooks/driver.py", "fixtures/compatibility/driver.py",
               "fixtures/sdk-seams/driver.py", "fixtures/distribution-provenance/driver.py",
               "fixtures/compatibility-policy/driver.py", "fixtures/binary-index/driver.py", "fixtures/build-benchmarks/driver.py")
    network = []
    sockets = []
    tcp_metadata = []
    symlinks = []
    bwrap_executions = set()
    executions = []
    file_count = 0
    executable_memory = []
    process_calls = []
    verifier_calls = []
    trace_files = sorted(directory.glob("syscalls.*"))
    started = time.monotonic()
    for index, path in enumerate(trace_files, 1):
        assert path.suffix[1:].isdigit(), path
        pid = path.suffix[1:]
        text = redact_trace("".join(pid + " " + line + "\n" for line in path.read_text().splitlines()), observer)
        path.write_text(text, encoding="utf-8")
        assert not re.search(r'\b(?:sendto|recvfrom)\([^\n]*?, "(?!<payload redacted>)', text)
        calls = observer.complete_syscalls(text.splitlines())
        verifier_calls.extend(line for line in calls if re.match(r'\d+\s+(?:execve|memfd_create|fcntl|openat|getpid|symlink|clone|clone3|fork|vfork)\(', line))
        process_calls.extend(line for line in calls if re.match(r'\d+\s+(?:execve|clone|clone3|fork|vfork|getpid|gettid)\(', line))
        bwrap_executions.update(observer.bound_bwrap_executions(calls,
            ("/inputs/host/codex-resources/bwrap", "/work/m03/process/独立 Host/codex-resources/bwrap",
             "/inputs/upgrade-baseline/host/codex-resources/bwrap")))
        sockets.extend(line for line in calls if re.match(r'\d+\s+socket\(', line))
        tcp_metadata.extend(line for line in calls if re.match(r'\d+\s+(?:getsockname|accept|accept4)\(', line))
        symlinks.extend(line for line in calls if re.match(r'\d+\s+symlink(?:at)?\(', line))
        executions.extend(line for line in calls if re.match(r'\d+\s+execve(?:at)?\(', line))
        network.extend(line for line in calls if re.match(r'\d+\s+(?:connect|sendto|socketpair)\(', line))
        file_count += sum(bool(re.match(r'\d+\s+(?:openat|readlink)\(', line)) for line in calls)
        # Executable mappings must be attributed to a sealed business interpreter below.
        executable_memory.extend(line for line in calls if "PROT_EXEC" in line and
            ("MAP_ANONYMOUS" in line or re.match(r'\d+\s+mprotect\(', line)))
        if index % 500 == 0 or index == len(trace_files):
            ci_progress.emit("outer-audit/traces-" + str(index) + "-of-" + str(len(trace_files)), "running", started)
    hosts = ("/inputs/host/bin/codex", "/work/m03/process/独立 Host/bin/codex", "/inputs/upgrade-baseline/host/bin/codex")
    aliases = observer.bound_sandbox_aliases(symlinks, hosts)
    alias_targets = {}
    for line in symlinks:
        paths = re.findall(r'"([^"]+)"', line)
        if len(paths) == 2 and paths[1] in aliases and paths[0] in hosts:
            assert paths[1] not in alias_targets or alias_targets[paths[1]] == paths[0]
            alias_targets[paths[1]] = paths[0]
    assert set(alias_targets) == aliases
    bound_hosts = bind_host_executables(executions, consumer_root or directory.parent)
    native_probes = bind_review_probes(executions, consumer_root or directory.parent)
    concurrency_probes = bind_concurrency_probes(executions, consumer_root or directory.parent)
    hook_probes = bind_hook_probes(executions, consumer_root or directory.parent)
    sdk_probes = bind_sdk_probes(executions, consumer_root or directory.parent)
    code_mode = bind_code_mode(process_calls, executable_memory, evidence, consumer_root or directory.parent, result_paths)
    verifiers = bind_distribution_verifiers(verifier_calls, consumer_root or directory.parent)
    observer.audit_executions(executions, python_scripts=scripts, sandbox_aliases=aliases,
        bwrap_executions=bwrap_executions | verifiers, native_probes=[*native_probes, *concurrency_probes, *hook_probes, *sdk_probes, *code_mode["executables"]])
    ports = set()
    tui_listeners = []
    for path in sorted(evidence.rglob("result.json") if result_paths is None else result_paths):
        assert not path.is_symlink(), "Linked runtime evidence: " + str(path)
        if not path.is_file():
            continue
        record = read(path)
        arguments = record.get("command", [])
        if len(arguments) > 7 and arguments[1:3] == ["cm", "--home"] and arguments[3].startswith("/profile/s03/"):
            source = arguments[arguments.index("--source") + 1] if "--source" in arguments else ""
            if source.startswith(("http://", "https://")):
                ports.add(bind_index_http_origin(record, tcp_metadata, bound_hosts, observer))
        else:
            ports.update(re.findall(r'http://127[.]0[.]0[.]1:(\d+)', " ".join(arguments)
                + " " + record.get("provider_endpoint", "")))
        if record.get("tui_mcp_listener"):
            listener = bind_tui_mcp_listener(record, tcp_metadata, bound_hosts, observer, process_calls=process_calls)
            tui_listeners.append({"evidence": str(path.relative_to(evidence)), **listener})
            ports.add(listener["port"])
    # The outer observer also sees the provider's responses. Normalize only the
    # reverse half of an already identified loopback provider connection.
    normalized = []
    for line in network:
        peer = re.search(r'<TCP:\[127\.0\.0\.1:(\d+)->127\.0\.0\.1:(\d+)\]>', line)
        if peer and peer[1] in ports:
            line = line[:peer.start()] + '<TCP:[127.0.0.1:' + peer[2] + '->127.0.0.1:' + peer[1] + ']>' + line[peer.end():]
        normalized.append(line)
    routes = observer.kernel_route_sockets(sockets)
    tcp_connections = observer.provider_tcp_connections(tcp_metadata, ports)
    audit_runtime_network(observer, normalized, Path("/evidence"), ports, routes, tcp_connections, tcp_metadata)
    # Writable executable mappings are unsupported, even if no compiler was exec'd.
    assert not code_mode["unclassified"], "Unclassified runtime code generation: " + repr(code_mode["unclassified"])
    assert file_count, "File-load observer produced no records"
    return {"status": "pass", "executions": executions, "network": network, "kernel_route_sockets": sorted(routes),
        "native_review_probes": native_probes,
        "native_concurrency_probes": concurrency_probes,
        "native_hook_probes": hook_probes,
        "native_sdk_probes": sdk_probes,
        "normal_business_interpreter": code_mode,
        "provider_tcp_connections": sorted(tcp_connections), "provider_tcp_metadata": tcp_metadata,
        "tui_mcp_listener": next((row for row in tui_listeners if row["evidence"] == "m03/terminal/actual-tui/result.json"), None),
        "tui_mcp_listeners": tui_listeners,
        "sandbox_aliases": [{"path": path, "target": alias_targets[path]} for path in sorted(aliases)],
        "packaged_bwrap_fd_executions": sorted(bwrap_executions),
        "distribution_verifier_executions": sorted(verifiers),
        "bound_host_executables": bound_hosts,
        "file_load_count": file_count, "trace_files": [path.name for path in trace_files],
        "compiler_linker_jit_build_service_calls": 0, "unclassified_executable_memory": code_mode["unclassified"],
        "executable_memory_record_count": len(executable_memory),
        "forbidden_mod_build_or_jit": 0,
        "boundary": "fixed audited native fixtures; not a generic malicious-native JIT detector",
        "socket_payloads": "sendto/recvfrom redacted in both audit and export"}


def budget_cases(producer):
    import retry
    cases = [label.removeprefix("g02a-") for label in retry.PHASES if label.startswith("g02a-")]
    assert len(cases) == 6 and producer["g02a"]["cases"] == cases, "Frozen budget cases differ from the consumer checkpoints"
    return cases


def audit_runtime_network(observer, lines, directory, ports, routes=(), tcp_connections=(), socket_metadata=()):
    # Both local pair types use the same observed endpoint-inode checks; retain raw records in the report.
    normalized = [re.sub(r'(socketpair\(AF_UNIX, )SOCK_SEQPACKET(?=[|,])', r'\1SOCK_STREAM', line)
        .replace("UNIX-SEQPACKET:", "UNIX-STREAM:") for line in lines]
    accepted = set()
    for line in socket_metadata:
        connection = re.fullmatch(r'\d+\s+accept4?\(\d+<UNIX-STREAM:\[\d+\]>, \{sa_family=AF_UNIX\}, \[\d+(?: => \d+)?\](?:, SOCK_CLOEXEC(?:\|SOCK_NONBLOCK)?)?\) = \d+<UNIX-STREAM:\[(\d+)\]>', line)
        if connection:
            accepted.add(connection[1])
    bound = set()
    for line in socket_metadata:
        local = re.fullmatch(r'\d+\s+getsockname\(\d+<UNIX-STREAM:\[(\d+)\]>, \{sa_family=AF_UNIX, sun_path="([^"]+)"\}, \[\d+(?: => \d+)?\]\) = 0', line)
        if local and local[1] in accepted and Path(local[2]).is_relative_to(directory) and ".." not in Path(local[2]).parts:
            bound.add(local[1])
    for line in normalized:
        connected = re.fullmatch(r'\d+\s+connect\(\d+<UNIX-STREAM:\[(\d+)\]>, \{sa_family=AF_UNIX, sun_path="([^"]+)"\}, \d+\) = 0', line)
        if connected and Path(connected[2]).is_relative_to(directory) and ".." not in Path(connected[2]).parts:
            bound.add(connected[1])
    remaining = []
    for line in normalized:
        reply = re.fullmatch(r'\d+\s+sendto\(\d+<UNIX-STREAM:\[(\d+)\]>, "<payload redacted>", \d+, (?:0|MSG_NOSIGNAL), NULL, 0\) = \d+', line)
        # Namespace-limited strace can omit peers on either end; require the exact scoped connection inode.
        if not reply or reply[1] not in bound:
            remaining.append(line)
    observer.audit_network(remaining, directory, ports, routes, tcp_connections)


def check_runtime_network():
    import runtime_composition as observer
    pair = '3 socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, [48<UNIX:[51]>, 49<UNIX:[52]>]) = 0'
    send = '4 sendto(48<UNIX:[51]>, "<payload redacted>", 4, 0, NULL, 0) = 4'
    for lines in ([pair, send], [send, pair],
            [pair.replace("UNIX:", "UNIX-SEQPACKET:"), send.replace("UNIX:", "UNIX-SEQPACKET:")]):
        audit_runtime_network(observer, lines, Path("/evidence"), set())
    accepted = '3826 accept4(3<UNIX-STREAM:[27403]>, {sa_family=AF_UNIX}, [110 => 2], SOCK_CLOEXEC) = 5<UNIX-STREAM:[27425]>'
    local = '3826 getsockname(5<UNIX-STREAM:[27425]>, {sa_family=AF_UNIX, sun_path="/evidence/g01/callback.sock"}, [128 => 62]) = 0'
    reply = '3826 sendto(5<UNIX-STREAM:[27425]>, "<payload redacted>", 1, 0, NULL, 0) = 1'
    for metadata in ([accepted, local], [local, accepted],
            [accepted.replace('accept4(', 'accept(').replace(', SOCK_CLOEXEC)', ')'), local]):
        audit_runtime_network(observer, [reply], Path("/evidence"), set(), socket_metadata=metadata)
    connected = '11304 connect(4<UNIX-STREAM:[146207]>, {sa_family=AF_UNIX, sun_path="/evidence/g01/callback.sock"}, 62) = 0'
    sent = '11304 sendto(4<UNIX-STREAM:[146207]>, "<payload redacted>", 17, MSG_NOSIGNAL, NULL, 0) = 17'
    for lines in ([connected, sent], [sent, connected], [connected, sent.replace('11304 ', '11305 ')]):
        audit_runtime_network(observer, lines, Path("/evidence"), set())
    for connection in (None, connected.replace(' = 0', ' = -1 ECONNREFUSED (Connection refused)'),
            connected.replace('[146207]', '[146208]'), connected.replace('/evidence/', '/outside/'),
            connected.replace('/evidence/', '/evidence-other/'),
            connected.replace('/evidence/', '/evidence/../outside/'), connected.replace('UNIX-STREAM', 'UNIX-DGRAM')):
        try:
            audit_runtime_network(observer, ([connection] if connection else []) + [sent], Path("/evidence"), set())
        except AssertionError:
            continue
        raise AssertionError("Runtime audit accepted an unbound Unix client")
    for metadata in ([accepted], [local], [accepted.replace('[27425]', '[27426]'), local],
            [accepted, local.replace('[27425]', '[27426]')],
            [accepted, local.replace('/evidence/', '/outside/')],
            [accepted, local.replace('/evidence/', '/evidence-other/')],
            [accepted, local.replace('/evidence/', '/evidence/../outside/')],
            [accepted.replace(' = 5<UNIX-STREAM:[27425]>', ' = -1 EAGAIN (Resource temporarily unavailable)'), local],
            [accepted, local.replace(' = 0', ' = -1 EBADF (Bad file descriptor)')]):
        try:
            audit_runtime_network(observer, [reply], Path("/evidence"), set(), socket_metadata=metadata)
        except AssertionError:
            continue
        raise AssertionError("Runtime audit accepted an unbound Unix reply")
    for lines in ([reply.replace('[27425]', '[27426]')], [reply.replace('UNIX-STREAM', 'UNIX-DGRAM')],
            [reply, '3826 connect(8<UNIX-STREAM:[99]>, {sa_family=AF_UNIX, sun_path="/outside/socket"}, 32) = 0']):
        try:
            audit_runtime_network(observer, lines, Path("/evidence"), set(), socket_metadata=[accepted, local])
        except AssertionError:
            continue
        raise AssertionError("Runtime audit accepted an unrelated Unix peer")
    for lines in ([send], [pair, send.replace("[51]", "[53]")],
            [pair.replace("SOCK_SEQPACKET", "SOCK_DGRAM"), send],
            [pair.replace("AF_UNIX", "AF_INET"), send],
            [pair.replace("[52]", "[51]"), send],
            [pair, '3 connect(48<UNIX:[51]>, {sa_family=AF_UNIX, sun_path="/outside/socket"}, 32) = 0']):
        try:
            audit_runtime_network(observer, lines, Path("/evidence"), set())
        except AssertionError:
            continue
        raise AssertionError("Runtime audit accepted an unbound socket pair or peer")


def classify_code_mode(calls, executable_memory, helper, hosts, events):
    """Use outer PID identities from strace, never process names or a blanket JIT exemption."""
    edges, inner, executed = {}, {}, {}
    for line in calls:
        pid = line.split()[0]
        spawned = re.search(r'\b(clone3?|vfork|fork)\(.*\)\s+=\s+(\d+)(?: /\* (\d+) in strace\x27s PID NS \*/)?$', line)
        if spawned and int(spawned[2]) > 0:
            child = spawned[3] or spawned[2]
            assert child not in edges, "Ambiguous process lineage"
            edges[child] = (pid, spawned[2], "CLONE_THREAD" in line)
        identity = re.search(r'\bgetpid\(\)\s+=\s+(\d+)(?: /\* (\d+) in strace\x27s PID NS \*/)?$', line)
        if identity:
            inner[pid] = identity[1]
        execution = re.search(r'execve\("([^"]+)".*\)\s+=\s+0$', line)
        if execution:
            executed.setdefault(pid, []).append((execution[1], line))

    def process(pid):
        seen = set()
        while pid in edges and edges[pid][2]:
            assert pid not in seen, "Cyclic thread lineage"
            seen.add(pid)
            pid = edges[pid][0]
        return pid

    allowed, bindings = set(), []
    for pid, entries in executed.items():
        if not any(path == helper for path, _line in entries):
            continue
        assert len(entries) == 1, entries
        arguments = re.search(r'execve\("[^"]+", (\[.*?\]), ', entries[0][1])
        assert arguments, entries
        arguments = json.loads(arguments[1])
        assert arguments in ([helper], [helper, "--listen", "grpc+stdio://"]), arguments
        transport = "stdio://" if arguments == [helper] else "grpc+stdio://"
        parent, helper_inner, is_thread = edges[pid]
        assert not is_thread
        host = process(parent)
        assert any(path in hosts for path, _line in executed.get(host, ())), "Helper parent is not the sealed Host"
        host_inner = inner.get(parent) or inner.get(host) or (edges[host][1] if host in edges else None)
        assert host_inner is not None, "Host PID namespace identity missing"
        transports = [row["detail"] for row in events if row["event"] == "code-mode-transport"
            and str(row["detail"]["host_pid"]) == host_inner and str(row["detail"]["helper_pid"]) == helper_inner
            and row["detail"]["program"] == helper and row["detail"]["transport"] == "grpc+stdio://"]
        if transport == "grpc+stdio://":
            assert transports, "Helper lacks the actual Host transport event"
        cells = [row["detail"] for row in events if row["event"] == "code-mode-cell"
            and str(row["detail"]["host_pid"]) == host_inner]
        assert cells, "Interpreter did not execute an observed business cell"
        leaves = [row["detail"] for row in events if row["event"] == "tool-concurrency-role"
            and row["detail"].get("parent") is not None and row["detail"]["role"] == "leaf"]
        assert any(leaf["parent"]["cell_id"] == cell["cell_id"] and leaf["turn"] == cell["turn"]
            for leaf in leaves for cell in cells), "Cell has no actual nested Core leaf"
        family = {value for value in {pid, *edges} if process(value) == pid}
        assert not any(value != pid and value in executed for value in family), "Interpreter thread executed another program"
        allowed.update(family)
        bindings.append({"outer_pid": pid, "outer_host_pid": host, "inner_host_pid": host_inner,
            "inner_helper_pid": helper_inner, "transport": transport, "thread_ids": sorted(family),
            "cell_ids": sorted({cell["cell_id"] for cell in cells})})
    classified = [line for line in executable_memory if line.split()[0] in allowed]
    return {"executables": [helper] if bindings else [], "bindings": bindings,
        "executable_memory_records": classified,
        "unclassified": [line for line in executable_memory if line.split()[0] not in allowed],
        "boundary": "sealed Code Mode business interpreter; does not authorize Mod compilation or JIT"}


def bind_code_mode(calls, executable_memory, evidence, root, result_paths=None):
    producer = read(root / "rootfs/inputs/producer.json")
    concurrency = producer.get("concurrency")
    if concurrency is None:
        return {"executables": [], "bindings": [], "executable_memory_records": [], "unclassified": executable_memory}
    helper = concurrency["code_mode_helper"]
    assert helper["path"] == "/inputs/host/bin/codex-code-mode-host" and helper["transport"] == "grpc+stdio://"
    assert sha(root / "rootfs" / helper["path"].lstrip("/")) == helper["sha256"], "Code Mode helper hash mismatch"
    executions = [line for line in calls if re.match(r'\d+\s+execve\(', line)]
    hosts = bind_host_executables(executions, root)
    events = []
    paths = evidence.rglob("native.jsonl") if result_paths is None else {
        path.parent / "native.jsonl" for path in result_paths if (path.parent / "native.jsonl").is_file()}
    for path in paths:
        assert not path.is_symlink()
        events.extend(json.loads(line) for line in path.read_text().splitlines(keepends=True) if line.endswith("\n"))
    return classify_code_mode(calls, executable_memory, helper["path"], hosts, events)


def check_code_mode_classification():
    helper, host = "/inputs/host/bin/codex-code-mode-host", "/inputs/host/bin/codex"
    calls = ['10 execve("' + host + '", ["codex"], 0x0) = 0',
        '10 getpid() = 2 /* 10 in strace\x27s PID NS */',
        '10 clone(child_stack=NULL, flags=SIGCHLD) = 3 /* 20 in strace\x27s PID NS */',
        '20 execve("' + helper + '", ["' + helper + '", "--listen", "grpc+stdio://"], 0x0) = 0',
        '20 clone(child_stack=0x0, flags=CLONE_VM|CLONE_THREAD) = 4 /* 21 in strace\x27s PID NS */']
    events = [{"event":"code-mode-transport","detail":{"host_pid":2,"helper_pid":3,"program":helper,"transport":"grpc+stdio://"}},
        {"event":"code-mode-cell","detail":{"host_pid":2,"cell_id":"c1","turn":"t1"}},
        {"event":"tool-concurrency-role","detail":{"role":"leaf","parent":{"cell_id":"c1"},"turn":"t1"}}]
    memory = ['21 mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_ANONYMOUS, -1, 0) = 0x1']
    assert not classify_code_mode(calls, memory, helper, {host: "sealed"}, events)["unclassified"]
    stdio = [line.replace(', "--listen", "grpc+stdio://"', "") for line in calls]
    result = classify_code_mode(stdio, memory, helper, {host: "sealed"}, events[1:])
    assert not result["unclassified"] and result["bindings"][0]["transport"] == "stdio://"
    spawned_host = ['1 clone(child_stack=NULL, flags=SIGCHLD) = 2 /* 10 in strace\x27s PID NS */',
        *(line for line in stdio if not line.startswith("10 getpid"))]
    assert classify_code_mode(spawned_host, memory, helper, {host: "sealed"}, events[1:])["bindings"][0]["inner_host_pid"] == "2"
    assert classify_code_mode(calls, [memory[0].replace("21 mmap", "10 mmap")], helper, {host: "sealed"}, events)["unclassified"]
    for bad_calls, bad_events in ((calls, events[:1]), (calls, events[:2]), (calls, events[1:]),
        (stdio, events[1:2]), (stdio, events[2:]),
        ([line for line in stdio if not line.startswith("10 getpid")], events[1:]),
        ([line.replace(' = 2 /* 10', ' = 9 /* 10') for line in spawned_host], events[1:]),
        ([line.replace('["' + helper + '"]', '["' + helper + '", "--unknown"]') for line in stdio], events),
        ([line.replace(host, "/work/unbound") if line.startswith("10 execve") else line for line in calls], events)):
        try:
            classify_code_mode(bad_calls, memory, helper, {host:"sealed"}, bad_events)
        except (AssertionError, KeyError):
            continue
        raise AssertionError("Unbound business interpreter accepted")


def bind_hook_probes(executions, root):
    hooks = read(root / "rootfs/inputs/producer.json").get("hooks")
    if hooks is None:
        return []
    probe = hooks["probe"]
    assert probe["path"] == "/inputs/probes/cm-hook-policy" and probe["separate_from_cli"]
    assert sha(root / "rootfs" / probe["path"].lstrip("/")) == probe["sha256"]
    for line in executions:
        if 'execve("' + probe["path"] + '"' in line:
            assert re.search(r', \["' + re.escape(probe["path"]) + r'", "/profile/g01/(?:binding-drift|cancel-callback|'
                r'next-repeat/repeat|next-stale-owner/(?:stale|owner)|next-thread/thread|cancel-before/cancel-before)"\], ', line), line
    return [probe["path"]]


def bind_concurrency_probes(executions, root):
    producer = read(root / "rootfs/inputs/producer.json")
    concurrency = producer.get("concurrency")
    if concurrency is None:
        return []
    if producer.get("benchmark_scope") == "CM-S04":
        assert set(concurrency) == {"code_mode_helper"} and not (root / "rootfs/inputs/probes").exists()
        return []
    result = []
    for key, expected in (("probe", "/inputs/probes/cm-concurrency-core"),
                          ("backend_probe", "/inputs/probes/cm-concurrency-backend")):
        probe = concurrency[key]
        assert probe["path"] == expected and probe["separate_from_cli"]
        assert sha(root / "rootfs" / probe["path"].lstrip("/")) == probe["sha256"]
        names = list(probe["names"])
        if key == "probe" and producer.get("sdk_seams"):
            assert producer["sdk_seams"]["private_core_probe"] == expected
            names.append("thread_manager::tests::cm_sdk_seams_protocol")
        for line in executions:
            if 'execve("' + probe["path"] + '"' in line:
                assert '"--ignored"' in line and '"--exact"' in line and any('"' + name + '"' in line for name in names), line
        result.append(probe["path"])
    return result


def bind_sdk_probes(executions, root):
    sdk = read(root / "rootfs/inputs/producer.json").get("sdk_seams")
    if sdk is None:
        return []
    probe = "/inputs/probes/cm-sdk-c-abi"
    assert sha(root / ("rootfs" + probe)) == sdk["c_probe_sha256"]
    modes = ("valid", "major", "minor", "old-minor", "short-prefix", "short-tail", "huge",
        "null-host", "misaligned", "null-runtime", "runtime-short", "runtime-minor", "runtime-reserved",
        "null-complete", "null-state-get", "null-state-set", "null-next", "next-short", "next-minor",
        "next-reserved", "null-start", "null-poll", "null-cancel", "null-release")
    for line in executions:
        if 'execve("' + probe + '"' in line:
            assert re.search(r', \["' + re.escape(probe) + r'", "/inputs/mods/g06/a/v1/payload[.]so", "(?:'
                + "|".join(modes) + r')"\], ', line), line
    return [probe]


def bind_review_probes(executions, root):
    producer = read(root / "rootfs/inputs/producer.json")
    review = producer.get("review")
    if review is None:
        return []
    probe = review["probe"]
    assert probe["path"] == "/inputs/probes/cm-review-tui" and probe["separate_from_cli"]
    assert sha(root / "rootfs" / probe["path"].lstrip("/")) == probe["sha256"]
    prefix = "bottom_pane::chat_composer::submit_review::cm_probe::cm_review_"
    dispatch_prefix = "chatwidget::tests::cm_review_probe::cm_review_"
    names = {prefix + case.replace("-", "_") for case in review["cases"]}
    names.add(prefix + "protocol")
    names.update(dispatch_prefix + name for name in ("programmatic", "admission", "queue", "cli_image"))
    names.add("app::tests::cm_review_probe::cm_review_programmatic_events")
    for line in executions:
        if 'execve("' + probe["path"] + '"' in line:
            assert '"--exact"' in line and any('"' + name + '"' in line for name in names), line
    return [probe["path"]]


def review_cases(producer):
    import retry
    cases = [label.removeprefix("review-") for label in retry.PHASES if label.startswith("review-")]
    assert len(cases) == 6 and producer["review"]["cases"] == cases
    return cases


def consume():
    import retry
    import runtime_cases
    hosted()
    assert os.environ["CM_CACHE_MODE"] == "none" and os.environ["ACTIONS_CACHE_MODE"] == "none"
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"]).resolve()
    manifest = validate_inputs(inputs)
    producer = read(inputs / "producer.json")
    validation = read(inputs / "validation.json")
    assert validation["provenance"] == provenance(), "Validation inputs are not from this exact run/attempt/request/source/workflow"
    origin = validation["production_origin"]
    assert producer["provenance"] == {**provenance(), "CM_SOURCE_SHA": origin["source_sha"],
        "GITHUB_WORKFLOW_SHA": origin["workflow_sha"], "GITHUB_RUN_ID": str(origin["run_id"]),
        "GITHUB_RUN_ATTEMPT": str(origin["run_attempt"]), "CM_REQUEST_ID": origin["request_id"]}, "Original producer provenance changed"
    assert producer["task_id"] in ("CM-P04", "CM-M01", "CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03") and producer["target"] == TARGET
    m05_only = producer["task_id"] == "CM-M05" and producer["m05"]["build_kind"] == "mod-only"
    if producer["task_id"] == "CM-M05":
        assert producer["m05"]["build_kind"] == os.environ["CM_BUILD_KIND"]
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    artifact.mkdir(parents=True)
    logs.mkdir(parents=True, exist_ok=True)
    if not runtime_cases.historical_hosts():
        scope = runtime_cases.qualification_scope()
        write(artifact / "qualification-scope.json", scope)
        write(logs / "qualification-scope.json", scope)
        print("CM qualification scope:", json.dumps(scope, sort_keys=True), flush=True)
    p04_acceptance = {"schema_version": 1, "task_id": "CM-P04", "target": TARGET, "status": "not_run",
        "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-P04-AC0" + str(index),
        "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate((
        "frozen-host-independent-mods.json", "zero-build-runtime-environment.json", "plug-and-play-matrix.json",
        "runtime-package-integrity.json", "zero-build-failure-matrix.json", "empty-host-independent-install.json"), 1)]}
    sys.path.insert(0, str(inputs / "fixture/ci/scripts"))
    import mod_manifest
    report_audit_self_check()
    m01_acceptance = None
    if not m05_only and producer["task_id"] in ("CM-M01", "CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        m01_acceptance = {"schema_version": 1, "task_id": "CM-M01", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M01-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(mod_manifest.REPORTS, 1)]}
    m02_acceptance = None
    if not m05_only and producer["task_id"] in ("CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_sdk
        m02_acceptance = {"schema_version": 1, "task_id": "CM-M02", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M02-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(runtime_sdk.REPORTS, 1)]}
    m03_acceptance = None
    if not m05_only and producer["task_id"] in ("CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import managed_package
        m03_acceptance = {"schema_version": 1, "task_id": "CM-M03", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M03-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(managed_package.REPORTS, 1)]}
    m04_acceptance = None
    if not m05_only and producer["task_id"] in ("CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_state
        m04_acceptance = {"schema_version": 1, "task_id": "CM-M04", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M04-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(runtime_state.REPORTS, 1)]}
    m05_acceptance = None
    if producer["task_id"] in ("CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import mod_author
        m05_acceptance = {"schema_version": 1, "task_id": "CM-M05", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M05-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(mod_author.REPORTS, 1)]}
    g02a_acceptance = None
    if producer["task_id"] in ("CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        cases = budget_cases(producer)
        g02a_acceptance = {"schema_version": 1, "task_id": "CM-G02A", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [
                {"id": "CM-G02A-AC0" + str(index), "status": "not_run", "phase": "g02a-" + case,
                 "evidence": ["evidence/budget-" + case + ".json"]} for index, case in enumerate(cases, 1)]}
    review_acceptance = None
    if producer["task_id"] in ("CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        review_steps = review_cases(producer)
        review_acceptance = {"schema_version": 1, "task_id": "CM-G02B", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [
                {"id": "CM-G02B-AC0" + str(index), "status": "not_run", "phase": "review-" + case,
                 "evidence": ["evidence/review-" + case + ".json"]} for index, case in enumerate(review_steps, 1)]}
    concurrency_acceptance = None
    if producer["task_id"] in ("CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        concurrency_steps = [label.removeprefix("concurrency-") for label in retry.PHASES if label.startswith("concurrency-")]
        assert len(concurrency_steps) == 7 and producer["concurrency"]["cases"] == concurrency_steps
        concurrency_acceptance = {"schema_version": 1, "task_id": "CM-G03", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [
                {"id": "CM-G03-AC0" + str(index), "status": "not_run", "phase": "concurrency-" + case,
                 "evidence": ["evidence/concurrency-" + case + ".json"]} for index, case in enumerate(concurrency_steps, 1)]}
    g04_acceptance = None
    if producer["task_id"] in ("CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_qualification
        g04_acceptance = {"schema_version": 1, "task_id": "CM-G04", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-G04-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(runtime_qualification.REPORTS, 1)]}
    hooks_acceptance = None
    if producer["task_id"] in ("CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_hooks
        hooks_acceptance = {"schema_version": 1, "task_id": "CM-G01", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-G01-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(runtime_hooks.REPORTS, 1)]}
    upgrade_acceptance = None
    if runtime_cases.historical_hosts() and producer["task_id"] in ("CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import runtime_upgrade
        upgrade_acceptance = {"schema_version": 1, "task_id": "CM-G05", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-G05-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(runtime_upgrade.REPORTS, 1)]}
    seams_acceptance = None
    if producer["task_id"] in ("CM-G06", "CM-S01", "CM-S02", "CM-S03"):
        import sdk_seams
        seams_acceptance = {"schema_version": 1, "task_id": "CM-G06", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-G06-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(sdk_seams.REPORTS, 1)]}
    distribution_acceptance = None
    if producer["task_id"] in ("CM-S01", "CM-S02", "CM-S03"):
        import distribution_provenance
        check_distribution_verifier_binding(inputs / "fixture")
        distribution_acceptance = {"schema_version": 1, "task_id": "CM-S01", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-S01-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(distribution_provenance.REPORTS, 1)]}
    support_acceptance = None
    if validation.get("task_id", producer["task_id"]) in ("CM-S02", "CM-S03"):
        import support_policy
        assert distribution_acceptance is not None, "S02 requires the original distribution baseline"
        support_acceptance = {"schema_version": 1, "task_id": "CM-S02", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-S02-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(support_policy.REPORTS, 1)]}
    index_acceptance = None
    if validation.get("task_id", producer["task_id"]) == "CM-S03":
        import binary_index
        assert support_acceptance is not None
        index_acceptance = {"schema_version": 1, "task_id": "CM-S03", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-S03-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(binary_index.REPORTS, 1)]}
    program_acceptance = None
    if validation.get("program"):
        import program_integration
        assert producer["task_id"] == "CM-S03" and index_acceptance is not None
        assert validation["build_request"] == {"kind": "program", "host_origin": None}
        program_acceptance = {"schema_version": 1, "task_id": "CM-PROGRAM", "target": TARGET,
            "status": "not_run", "implementation_commit": os.environ["CM_SOURCE_SHA"], "release_ready": False,
            "checks": [{"id": "CM-PROGRAM-AC0" + str(index), "status": "not_run"} for index in range(1, 5)]}
    acceptance = program_acceptance or index_acceptance or support_acceptance or distribution_acceptance or seams_acceptance or upgrade_acceptance or hooks_acceptance or g04_acceptance or concurrency_acceptance or review_acceptance or g02a_acceptance or m05_acceptance or m04_acceptance or m03_acceptance or m02_acceptance or m01_acceptance or p04_acceptance
    write(artifact / "acceptance.json", acceptance)
    stage = "rootfs"
    try:
        temp = Path(os.environ["RUNNER_TEMP"]) / "cm-runtime-consumer"
        temp.mkdir()
        root = temp / "rootfs"
        closure = rootfs(inputs, root)
        if index_acceptance is not None:
            closure["binary_index_inputs"] = binary_index.native_inputs(inputs)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        canary_hits = []
        listener.settimeout(0.2)
        stopped = threading.Event()

        def canary():
            while not stopped.is_set():
                try:
                    connection, _ = listener.accept()
                    canary_hits.append("unexpected cross-namespace connection")
                    connection.close()
                except socket.timeout:
                    continue

        thread = threading.Thread(target=canary, daemon=True)
        thread.start()
        context = {"outer_namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ("user", "mnt", "pid", "ipc", "uts", "net")},
                   "canary_port": listener.getsockname()[1], "provenance": provenance(), "cache_mode": "none",
                   "input_manifest_sha256": manifest["sha256"],
                   "image_os": os.environ["ImageOS"], "image_version": os.environ["ImageVersion"],
                   "bind_roots": {point: str((temp / name).resolve()) for point, name in
                       (("/", "rootfs"), ("/profile", "profile"), ("/work", "work"), ("/evidence", "evidence"))}}
        write(root / "fixture/context.json", context)
        closure["files"] = inventory(root)
        closure["sha256"] = digest(closure["files"])
        write(artifact / "rootfs-manifest.json", closure)
        write(logs / "rootfs-manifest.json", closure)
        for directory in ("profile", "work", "evidence"):
            (temp / directory).mkdir()
        evidence = temp / "evidence"
        base = [str(inputs / "host/codex-resources/bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-net", "--uid", "1000", "--gid", "1000", "--cap-drop", "ALL",
            "--new-session", "--die-with-parent", "--hostname", "cm-consumer", "--ro-bind", str(root), "/",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--bind", str(temp / "profile"), "/profile", "--bind", str(temp / "work"), "/work",
            "--bind", str(evidence), "/evidence", "--chdir", "/work", "--clearenv"]
        for key, value in {"PATH": "/usr/bin:/bin:/inputs/host/codex-path", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                           "CM_TARGET": TARGET, "CM_PLATFORM": linux_native()["key"],
                           "TERM": "dumb", "TMPDIR": "/tmp", "HOME": "/home/fixture", "PYTHONNOUSERSITE": "1",
                           "PYTHONDONTWRITEBYTECODE": "1"}.items():
            base += ["--setenv", key, value]
        driver = [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B", "/fixture/fixtures/runtime-consumer/driver.py"]
        try:
            trusted = temp / "trusted-observer"
            trusted.mkdir()
            trace = ["strace", "-ff", "-qq", "-yy", "--pidns-translation", "-s", "1024", "-e",
                TRACE_SYSCALLS,
                "-o", "CM_PHASE_TRACE", "--"]

            def command(label, arguments, sandbox=base):
                directory = trusted / label
                directory.mkdir(exist_ok=True)
                return [str(directory / "syscalls") if part == "CM_PHASE_TRACE" else part for part in trace] + ([*sandbox, "--"] if sandbox else []) + arguments
            current_audit = None
            if distribution_acceptance is not None:
                stage = "independent offline bootstrap before candidate execution"
                label = "s01-current-verification"
                current = ci_progress.run(logs, label, command(label, [*CONSUMER_ENV_PREFIX,
                    "/usr/bin/python3", "-B", "/fixture/fixtures/distribution-provenance/driver.py", "verify-current"],
                    sandbox=["/usr/bin/bwrap", *base[1:]]), 300)
                assert current.returncode == 0, "Current distribution proof verification failed"
                current_audit = observe(trusted / label, evidence, consumer_root=temp)
                audit_offline_bootstrap(current_audit)
            index_current_audit = None
            if index_acceptance is not None:
                label = "s03-current-verification"
                current = ci_progress.run(logs, label, command(label, [*CONSUMER_ENV_PREFIX,
                    "/usr/bin/python3", "-B", "/fixture/fixtures/binary-index/driver.py", "verify-current"],
                    sandbox=["/usr/bin/bwrap", *base[1:]]), 300)
                assert current.returncode == 0, "Current index proof verification failed"
                index_current_audit = observe(trusted / label, evidence, consumer_root=temp)
                audit_offline_bootstrap(index_current_audit)
            stage = "strict isolation probes"
            result = ci_progress.run(logs, "consumer-probes", [*base, "--", *driver, "probe"], 180)
            write(logs / "consumer-probes.json", {"return_code": result.returncode, "stage": stage})
            assert result.returncode == 0, "Strict namespace/probe setup failed"
            assert not canary_hits
            report_names = {"consumer-matrix": [Path(row["evidence"][0]).name for row in p04_acceptance["checks"]]}
            for label, report_set in (("m01", m01_acceptance), ("m02", m02_acceptance), ("m03", m03_acceptance),
                                      ("m04", m04_acceptance), ("m05", m05_acceptance)):
                if report_set:
                    report_names[label + "-consumer-matrix"] = [Path(row["evidence"][0]).name for row in report_set["checks"]]
            if g02a_acceptance is not None:
                report_names.update({row["phase"]: [Path(row["evidence"][0]).name] for row in g02a_acceptance["checks"]})
            if review_acceptance is not None:
                report_names.update({row["phase"]: [Path(row["evidence"][0]).name] for row in review_acceptance["checks"]})
            if concurrency_acceptance is not None:
                report_names.update({row["phase"]: [Path(row["evidence"][0]).name] for row in concurrency_acceptance["checks"]})
            phase_reports = {"p04": report_names.pop("consumer-matrix")}
            for phase in ("m01", "m02", "m03", "m04", "m05"):
                coarse = phase + "-consumer-matrix"
                if coarse in report_names:
                    phase_reports[phase] = report_names.pop(coarse)
            if g04_acceptance is not None:
                phase_reports["g04"] = list(runtime_qualification.REPORTS)
            if hooks_acceptance is not None:
                phase_reports["g01"] = list(runtime_hooks.REPORTS)
            if upgrade_acceptance is not None:
                phase_reports["g05"] = list(runtime_upgrade.REPORTS)
            if seams_acceptance is not None:
                phase_reports["g06"] = list(sdk_seams.REPORTS)
            if distribution_acceptance is not None:
                phase_reports["s01"] = list(distribution_provenance.REPORTS)
            if support_acceptance is not None:
                phase_reports["s02"] = list(support_policy.REPORTS)
            if index_acceptance is not None:
                phase_reports["s03"] = list(binary_index.REPORTS)
            if program_acceptance is not None:
                phase_reports["program"] = list(program_integration.REPORTS)
            for phase in phase_reports:
                for case in runtime_cases.cases(phase):
                    report_names[phase + "-" + case] = [phase + "/" + case + "/reports.json"]
            checkpoints = retry.Checkpoints(sys.modules[__name__], validation, closure, temp, evidence, logs, report_names, canary_hits)
            stage = "independent isolated matrices"

            write(logs / "consumer-command.json", {"command": command("consumer-matrix", [*driver, "matrix"]),
                "cache_mode": "none", "producer_input_manifest_sha256": manifest["sha256"], "provenance": provenance()})
            commands = []
            for phase in ("p04", "m01", "m02", "m05", "g04", "g01", "g05", "g06", "s01", "s02", "s03", "program"):
                if phase not in phase_reports or m05_only and phase == "p04":
                    continue
                wrapper = {"p04": "fixtures/runtime-consumer/driver.py", "m01": "ci/scripts/mod_manifest.py",
                    "m02": "ci/scripts/runtime_sdk.py", "m05": "ci/scripts/mod_author.py",
                    "g04": "fixtures/runtime-qualification/driver.py", "g01": "fixtures/runtime-hooks/driver.py",
                    "g05": "fixtures/compatibility/driver.py", "g06": "fixtures/sdk-seams/driver.py",
                    "s01": "fixtures/distribution-provenance/driver.py", "s02": "fixtures/compatibility-policy/driver.py",
                    "s03": "fixtures/binary-index/driver.py", "program": "fixtures/tool-concurrency/driver.py"}[phase]
                for case in runtime_cases.cases(phase):
                    if phase == "g04" and case == "missing-library":
                        continue
                    label = phase + "-" + case
                    commands.append((label, command(label, [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B",
                        "/fixture/" + wrapper, "program-matrix" if phase == "program" else "matrix", case]), 1200))
            if g02a_acceptance is not None:
                for case in cases:
                    label = "g02a-" + case
                    commands.append((label, command(label, [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B",
                        "/fixture/fixtures/turn-budget/driver.py", case]), 600))
            if review_acceptance is not None:
                for case in review_steps:
                    label = "review-" + case
                    commands.append((label, command(label, [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B",
                        "/fixture/fixtures/review-before-send/driver.py", case]), 600))
            if concurrency_acceptance is not None:
                for case in concurrency_steps:
                    label = "concurrency-" + case
                    commands.append((label, command(label, [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B",
                        "/fixture/fixtures/tool-concurrency/driver.py", case]), 900))
            results = parallel_matrices(logs, commands, checkpoints.run)
            write(logs / "consumer-return.json", {"return_code": int(any(row.returncode for row in results.values())), "stage": stage})
            stage = "actual removed runtime library"
            missing_root = temp / "missing-library-root"
            copy_runtime_tree(root, missing_root)
            candidates = [path for path in closure["system_paths"]
                if Path(path).name in ("libcap.so.2", "libasound.so.2", "libstdc++.so.6")]
            assert candidates, "No removable packaged runtime dependency counterexample"
            removed = candidates[0]
            mutation = {"removed_library": removed, "sha256": sha(missing_root / removed.lstrip("/")),
                        "rootfs_before_sha256": closure["sha256"]}
            (missing_root / removed.lstrip("/")).unlink()
            write(missing_root / "fixture/missing-library.json", mutation)
            missing_base = [str(missing_root) if argument == str(root) else argument for argument in base]
            checkpoints.constraints["consumer-missing-library"] = {key: mutation[key] for key in ("removed_library", "sha256")}
            library_result = checkpoints.run(logs, "consumer-missing-library",
                command("consumer-missing-library", [*driver, "missing-library"], missing_base), 90)
            results["consumer-missing-library"] = library_result
            write(logs / "consumer-missing-library.json", {"return_code": library_result.returncode, "mutation": mutation})
            recovery_result = checkpoints.run(logs, "consumer-library-recovery",
                command("consumer-library-recovery", [*driver, "recovery"]), 120)
            results["consumer-library-recovery"] = recovery_result
            write(logs / "consumer-library-recovery.json", {"return_code": recovery_result.returncode})
            if g04_acceptance is not None:
                import shlex
                label = "g04-missing-library"
                checkpoints.constraints[label] = {key: mutation[key] for key in ("removed_library", "sha256")}
                transactions = [[*sandbox, "--", *CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B",
                    "/fixture/fixtures/runtime-qualification/driver.py", "matrix", "missing-library", step]
                    for step, sandbox in (("prepare", base), ("reject", missing_base), ("recover", base))]
                # Keep the shell program distinct from an absolute path in strace argv.
                script = "set -e; " + "; ".join(shlex.join(parts) for parts in transactions)
                results[label] = checkpoints.run(logs, label,
                    command(label, ["/usr/bin/bash", "-c", script], sandbox=[]), 600)
            remaining = []
            for phase in ("m03", "m04"):
                if phase not in phase_reports:
                    continue
                wrapper = {"m03": "managed_package", "m04": "runtime_state"}[phase]
                for case in runtime_cases.cases(phase):
                    label = phase + "-" + case
                    remaining.append((label, command(label, [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B",
                        "/fixture/ci/scripts/" + wrapper + ".py", "matrix", case]), 1800))
            results.update(parallel_matrices(logs, remaining, checkpoints.run))
            # Audit and sanitize even on a failed matrix, before exporting any trace.
            stage = "outer runtime audit"
            audits = {label: row["audit"] for label, row in checkpoints.results.items() if row["status"] == "pass"}
            if current_audit is not None:
                audits["s01-current-verification"] = current_audit
            if index_current_audit is not None:
                audits["s03-current-verification"] = index_current_audit
            audit = {"status": "pass", "compiler_linker_jit_build_service_calls": 0,
                "unclassified_executable_memory": [], "steps": audits,
                "normal_business_interpreter": {label: row["normal_business_interpreter"] for label, row in audits.items()
                    if row.get("normal_business_interpreter", {}).get("bindings")},
                "executable_memory_record_count": sum(row.get("executable_memory_record_count", 0) for row in audits.values()),
                "forbidden_mod_build_or_jit": 0,
                "executions": [line for row in audits.values() for line in row["executions"]],
                "packaged_bwrap_fd_executions": sorted({pid for row in audits.values() for pid in row["packaged_bwrap_fd_executions"]}),
                "tui_mcp_listener": next((row["tui_mcp_listener"] for row in audits.values() if row["tui_mcp_listener"]), None)}
            if any(row["status"] != "pass" for row in checkpoints.results.values()):
                audit.update(status="failed", compiler_linker_jit_build_service_calls=None,
                             note="Only independently passed steps have a reusable audit; failed traces remain failure evidence.")
            write(evidence / "outer-runtime-audit.json", audit)
            stage = "isolated matrix results"
            assert all(item.returncode == 0 for item in results.values()), "Independent isolated matrix failed"
            for phase, names in phase_reports.items():
                if not m05_only or phase != "p04":
                    runtime_cases.aggregate(evidence, phase, names)
            assert audit["packaged_bwrap_fd_executions"], "No actual nested packaged sandbox helper"
            assert any('execve("/inputs/host/codex-path/rg"' in line for line in audit["executions"]), "No actual packaged rg execution"
            assert not canary_hits
            stage = "final read-only input audit"
            assert inventory(root) == closure["files"], "Read-only runtime inputs changed"
            suite = read(evidence / ("m05/suite.json" if m05_only else "suite.json"))
            assert suite["status"] == "pass"
            missing = read(evidence / "missing-library.json")
            assert missing["status"] == "pass"
            for name in (() if m05_only else ("runtime-package-integrity.json", "zero-build-failure-matrix.json")):
                report = read(evidence / name)
                report["actual_removed_library"] = missing
                report["actual_library_recovery"] = read(evidence / "actual-missing-library-recovery.json")
                write(evidence / name, report)
            common = {"provenance": provenance(), "producer_job": producer["producer_job"],
                "consumer_job": os.environ["GITHUB_JOB"], "consumer_cache_mode": "none", "target": TARGET,
                "host": producer["host"], "input_manifest_sha256": manifest["sha256"], "rootfs_sha256": closure["sha256"],
                "outer_audit": report_audit(audit, evidence), "release_ready": False}
            common["production_origin"] = origin
            if not runtime_cases.historical_hosts():
                common["qualification_scope"] = runtime_cases.qualification_scope()
                write(evidence / "qualification-scope.json", common["qualification_scope"])
            common["test_build_origins"] = validation.get("test_builds", {})
            common["runtime_steps"] = {label: {k: v for k, v in row.items() if k != "audit"} for label, row in checkpoints.results.items()}
            if m05_acceptance is not None:
                common["host_origin"] = producer.get("host_origin")
                common["baseline_origin"] = producer.get("baseline_origin")
                common["build_kind"] = producer["m05"]["build_kind"]
            if m01_acceptance is not None:
                assert read(evidence / "m01/suite.json")["status"] == "pass"
                stage = "evidence redaction audit"
                check_evidence_redaction([*evidence.rglob("*.json"), *evidence.rglob("*.jsonl"),
                                          *evidence.rglob("*.log"), *logs.glob("*.log")])
                report = read(evidence / "metadata-only-resolution.json")
                report["producer_source_attachment_audit"] = producer["metadata_source_attachment_audit"]
                assert report["producer_source_attachment_audit"]["status"] == "pass"
                write(evidence / "metadata-only-resolution.json", report)
            if m02_acceptance is not None:
                assert read(evidence / "m02/suite.json")["status"] == "pass"
            if m05_acceptance is not None:
                check_evidence_redaction([*evidence.rglob("*.json"), *evidence.rglob("*.jsonl"),
                                          *evidence.rglob("*.log"), *logs.glob("*.log")])
            stage = "acceptance report promotion"
            report_sets = [] if m05_only else [p04_acceptance]
            if m01_acceptance is not None:
                report_sets.append(m01_acceptance)
            if m02_acceptance is not None:
                report_sets.append(m02_acceptance)
            if m03_acceptance is not None:
                assert read(evidence / "m03/suite.json")["status"] == "pass"
                report_sets.append(m03_acceptance)
            if m04_acceptance is not None:
                assert read(evidence / "m04/suite.json")["status"] == "pass"
                report_sets.append(m04_acceptance)
            if m05_acceptance is not None:
                assert read(evidence / "m05/suite.json")["status"] == "pass"
                report_sets.append(m05_acceptance)
            if g02a_acceptance is not None:
                for case in cases:
                    assert read(evidence / "g02a" / case / "suite.json")["status"] == "pass"
                report_sets.append(g02a_acceptance)
            if review_acceptance is not None:
                for case in review_steps:
                    assert read(evidence / "review" / case / "suite.json")["status"] == "pass"
                report_sets.append(review_acceptance)
            if concurrency_acceptance is not None:
                for case in concurrency_steps:
                    assert read(evidence / "concurrency" / case / "suite.json")["status"] == "pass"
                report_sets.append(concurrency_acceptance)
            if g04_acceptance is not None:
                runtime_qualification.reports(inputs, root, closure, evidence, audit, checkpoints.results, checkpoints.index)
                report_sets.append(g04_acceptance)
            if hooks_acceptance is not None:
                runtime_hooks.reports(evidence, checkpoints.results, audit)
                report_sets.append(hooks_acceptance)
            if upgrade_acceptance is not None:
                runtime_upgrade.reports(evidence, checkpoints.results, audit)
                report_sets.append(upgrade_acceptance)
            if seams_acceptance is not None:
                sdk_seams.reports(evidence, checkpoints.results, audit)
                report_sets.append(seams_acceptance)
            if distribution_acceptance is not None:
                distribution_provenance.reports(evidence, checkpoints.results, audit)
                report_sets.append(distribution_acceptance)
            if support_acceptance is not None:
                report_sets.append(support_acceptance)
            if index_acceptance is not None:
                binary_index.reports(evidence, checkpoints.results, audit)
                report_sets.append(index_acceptance)
            for report_set in report_sets:
                if not runtime_cases.historical_hosts():
                    report_set["qualification_scope"] = common["qualification_scope"]
                if report_set is support_acceptance:
                    # Hash baseline reports after their final provenance fields have been written.
                    support_policy.reports(evidence, inputs, validation, closure, checkpoints.results, audit, common)
                for check in report_set["checks"]:
                    path = evidence / Path(check["evidence"][0]).name
                    report = read(path)
                    assert report["status"] == "behavior_pass" and common.keys().isdisjoint(report)
                    status = "behavior_pass" if report_set is index_acceptance else "pass"
                    write(path, {**report, **common, "status": status})
                    label = check.get("phase")
                    phase = report_set["task_id"][3:].lower()
                    executions = {label: checkpoints.results[label]} if label else {
                        phase + "-" + case: checkpoints.results[phase + "-" + case] for case in runtime_cases.cases(phase)}
                    kinds = {row["kind"] for row in executions.values()}
                    check.update(status=status, command="isolated compiler-free consumer: " + (label or phase),
                        execution_kind=next(iter(kinds)) if len(kinds) == 1 else "mixed",
                        execution_origin={name: row["origin"] for name, row in executions.items()})
                    print("CM acceptance:", json.dumps({"report": path.name, "status": check["status"],
                        "execution_kind": check["execution_kind"],
                        "origin_runs": sorted({row["origin"]["GITHUB_RUN_ID"] for row in executions.values()})},
                        sort_keys=True), flush=True)
                report_set["status"] = "behavior_pass" if report_set is index_acceptance else "pass"
            if index_acceptance is not None and program_acceptance is None:
                binary_index.qualification_inputs(artifact, evidence, acceptance, common)
            print("CM runtime summary:", json.dumps({"steps": len(checkpoints.results),
                "executed": sum(row["kind"] == "executed" for row in checkpoints.results.values()),
                "reused": sum(row["kind"] == "reused" for row in checkpoints.results.values()),
                "audit_status": audit["status"],
                "compiler_linker_jit_build_service_calls": audit["compiler_linker_jit_build_service_calls"],
                "input_inventory": "pass", "isolation_probes": "pass", "canary_hits": len(canary_hits)},
                sort_keys=True), flush=True)
            if m01_acceptance is not None:
                write(artifact / "p04-baseline-acceptance.json", p04_acceptance)
                write(logs / "p04-baseline-acceptance.json", p04_acceptance)
            if m02_acceptance is not None:
                write(artifact / "m01-baseline-acceptance.json", m01_acceptance)
                write(logs / "m01-baseline-acceptance.json", m01_acceptance)
            if m03_acceptance is not None:
                write(artifact / "m02-baseline-acceptance.json", m02_acceptance)
                write(logs / "m02-baseline-acceptance.json", m02_acceptance)
            if m04_acceptance is not None:
                write(artifact / "m03-baseline-acceptance.json", m03_acceptance)
                write(logs / "m03-baseline-acceptance.json", m03_acceptance)
            if m05_acceptance is not None and not m05_only:
                write(artifact / "m04-baseline-acceptance.json", m04_acceptance)
                write(logs / "m04-baseline-acceptance.json", m04_acceptance)
            if g02a_acceptance is not None:
                write(artifact / "m05-baseline-acceptance.json", m05_acceptance)
                write(logs / "m05-baseline-acceptance.json", m05_acceptance)
            if review_acceptance is not None:
                write(artifact / "g02a-baseline-acceptance.json", g02a_acceptance)
                write(logs / "g02a-baseline-acceptance.json", g02a_acceptance)
            if concurrency_acceptance is not None:
                write(artifact / "g02b-baseline-acceptance.json", review_acceptance)
                write(logs / "g02b-baseline-acceptance.json", review_acceptance)
            if g04_acceptance is not None:
                write(artifact / "g03-baseline-acceptance.json", concurrency_acceptance)
                write(logs / "g03-baseline-acceptance.json", concurrency_acceptance)
            if upgrade_acceptance is not None or seams_acceptance is not None:
                for name, baseline in (("g04", g04_acceptance), ("g01", hooks_acceptance)):
                    write(artifact / (name + "-baseline-acceptance.json"), baseline)
                    write(logs / (name + "-baseline-acceptance.json"), baseline)
            if seams_acceptance is not None:
                if upgrade_acceptance is None:
                    import runtime_upgrade
                    upgrade_record = {"schema_version": 1, "task_id": "CM-G05", "target": TARGET, "status": "not_run",
                        "implementation_commit": os.environ["CM_SOURCE_SHA"], "qualification_scope": common["qualification_scope"],
                        "checks": [{"id": "CM-G05-AC0" + str(index), "status": "not_run",
                            "reason": runtime_cases.deferred_check("CM-G05")["reason"]}
                            for index, _ in enumerate(runtime_upgrade.REPORTS, 1)]}
                else:
                    upgrade_record = upgrade_acceptance
                write(artifact / "g05-baseline-acceptance.json", upgrade_record)
                write(logs / "g05-baseline-acceptance.json", upgrade_record)
            if distribution_acceptance is not None:
                write(artifact / "g06-baseline-acceptance.json", seams_acceptance)
                write(logs / "g06-baseline-acceptance.json", seams_acceptance)
            if support_acceptance is not None:
                write(artifact / "s01-baseline-acceptance.json", distribution_acceptance)
                write(logs / "s01-baseline-acceptance.json", distribution_acceptance)
            if index_acceptance is not None:
                write(artifact / "s02-baseline-acceptance.json", support_acceptance)
                write(logs / "s02-baseline-acceptance.json", support_acceptance)
            if program_acceptance is not None:
                write(artifact / "s03-behavior-baseline.json", index_acceptance)
                program_integration.reports(inputs, artifact, evidence, validation, checkpoints.results,
                    audit, common, program_acceptance)
        finally:
            stopped.set()
            thread.join(timeout=1)
            listener.close()
            if (temp / "trusted-observer").exists():
                import observer
                for path in (temp / "trusted-observer").rglob("syscalls.*"):
                    # No raw payload escapes on exception paths either.
                    text = path.read_text()
                    if not re.match(r'^\d+ ', text):
                        text = "".join(path.suffix[1:] + " " + line + "\n" for line in text.splitlines())
                    path.write_text(redact_trace(text, observer), encoding="utf-8")
                    target = evidence / "traces" / path.relative_to(temp / "trusted-observer")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
            copy_evidence(evidence, artifact / "evidence")
    except BaseException as error:
        acceptance.update(status="failed", failed_stage=stage, error=repr(error))
        raise
    finally:
        write(artifact / "acceptance.json", acceptance)
        shutil.copyfile(artifact / "acceptance.json", logs / "acceptance.json")
        copy_evidence(artifact / "evidence", logs / "acceptance-evidence")
        for path in logs.rglob("*"):
            if path.is_file() and path.suffix in {".json", ".jsonl", ".log"}:
                text = path.read_text()
                safe = mod_manifest.redact(text)
                if safe != text:
                    path.write_text(safe, encoding="utf-8")


def consume_index_proof():
    """Always fresh, small, cache-none proof consumption; no matrix replay or build toolchain."""
    hosted()
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    validate_inputs(inputs)
    sys.path.insert(0, str(inputs / "fixture/ci/scripts"))
    import binary_index
    import mod_manifest
    logs, artifact = Path(os.environ["CM_CI_LOG_DIR"]), Path(os.environ["CM_CI_ARTIFACT_DIR"])
    artifact.mkdir(parents=True, exist_ok=True)
    temp = Path(os.environ["RUNNER_TEMP"]) / "cm-index-proof-consumer"
    temp.mkdir()
    root = temp / "rootfs"
    closure = rootfs(inputs, root, upgrade_baseline=False)
    assert not (root / "inputs/upgrade-baseline").exists(), "Proof consumer must not require a historical Host"
    for name in ("profile", "work", "evidence", "trusted-observer"):
        (temp / name).mkdir()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    stopped, hits = threading.Event(), []
    def canary():
        while not stopped.is_set():
            try:
                connection, _ = listener.accept()
                hits.append("unexpected cross-namespace connection")
                connection.close()
            except socket.timeout:
                pass
    thread = threading.Thread(target=canary, daemon=True)
    thread.start()
    context = {"outer_namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ("user", "mnt", "pid", "ipc", "uts", "net")},
        "canary_port": listener.getsockname()[1], "provenance": provenance(), "cache_mode": "none",
        "input_manifest_sha256": read(inputs / "input-manifest.json")["sha256"],
        "image_os": os.environ["ImageOS"], "image_version": os.environ["ImageVersion"],
        "bind_roots": {point: str((temp / name).resolve()) for point, name in
            (("/", "rootfs"), ("/profile", "profile"), ("/work", "work"), ("/evidence", "evidence"))}}
    write(root / "fixture/context.json", context)
    closure["files"] = inventory(root)
    closure["sha256"] = digest(closure["files"])
    write(artifact / "rootfs-manifest.json", closure)
    base = ["/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
        "--uid", "1000", "--gid", "1000", "--cap-drop", "ALL", "--new-session", "--die-with-parent",
        "--hostname", "cm-consumer", "--ro-bind", str(root), "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--bind", str(temp / "profile"), "/profile", "--bind", str(temp / "work"), "/work",
        "--bind", str(temp / "evidence"), "/evidence", "--chdir", "/work", "--clearenv"]
    for key, value in {"PATH": "/usr/bin:/bin:/inputs/host/codex-path", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "CM_TARGET": TARGET, "CM_PLATFORM": linux_native()["key"],
            "TERM": "dumb", "TMPDIR": "/tmp", "HOME": "/home/fixture", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}.items():
        base += ["--setenv", key, value]
    evidence, audits = temp / "evidence", {}
    try:
        for label, script, action in (("s01-current-verification", "distribution-provenance", "verify-current"),
                ("s03-qualified-verification", "binary-index", "verify-qualified"), ("s03-proof", "binary-index", "proof")):
            trace = temp / "trusted-observer" / label
            trace.mkdir()
            argv = ["strace", "-ff", "-qq", "-yy", "--pidns-translation", "-s", "1024", "-e",
                TRACE_SYSCALLS,
                "-o", str(trace / "syscalls"), "--", *base, "--", *CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B",
                "/fixture/fixtures/" + script + "/driver.py", action]
            if label == "s03-proof":
                probe = ci_progress.run(logs, "index-proof-isolation", [*base, "--", *CONSUMER_ENV_PREFIX,
                    "/usr/bin/python3", "-B", "/fixture/fixtures/runtime-consumer/driver.py", "probe"], 180)
                assert probe.returncode == 0 and not hits
            result = ci_progress.run(logs, label, argv, 600)
            assert result.returncode == 0, label
            audits[label] = observe(trace, evidence, consumer_root=temp)
            if action != "proof":
                audit_offline_bootstrap(audits[label])
        assert inventory(root) == closure["files"] and not hits
        audit = {"status": "pass", "cache_mode": "none", "steps": audits, "provenance": provenance(),
            "isolation_probes": "pass", "canary_hits": hits, "toolchain_present": False}
        binary_index.final_reports(inputs, evidence, artifact, audit)
        write(artifact / "proof-consumer-binding.json", {"provenance": provenance(),
            "production_origin": read(inputs / "validation.json")["production_origin"],
            "qualification_artifact": read(logs / "index-qualification-artifact.json"), "audit": audit})
    finally:
        stopped.set()
        thread.join(1)
        listener.close()
        import observer
        for path in (temp / "trusted-observer").rglob("syscalls.*"):
            raw = "".join(path.suffix[1:] + " " + line + "\n" for line in path.read_text().splitlines())
            safe = mod_manifest.redact(redact_trace(raw, observer))
            target = logs / "traces" / path.relative_to(temp / "trusted-observer")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(safe, encoding="utf-8")
        copy_evidence(evidence, logs / "proof-evidence")


if __name__ == "__main__":
    {"produce": produce, "consume": lambda: consume(), "index-proof": consume_index_proof, "self-check": self_check}[sys.argv[1]]()
