"""P04 producer and trusted outer consumer. Never copied into the runtime root."""
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
import types

TARGET = "x86_64-unknown-linux-gnu"
CAPABILITY = "core.exec_output_limit.v1"
CONSUMER_ENV_PREFIX = ("/usr/bin/env", "-u", "PWD")
ENTRY_INVALID = ("short-prefix", "short-tail", "future-minor", "stride", "count", "null-array",
                 "misaligned-array", "reserved", "descriptor-size", "descriptor-minor",
                 "descriptor-reserved", "null-callback", "null-view", "huge-view", "utf8")
CALL_INVALID = ("callback-fail", "status", "cancelled", "increase", "zero", "keep-nonzero",
                "decision", "output-header", "output-reserved", "output-canary", "error-length",
                "error-null", "error-utf8", "error-canary")


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
        assert path.suffix not in (".rs", ".c", ".h", ".a"), path
        if "link" in entry:
            target = Path(entry["link"])
            assert not target.is_absolute() and (root / path).resolve().is_relative_to(root), path


def provenance():
    return {key: os.environ[key] for key in ("CM_SOURCE_REPOSITORY", "CM_SOURCE_SHA", "GITHUB_REPOSITORY",
            "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "CM_REQUEST_ID")}


def hosted():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64"
    assert os.environ["GITHUB_REPOSITORY"] == "DSLZL/CM-build-linux-x64"


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
                    *(("config",) if cfg["task_id"] in ("CM-M01", "CM-M02", "CM-M03") else ())):
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
                     "ci/scripts/mod_manifest.py"):
        destination = inputs / "fixture" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    metadata_audit = None
    binary_packages = None
    if cfg["task_id"] in ("CM-M01", "CM-M02", "CM-M03"):
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
    if cfg["task_id"] in ("CM-M02", "CM-M03"):
        from runtime_sdk import prepare
        runtime_sdk = prepare(inputs, package, authors)
    if cfg["task_id"] == "CM-M03":
        import managed_package
        managed_package.prepare(inputs, package, frozen, logs)
    write(inputs / "producer.json", {"schema_version": 1, "task_id": cfg["task_id"], "target": TARGET,
        "provenance": provenance(), "producer_job": os.environ["GITHUB_JOB"], "host": frozen, "authors": authors,
        "entry_invalid": ENTRY_INVALID, "call_invalid": CALL_INVALID,
        "regressions": {task: read(artifact / (task + "-baseline-acceptance.json")) for task in ("p01", "p02", "p03")},
        "maintained_source": read(logs / "host-source-provenance.json"), "official": host.manifest(inputs / "official"),
        "official_profile_setup": official_setup, "c_layout": read(logs / "output-limit-c-layout.log"),
        "metadata_source_attachment_audit": metadata_audit, "binary_packages": binary_packages,
        "runtime_sdk": runtime_sdk})
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
        matches = re.findall(r'^\s*' + re.escape(library) + r' .*x86-64.* => (/\S+)$', cache, re.MULTILINE)
        assert matches, "Unresolved ELF dependency: " + library
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


def rootfs(inputs, root):
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
    shutil.copytree(inputs / "fixture", root / "fixture")
    shutil.copyfile(inputs / "producer.json", root / "inputs/producer.json")
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


def self_check():
    import mod_manifest
    mod_manifest.self_check()
    import runtime_sdk
    runtime_sdk.self_check()
    import managed_package
    managed_package.self_check()
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
    unicode_host = "/work/m03/独立 Host/bin/codex"
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
            "/work/m03/独立 Host/bin/codex": data,
            "/work/m01/integrity/changed-host/codex": data + b"different executable identity",
            "/work/m01/integrity/changed-host-build-id/codex": data.replace(build_id.encode(), b"sha256:" + b"0" * 64),
        }
        for name, content in copies.items():
            actual = root / ("rootfs" + name if name.startswith("/inputs/") else name.lstrip("/"))
            actual.parent.mkdir(parents=True, exist_ok=True)
            actual.write_bytes(content)
        calls = ['1 execve("' + name + '", ["codex"], 0x1) = 0' for name in copies]
        bound = bind_host_executables(calls, root)
        assert bound == {name: hashlib.sha256(content).hexdigest() for name, content in copies.items()}
        tui = {"command": ["/inputs/host/bin/codex", "cm", "--home", "/profile/m03/tui", "launch", "--"],
            "tui": True, "empty_launch_argv": True,
            "identity": {"proc_exe": "/inputs/host/bin/codex", "executable_sha256": bound["/inputs/host/bin/codex"]},
            "provider_requests": [{"tools": [{"name": "mcp__codex_worktrees"}]}],
            "tui_mcp_listener": {"inode": "81", "port": 8080}}
        metadata = [
            '4 accept4(6<TCP:[81]>, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("127.0.0.1")}, [128 => 16], SOCK_CLOEXEC|SOCK_NONBLOCK) = 5<TCP:[71]>',
            '3 getsockname(6<TCP:[81]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, [128 => 16]) = 0']
        assert bind_tui_mcp_listener(tui, metadata, bound, observer) == {
            "port": "8080", "listener_inode": "81", "accepted_socket_inodes": ["71"]}
        for change in ({"tui": False}, {"empty_launch_argv": False},
                       {"command": [*tui["command"], "exec"]}, {"provider_requests": []},
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
        for name in ("/work/m03/独立 Host/bin/codex", "/work/m01/integrity/changed-host/codex",
                     "/work/m01/integrity/changed-host-build-id/codex", "/work/m01/integrity/changed-host-extra/codex"):
            actual = root / name.lstrip("/")
            actual.parent.mkdir(parents=True, exist_ok=True)
            actual.write_bytes(b"unexpected executable")
            try:
                bind_host_executables(['1 execve("' + name + '", ["codex"], 0x1) = 0'], root)
            except AssertionError:
                pass
            else:
                raise AssertionError("Unpinned Host bytes accepted: " + name)
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

    loader = "/lib64/ld-linux-x86-64.so.2"
    diversions = "diversion by libc6 from: " + loader + "\ndiversion by libc6 to: " + loader + ".usr-is-merged\n"
    assert dpkg_owners(diversions + "libc6:amd64: " + loader + "\n", loader) == ["libc6:amd64"]
    assert dpkg_owners("libc6:amd64, libc6-compat:amd64: " + loader, loader) == ["libc6-compat:amd64", "libc6:amd64"]
    assert dpkg_owners("bash: /bin/bash\n", "/bin/bash") == ["bash"]
    for invalid in (diversions, "not a package: " + loader, "-invalid: " + loader,
                    "libc6:amd64: " + loader + ".other", ""):
        assert dpkg_owners(invalid, loader) == []
    actual_owners = system_package_owners(Path(loader))
    assert "libc6:amd64" in actual_owners, actual_owners
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
    host = read(root / "rootfs/inputs/producer.json")["host"]
    assert expected == host["executable_sha256"], "Frozen Host differs from the producer"
    before = host["host_identity"]["host_build_id"].encode()
    data = primary.read_bytes()
    assert re.fullmatch(rb"sha256:[0-9a-f]{64}", before) and before in data
    after = b"sha256:" + (b"0" if before != b"sha256:" + b"0" * 64 else b"1") * 64
    # The M01 rejection matrix executes exactly these two deterministic mutations.
    rejected = {
        "/work/m01/integrity/changed-host/codex": hashlib.sha256(data + b"different executable identity").hexdigest(),
        "/work/m01/integrity/changed-host-build-id/codex": hashlib.sha256(data.replace(before, after)).hexdigest(),
    }
    del data
    bound = {}
    for line in executions:
        match = re.search(r'execve\("([^"]+)"', line)
        if not match or Path(match[1]).name != "codex":
            continue
        path = Path(match[1])
        if path.is_relative_to("/inputs/host"):
            actual = root / "rootfs" / path.relative_to("/")
        elif path.is_relative_to("/work") or path.is_relative_to("/profile"):
            actual = root / path.relative_to("/")
        else:
            raise AssertionError("Unbound Host executable: " + str(path))
        wanted = rejected.get(str(path), expected)
        assert ".." not in path.parts and actual.is_file() and sha(actual) == wanted, "Host bytes differ: " + str(path)
        bound[str(path)] = wanted
    return bound


def bind_tui_mcp_listener(record, metadata, bound_hosts, observer):
    command = ["/inputs/host/bin/codex", "cm", "--home", "/profile/m03/tui", "launch", "--"]
    assert record["command"] == command and record["tui"] and record["empty_launch_argv"]
    assert record["identity"]["proc_exe"] == command[0]
    assert record["identity"]["executable_sha256"] == bound_hosts[command[0]]
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
    return {"port": port, "listener_inode": inode, "accepted_socket_inodes": sorted(connections)}


def observe(directory, evidence):
    import observer
    observer.check_network_audit()
    scripts = ("fixtures/native-loader/tool_barrier.py", "fixtures/runtime-consumer/driver.py",
               "ci/scripts/mod_manifest.py", "ci/scripts/runtime_sdk.py", "ci/scripts/managed_package.py")
    network = []
    sockets = []
    tcp_metadata = []
    symlinks = []
    bwrap_executions = set()
    executions = []
    files = []
    executable_memory = []
    for path in sorted(directory.glob("syscalls.*")):
        assert path.suffix[1:].isdigit(), path
        pid = path.suffix[1:]
        text = redact_trace("\n".join(pid + " " + line for line in path.read_text().splitlines()) + "\n", observer)
        path.write_text(text, encoding="utf-8")
        assert not re.search(r'\b(?:sendto|recvfrom)\([^\n]*?, "(?!<payload redacted>)', text)
        calls = observer.complete_syscalls(text.splitlines())
        bwrap_executions.update(observer.bound_bwrap_executions(calls,
            ("/inputs/host/codex-resources/bwrap", "/work/m03/独立 Host/codex-resources/bwrap")))
        sockets.extend(line for line in calls if re.match(r'\d+\s+socket\(', line))
        tcp_metadata.extend(line for line in calls if re.match(r'\d+\s+(?:getsockname|accept|accept4)\(', line))
        symlinks.extend(line for line in calls if re.match(r'\d+\s+symlink(?:at)?\(', line))
        executions.extend(line for line in calls if re.match(r'\d+\s+execve(?:at)?\(', line))
        network.extend(line for line in calls if re.match(r'\d+\s+(?:connect|sendto|socketpair)\(', line))
        files.extend(line for line in calls if re.match(r'\d+\s+(?:openat|readlink)\(', line))
        # This fixed native fixture has no supported in-process code generator.
        executable_memory.extend(line for line in calls if "PROT_EXEC" in line and
            ("MAP_ANONYMOUS" in line or re.match(r'\d+\s+mprotect\(', line)))
    hosts = ("/inputs/host/bin/codex", "/work/m03/独立 Host/bin/codex")
    aliases = observer.bound_sandbox_aliases(symlinks, hosts)
    alias_targets = {}
    for line in symlinks:
        paths = re.findall(r'"([^"]+)"', line)
        if len(paths) == 2 and paths[1] in aliases and paths[0] in hosts:
            assert paths[1] not in alias_targets or alias_targets[paths[1]] == paths[0]
            alias_targets[paths[1]] = paths[0]
    assert set(alias_targets) == aliases
    bound_hosts = bind_host_executables(executions, directory.parent)
    observer.audit_executions(executions, python_scripts=scripts, sandbox_aliases=aliases, bwrap_executions=bwrap_executions)
    assert bwrap_executions, "No actual nested packaged sandbox helper"
    assert any('execve("/inputs/host/codex-path/rg"' in line for line in executions), "No actual packaged rg execution"
    ports = set()
    for path in evidence.rglob("result.json"):
        record = read(path)
        ports.update(re.findall(r'http://127[.]0[.]0[.]1:(\d+)', " ".join(record.get("command", []))
            + " " + record.get("provider_endpoint", "")))
    tui_mcp = None
    tui_result = evidence / "m03/actual-tui/result.json"
    if tui_result.exists() and read(tui_result).get("tui_mcp_listener"):
        tui_mcp = bind_tui_mcp_listener(read(tui_result), tcp_metadata, bound_hosts, observer)
        ports.add(tui_mcp["port"])
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
    observer.audit_network(normalized, Path("/evidence"), ports, routes, tcp_connections)
    # Writable executable mappings are unsupported, even if no compiler was exec'd.
    assert not executable_memory, "Unclassified runtime code generation: " + repr(executable_memory)
    assert files, "File-load observer produced no records"
    return {"status": "pass", "executions": executions, "network": network, "kernel_route_sockets": sorted(routes),
        "provider_tcp_connections": sorted(tcp_connections), "provider_tcp_metadata": tcp_metadata,
        "tui_mcp_listener": tui_mcp,
        "sandbox_aliases": [{"path": path, "target": alias_targets[path]} for path in sorted(aliases)],
        "packaged_bwrap_fd_executions": sorted(bwrap_executions),
        "bound_host_executables": bound_hosts,
        "file_load_count": len(files), "trace_files": [path.name for path in sorted(directory.glob("syscalls.*"))],
        "compiler_linker_jit_build_service_calls": 0, "unclassified_executable_memory": executable_memory,
        "boundary": "fixed audited native fixtures; not a generic malicious-native JIT detector",
        "socket_payloads": "sendto/recvfrom redacted in both audit and export"}


def consume():
    hosted()
    assert os.environ["CM_CACHE_MODE"] == "none" and os.environ["ACTIONS_CACHE_MODE"] == "none"
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"]).resolve()
    manifest = validate_inputs(inputs)
    producer = read(inputs / "producer.json")
    assert producer["provenance"] == provenance(), "Input is not from this exact run/attempt/request/source/workflow"
    assert producer["task_id"] in ("CM-P04", "CM-M01", "CM-M02", "CM-M03") and producer["target"] == TARGET
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    artifact.mkdir(parents=True)
    logs.mkdir(parents=True, exist_ok=True)
    p04_acceptance = {"schema_version": 1, "task_id": "CM-P04", "target": TARGET, "status": "not_run",
        "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-P04-AC0" + str(index),
        "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate((
        "frozen-host-independent-mods.json", "zero-build-runtime-environment.json", "plug-and-play-matrix.json",
        "runtime-package-integrity.json", "zero-build-failure-matrix.json", "empty-host-independent-install.json"), 1)]}
    sys.path.insert(0, str(inputs / "fixture/ci/scripts"))
    import mod_manifest
    m01_acceptance = None
    if producer["task_id"] in ("CM-M01", "CM-M02", "CM-M03"):
        m01_acceptance = {"schema_version": 1, "task_id": "CM-M01", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M01-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(mod_manifest.REPORTS, 1)]}
    m02_acceptance = None
    if producer["task_id"] in ("CM-M02", "CM-M03"):
        import runtime_sdk
        m02_acceptance = {"schema_version": 1, "task_id": "CM-M02", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M02-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(runtime_sdk.REPORTS, 1)]}
    acceptance = m02_acceptance or m01_acceptance or p04_acceptance
    if producer["task_id"] == "CM-M03":
        import managed_package
        acceptance = {"schema_version": 1, "task_id": "CM-M03", "target": TARGET, "status": "not_run",
            "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-M03-AC0" + str(index),
            "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate(managed_package.REPORTS, 1)]}
    write(artifact / "acceptance.json", acceptance)
    stage = "rootfs"
    try:
        temp = Path(os.environ["RUNNER_TEMP"]) / "cm-runtime-consumer"
        temp.mkdir()
        root = temp / "rootfs"
        closure = rootfs(inputs, root)
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
                           "TERM": "dumb", "TMPDIR": "/tmp", "HOME": "/home/fixture", "PYTHONNOUSERSITE": "1",
                           "PYTHONDONTWRITEBYTECODE": "1"}.items():
            base += ["--setenv", key, value]
        driver = [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B", "/fixture/fixtures/runtime-consumer/driver.py"]
        try:
            stage = "strict isolation probes"
            with (logs / "consumer-probes.log").open("w") as stream:
                result = subprocess.run([*base, "--", *driver, "probe"], stdout=stream, stderr=subprocess.STDOUT,
                                        close_fds=True, timeout=180)
            write(logs / "consumer-probes.json", {"return_code": result.returncode, "stage": stage})
            assert result.returncode == 0, "Strict namespace/probe setup failed"
            assert not canary_hits
            trusted = temp / "trusted-observer"
            trusted.mkdir()
            stage = "actual isolated matrix"
            trace = ["strace", "-ff", "-qq", "-yy", "-s", "1024", "-e",
                "trace=execve,execveat,socket,getsockname,accept,accept4,connect,sendto,recvfrom,socketpair,symlink,symlinkat,open,openat,openat2,close,close_range,dup,dup2,dup3,fcntl,readlink,mmap,mprotect,memfd_create",
                "-o", str(trusted / "syscalls"), "--"]
            write(logs / "consumer-command.json", {"command": [*trace, *base, "--", *driver, "matrix"],
                "cache_mode": "none", "producer_input_manifest_sha256": manifest["sha256"], "provenance": provenance()})
            with (logs / "consumer-matrix.log").open("w") as stream:
                result = subprocess.run([*trace, *base, "--", *driver, "matrix"], stdout=stream,
                    stderr=subprocess.STDOUT, close_fds=True, timeout=1800)
            write(logs / "consumer-return.json", {"return_code": result.returncode, "stage": stage})
            if result.returncode == 0:
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
                with (logs / "consumer-missing-library.log").open("w") as stream:
                    library_result = subprocess.run([*trace, *missing_base, "--", *driver, "missing-library"],
                        stdout=stream, stderr=subprocess.STDOUT, close_fds=True, timeout=90)
                write(logs / "consumer-missing-library.json", {"return_code": library_result.returncode, "mutation": mutation})
                assert library_result.returncode == 0, "Missing actual runtime dependency was not rejected"
                with (logs / "consumer-library-recovery.log").open("w") as stream:
                    recovery_result = subprocess.run([*trace, *base, "--", *driver, "recovery"],
                        stdout=stream, stderr=subprocess.STDOUT, close_fds=True, timeout=120)
                write(logs / "consumer-library-recovery.json", {"return_code": recovery_result.returncode})
                assert recovery_result.returncode == 0, "Known successful selection failed after the missing-library candidate"
                if producer["task_id"] in ("CM-M01", "CM-M02", "CM-M03"):
                    stage = "M01 actual packaged CLI and native configuration"
                    m01_driver = [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B", "/fixture/ci/scripts/mod_manifest.py", "matrix"]
                    with (logs / "m01-consumer-matrix.log").open("w") as stream:
                        result = subprocess.run([*trace, *base, "--", *m01_driver], stdout=stream,
                            stderr=subprocess.STDOUT, close_fds=True, timeout=1200)
                    write(logs / "m01-consumer-return.json", {"return_code": result.returncode, "stage": stage})
                    assert result.returncode == 0, "M01 current-source regression failed"
                if producer["task_id"] in ("CM-M02", "CM-M03"):
                    stage = "M02 actual runtime SDK and packaged Host adapter"
                    m02_driver = [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B", "/fixture/ci/scripts/runtime_sdk.py", "matrix"]
                    with (logs / "m02-consumer-matrix.log").open("w") as stream:
                        result = subprocess.run([*trace, *base, "--", *m02_driver], stdout=stream,
                            stderr=subprocess.STDOUT, close_fds=True, timeout=1200)
                    write(logs / "m02-consumer-return.json", {"return_code": result.returncode, "stage": stage})
                if producer["task_id"] == "CM-M03":
                    assert result.returncode == 0, "M02 current-source regression failed"
                    stage = "M03 managed install and actual PTY TUI"
                    m03_driver = [*CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B", "/fixture/ci/scripts/managed_package.py", "matrix"]
                    with (logs / "m03-consumer-matrix.log").open("w") as stream:
                        result = subprocess.run([*trace, *base, "--", *m03_driver], stdout=stream,
                            stderr=subprocess.STDOUT, close_fds=True, timeout=1200)
                    write(logs / "m03-consumer-return.json", {"return_code": result.returncode, "stage": stage})
            # Audit and sanitize even on a failed matrix, before exporting any trace.
            audit = observe(trusted, evidence)
            write(evidence / "outer-runtime-audit.json", audit)
            assert result.returncode == 0, "Isolated product matrix failed"
            assert not canary_hits
            assert inventory(root) == closure["files"], "Read-only runtime inputs changed"
            suite = read(evidence / "suite.json")
            assert suite["status"] == "pass"
            missing = read(evidence / "missing-library.json")
            assert missing["status"] == "pass"
            for name in ("runtime-package-integrity.json", "zero-build-failure-matrix.json"):
                report = read(evidence / name)
                report["actual_removed_library"] = missing
                report["actual_library_recovery"] = read(evidence / "actual-missing-library-recovery.json")
                write(evidence / name, report)
            common = {"provenance": provenance(), "producer_job": producer["producer_job"],
                "consumer_job": os.environ["GITHUB_JOB"], "consumer_cache_mode": "none", "target": TARGET,
                "host": producer["host"], "input_manifest_sha256": manifest["sha256"], "rootfs_sha256": closure["sha256"],
                "outer_audit": audit, "release_ready": False}
            if producer["task_id"] in ("CM-M01", "CM-M02", "CM-M03"):
                assert read(evidence / "m01/suite.json")["status"] == "pass"
                for path in [*evidence.rglob("*.json"), *evidence.rglob("*.jsonl"), *evidence.rglob("*.log"),
                             *logs.glob("*.log")]:
                    assert all(secret not in path.read_text() for secret in mod_manifest.CANARIES), "Configuration value leaked into evidence"
                report = read(evidence / "metadata-only-resolution.json")
                report["producer_source_attachment_audit"] = producer["metadata_source_attachment_audit"]
                assert report["producer_source_attachment_audit"]["status"] == "pass"
                write(evidence / "metadata-only-resolution.json", report)
            if producer["task_id"] in ("CM-M02", "CM-M03"):
                assert read(evidence / "m02/suite.json")["status"] == "pass"
            report_sets = [p04_acceptance]
            if m01_acceptance is not None:
                report_sets.append(m01_acceptance)
            if m02_acceptance is not None:
                report_sets.append(m02_acceptance)
            if producer["task_id"] == "CM-M03":
                assert read(evidence / "m03/suite.json")["status"] == "pass"
                report_sets.append(acceptance)
            for report_set in report_sets:
                for check in report_set["checks"]:
                    path = evidence / Path(check["evidence"][0]).name
                    report = read(path)
                    assert report["status"] == "behavior_pass" and common.keys().isdisjoint(report)
                    write(path, {**report, **common, "status": "pass"})
                    check.update(status="pass", command="isolated compiler-free consumer: " + report_set["task_id"] + " matrix")
                report_set["status"] = "pass"
            if producer["task_id"] in ("CM-M01", "CM-M02", "CM-M03"):
                write(artifact / "p04-baseline-acceptance.json", p04_acceptance)
                write(logs / "p04-baseline-acceptance.json", p04_acceptance)
            if producer["task_id"] in ("CM-M02", "CM-M03"):
                write(artifact / "m01-baseline-acceptance.json", m01_acceptance)
                write(logs / "m01-baseline-acceptance.json", m01_acceptance)
            if producer["task_id"] == "CM-M03":
                write(artifact / "m02-baseline-acceptance.json", m02_acceptance)
                write(logs / "m02-baseline-acceptance.json", m02_acceptance)
        finally:
            stopped.set()
            thread.join(timeout=1)
            listener.close()
            if (temp / "trusted-observer").exists():
                import observer
                for path in (temp / "trusted-observer").glob("syscalls.*"):
                    # No raw payload escapes on exception paths either.
                    text = path.read_text()
                    if not re.match(r'^\d+ ', text):
                        text = "\n".join(path.suffix[1:] + " " + line for line in text.splitlines()) + "\n"
                    path.write_text(redact_trace(text, observer), encoding="utf-8")
                    shutil.copyfile(path, evidence / path.name)
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


if __name__ == "__main__":
    {"produce": produce, "consume": lambda: consume(), "self-check": self_check}[sys.argv[1]]()
