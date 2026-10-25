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

TARGET = "x86_64-unknown-linux-gnu"
CAPABILITY = "core.exec_output_limit.v1"
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


def produce():
    import host
    import runtime_composition as composition
    from linux_ci import cargo_args, execute, load_config

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
    for variant in ("normal", "two-limiters", "init-fail", *ENTRY_INVALID, *CALL_INVALID):
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
    assert "linux_x64_additive_layout ... ok" in (logs / "host-test.log").read_text()
    for relative in ("fixtures/runtime-consumer/driver.py", "fixtures/native-loader/core_acceptance.py", "fixtures/native-loader/tool_barrier.py"):
        destination = inputs / "fixture" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    # Only runtime parser functions are handed to the outer observer, not build modules.
    observer = "import json\nimport re\nfrom pathlib import Path\n\n" + "\n\n".join(inspect.getsource(getattr(composition, name))
        for name in ("redact_syscalls", "complete_syscalls", "audit_network", "audit_executions", "check_network_audit"))
    (inputs / "observer.py").write_text(observer, encoding="utf-8")
    shutil.copyfile(Path(__file__), inputs / "runtime_consumer.py")
    official_root = Path(os.environ["RUNNER_TEMP"]) / "cm-p04-official"
    official_root.mkdir()
    installation, official = host.official_fixture(root, official_root)
    profile = official_root / "profile"
    profile.mkdir()
    subprocess.run([str(official), "--version"], env={"PATH": "/usr/bin:/bin", "HOME": str(profile), "CODEX_HOME": str(profile)}, check=True)
    shutil.copytree(installation, inputs / "official/install", symlinks=True)
    shutil.copytree(profile, inputs / "official/profile", symlinks=True)
    write(inputs / "producer.json", {"schema_version": 1, "task_id": "CM-P04", "target": TARGET,
        "provenance": provenance(), "producer_job": os.environ["GITHUB_JOB"], "host": frozen, "authors": authors,
        "entry_invalid": ENTRY_INVALID, "call_invalid": CALL_INVALID,
        "regressions": {task: read(artifact / (task + "-baseline-acceptance.json")) for task in ("p01", "p02", "p03")},
        "maintained_source": read(logs / "host-source-provenance.json"), "official": host.manifest(inputs / "official"),
        "c_layout": read(logs / "output-limit-c-layout.log")})
    entries = inventory(inputs)
    write(inputs / "input-manifest.json", {"files": entries, "sha256": digest(entries)})
    transfer = Path(os.environ["CM_CONSUMER_TRANSFER_DIR"])
    transfer.mkdir()
    with tarfile.open(transfer / "runtime-inputs.tar", "w") as archive:
        archive.add(inputs, arcname="runtime-inputs")
    assert host.manifest_digest(host.manifest(package)) == frozen["package_manifest_sha256"]
    write(artifact / "producer-inputs.json", {"status": "pass", "task_id": "CM-P04", "input_manifest_sha256": digest(entries),
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
        owner = None
        for candidate in dict.fromkeys((str(path), str(path.resolve()), str(path.resolve()).removeprefix("/usr"))):
            query = subprocess.run(["dpkg-query", "-S", candidate], capture_output=True, text=True)
            if query.returncode == 0:
                owner = query.stdout.split(": ")[0].splitlines()[0]
                break
        assert owner, "Unowned runtime input: " + str(path)
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
    shutil.copytree(inputs / "host", root / "inputs/host", copy_function=os.link, symlinks=True)
    shutil.copytree(inputs / "mods", root / "inputs/mods", copy_function=os.link, symlinks=True)
    shutil.copytree(inputs / "official", root / "inputs/official", copy_function=os.link, symlinks=True)
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


def self_check():
    import runtime_composition as observer
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fixtures/native-loader"))
    from core_acceptance import trace_rows

    observer.check_network_audit()
    for source in ('1 recvfrom(4<UNIX-STREAM:[1->2]>, "observer-secret", 15, 0, NULL, NULL) = 15',
                   '1 <... recvfrom resumed>"observer-secret", 15, 0, NULL, NULL) = 15'):
        sanitized = observer.redact_syscalls(source)
        assert "observer-secret" not in sanitized and "payload redacted" in sanitized
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


def observe(directory, evidence):
    import observer
    observer.check_network_audit()
    scripts = ("fixtures/native-loader/tool_barrier.py", "fixtures/runtime-consumer/driver.py")
    network = []
    executions = []
    files = []
    executable_memory = []
    for path in sorted(directory.glob("syscalls.*")):
        assert path.suffix[1:].isdigit(), path
        pid = path.suffix[1:]
        text = observer.redact_syscalls("\n".join(pid + " " + line for line in path.read_text().splitlines()) + "\n")
        path.write_text(text, encoding="utf-8")
        assert not re.search(r'\b(?:sendto|recvfrom)\([^\n]*?, "(?!<payload redacted>)', text)
        calls = observer.complete_syscalls(text.splitlines())
        executions.extend(line for line in calls if re.match(r'\d+\s+execve(?:at)?\(', line))
        network.extend(line for line in calls if re.match(r'\d+\s+(?:connect|sendto|socketpair)\(', line))
        files.extend(line for line in calls if re.match(r'\d+\s+(?:openat|readlink)\(', line))
        # This fixed native fixture has no supported in-process code generator.
        executable_memory.extend(line for line in calls if "PROT_EXEC" in line and
            ("MAP_ANONYMOUS" in line or re.match(r'\d+\s+mprotect\(', line)))
    observer.audit_executions(executions, python_scripts=scripts)
    assert any('execve("/inputs/host/codex-resources/bwrap"' in line for line in executions), "No actual nested packaged sandbox helper"
    assert any('execve("/inputs/host/codex-path/rg"' in line for line in executions), "No actual packaged rg execution"
    ports = set()
    for path in evidence.rglob("result.json"):
        ports.update(re.findall(r'http://127[.]0[.]0[.]1:(\d+)', " ".join(read(path).get("command", []))))
    # The outer observer also sees the provider's responses. Normalize only the
    # reverse half of an already identified loopback provider connection.
    normalized = []
    for line in network:
        peer = re.search(r'<TCP:\[127\.0\.0\.1:(\d+)->127\.0\.0\.1:(\d+)\]>', line)
        if peer and peer[1] in ports:
            line = line[:peer.start()] + '<TCP:[127.0.0.1:' + peer[2] + '->127.0.0.1:' + peer[1] + ']>' + line[peer.end():]
        normalized.append(line)
    observer.audit_network(normalized, Path("/evidence"), ports)
    # Writable executable mappings are unsupported, even if no compiler was exec'd.
    assert not executable_memory, "Unclassified runtime code generation: " + repr(executable_memory)
    assert files, "File-load observer produced no records"
    return {"status": "pass", "executions": executions, "network": network,
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
    assert producer["task_id"] == "CM-P04" and producer["target"] == TARGET
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    artifact.mkdir(parents=True)
    logs.mkdir(parents=True, exist_ok=True)
    acceptance = {"schema_version": 1, "task_id": "CM-P04", "target": TARGET, "status": "not_run",
        "implementation_commit": os.environ["CM_SOURCE_SHA"], "checks": [{"id": "CM-P04-AC0" + str(index),
        "status": "not_run", "evidence": ["evidence/" + name]} for index, name in enumerate((
        "frozen-host-independent-mods.json", "zero-build-runtime-environment.json", "plug-and-play-matrix.json",
        "runtime-package-integrity.json", "zero-build-failure-matrix.json", "empty-host-independent-install.json"), 1)]}
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
                   "input_manifest_sha256": manifest["sha256"]}
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
        driver = ["/usr/bin/python3", "-B", "/fixture/fixtures/runtime-consumer/driver.py"]
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
                "trace=execve,execveat,connect,sendto,recvfrom,socketpair,openat,readlink,mmap,mprotect,memfd_create",
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
                shutil.copytree(root, missing_root, copy_function=os.link, symlinks=True)
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
            for check in acceptance["checks"]:
                path = evidence / Path(check["evidence"][0]).name
                report = read(path)
                assert report["status"] == "behavior_pass" and common.keys().isdisjoint(report)
                write(path, {**report, **common, "status": "pass"})
                check.update(status="pass", command="isolated compiler-free consumer: driver.py matrix")
            acceptance["status"] = "pass"
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
                    path.write_text(observer.redact_syscalls(text), encoding="utf-8")
                    shutil.copyfile(path, evidence / path.name)
            shutil.copytree(evidence, artifact / "evidence", dirs_exist_ok=True)
    except BaseException as error:
        acceptance.update(status="failed", failed_stage=stage, error=repr(error))
        raise
    finally:
        write(artifact / "acceptance.json", acceptance)
        shutil.copyfile(artifact / "acceptance.json", logs / "acceptance.json")
        for path in (artifact / "evidence").rglob("*"):
            if path.is_file() and path.suffix in {".json", ".jsonl", ".log"} or (path.is_file() and path.name.startswith("syscalls.")):
                data = path.read_bytes()
                data.decode("utf-8")
                assert b"\0" not in data and len(data) <= 16 * 1024 * 1024, path
                destination = logs / "acceptance-evidence" / path.relative_to(artifact / "evidence")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)


if __name__ == "__main__":
    {"produce": produce, "consume": lambda: consume(), "self-check": self_check}[sys.argv[1]]()
