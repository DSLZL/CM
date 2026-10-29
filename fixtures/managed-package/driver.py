#!/usr/bin/env python3
"""Actual managed CLI and PTY TUI; runs only inside the independent runtime consumer."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci/scripts"))
import ci_progress

INPUTS = Path("/inputs")
BINARY = INPUTS / "host/bin/codex"
WORK = Path("/work/m03")
PROFILE = Path("/profile/m03")
EVIDENCE = Path("/evidence/m03")
COPY = WORK / "独立 Host"
OFFICIAL_PROFILE = WORK / "official-profile"
_counter = 0


def sdk_module():
    path = Path(__file__).resolve().parents[1] / "runtime-sdk/driver.py"
    spec = importlib.util.spec_from_file_location("cm_m03_sdk", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def state(home):
    active = home / "cm-profile.json"
    raw = active.read_bytes()
    value = json.loads(raw)
    generation = home / "store/generations" / value["generation"]
    assert sha(generation) == value["generation"]
    return raw, json.loads(generation.read_bytes())


def protected_inventory(root):
    result = []
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        result.append({"path": path.relative_to(root).as_posix(), "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid, "mtime_ns": info.st_mtime_ns,
            "sha256": sha(path) if stat.S_ISREG(info.st_mode) else None,
            "link": os.readlink(path) if stat.S_ISLNK(info.st_mode) else None})
    return result


def official_entrypoint(installation):
    binaries = [path for path in installation.rglob("*") if path.is_file() and
                path.name in {"codex", "codex-x86_64-unknown-linux-musl"}]
    assert len(binaries) == 1, "Official fixture must contain exactly one Codex entrypoint"
    return binaries[0]


def environment(directory, *, official=True):
    directory.mkdir(parents=True, exist_ok=True)
    home = directory / "shell-home"
    home.mkdir(exist_ok=True)
    return {"PATH": "/work/m03/global:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "TERM": "xterm-256color", "HOME": str(home),
        "CODEX_HOME": str(OFFICIAL_PROFILE) if official else str(home),
        "CODEX_SQLITE_HOME": str(OFFICIAL_PROFILE) if official else str(home),
        "CM_NATIVE_TRACE": str(directory / "native.jsonl"),
        "CM_RUNTIME_EVENTS": str(directory / "events.jsonl"),
        "CM_REPLACEMENT_SENTINEL": str(directory / "constructor-sentinel")}


@ci_progress.case()
def cm(home, *args, success=True, binary=BINARY):
    global _counter
    _counter += 1
    directory = EVIDENCE / ("management-" + str(_counter))
    command = [str(binary), "cm", "--home", str(home), *map(str, args)]
    result = subprocess.run(command, env=environment(directory), cwd=WORK,
        capture_output=True, text=True, timeout=90)
    value = json.loads(result.stdout) if result.returncode == 0 else None
    record = {"command": command, "return_code": result.returncode, "output": value, "stderr": result.stderr}
    write(directory / "result.json", record)
    assert (result.returncode == 0) is success, record
    assert not any((directory / name).exists() for name in ("constructor-sentinel", "native.jsonl", "events.jsonl"))
    return value if success else record


def populated(home, *, binary=BINARY, runtime=True):
    packages = ("lifecycle-audit", "example-tool") if runtime else ("m01-a", "m01-b")
    for owner in packages:
        source = INPUTS / "mods/m02" / owner / "normal" if runtime else INPUTS / "mods" / owner
        cm(home, "install", source, binary=binary)
    return state(home)


def launch_command(binary, home, arguments):
    return [str(binary), "cm", "--home", str(home), "launch", "--", *arguments]


def identity(process, expected):
    path = Path("/proc") / str(process.pid) / "exe"
    actual = os.readlink(path)
    assert sha(path) == expected
    return {"pid": process.pid, "proc_exe": actual, "executable_sha256": sha(path)}


def tui_configuration(arguments, directory):
    flags = arguments[:arguments.index("exec")]
    settings = [flags[index + 1] for index, flag in enumerate(flags) if flag == "-c"]
    settings += ['model="gpt-5.4"', 'sandbox_mode="workspace-write"',
                 'projects.' + json.dumps(str(directory)) + '.trust_level="trusted"']
    text = "\n".join(settings) + "\n"
    tomllib.loads(text)
    return text


def tui_message_visible(output, token):
    # Terminal redraws position words separately; window titles are not screen output.
    text = re.sub(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", b"", bytes(output))
    text = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", text)
    return ("M02complete" + token).encode() in re.sub(rb"\s+", b"", text)


def tui_mcp_listener(pid):
    owned = set()
    for path in (Path("/proc") / str(pid) / "fd").iterdir():
        try:
            link = os.readlink(path)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", link)
        if match:
            owned.add(match[1])
    listeners = []
    for line in (Path("/proc") / str(pid) / "net/tcp").read_text().splitlines()[1:]:
        row = line.split()
        address, port = row[1].split(":")
        if row[3] == "0A" and address == "0100007F" and row[9] in owned:
            listeners.append({"inode": row[9], "port": int(port, 16)})
    assert len(listeners) == 1, listeners
    return listeners[0]


@ci_progress.case("name")
def business(name, home, sdk, *, binary=BINARY, tui=False, tool=True, mutate=None):
    directory = EVIDENCE / name
    directory.mkdir(parents=True)
    provider = sdk.Provider(tool=tool)
    env = sdk.environment(home, directory, mode="async" if mutate else "handles")
    env["PATH"] = "/work/m03/global:" + env["PATH"]
    env["TERM"] = "xterm-256color"
    env["CODEX_HOME"] = env["CODEX_SQLITE_HOME"] = str(OFFICIAL_PROFILE)
    token = re.sub("[^a-z0-9_-]", "-", name)
    arguments = sdk.command(directory, provider.endpoint, "embedded", token=token)[1:]
    expected_input = "CM_M02_" + token + " 中文 空格 '引号' \"双引号\" -- ; $(false)"
    arguments[-1] = expected_input
    before_launch = state(home)
    initial = before_launch
    terminal = None
    reader = None
    stdout = None
    stderr = None
    process = None
    observed = None
    mcp_listener = None
    output = bytearray()
    stop = threading.Event()
    try:
        if tui:
            # An empty argv enters the real terminal UI. Provider/project settings live in its independent home.
            (home / "config.toml").write_text(tui_configuration(arguments, directory))
            command = launch_command(binary, home, [])
            master, slave = pty.openpty()
            terminal = master
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))

            def child_terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)

            process = subprocess.Popen(command, env=env, cwd=directory, stdin=slave, stdout=slave, stderr=slave,
                close_fds=True, preexec_fn=child_terminal)
            os.close(slave)

            def drain():
                while not stop.is_set():
                    if not select.select([master], [], [], 0.1)[0]:
                        continue
                    try:
                        block = os.read(master, 65536)
                    except OSError:
                        break
                    if not block:
                        break
                    output.extend(block)
                    assert len(output) <= 8 * 1024 * 1024
                    if b"\x1b[6n" in block:
                        os.write(master, b"\x1b[1;1R")

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            sdk.core.await_barrier(lambda: any(row["event"] == "backend-selected" for row in
                sdk.rows(directory / "native.jsonl")), process, "actual TUI Embedded InProcess start")
            observed = identity(process, sha(binary))
            os.write(master, expected_input.encode())
            # A separate Enter follows the upstream 120 ms paste-suppression window.
            time.sleep(0.2)
            os.write(master, b"\r")
        else:
            command = launch_command(binary, home, arguments)
            stdout = (directory / "stdout.jsonl").open("w")
            stderr = (directory / "stderr.log").open("w")
            process = subprocess.Popen(command, env=env, cwd=directory, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, close_fds=True, start_new_session=True)
        sdk.core.await_barrier(lambda: any(row["event"] == "ready" for row in
            sdk.rows(directory / "native.jsonl")), process, "managed generation Ready")
        initial = state(home)
        if mutate:
            sdk.core.await_barrier(lambda: any(row["event"] == "worker-entered" for row in
                sdk.rows(directory / "events.jsonl")), process, "live managed native worker")
            observed = identity(process, sha(binary))
            mutate()
            assert state(home)[0] != initial[0], "Writer did not actually publish the next generation"
            (directory / "release").touch()
        sdk.core.await_barrier(lambda: any(request["outputs"] for request in provider.requests) if tool
            else bool(provider.requests), process, "actual model/native round trip")
        if tui:
            assert any(item.get("name") == "mcp__codex_worktrees" for request in provider.requests for item in request["tools"])
            mcp_listener = tui_mcp_listener(process.pid)
            sdk.core.await_barrier(lambda: tui_message_visible(output, token), process, "TUI displayed final model message")
            os.write(terminal, b"/quit")
            time.sleep(0.2)
            os.write(terminal, b"\r")
        code = process.wait(timeout=45)
        if not tui:
            stdout.close()
            stderr.close()
        assert code == 0 and not provider.errors, (code, provider.errors, bytes(output).decode(errors="replace"))
        assert any(expected_input in sdk.text_values(request["input"]) for request in provider.requests), "argv/user input changed"
        native = sdk.rows(directory / "native.jsonl")
        ready = next(row["detail"] for row in native if row["event"] == "ready")
        assert ready["plan"]["host"]["executable_sha256"] == sha(binary)
        assert set(ready["plan"]["mods"]) == set(initial[1]["enabled"])
        assert any(row["event"] == "stopped" for row in native), "Normal exit did not drain"
        if tui:
            assert any(row["event"] == "backend-selected" and row["detail"]["transport"] == "InProcess" for row in native)
        if mutate:
            assert "example-tool" in ready["plan"]["mods"]
        result = {"command": command, "provider_endpoint": provider.endpoint,
            "return_code": code, "provider_requests": provider.requests, "provider_errors": provider.errors,
            "identity": observed, "tui": tui, "empty_launch_argv": tui, "tui_mcp_listener": mcp_listener,
            "generation_before": initial[0].decode(),
            "descriptor_before_launch": before_launch[0].decode(),
            "generation_after": state(home)[0].decode(), "business": sdk.business_evidence(provider, tool=tool),
            "lifetime": sdk.settled(directory, modules=len(ready["plan"]["mods"]))}
        write(directory / "result.json", result)
        return result
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        if process and not (directory / "result.json").exists():
            write(directory / "result.json", {"command": command, "provider_endpoint": provider.endpoint,
                "return_code": process.returncode, "error": repr(sys.exc_info()[1]),
                "provider_requests": provider.requests, "provider_errors": provider.errors,
                "identity": observed, "tui": tui, "empty_launch_argv": tui, "tui_mcp_listener": mcp_listener})
        stop.set()
        if reader:
            reader.join(timeout=2)
        if terminal is not None:
            os.close(terminal)
            (directory / "terminal.log").write_text(bytes(output).decode(errors="replace"))
        provider.close()


def reject_install(home, package, name):
    before = state(home)
    rejected = cm(home, "install", package, success=False)
    assert state(home) == before, "Rejected package changed active descriptor/generation: " + name
    return {"case": name, "diagnostic": rejected["stderr"], "active_unchanged": True}


def profile_rejections(inventory):
    source = INPUTS / "mods/m02/lifecycle-audit/normal"
    foreign = PROFILE / "unmarked-official"
    foreign.mkdir(mode=0o700)
    (foreign / "config.toml").write_text('model="preserve-official"\n')
    before = inventory(foreign)
    rows = [cm(foreign, "install", source, success=False)]
    assert inventory(foreign) == before and not (foreign / ".cm-owner").exists()
    alias = PROFILE / "linked-home"
    alias.symlink_to(foreign, target_is_directory=True)
    rows.append(cm(alias, "install", source, success=False))
    assert inventory(foreign) == before
    home = PROFILE / "linked-inputs"
    cm(home, "install", source)
    previous = state(home)
    for index, relative in enumerate((".cm-owner", "cm-profile.json", ".cm-write.lock", "store/objects", "store/generations")):
        path = home / relative
        saved = home / ("kept-input-" + str(index))
        path.rename(saved)
        path.symlink_to(saved, target_is_directory=saved.is_dir())
        preserved = inventory(saved) if saved.is_dir() else saved.read_bytes()
        try:
            result = cm(home, "install", INPUTS / "mods/m02/example-tool/normal", success=False)
            assert (inventory(saved) if saved.is_dir() else saved.read_bytes()) == preserved
            assert state(home) == previous
            rows.append({"case": relative + "-symlink", **result})
        finally:
            path.unlink()
            saved.rename(path)
        cm(home, "doctor")
    return rows


def process_contracts(home, sdk):
    rows = []
    for launched in (False, True):
        directory = EVIDENCE / ("exit-launch" if launched else "exit-direct")
        env = environment(directory)
        if not launched:
            env["CODEX_HOME"] = env["CODEX_SQLITE_HOME"] = str(home)
        arguments = ["exec", "--cm-m03-invalid-option"]
        command = launch_command(BINARY, home, arguments) if launched else [str(BINARY), *arguments]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        rows.append({"command": command, "return_code": result.returncode, "stderr": result.stderr})
    assert rows[0]["return_code"] == rows[1]["return_code"] != 0
    for launched in (False, True):
        name = "signal-launch" if launched else "signal-direct"
        directory = EVIDENCE / name
        directory.mkdir()
        provider = sdk.Provider()
        env = sdk.environment(home, directory, mode="async")
        if launched:
            env["CODEX_HOME"] = env["CODEX_SQLITE_HOME"] = str(OFFICIAL_PROFILE)
        else:
            env["CM_MANAGED_HOME"] = str(home)
            env["CM_MANAGED_GENERATION"] = json.loads(state(home)[0])["generation"]
        arguments = sdk.command(directory, provider.endpoint, "embedded", token=name)[1:]
        command = launch_command(BINARY, home, arguments) if launched else [str(BINARY), *arguments]
        with (directory / "stdout.jsonl").open("w") as stdout, (directory / "stderr.log").open("w") as stderr:
            process = subprocess.Popen(command, env=env, cwd=directory, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                sdk.core.await_barrier(lambda: any(row["event"] == "worker-entered" for row in
                    sdk.rows(directory / "events.jsonl")), process, "actual native worker before signal")
                observed = identity(process, sha(BINARY))
                process.send_signal(signal.SIGKILL)
                code = process.wait(timeout=15)
                assert code == -signal.SIGKILL
                result = {"command": command, "provider_endpoint": provider.endpoint, "identity": observed,
                    "return_code": code, "signal": "SIGKILL", "provider_requests": provider.requests}
                write(directory / "result.json", result)
                rows.append(result)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                provider.close()
    return rows


def m01_rejection_inputs(work):
    archives = sorted((work / "zip").glob("zip-*/mods/bad.cmod"))
    assert len(archives) == 19, ("Missing M01 archive rejection fixtures", archives)
    directories = [work / "rejections" / name / "mods/output-fixture" for name in
        ("missing-payload", "ordinary-executable", "directory-link", "directory-hardlink", "directory-special")]
    assert all(path.is_dir() for path in directories), ("Missing M01 directory rejection fixtures", directories)
    return archives + directories


@ci_progress.case()
def rejections(home):
    result = []
    # Reuse the exact malformed files already rejected by the current-source M01 matrix.
    for package in m01_rejection_inputs(Path("/work/m01")):
        result.append(reject_install(home, package, package.parents[1].name))
    import mod_manifest
    for name, change in (
        ("target", lambda fields: fields["binary"].update(target="aarch64-unknown-linux-gnu")),
        ("cpu", lambda fields: fields["binary"].update(cpu="x86-64-v3")),
        ("glibc-understated", lambda fields: fields["binary"].update(glibc_min="2.2")),
        ("dependency", lambda fields: fields.update(dependencies=[{"id": "missing", "version": "^1"}])),
    ):
        package = WORK / name
        shutil.copytree(INPUTS / "mods/m01-b", package)
        fields = tomllib.loads((package / "mod.toml").read_text())
        change(fields)
        mod_manifest.manifest(package, fields)
        result.append(reject_install(home, package, name))
    for name in ("elf-architecture", "runpath", "actual-glibc", "actual-cpu-property"):
        package = WORK / name
        shutil.copytree(INPUTS / "mods/constructor-sentinel", package)
        fields = tomllib.loads((package / "mod.toml").read_text())
        payload = package / fields["binary"]["path"]
        data = bytearray(payload.read_bytes())
        if name == "elf-architecture":
            struct.pack_into("<H", data, 18, 183)
        elif name == "actual-glibc":
            match = re.search(rb"GLIBC_[0-9][.][0-9]+(?:[.][0-9]+)?\x00", data)
            assert match
            replacement = b"GLIBC_9." + b"9" * (len(match[0]) - 9) + b"\x00"
            assert len(replacement) == len(match[0])
            data[match.start():match.end()] = replacement
        elif name == "actual-cpu-property":
            data = mandatory_cpu(data)
        else:
            headers = struct.unpack_from("<Q", data, 32)[0]
            stride, count = struct.unpack_from("<HH", data, 54)
            dynamic = next(struct.unpack_from("<QQ", data, headers + index * stride + 8)
                for index in range(count) if struct.unpack_from("<I", data, headers + index * stride)[0] == 2)
            # p_offset is the first field. Replace an actual DT_NEEDED with forbidden DT_RUNPATH.
            offset = dynamic[0]
            while struct.unpack_from("<q", data, offset)[0] != 1:
                assert struct.unpack_from("<q", data, offset)[0] != 0
                offset += 16
            struct.pack_into("<q", data, offset, 29)
        payload.write_bytes(data)
        fields["binary"].update(size=len(data), sha256=sha(payload))
        mod_manifest.manifest(package, fields)
        result.append(reject_install(home, package, name))
    return result


def mandatory_cpu(data):
    result = bytearray(data)
    headers = struct.unpack_from("<Q", result, 32)[0]
    stride, count = struct.unpack_from("<HH", result, 54)
    header = next(headers + index * stride for index in range(count)
        if struct.unpack_from("<I", result, headers + index * stride)[0] == 0x6474e551)
    note = struct.pack("<III4sIII4x", 4, 16, 5, b"GNU\x00", 0xc0008002, 4, 2)
    offset = len(result)
    result.extend(note)
    struct.pack_into("<IIQQQQQQ", result, header, 4, 4, offset, 0, 0, len(note), len(note), 8)
    return result


def failures(home):
    rows = []
    # Existing directories/descriptor remain; only this operation's write permission is denied.
    for name, target in (("object-write", "store/objects"), ("generation-write", "store/generations"), ("active-write", ".")):
        before = state(home)
        path = home / target
        path.chmod(0o500)
        try:
            rejected = cm(home, "install", INPUTS / "mods/m02/example-tool/normal", success=False)
        finally:
            path.chmod(0o700)
        assert state(home) == before
        rows.append({"case": name, "diagnostic": rejected["stderr"], "old_generation_preserved": True})
    # Stop a real public CLI while it owns unpublished staging, then kill it.
    package = WORK / "interrupted-source"
    shutil.copytree(INPUTS / "mods/m02/example-tool/normal", package)
    for index in range(48):
        (package / ("attachment-" + str(index))).write_bytes(b"x" * (1024 * 1024))
    before = state(home)
    directory = EVIDENCE / "interrupted-writer"
    env = environment(directory)
    command = [str(BINARY), "cm", "--home", str(home), "install", str(package)]
    with (directory / "stdout.log").open("w") as out, (directory / "stderr.log").open("w") as err:
        process = subprocess.Popen(command, env=env, cwd=WORK, stdout=out, stderr=err, close_fds=True)
        try:
            deadline = time.monotonic() + 30
            while not list((home / "store/objects").glob(".object.*.tmp")):
                assert process.poll() is None and time.monotonic() < deadline, "Missed real staging interval"
                time.sleep(0.001)
            os.kill(process.pid, signal.SIGSTOP)
            assert state(home) == before
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    assert state(home) == before
    cm(home, "doctor")
    rows.append({"case": "real-process-interruption", "command": command, "return_code": process.returncode,
        "old_generation_preserved": True, "unpublished_staging_never_loaded": True})
    return rows


@ci_progress.case()
def writers(home):
    packages = (INPUTS / "mods/m01-a", INPUTS / "mods/m01-b")
    commands = [[str(BINARY), "cm", "--home", str(home), "install", str(package)] for package in packages]
    envs = [environment(EVIDENCE / ("writer-" + str(index))) for index in range(2)]
    processes = [subprocess.Popen(command, env=env, cwd=WORK, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, close_fds=True) for command, env in zip(commands, envs)]
    rows = []
    for index, process in enumerate(processes):
        out, err = process.communicate(timeout=60)
        rows.append({"command": commands[index], "return_code": process.returncode, "stdout": out, "stderr": err})
    # Both original writers must release their locks before retrying a rejected one.
    for index, row in enumerate(rows):
        if row["return_code"]:
            cm(home, "install", packages[index])
    assert set(state(home)[1]["installed"]) == {"serial-fixture", "output-fixture"}
    conflict = WORK / "same-id-other-content"
    shutil.copytree(packages[1], conflict)
    (conflict / "different-content").write_text("same ID, different package")
    rows.append(reject_install(home, conflict, "same-id-other-content"))
    return rows


@ci_progress.case()
def backend_rejections(home):
    rows = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.setblocking(False)
    endpoint = "ws://127.0.0.1:" + str(listener.getsockname()[1])
    try:
        for name in ("cli", "environment", "configuration"):
            directory = EVIDENCE / ("backend-" + name)
            env = environment(directory)
            if name == "environment":
                env["CODEX_EXEC_SERVER_URL"] = endpoint
            if name == "configuration":
                (home / "environments.toml").write_text('default_environment="old"\n[environments.old]\nexec_server_url='
                    + json.dumps(endpoint) + "\n")
            arguments = ["--remote", endpoint] if name == "cli" else ["exec", "--skip-git-repo-check", "never reach provider"]
            command = launch_command(BINARY, home, arguments)
            try:
                result = subprocess.run(command, env=env, cwd=WORK, capture_output=True, text=True, timeout=30)
            finally:
                (home / "environments.toml").unlink(missing_ok=True)
            assert result.returncode != 0
            assert not (directory / "events.jsonl").exists()
            if (directory / "native.jsonl").exists():
                assert not any(json.loads(line)["event"] == "ready" for line in (directory / "native.jsonl").read_text().splitlines())
            rows.append({"case": name, "command": command, "return_code": result.returncode, "stderr": result.stderr})
        assert not select.select([listener], [], [], 0)[0], "Wrong backend was contacted before rejection"
    finally:
        listener.close()
    for helper in ("codex-resources/bwrap", "codex-path/rg", "bin/codex-code-mode-host", "dependency-inventory.json"):
        package = WORK / ("missing-" + Path(helper).name)
        shutil.copytree(INPUTS / "host", package, symlinks=True)
        (package / helper).unlink()
        directory = EVIDENCE / ("missing-" + Path(helper).name)
        command = launch_command(package / "bin/codex", PROFILE / ("missing-" + Path(helper).name), ["exec", "unused"])
        result = subprocess.run(command, env=environment(directory), capture_output=True, text=True, timeout=30)
        assert result.returncode != 0
        assert not (directory / "native.jsonl").exists()
        rows.append({"case": "missing-" + helper, "command": command, "return_code": result.returncode, "stderr": result.stderr})
    return rows


def self_check():
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        inputs, work, evidence = (base / name for name in ("inputs", "work", "evidence"))
        work.mkdir()
        for owner in ("m01-a", "m01-b"):
            (inputs / "mods" / owner).mkdir(parents=True)
        completed = []

        class Writer:
            def __init__(self, index):
                self.index = index
                self.returncode = 1 if index == 0 else 0

            def communicate(self, timeout):
                completed.append(self.index)
                return "", "profile write lock is busy" if self.returncode else ""

        retried = []

        def retry(*args):
            assert completed == [0, 1], "Retry raced a still-running original writer"
            retried.append(args)

        with patch.dict(globals(), INPUTS=inputs, WORK=work, EVIDENCE=evidence,
                environment=lambda directory: {}, cm=retry,
                state=lambda home: (b"", {"installed": ["serial-fixture", "output-fixture"]}),
                reject_install=lambda *args: {}), \
                patch.object(subprocess, "Popen", side_effect=[Writer(0), Writer(1)]):
            writers(base / "profile")
        assert len(retried) == 1 and retried[0][-1] == inputs / "mods/m01-a"
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        archives = [work / "zip" / ("zip-" + str(index)) / "mods/bad.cmod" for index in range(19)]
        directories = [work / "rejections" / name / "mods/output-fixture" for name in
            ("missing-payload", "ordinary-executable", "directory-link", "directory-hardlink", "directory-special")]
        for path in archives:
            path.parent.mkdir(parents=True)
            path.write_bytes(b"malformed fixture")
        for path in directories:
            path.mkdir(parents=True)
        assert set(m01_rejection_inputs(work)) == set(archives + directories)
        for missing in (archives[0], directories[0]):
            saved = missing.with_name(missing.name + ".saved")
            missing.rename(saved)
            try:
                m01_rejection_inputs(work)
            except AssertionError:
                pass
            else:
                raise AssertionError("Incomplete M01 rejection fixtures accepted")
            saved.rename(missing)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        assert tui_mcp_listener(os.getpid())["port"] == listener.getsockname()[1]
    assert tui_message_visible(b"M02 complete case", "case")
    assert tui_message_visible(b"M02\x1b[9;7Hcomplete\x1b[9;16Hcase\x1b[0m", "case")
    for output in (b"M02 complete other", b"M02 complete", b"\x1b]0;M02 complete case\x07",
                   b"\x1b]0;M02 complete case\x1b\\"):
        assert not tui_message_visible(output, "case"), output
    directory = Path("/evidence/m03/用户 空格")
    arguments = sdk_module().command(directory, "http://127.0.0.1:1234", "embedded")[1:]
    config = tomllib.loads(tui_configuration(arguments, directory))
    assert config["approval_policy"] == "never" and config["sandbox_mode"] == "workspace-write"
    assert config["model"] == "gpt-5.4" and config["projects"][str(directory)]["trust_level"] == "trusted"
    assert config["model_providers"]["cm_fixture"]["base_url"] == "http://127.0.0.1:1234/v1"
    with tempfile.TemporaryDirectory() as directory:
        installation = Path(directory)
        binary = installation / "codex-x86_64-unknown-linux-musl"
        binary.write_bytes(b"official fixture")
        assert official_entrypoint(installation) == binary
        (installation / "codex").write_bytes(b"ambiguous entrypoint")
        try:
            official_entrypoint(installation)
        except AssertionError:
            pass
        else:
            raise AssertionError("Ambiguous official entrypoint accepted")
    command = launch_command(Path("/work/独立 Host/bin/codex"), Path("/profile/用户 数据"),
        ["exec", "空格 '引号' -- ; $(false)"])
    assert command[-2:] == ["exec", "空格 '引号' -- ; $(false)"] and command[4] == "launch"
    # The actual CPU negative mutates an ELF program header, not only a manifest string.
    elf = bytearray(128)
    struct.pack_into("<Q", elf, 32, 64)
    struct.pack_into("<HH", elf, 54, 56, 1)
    struct.pack_into("<I", elf, 64, 0x6474e551)
    changed = mandatory_cpu(elf)
    assert len(changed) == 160 and struct.unpack_from("<I", changed, 64)[0] == 4
    assert struct.unpack_from("<I", changed, 152)[0] == 2


def matrix():
    import mod_manifest
    import managed_package
    assert os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
    sdk = sdk_module()
    WORK.mkdir(parents=True)
    PROFILE.mkdir(parents=True)
    EVIDENCE.mkdir(parents=True)
    producer = read(INPUTS / "producer.json")
    authored = read(Path("/fixture/m03-producer.json"))
    assert authored["status"] == "pass"
    frozen = sha(BINARY)
    assert frozen == producer["host"]["executable_sha256"] == authored["host_executable_sha256"]
    official_before = protected_inventory(INPUTS / "official")
    shutil.copytree(INPUTS / "official/profile", OFFICIAL_PROFILE, symlinks=True)
    for path in (OFFICIAL_PROFILE, *OFFICIAL_PROFILE.rglob("*")):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)
    (OFFICIAL_PROFILE / "config.toml").write_text('model="official-profile-fixture"\n')
    (OFFICIAL_PROFILE / "auth.json").write_text('{"fixture":"preserve-authentication"}\n')
    (OFFICIAL_PROFILE / "sessions").mkdir(exist_ok=True)
    (OFFICIAL_PROFILE / "sessions/retained.jsonl").write_text('{"fixture":"preserve-session"}\n')
    writable_official_before = protected_inventory(OFFICIAL_PROFILE)
    global_path = WORK / "global"
    global_path.mkdir()
    official_binary = official_entrypoint(INPUTS / "official/install")
    (global_path / "codex").symlink_to(official_binary)
    path_before = os.environ["PATH"]
    drop = []
    homes = []
    for method in ("directory", "archive", "explicit"):
        home = PROFILE / method
        cm(home, "install", INPUTS / "mods/m02/lifecycle-audit/normal")
        if method == "explicit":
            cm(home, "install", INPUTS / "mods/m02/example-tool/normal")
        elif method == "archive":
            shutil.copyfile(INPUTS / "mods/example-tool.cmod", home / "mods/example.cmod")
            (home / "mods/upload.cmod.part").write_bytes(b"PK half upload")
        else:
            shutil.copytree(INPUTS / "mods/m02/example-tool/normal", home / "mods/inbox")
            (home / "mods/upload.tmp").mkdir()
        drop.append(business("drop-" + method, home, sdk))
        homes.append(home)
    assert len({state(home)[1]["lock_sha256"] for home in homes}) == 1
    assert len({json.dumps(state(home)[1]["installed"], sort_keys=True) for home in homes}) == 1
    archive_home = homes[1]
    previous = state(archive_home)
    cm(archive_home, "install", INPUTS / "mods/example-tool.cmod")
    assert state(archive_home) == previous
    state_file = archive_home / "state/用户 文件"
    state_file.parent.mkdir(exist_ok=True)
    state_file.write_text("preserve user data")
    cm(archive_home, "disable", "example-tool")
    disabled = business("disabled-inbox", archive_home, sdk, tool=False)
    assert state(archive_home)[1]["enabled"] == ["lifecycle-audit"]
    cm(archive_home, "enable", "example-tool")
    enabled = business("reenabled", archive_home, sdk)
    cm(archive_home, "remove", "example-tool")
    removed = business("removed-inbox", archive_home, sdk, tool=False)
    assert "example-tool" not in state(archive_home)[1]["installed"]
    assert state_file.read_text() == "preserve user data"
    shutil.copytree(INPUTS / "host", COPY, symlinks=True)
    unicode_home = PROFILE / "用户 数据"
    populated(unicode_home, binary=COPY / "bin/codex")
    independent = business("unicode-exec", unicode_home, sdk, binary=COPY / "bin/codex")
    process_behavior = process_contracts(homes[2], sdk)
    unsafe_profiles = profile_rejections(protected_inventory)
    # A known reachable old daemon is present during the real empty-argv TUI launch.
    tui_home = PROFILE / "tui"
    populated(tui_home)
    implicit = socket.socket(socket.AF_UNIX)
    implicit_path = tui_home / "app-server-control/app-server-control.sock"
    implicit_path.parent.mkdir(mode=0o700)
    implicit.bind(str(implicit_path))
    implicit.listen()
    try:
        terminal = business("actual-tui", tui_home, sdk, tui=True)
        assert not (tui_home / "packages/app-server-daemon").exists(), "TUI attempted managed daemon installation"
        assert not select.select([implicit], [], [], 0)[0], "TUI probed the old daemon"
    finally:
        implicit.close()
        implicit_path.unlink()
    live = business("live-generation", homes[2], sdk,
        mutate=lambda: cm(homes[2], "disable", "example-tool"))
    restarted = business("next-generation", homes[2], sdk, tool=False)
    negative_home = PROFILE / "negative"
    populated(negative_home, runtime=False)
    rejected = rejections(negative_home)
    legacy_home = PROFILE / "legacy-managed"
    for relative in ("a", "b/normal"):
        cm(legacy_home, "install", INPUTS / "mods" / relative)
    legacy_plan = cm(legacy_home, "plan")["plan_projection"]
    assert {owner: row["content_tree_sha256"] for owner, row in legacy_plan["mods"].items()} == state(legacy_home)[1]["installed"]
    fault_home = PROFILE / "faults"
    cm(fault_home, "install", INPUTS / "mods/m02/lifecycle-audit/normal")
    faults = failures(fault_home)
    cm(fault_home, "install", INPUTS / "mods/m02/example-tool/normal")
    recovered = business("after-interrupted-writer", fault_home, sdk)
    concurrent_home = PROFILE / "concurrent"
    concurrent = writers(concurrent_home)
    # Dependency-breaking management uses the same resolver and cannot commit.
    dependency = WORK / "dependent"
    shutil.copytree(INPUTS / "mods/m01-b", dependency)
    fields = tomllib.loads((dependency / "mod.toml").read_text())
    fields.update(id="dependent", dependencies=[{"id": "serial-fixture", "version": "^1"}])
    fields["state"]["owner"] = "dependent"
    mod_manifest.manifest(dependency, fields)
    cm(concurrent_home, "install", dependency)
    prior = state(concurrent_home)
    cm(concurrent_home, "disable", "serial-fixture", success=False)
    cm(concurrent_home, "remove", "serial-fixture", success=False)
    assert state(concurrent_home) == prior
    sentinel_home = PROFILE / "sentinel"
    cm(sentinel_home, "install", INPUTS / "mods/constructor-sentinel")
    cm(sentinel_home, "remove", "constructor-sentinel")
    backends = backend_rejections(fault_home)
    assert protected_inventory(INPUTS / "official") == official_before
    assert protected_inventory(OFFICIAL_PROFILE) == writable_official_before
    assert shutil.which("codex", path=str(global_path)) == str(global_path / "codex")
    assert os.environ["PATH"] == path_before and sha(BINARY) == sha(COPY / "bin/codex") == frozen
    assert read(Path("/evidence/missing-library.json"))["status"] == "pass"
    assert read(Path("/evidence/actual-missing-library-recovery.json"))["status"] == "pass"
    reports = (
        {"frozen_host_sha256": frozen, "package_inventory": read(INPUTS / "host/cm-runtime-files.json"),
         "author_preparation": authored, "runtime_regressions": ["P01", "P02", "P03", "P04", "M01", "M02"]},
        {"three_install_paths": drop, "idempotent_generation": previous[0].decode(),
         "disabled_inbox": disabled, "reenabled": enabled, "removed_inbox": removed,
         "live_generation": live, "next_generation": restarted, "data_preserved": True},
        {"unicode_host_and_home": independent, "argv_contains_unicode_spaces_quotes_and_shell_metacharacters": True,
         "official_inventory_unchanged": True, "writable_official_profile_unchanged": True,
         "path_unchanged": True, "exit_and_signal": process_behavior, "actual_tui": terminal},
        {"rejections": rejected, "public_cli_faults": faults, "precise_unit_evidence": authored,
         "legacy_managed_plan": legacy_plan,
         "unsafe_profiles": unsafe_profiles,
         "two_real_writers": concurrent, "recovery": recovered, "dependency_breaking_changes_rejected": True,
         "constructor_entry_and_postinstall_executions_during_install": 0},
        {"actual_tui": terminal, "actual_exec": independent, "reachable_old_backend_rejections": backends,
         "implicit_daemon_listener_connections": 0, "implicit_daemon_installations": 0,
         "transport": "InProcess", "implicit_daemon_socket": str(implicit_path)},
        {"native_rejections": [row for row in rejected if row["case"] in
            ("target", "cpu", "glibc-understated", "elf-architecture", "runpath", "actual-glibc", "actual-cpu-property")],
         "actual_removed_library": read(Path("/evidence/missing-library.json")),
         "actual_library_recovery": read(Path("/evidence/actual-missing-library-recovery.json")),
         "baseline": authored["baseline"], "installation_native_execution": False},
    )
    for name, report in zip(managed_package.REPORTS, reports):
        write(Path("/evidence") / name, {"status": "behavior_pass", **report})
    write(EVIDENCE / "suite.json", {"status": "pass", "frozen_host_sha256": frozen, "reports": list(managed_package.REPORTS)})
