#!/usr/bin/env python3
"""P03 producer/acceptance; executable only in the independent hosted builder."""
import copy
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time
import tomllib

import host
import native_mod
from linux_ci import TARGET, cargo_args, execute, load_config, source_file
from record_run import require_hosted_linux

CAPABILITY = native_mod.CAPABILITY
COMPOSE = "core.tool_parallel_eligibility.compose.v1"
CHECKS = dict(zip(
    ("CM-P03-AC01", "CM-P03-AC02", "CM-P03-AC03", "CM-P03-AC04", "CM-P03-AC05", "CM-P03-AC06"),
    ("runtime-plan-determinism.json", "hook-order-contract.json", "runtime-plan-drift.json",
     "exclusive-hook-conflict.json", "runtime-conflict-matrix.json", "registration-transaction.json")))
INVALID = (
    "extra", "missing", "duplicate", "kind", "capability", "resource", "null-callback", "descriptor-size",
    "descriptor-version", "short-prefix", "short-table", "major", "minor", "mod-id",
    "null-view", "huge-view", "utf8", "null-init", "null-release", "null-array",
    "huge-array", "reserved", "entry-next", "entry-fail", "entry-status", "table-overflow",
    "misaligned-array", "misaligned-table", "zero-array", "null-table")


def toml_value(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(key + " = " + toml_value(item) for key, item in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False)


def write_manifest(package, fields):
    text = "\n".join(key + " = " + toml_value(value) for key, value in fields.items()) + "\n"
    assert tomllib.loads(text) == fields
    (package / "mod.toml").write_text(text, encoding="utf-8")


def install(home, receipt, *, directory=None, dependencies=(), changes=None, hooks=None):
    owner = receipt["mod_id"]
    package = home / "mods" / (directory or owner)
    package.mkdir(parents=True)
    payload = package / "payload.so"
    shutil.copyfile(receipt["payload"], payload)
    resource_file = package / "data.txt"
    resource_file.write_text("composition-resource-v1\n")
    kinds = [("terminal", "replacement")] if receipt["variant"] == "replacement" else [
        ("before", "before"), ("around", "around"), ("after", "after")]
    if receipt["variant"] == "nested-next":
        kinds.insert(2, ("around-inner", "around"))
    contributions = hooks or [
        {"id": name, "kind": kind, "capability": COMPOSE, "resource": CAPABILITY,
         "order_before": [], "order_after": [], "priority": 0} for name, kind in kinds]
    fields = {
        "format_version": 2, "id": owner, "version": "0.1.0",
        "payload": "payload.so", "payload_size": payload.stat().st_size,
        "payload_sha256": host.sha(payload), "target": TARGET, "abi_major": 2, "abi_minor": 0,
        "required_capabilities": [COMPOSE], "dependencies": list(dependencies), "conflicts": [],
        "contributions": contributions,
        "resources": [{"path": "data.txt", "size": resource_file.stat().st_size, "sha256": host.sha(resource_file)}],
    }
    fields.update(changes or {})
    write_manifest(package, fields)
    return package


def selection(home, enabled):
    home.mkdir(parents=True, exist_ok=True)
    (home / "cm-runtime.toml").write_text("format_version = 1\nenabled = " + toml_value(enabled) + "\n")


def pair(home, mods, variant_a="normal", variant_b="normal", dependency=True, explicit=True, reverse=False):
    receipts = [mods["a/" + variant_a], mods["b/" + variant_b]]
    if reverse:
        receipts.reverse()
    for receipt in receipts:
        dependencies = [{"id": "compose-b", "version": "0.1.0"}] if dependency and receipt["mod_id"] == "compose-a" else []
        package = install(home, receipt, dependencies=dependencies)
        fields = tomllib.loads((package / "mod.toml").read_text())
        if explicit and receipt["mod_id"] == "compose-a" and variant_b != "replacement" and variant_a != "replacement":
            for hook in fields["contributions"]:
                hook["order_before"] = ["compose-b::" + hook["id"]]
            write_manifest(package, fields)
    return home


def build_mods(root, logs, package, frozen):
    cfg = load_config(root)
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    assert host.read(logs / "composition-observer-self-check.json")["status"] == "pass"
    events = [json.loads(line) for line in (logs / "phase-results.jsonl").read_text().splitlines()]
    assert any(
        row["phase"] == "composition-shared-fmt" and row["return_code"] == 0 for row in events
    ), "Shared fixture formatting must pass before the Host build"
    mods = {}
    for role, variants in (
        ("a", ("normal", "nested-next", "replacement", "short", "init-fail", "release-fail", "max-table", *INVALID)),
        ("b", ("normal", "replacement")),
    ):
        relative = "fixtures/mods/composition-" + role
        name = "cm-composition-" + role + "-fixture"
        unit = {"manifest": relative + "/Cargo.toml", "lockfile": relative + "/Cargo.lock",
                "packages": [name], "features": []}
        lock_sha = host.sha(root / unit["lockfile"])
        for variant in variants:
            label = "composition-" + role + "-" + variant
            target = Path(os.environ["CARGO_TARGET_DIR"]) / label
            assert not target.exists(), "Author target was not empty: " + str(target)
            env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CM_COMPOSITION_VARIANT": variant}
            for phase in (("fmt", "clippy", "test", "build") if variant == "normal" else ("build",)):
                command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"]
                           if phase == "fmt" else cargo_args(unit, phase, cfg, cfg["build_profile"]))
                if phase == "clippy":
                    command += ["--all-targets", "--", "-D", "warnings"]
                execute(root, logs, label + "-" + phase, command, env)
            metadata_command = ["cargo", "metadata", "--locked", "--format-version", "1",
                                "--filter-platform", TARGET, "--manifest-path", str(root / unit["manifest"])]
            metadata = json.loads(subprocess.check_output(metadata_command, cwd=root / relative, env=env, text=True))
            names = sorted(value["name"] for value in metadata["packages"])
            assert names == ["cm-abi", name]
            assert not any(value["name"] == name for value in host.read(package / "dependency-inventory.json")["packages"])
            assert host.sha(root / unit["lockfile"]) == lock_sha
            source = target / TARGET / cfg["build_profile"] / ("lib" + name.replace("-", "_") + ".so")
            published = Path(os.environ["CM_CI_ARTIFACT_DIR"]) / "composition-mods" / role / variant
            published.mkdir(parents=True)
            shutil.copyfile(source, published / "payload.so")
            for header in ("cm_mod_v1.h", "cm_mod_v2.h"):
                shutil.copyfile(root / "crates/cm-abi/include" / header, published / header)
            shutil.copyfile(root / host.HOST / "LICENSE", published / "LICENSE")
            inputs = {"source_manifest": host.manifest(root, [
                root / relative / "Cargo.toml", root / relative / "Cargo.lock", root / relative / "src/lib.rs",
                root / "fixtures/mods/composition-common.rs",
                *source_file(root, "crates/cm-abi/Cargo.toml").parent.rglob("*")]),
                "lock_sha256": lock_sha, "target": TARGET, "variant": variant,
                "toolchain": frozen["host_identity"]["inputs"]["toolchain"],
                "flags": frozen["host_identity"]["inputs"]["flags"]}
            receipt = {"mod_id": "compose-" + role, "variant": variant, "inputs": inputs,
                       "mod_build_id": "sha256:" + host.digest(inputs), "dependencies": names,
                       "workspace": relative, "target_directory": str(target), "initial_target_empty": True,
                       "metadata_command": metadata_command, "payload": str(published / "payload.so"),
                       "payload_sha256": host.sha(published / "payload.so"),
                       "host_frozen_before_author_build": frozen["executable_sha256"]}
            host.write(published / "mod-build.json", receipt)
            mods[role + "/" + variant] = receipt
    native = Path(os.environ["RUNNER_TEMP"]) / "cm-composition-native"
    native.mkdir()
    execute(root, logs, "composition-c-layout-build", [
        "cc", "-std=c11", str(root / "fixtures/runtime-composition/layout.c"), "-o", str(native / "layout")])
    execute(root, logs, "composition-c-layout", [str(native / "layout")])
    assert json.loads((logs / "composition-c-layout.log").read_text())["v2_all_sizes_alignments_offsets"]
    assert "linux_x64_composition_layout ... ok" in host.build_log(logs, "host-test").read_text()
    if shutil.which("strace") is None:
        execute(root, logs, "composition-observer-install", ["sudo", "apt-get", "update"])
        execute(root, logs, "composition-observer-package", ["sudo", "apt-get", "install", "-y", "strace"])
    execute(root, logs, "composition-observer-version", ["strace", "--version"])
    host.write(logs / "composition-builds.json", mods)
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    return mods


def prefix(directory):
    return ["strace", "-f", "-qq", "-yy", "-s", "1024", "-e",
            "trace=execve,execveat,connect,sendto,socketpair", "-o", str(directory / "syscalls.log"), "--"]


def redact_syscalls(text):
    lines = text.split("\n")
    for index, line in enumerate(lines):
        prefix = re.match(r'^(?:\d+\s+(?:sendto|recvfrom)\(\d+(?:<.*?>)?, |\d+\s+<\.\.\. (?:sendto|recvfrom) resumed>\s*)\[', line)
        if not prefix:
            continue
        start = prefix.end() - 1
        depth, quoted, escaped = 0, False, False
        for end in range(start, len(line)):
            char = line[end]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    tail = line[end + 1:]
                    lines[index] = line[:start] + '"<payload redacted>"' + tail.removeprefix("...")
                    break
        else:
            raise AssertionError("Truncated structured syscall payload")
    text = "\n".join(lines)
    text = re.sub(r'(^\d+\s+(?:sendto|recvfrom)\(\d+(?:<.*?>)?, )"(?:[^"\\]|\\.)*"(\.\.\.)?',
                  r'\1"<payload redacted>"', text, flags=re.MULTILINE)
    return re.sub(r'(^\d+\s+<\.\.\. (?:sendto|recvfrom) resumed>\s*)"(?:[^"\\]|\\.)*"(\.\.\.)?',
                  r'\1"<payload redacted>"', text, flags=re.MULTILINE)


def complete_syscalls(lines):
    pending = {}
    complete = []
    for line in lines:
        start = re.fullmatch(r'(\d+)\s+(\w+\(.*) <unfinished \.\.\.>', line)
        resumed = re.fullmatch(r'(\d+)\s+<\.\.\. (\w+) resumed>(.*)', line)
        if start:
            assert start[1] not in pending, line
            pending[start[1]] = start[2]
            continue
        if resumed:
            head = pending.pop(resumed[1], "")
            assert head.startswith(resumed[2] + "("), line
            line = resumed[1] + " " + head + re.sub(r'\)\s+=', ') =', resumed[3])
        complete.append(line)
    assert not pending, "Observer missed syscall completion: " + repr(pending)
    return complete


def kernel_route_sockets(lines):
    sockets = set()
    for line in lines:
        match = re.fullmatch(r'(\d+)\s+socket\(AF_NETLINK, SOCK_RAW(?:\|SOCK_CLOEXEC)?, NETLINK_ROUTE\) = (\d+)<(NETLINK:\[[^\]]+\])>', line)
        if match:
            sockets.add((match[1], match[2], match[3]))
    return sockets


def provider_tcp_connections(lines, ports):
    listeners = set()
    connections = set()
    for line in lines:
        local = re.fullmatch(r'\d+\s+getsockname\(\d+<TCP:\[(\d+)\]>, \{sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("127\.0\.0\.1"\)\}, \[\d+(?: => \d+)?\]\) = 0', line)
        if local and local[2] in ports:
            listeners.add(local[1])
    for line in lines:
        accepted = re.fullmatch(r'\d+\s+accept4?\(\d+<TCP:\[(\d+)\]>, \{sa_family=AF_INET, sin_port=htons\(\d+\), sin_addr=inet_addr\("127\.0\.0\.1"\)\}, \[\d+(?: => \d+)?\](?:, SOCK_CLOEXEC(?:\|SOCK_NONBLOCK)?)?\) = \d+<TCP:\[(\d+)\]>', line)
        if accepted and accepted[1] in listeners:
            connections.add(accepted[2])
    return connections


def audit_network(lines, directory, ports, kernel_routes=(), tcp_connections=()):
    unix_connections = set()
    unix_pairs = set()
    connected_tcp = set(tcp_connections)
    # Per-thread trace files do not preserve cross-thread creation/send order.
    for line in lines:
        if re.match(r'\d+\s+socketpair\(', line):
            fd = r'\d+<UNIX(?:-STREAM)?:\[(\d+)(?:->(\d+))?\]>'
            pair = re.fullmatch(r'\d+\s+socketpair\(AF_UNIX, SOCK_STREAM(?:\|SOCK_(?:CLOEXEC|NONBLOCK))*, 0, \['
                                + fd + ', ' + fd + r'\]\) = 0', line)
            assert pair and pair[1] != pair[3], "Unclassified socketpair: " + line
            assert pair[2] in (None, pair[3]) and pair[4] in (None, pair[1]), line
            unix_pairs.update(((pair[1], pair[3]), (pair[3], pair[1])))
    for line in lines:
        if re.match(r'\d+\s+socketpair\(', line):
            continue
        call = re.match(r'(\d+)\s+(connect|sendto)\((\d+)(?:<(.*?)>)?, ', line)
        assert call, "Unclassified network syscall: " + line
        descriptor = call[4] or ""
        if descriptor.startswith("NETLINK:"):
            assert call[2] == "sendto" and (call[1], call[3], descriptor) in kernel_routes, line
            assert re.search(r', \{sa_family=AF_NETLINK, nl_pid=0, nl_groups=0+\}, \d+\) = \d+$', line), line
            continue
        address = re.search(r', (\{sa_family=(?:AF_UNIX|AF_INET6?), [^}]*\}), \d+\)?(?: = [^"]*| <unfinished \.\.\.>)$', line)
        if address:
            if "sa_family=AF_UNIX" in address[1]:
                scoped = 'sun_path="' + str(directory) + '/' in address[1]
                denied_nscd = (call[2] == "connect" and address[1] == '{sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}' and
                               line.endswith((' = -1 ENOENT (No such file or directory)', ' = -1 EPERM (Operation not permitted)')))
                # The fixed TUI fixture can probe its absent user session bus; no connection succeeds.
                denied_session_bus = (call[2] == "connect" and
                    address[1] == '{sa_family=AF_UNIX, sun_path="/run/user/1000/bus"}' and
                    re.fullmatch(r'UNIX-STREAM:\[\d+\]', descriptor) and
                    line.endswith(' = -1 ENOENT (No such file or directory)'))
                assert scoped or denied_nscd or denied_session_bus, line
                if scoped:
                    inode = re.fullmatch(r'UNIX(?:-[A-Z]+)?:\[(\d+)[^\]]*\]', descriptor)
                    assert inode, "Missing Unix socket identity: " + line
                    unix_connections.add(inode[1])
            else:
                port = re.search(r'sin6?_port=htons\(([0-9]+)\)', address[1])
                local = 'inet_addr("127.0.0.1")' in address[1] or 'inet_pton(AF_INET6, "::1",' in address[1]
                assert local and port and port[1] in ports, "Unexpected runtime network: " + line
                inode = re.fullmatch(r'TCP:\[(\d+)\]', descriptor)
                if call[2] == "connect" and inode and line.endswith((' = 0', ' = -1 EINPROGRESS (Operation now in progress)')):
                    connected_tcp.add(inode[1])
        else:
            assert call[2] == "sendto" and re.search(r', NULL, 0\)?(?: = [^"]*| <unfinished \.\.\.>)$', line), line
            # Decoded socket identity ties address-less sends to the observed fixture connection.
            unix = re.fullmatch(r'UNIX(?:-[A-Z]+)?:\[(\d+)->(\d+)(?:,[^\]]*)?\]', descriptor)
            tcp = re.fullmatch(r'TCP:\[127[.]0[.]0[.]1:\d+->127[.]0[.]0[.]1:(\d+)\]', descriptor)
            pair_end = re.fullmatch(r'UNIX(?:-STREAM)?:\[(\d+)\]', descriptor)
            tcp_inode = re.fullmatch(r'TCP:\[(\d+)\]', descriptor)
            # Cross-namespace decoding can retain only the observed socket inode.
            assert ((unix and (unix[1] in unix_connections or (unix[1], unix[2]) in unix_pairs))
                    or (pair_end and any(pair_end[1] == inode for inode, _ in unix_pairs))
                    or (tcp_inode and tcp_inode[1] in connected_tcp)
                    or (tcp and tcp[1] in ports)), "Unknown socket peer: " + line


def sandbox_path(path, leaf):
    prefix, separator, tail = path.rpartition("/tmp/arg0-linux/")
    return bool(separator and re.fullmatch(r'/(?:profile|work)(?:/[^/\\\x00-\x1f]+)*', prefix)
        and all(part not in (".", "..") for part in prefix.split("/")[1:])
        and re.fullmatch(r'codex-arg0[A-Za-z0-9]+/' + re.escape(leaf), tail))


def bound_sandbox_aliases(lines, hosts=("/inputs/host/bin/codex",)):
    aliases = set()
    for line in lines:
        match = re.fullmatch(r'\d+\s+symlink(?:at)?\("([^"]+)", (?:AT_FDCWD(?:<[^>]*>)?, )?"([^"]+)"\) = 0', line)
        # Rejected package copies can create unused aliases; bind only the frozen Host.
        if not match or Path(match[2]).name != "codex-linux-sandbox" or match[1] not in hosts:
            continue
        assert sandbox_path(match[2], "codex-linux-sandbox"), line
        aliases.add(match[2])
    return aliases


def bound_bwrap_executions(calls, helper):
    helpers = (helper,) if isinstance(helper, str) else tuple(helper)
    descriptors = set()
    executions = set()
    for line in calls:
        pid, call = line.split(None, 1)
        allocated = re.search(r'\) = (\d+)(?:<[^>]*>)?$', call)
        if allocated and (re.match(r'(?:open(?:at2?)?|dup[23]?)\(', call) or
                          (call.startswith("fcntl(") and ", F_DUPFD" in call)):
            descriptors.discard((pid, allocated[1]))
        opened = re.fullmatch(r'openat\(AT_FDCWD(?:<[^>]*>)?, "([^"]+)", O_RDONLY\|O_CLOEXEC\) = (\d+)<([^>]+)>', call)
        if opened and opened[1] == opened[3] and opened[1] in helpers:
            descriptors.add((pid, opened[2]))
        closed = re.match(r'close\((\d+)(?:<[^>]*>)?\) =', call)
        if closed:
            descriptors.discard((pid, closed[1]))
        closed_range = re.match(r'close_range\((\d+), (\d+|~0U), [^)]*\) =', call)
        if closed_range:
            first, last = int(closed_range[1]), 2**32 - 1 if closed_range[2] == "~0U" else int(closed_range[2])
            descriptors = {item for item in descriptors if item[0] != pid or not first <= int(item[1]) <= last}
        execution = re.match(r'execve\("/proc/self/fd/(\d+)", \["bwrap",', call)
        if execution:
            assert (pid, execution[1]) in descriptors and call.endswith(" = 0"), "Unbound packaged helper FD: " + line
            executions.add(line)
        if re.match(r'execve(?:at)?\(', call) and call.endswith(" = 0"):
            descriptors = {item for item in descriptors if item[0] != pid}
    return executions


def audit_executions(executions, python_scripts=("fixtures/native-loader/tool_barrier.py",), sandbox_aliases=(), bwrap_executions=(), native_probes=()):
    assert executions, "Observer missed the initial exec"
    forbidden = re.compile(r'/(?:cargo|rustc|rustdoc|cc|gcc(?:-[0-9]+)?|g\+\+(?:-[0-9]+)?|c\+\+|clang(?:\+\+)?|ld(?:\.[a-z]+)?|lld|collect2|as|ar|make|cmake|ninja|sccache|node|bun|deno|java)(?=[" ])')
    assert not any(forbidden.search(line) for line in executions), executions
    allowed = {"codex", "native_probe", "bash", "sh", "env", "python3", "python3.12", "bwrap",
               "rg", "uname", "id", "tty", "stty", "getent", "ps", "which", "readlink",
               "lsb_release", "getopt", "cut", "tr", "getconf"}
    for line in executions:
        match = re.search(r'execve\("([^"]+)"', line)
        assert match, "Unclassified execveat: " + line
        # The upstream sandbox probe searches for true, absent from the minimal rootfs.
        missing_probe = (', ["true"], ' in line and line.endswith(' = -1 ENOENT (No such file or directory)') and (
            match[1] in ("/inputs/host/codex-path/true", "/usr/bin/true", "/bin/true") or
            sandbox_path(match[1], "true")))
        helper = (match[1] == "/proc/self/exe" and '"--codex-run-as-process-setup"' in line) or (
            match[1] in sandbox_aliases and '"--sandbox-policy-cwd"' in line and '"--permission-profile"' in line) or line in bwrap_executions
        assert Path(match[1]).name in allowed or match[1] in native_probes or helper or missing_probe, "Unclassified executable: " + line
        if Path(match[1]).name.startswith("python"):
            assert any(script in line for script in python_scripts), line


def check_network_audit():
    directory = Path("/fixture")
    connect = '1 connect(4<UNIX-STREAM:[41]>, {sa_family=AF_UNIX, sun_path="/fixture/callback.sock"}, 32) = 0'
    send = '1 sendto(4<UNIX-STREAM:[41->42]>, "callback-entered\\n", 17, MSG_NOSIGNAL, NULL, 0) = 17'
    tcp = '2 sendto(5<TCP:[127.0.0.1:1234->127.0.0.1:8080]>, "request", 7, MSG_NOSIGNAL, NULL, 0) = 7'
    pair = '3 socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, [8<UNIX-STREAM:[51->52]>, 9<UNIX-STREAM:[52->51]>]) = 0'
    ipc = '3 sendto(8<UNIX-STREAM:[51->52]>, "CI_TOKEN=observer-canary\\0", 25, MSG_NOSIGNAL, NULL, 0) = 25'
    split = ['3 socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0,  <unfinished ...>',
             '3 <... socketpair resumed>[8<UNIX-STREAM:[51->52]>, 9<UNIX-STREAM:[52->51]>])             = 0']
    assert complete_syscalls(split) == [pair]
    for incomplete in ([split[0]], [split[1]], [split[0], split[1].replace("socketpair resumed", "sendto resumed")]):
        try:
            complete_syscalls(incomplete)
        except AssertionError:
            continue
        raise AssertionError("Observer accepted incomplete syscalls: " + repr(incomplete))
    sanitized = redact_syscalls(ipc)
    assert "observer-canary" not in sanitized and "<payload redacted>" in sanitized
    assert sanitized.endswith(', 25, MSG_NOSIGNAL, NULL, 0) = 25')
    audit_network([connect, send, tcp, *complete_syscalls(split), sanitized], directory, {"8080"})
    bare_pair = pair.replace("51->52", "51").replace("52->51", "52")
    bare_ipc = sanitized.replace("51->52", "51")
    audit_network([bare_pair, bare_ipc], directory, set())
    other_thread = bare_ipc.replace("3 sendto", "2 sendto")
    audit_network([other_thread, bare_pair], directory, set())
    audit_network([sanitized.replace("3 sendto", "2 sendto"), pair], directory, set())
    tcp_connect = '4 connect(5<TCP:[71]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0'
    bare_tcp = '4 sendto(5<TCP:[71]>, "<payload redacted>", 4, 0, NULL, 0) = 4'
    audit_network([tcp_connect, bare_tcp], directory, {"8080"})
    audit_network([tcp_connect.replace(' = 0', ' = -1 EINPROGRESS (Operation now in progress)'), bare_tcp], directory, {"8080"})
    listener = '4 getsockname(6<TCP:[81]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0'
    accepted = '4 accept4(6<TCP:[81]>, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("127.0.0.1")}, [16], SOCK_CLOEXEC) = 5<TCP:[71]>'
    assert provider_tcp_connections([listener, accepted], {"8080"}) == {"71"}
    assert provider_tcp_connections([listener, accepted.replace('accept4(', 'accept(').replace(', SOCK_CLOEXEC)', ')')], {"8080"}) == {"71"}
    resized = listener.replace('[16]', '[128 => 16]')
    nonblocking = accepted.replace('SOCK_CLOEXEC)', 'SOCK_CLOEXEC|SOCK_NONBLOCK)')
    assert provider_tcp_connections([nonblocking, resized], {"8080"}) == {"71"}
    audit_network([bare_tcp], directory, {"8080"}, tcp_connections=provider_tcp_connections([listener, accepted], {"8080"}))
    for invalid in ([accepted], [listener, accepted.replace('[81]', '[82]')],
                    [listener.replace('htons(8080)', 'htons(8081)'), accepted],
                    [listener.replace(' = 0', ' = -1 EBADF (Bad file descriptor)'), accepted],
                    [resized.replace('127.0.0.1', '0.0.0.0'), nonblocking],
                    [listener, accepted.replace('127.0.0.1', '198.51.100.1')],
                    [listener, accepted.replace(' = 5<TCP:[71]>', ' = -1 EAGAIN (Resource temporarily unavailable)')]):
        assert not provider_tcp_connections(invalid, {"8080"}), invalid
    nscd = '3 connect(8<UNIX-STREAM:[51]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)'
    audit_network([nscd, nscd.replace('ENOENT (No such file or directory)', 'EPERM (Operation not permitted)')], directory, set())
    dbus = '8430 connect(10<UNIX-STREAM:[81562]>, {sa_family=AF_UNIX, sun_path="/run/user/1000/bus"}, 21) = -1 ENOENT (No such file or directory)'
    audit_network([dbus], directory, set())
    route = '4 socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 5<NETLINK:[123]>'
    tail = ', 40, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 40'
    structured = '4 sendto(5<NETLINK:[123]>, [{nlmsg_type=RTM_NEWLINK}, ["observer-secret]", "escaped\\\"quote"]]' + tail
    packet = redact_syscalls(structured)
    assert packet == '4 sendto(5<NETLINK:[123]>, "<payload redacted>"' + tail
    assert redact_syscalls(packet) == packet
    for prefix in ('4 recvfrom(5<NETLINK:[123]>, ', '4 <... recvfrom resumed>', '4 <... sendto resumed>'):
        assert redact_syscalls(prefix + '["observer-secret"]' + tail) == prefix + '"<payload redacted>"' + tail
    try:
        redact_syscalls('4 sendto(5<NETLINK:[123]>, ["observer-secret"')
    except AssertionError:
        pass
    else:
        raise AssertionError("Unterminated structured payload accepted")
    routes = kernel_route_sockets([route])
    assert routes == {("4", "5", "NETLINK:[123]")}
    audit_network([packet], directory, set(), routes)
    for invalid, observed_routes in ((packet, set()), (packet.replace('4 sendto', '5 sendto'), routes),
                                    (packet.replace('[123]', '[124]'), routes),
                                    (packet.replace('nl_pid=0', 'nl_pid=9'), routes),
                                    (packet.replace('nl_groups=00000000', 'nl_groups=00000001'), routes),
                                    (packet, kernel_route_sockets([route.replace('NETLINK_ROUTE', 'NETLINK_USERSOCK')]))):
        try:
            audit_network([invalid], directory, set(), observed_routes)
        except AssertionError:
            continue
        raise AssertionError("Network audit accepted an unknown Netlink peer")
    for unknown in ([send], [connect, send.replace("41->42", "43->42")],
                    [bare_ipc], [bare_pair, bare_ipc.replace('[51]', '[53]')],
                    [other_thread.replace('[51]', '[53]'), bare_pair],
                    [bare_pair, bare_ipc.replace('UNIX-STREAM', 'UNIX-DGRAM')],
                    [bare_tcp], [tcp_connect, bare_tcp.replace('[71]', '[72]')],
                    [tcp_connect.replace(' = 0', ' = -1 ECONNREFUSED (Connection refused)'), bare_tcp],
                    [nscd.replace(' = -1 ENOENT (No such file or directory)', ' = 0')],
                    [nscd.replace('/var/run/nscd/socket', '/outside/nscd/socket')],
                    [nscd.replace('ENOENT (No such file or directory)', 'EACCES (Permission denied)')],
                    [nscd, ipc],
                    [dbus.replace(' = -1 ENOENT (No such file or directory)', ' = 0')],
                    [dbus.replace('ENOENT (No such file or directory)', 'EPERM (Operation not permitted)')],
                    [dbus.replace('/run/user/1000/bus', '/run/user/1001/bus')],
                    [dbus.replace('/run/user/1000/bus', '/run/user/1000/bus-extra')],
                    [dbus.replace('connect(', 'sendto(')], [dbus.replace('UNIX-STREAM', 'UNIX-DGRAM')],
                    [dbus, bare_ipc.replace('[51]', '[81562]')],
                    [connect, send.replace("<UNIX-STREAM:[41->42]>", "")],
                    [tcp.replace(":8080]", ":8081]")], [tcp.replace("->127.0.0.1", "->198.51.100.1")],
                    [connect.replace("/fixture/", "/outside/")], [ipc],
                    [pair, ipc.replace("51->52", "51->53")], [pair.replace("52->51", "52->53")]):
        try:
            audit_network(unknown, directory, {"8080"})
        except AssertionError:
            continue
        raise AssertionError("Network audit accepted an unknown peer: " + repr(unknown))
    helper = '4 execve("/proc/self/exe", ["/proc/self/exe", "--codex-run-as-process-setup"], 0x1 /* 0 vars */) = 0'
    audit_executions([helper, '4 execve("/usr/bin/lsb_release", ["lsb_release", "-a"], 0x1) = 0'])
    missing_probe = '4 execve("/usr/bin/true", ["true"], 0x1 /* 27 vars */) = -1 ENOENT (No such file or directory)'
    for path in ("/inputs/host/codex-path/true", "/usr/bin/true", "/bin/true",
                 "/profile/tmp/arg0-linux/codex-arg0ABC123/true", "/work/zero-0/tmp/arg0-linux/codex-arg0ABC123/true",
                 "/profile/m02/embedded/tmp/arg0-linux/codex-arg0ABC123/true"):
        audit_executions([missing_probe.replace("/usr/bin/true", path)])
    alias = "/profile/tmp/arg0-linux/codex-arg0ABC123/codex-linux-sandbox"
    creation = '4 symlink("/inputs/host/bin/codex", "' + alias + '") = 0'
    bindings = bound_sandbox_aliases([creation])
    assert bindings == {alias}
    assert bound_sandbox_aliases([creation.replace('symlink(', 'symlinkat(').replace(', "' + alias, ', AT_FDCWD</work>, "' + alias)]) == bindings
    sandbox = '4 execve("' + alias + '", ["' + alias + '", "--sandbox-policy-cwd", "/work", "--permission-profile", "{}"], 0x1) = 0'
    audit_executions([sandbox], sandbox_aliases=bindings)
    for profile in ("/profile/m02/embedded", "/profile/m02/stdio-live"):
        nested_alias = alias.replace("/profile", profile, 1)
        nested_bindings = bound_sandbox_aliases([creation.replace(alias, nested_alias)])
        assert nested_bindings == {nested_alias}
        audit_executions([sandbox.replace(alias, nested_alias)], sandbox_aliases=nested_bindings)
    packaged = "/inputs/host/codex-resources/bwrap"
    opened = '4 openat(AT_FDCWD</work>, "' + packaged + '", O_RDONLY|O_CLOEXEC) = 3<' + packaged + '>'
    fd_exec = '4 execve("/proc/self/fd/3", ["bwrap", "--unshare-user", "--unshare-net", "--", "true"], 0x1) = 0'
    fd_bindings = bound_bwrap_executions([opened, fd_exec], packaged)
    assert fd_bindings == {fd_exec}
    aligned_exec = fd_exec.replace("4 ", "4\t ", 1)
    assert bound_bwrap_executions([opened.replace("4 ", "4     ", 1), aligned_exec], packaged) == {aligned_exec}
    audit_executions([fd_exec], bwrap_executions=fd_bindings)
    assert bound_bwrap_executions([opened, '4 close(4<' + packaged + '>) = 0', fd_exec], packaged) == fd_bindings
    for invalid in ([fd_exec], [opened.replace(packaged, "/tmp/bwrap"), fd_exec],
                    [opened, fd_exec.replace("4 execve", "5 execve")],
                    [opened, fd_exec.replace("/fd/3", "/fd/4")],
                    [opened, '4 close(3<' + packaged + '>) = 0', fd_exec],
                    [opened, '4 close(3<' + packaged + '>) = -1 EINTR (Interrupted)', fd_exec],
                    [opened, '4 close_range(3, 4294967295, 0) = 0', fd_exec],
                    [opened, '4 dup2(5</tmp/unknown>, 3<' + packaged + '>) = 3</tmp/unknown>', fd_exec],
                    [opened, '4 openat(AT_FDCWD, "/tmp/unknown", O_RDONLY) = 3</tmp/unknown>', fd_exec],
                    [opened, fd_exec, fd_exec]):
        try:
            bound_bwrap_executions(invalid, packaged)
        except AssertionError:
            continue
        raise AssertionError("Unknown or stale packaged helper FD accepted")
    unused = creation.replace("/inputs/host/bin/codex", "/work/packages/missing-helper/bin/codex")
    assert not bound_sandbox_aliases([unused])
    for invalid in (creation.replace("/inputs/host/bin/codex", "/tmp/codex"), unused,
                    creation.replace("/profile/tmp/", "/outside/tmp/"),
                    creation.replace("/profile/tmp/", "/profile/m02/../tmp/"),
                    creation.replace("/profile/tmp/", "/profile/m02//tmp/"),
                    creation.replace("/profile/tmp/", "/profile-extra/tmp/")):
        try:
            audit_executions([sandbox], sandbox_aliases=bound_sandbox_aliases([invalid]))
        except AssertionError:
            continue
        raise AssertionError("Unknown sandbox alias accepted")
    for unknown in ('4 execve("/usr/bin/cargo", ["cargo"], 0x1) = 0',
                    '4 execve("/tmp/codex-tools/unknown", ["unknown"], 0x1) = 0',
                    missing_probe.replace(' = -1 ENOENT (No such file or directory)', ' = 0'),
                    missing_probe.replace('ENOENT (No such file or directory)', 'EACCES (Permission denied)'),
                    missing_probe.replace('["true"]', '["true", "--unexpected"]'),
                    missing_probe.replace('/usr/bin/true', '/outside/true'),
                    missing_probe.replace('/usr/bin/true', '/usr/bin/cargo'),
                    missing_probe.replace('/usr/bin/true', '/profile/m02/../tmp/arg0-linux/codex-arg0ABC123/true'),
                    sandbox,
                    fd_exec,
                    helper.replace('"--codex-run-as-process-setup"', '"--unknown"')):
        try:
            audit_executions([unknown])
        except AssertionError:
            continue
        raise AssertionError("Execution audit accepted an unknown executable: " + unknown)


def audit(directory, pure=False):
    path = directory / "syscalls.log"
    text = redact_syscalls(path.read_text())
    path.write_text(text)
    calls = complete_syscalls(text.splitlines())
    executions = [line for line in calls if re.match(r"\d+\s+execve(?:at)?\(", line)]
    audit_executions(executions)
    observed = [line for line in calls if re.match(r'\d+\s+(?:connect|sendto|socketpair)\(', line)]
    network = [line for line in observed if not re.match(r'\d+\s+socketpair\(', line)]
    pairs = [line for line in observed if re.match(r'\d+\s+socketpair\(', line)]
    command = host.read(directory / "result.json")["command"]
    ports = set(re.findall(r"http://127[.]0[.]0[.]1:([0-9]+)", " ".join(command)))
    audit_network(observed, directory, ports)
    if pure:
        assert len(executions) == 1 and not observed, "Pure planning spawned code/network"
    result = {"status": "pass", "exec_count": len(executions), "network_count": len(network),
              "compiler_linker_jit_build_service_calls": 0, "syscalls": str(directory / "syscalls.log"),
              "executions": executions, "network": network, "pure_planning": pure,
              "socketpair_count": len(pairs), "socketpairs": pairs,
              "socket_payloads": "redacted; syscall descriptors, targets, sizes and results retained"}
    host.write(directory / "audit.json", result)
    return result


def child(directory, probe, home, action="policy", expected=0, extra=None, pure=False):
    directory.mkdir(parents=True, exist_ok=True)
    result = native_mod.child_case(directory, [*prefix(directory), str(probe), str(home)],
        home, action=action, expected=expected, extra=extra)
    result["audit"] = audit(directory, pure=pure)
    host.write(directory / "result.json", result)
    return result


def plan_result(directory, probe, home):
    result = child(directory, probe, home, action="plan", pure=True)
    assert not result["trace"] and not result["mod_events"], "Planning executed native code"
    value = json.loads((directory / "stdout.log").read_text())
    result.update(value)
    host.write(directory / "result.json", result)
    return result


def startup_error(directory, probe, home, code=None, native=False):
    result = child(directory, probe, home, action="load", expected="nonzero")
    errors = [row["detail"] for row in result["trace"] if row["event"] == "startup-failed"]
    assert len(errors) == 1 and errors[0]["already_native_executed"] is native, result
    assert not any(row["event"] in ("ready", "registration-commit") for row in result["trace"])
    if not native:
        assert not result["mod_events"] and not any(row["event"] == "dlopen-start" for row in result["trace"])
    if code:
        assert errors[0]["code"] == code, errors
    assert errors[0]["resource"] == CAPABILITY, errors
    result["diagnostic"] = errors[0]
    host.write(directory / "result.json", result)
    return result


def callback_keys(result, event_name, call_id="probe-call"):
    return [row["detail"]["mod"] + "::" + row["detail"]["contribution"] for row in result["trace"]
            if row["event"] == event_name and row["detail"]["call_id"] == call_id]


def hook_contract(result, *, short=False, legacy=False, call_id="probe-call"):
    expected = ["compose-a::before", "compose-b::before", "compose-a::around"]
    if not short:
        expected += ["compose-b::around"]
    if legacy:
        expected += ["serial-fixture::" + CAPABILITY]
    expected += ["compose-a::after", "compose-b::after"]
    assert callback_keys(result, "hook-enter", call_id) == expected
    next_keys = callback_keys(result, "hook-next", call_id)
    assert next_keys == ([] if short else ["compose-a::around", "compose-b::around"])
    after = [row["detail"] for row in result["trace"] if row["event"] == "hook-enter"
             and row["detail"]["call_id"] == call_id and row["detail"]["phase"] == "after"]
    assert len(after) == 2 and all(row["extra"]["outcome"] == 0 for row in after)
    init = [row["detail"]["mod"] for row in result["trace"] if row["event"] == "init-complete"]
    assert init == (["compose-b", "compose-a"] + (["serial-fixture"] if legacy else [])), init


def determinism(cases, probe, mods):
    results = []
    for index, reverse in enumerate((False, True)):
        home = cases / ("permutation-" + str(index)) / "profile"
        pair(home, mods, reverse=reverse)
        insertion = ["compose-b", "compose-a"] if reverse else ["compose-a", "compose-b"]
        # Filesystem enumeration need not follow insertion; also reverse the loader's path-to-ID order.
        for slot, owner in enumerate(insertion):
            (home / "mods" / owner).rename(home / "mods" / ("slot-" + str(slot)))
        entries = list(os.scandir(home / "mods"))
        observed = [tomllib.loads((Path(entry.path) / "mod.toml").read_text())["id"]
                    for entry in sorted(entries, key=lambda entry: entry.name)]
        assert observed == insertion
        result = plan_result(cases / ("plan-permutation-" + str(index)), probe, home)
        result["insertion_order"] = insertion
        result["observed_directory_entries"] = [entry.name for entry in entries]
        result["discovery_order_kind"] = "loader_inventory_package_path"
        result["observed_discovery_order"] = observed
        host.write(cases / ("plan-permutation-" + str(index)) / "result.json", result)
        results.append(result)
    assert results[0]["observed_discovery_order"] != results[1]["observed_discovery_order"]
    assert results[0]["plan"] == results[1]["plan"]
    assert results[0]["plan_sha256"] == results[1]["plan_sha256"]
    graph_controls = []
    for name, dependency, explicit in (("no-edges", False, False), ("dependency-only", True, False),
                                       ("hook-only", False, True)):
        home = cases / name / "profile"
        pair(home, mods, dependency=dependency, explicit=explicit)
        result = plan_result(cases / ("plan-" + name), probe, home)
        plan = result["plan"]
        assert plan["initialization_order"] == (["compose-b", "compose-a"] if dependency else ["compose-a", "compose-b"])
        assert bool(plan["dependency_edges"]) is dependency and bool(plan["hook_edges"]) is explicit
        assert plan["phases"]["body"] == ["compose-a::around", "compose-b::around"]
        graph_controls.append(result)
    return {"permutations": results, "graph_independence_controls": graph_controls}


def read_line(process, timeout=30):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise TimeoutError("Missing explicit probe barrier output")
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("Probe exited before barrier: " + str(process.poll()))
        return line
    finally:
        selector.close()


def drift(cases, probe, binary, mods):
    results = []
    for kind in ("manifest", "payload", "resource", "config", "config-create", "inventory-add",
                 "inventory-remove", "disabled-manifest", "host"):
        for replace in ((False, True) if kind in ("manifest", "payload", "resource", "config") else (False,)):
            directory = cases / ("drift-" + kind + ("-rename" if replace else "-in-place"))
            home = directory / "profile"
            pair(home, mods)
            if kind != "config-create":
                selection(home, ["compose-a", "compose-b"])
            if kind == "disabled-manifest":
                disabled = install(home, mods["a/short"], directory="disabled", changes={"id": "disabled"})
            directory.mkdir(parents=True, exist_ok=True)
            env = {**os.environ, "CODEX_HOME": str(home), "CM_PROBE_ACTION": "prepared",
                   "CM_NATIVE_TRACE": str(directory / "trace.jsonl"),
                   "CM_FIXTURE_EVENTS": str(directory / "mod-events.jsonl")}
            if kind == "host":
                env["CM_PLAN_EXECUTABLE"] = str(binary)
            command = [*prefix(directory), str(probe), str(home)]
            with (directory / "stderr.log").open("w") as err:
                process = subprocess.Popen(command, cwd=directory, env=env, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=err, text=True, start_new_session=True)
                value = None
                try:
                    value = json.loads(read_line(process))
                    assert not native_mod.rows(directory / "mod-events.jsonl"), "Planning executed constructors"
                    path = None
                    data = None
                    if kind == "manifest":
                        path = home / "mods/compose-a/mod.toml"
                        data = path.read_bytes() + b"# changed manifest\n"
                    elif kind == "payload":
                        path = home / "mods/compose-a/payload.so"
                        data = Path(mods["a/short"]["payload"]).read_bytes()
                    elif kind == "resource":
                        path = home / "mods/compose-a/data.txt"
                        data = b"changed-resource\n"
                    elif kind in ("config", "config-create"):
                        path = home / "cm-runtime.toml"
                        data = b"format_version=1\nenabled=[]\n"
                    elif kind == "inventory-add":
                        install(home, mods["a/short"], directory="new", changes={"id": "new-mod"})
                    elif kind == "inventory-remove":
                        shutil.rmtree(home / "mods/compose-b")
                    elif kind == "disabled-manifest":
                        path = disabled / "mod.toml"
                        data = path.read_bytes() + b"# disabled input changed\n"
                    if path is not None:
                        if replace:
                            path.rename(path.with_name(path.name + ".previous"))
                        path.write_bytes(data)
                    process.stdin.write("commit\n")
                    process.stdin.flush()
                    remaining, _ = process.communicate(timeout=30)
                    (directory / "stdout.log").write_text(json.dumps(value) + "\n" + remaining)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    host.write(directory / "result.json", {
                        "command": command, "return_code": process.returncode, "input": kind,
                        "replace": replace, "prepared": value,
                        "trace": native_mod.rows(directory / "trace.jsonl")})
            assert process.returncode != 0
            trace = native_mod.rows(directory / "trace.jsonl")
            errors = [row["detail"] for row in trace if row["event"] == "startup-failed"]
            assert len(errors) == 1 and errors[0]["code"] == "input_drift"
            assert not errors[0]["already_native_executed"]
            assert not native_mod.rows(directory / "mod-events.jsonl")
            assert not any(row["event"] in ("ready", "dlopen-start") for row in trace)
            result = host.read(directory / "result.json")
            result["audit"] = audit(directory)
            result["diagnostic"] = errors[0]
            # A new pure plan must bind the current inputs; repair only the declared payload/resource hash.
            if kind in ("payload", "resource"):
                package = home / "mods/compose-a"
                fields = tomllib.loads((package / "mod.toml").read_text())
                if kind == "payload":
                    fields["payload_size"] = path.stat().st_size
                    fields["payload_sha256"] = host.sha(path)
                else:
                    fields["resources"][0].update(size=path.stat().st_size, sha256=host.sha(path))
                write_manifest(package, fields)
            if kind not in ("inventory-remove",):
                replanned = plan_result(cases / (directory.name + "-replan"), probe, home)
                assert replanned["plan_sha256"] != value["plan_sha256"], kind
                result["replanned"] = replanned
            host.write(directory / "result.json", result)
            results.append(result)
    return {"drift_cases": results, "actual_second_elf": {"path": str(binary), "sha256": host.sha(binary)},
            "scope": "probe uses owned prepared input; real Core positive separately binds packaged H"}


def exclusive(cases, probe, mods):
    results = []
    for index, (priority_a, priority_b, order, reverse) in enumerate((
        (0, 0, "none", False), (100, -100, "none", True), (-100, 100, "before", False),
        (100, 100, "cycle", True),
    )):
        home = cases / ("exclusive-" + str(index)) / "profile"
        pair(home, mods, "replacement", "replacement", dependency=False, reverse=reverse)
        for role, priority in (("a", priority_a), ("b", priority_b)):
            package = home / "mods" / ("compose-" + role)
            fields = tomllib.loads((package / "mod.toml").read_text())
            hook = fields["contributions"][0]
            hook["priority"] = priority
            if order == "cycle" or (order == "before" and role == "a"):
                hook["order_before"] = ["compose-" + ("b" if role == "a" else "a") + "::terminal"]
            write_manifest(package, fields)
        result = startup_error(cases / ("exclusive-result-" + str(index)), probe, home, "exclusive_conflict")
        diagnostic = result["diagnostic"]
        assert set(diagnostic["related_contributions"]) == {"compose-a::terminal", "compose-b::terminal"}
        assert diagnostic["contribution"] == diagnostic["mod_id"] + "::terminal"
        assert diagnostic["graph"] == "contribution" and diagnostic["resource"] == CAPABILITY
        results.append(result)
    home = cases / "exclusive-positive/profile"
    install(home, mods["a/normal"])
    install(home, mods["b/replacement"])
    positive = child(cases / "exclusive-positive-result", probe, home)
    assert "compose-b::terminal" in callback_keys(positive, "hook-enter")
    assert any(row["event"] == "policy-decision" and not row["detail"]["final_parallel"] for row in positive["trace"])
    return {"rejected_before_loading": results, "single_replacement": positive}


def declaration_matrix(cases, probe, mods):
    results = []
    mutations = (
        ("missing-dependency", {"dependencies": [{"id": "absent", "version": "0.1.0"}]}, "missing_dependency"),
        ("dependency-version", {"dependencies": [{"id": "compose-b", "version": "9.0.0"}]}, "dependency_version"),
        ("range", {"dependencies": [{"id": "compose-b", "version": "^0.1"}]}, "unsupported_version"),
        ("self-dependency", {"dependencies": [{"id": "compose-a", "version": "0.1.0"}]}, "dependency"),
        ("capability", {"required_capabilities": ["unknown"]}, "manifest_contract"),
        ("abi-major", {"abi_major": 99}, "manifest_contract"),
        ("abi-minor", {"abi_minor": 99}, "manifest_contract"),
        ("target", {"target": "aarch64-unknown-linux-gnu"}, "manifest_contract"),
        ("reserved-mod", {"id": "core.impersonator"}, "reserved_name"),
        ("explicit-conflict", {"conflicts": ["compose-b"]}, "declared_conflict"),
        ("resource-path", {"resources": [{"path": "../secret", "size": 0, "sha256": "0" * 64}]}, "resource_path"),
        ("resource-hash", {"resources": [{"path": "data.txt", "size": 24, "sha256": "0" * 64}]}, "package_input"),
        ("payload-budget", {"payload_size": 64 * 1024 * 1024 + 1}, "manifest_contract"),
    )
    for name, changes, code in mutations:
        home = cases / ("declaration-" + name) / "profile"
        install(home, mods["a/normal"], changes=changes)
        install(home, mods["b/normal"])
        result = startup_error(cases / ("result-" + name), probe, home, code)
        assert result["diagnostic"]["mod_id"], name
        results.append(result)
    for name in ("duplicate-mod", "dependency-cycle", "duplicate-hook", "reserved-hook", "missing-hook",
                 "cross-phase", "hook-cycle", "unknown-resource", "unknown-hook-capability",
                 "priority", "duplicate-resource", "duplicate-config", "unknown-config", "disabled",
                 "payload-symlink-parent", "resource-hardlink"):
        home = cases / ("declaration-" + name) / "profile"
        pair(home, mods, explicit=False)
        package = home / "mods/compose-a"
        fields = tomllib.loads((package / "mod.toml").read_text())
        if name == "duplicate-mod":
            install(home, mods["a/normal"], directory="duplicate")
        elif name == "dependency-cycle":
            other = home / "mods/compose-b"
            other_fields = tomllib.loads((other / "mod.toml").read_text())
            other_fields["dependencies"] = [{"id": "compose-a", "version": "0.1.0"}]
            write_manifest(other, other_fields)
        elif name == "duplicate-hook":
            fields["contributions"].append(copy.deepcopy(fields["contributions"][0]))
        elif name == "reserved-hook":
            fields["contributions"][0]["id"] = "core.stolen"
        elif name == "missing-hook":
            fields["contributions"][0]["order_before"] = ["compose-b::absent"]
        elif name == "cross-phase":
            fields["contributions"][0]["order_before"] = ["compose-b::around"]
        elif name == "hook-cycle":
            fields["contributions"][0]["order_before"] = ["compose-b::before"]
            other = home / "mods/compose-b"
            other_fields = tomllib.loads((other / "mod.toml").read_text())
            other_fields["contributions"][0]["order_before"] = ["compose-a::before"]
            write_manifest(other, other_fields)
        elif name == "unknown-resource":
            fields["contributions"][0]["resource"] = "unknown.resource"
        elif name == "unknown-hook-capability":
            fields["contributions"][0]["capability"] = "unknown.capability"
        elif name == "priority":
            fields["contributions"][0]["priority"] = 1_000_001
        elif name == "duplicate-resource":
            fields["resources"] *= 2
        elif name == "duplicate-config":
            selection(home, ["compose-a", "compose-a"])
        elif name == "unknown-config":
            selection(home, ["absent"])
        elif name == "disabled":
            fields.update(abi_major=99, target="unsupported", payload_sha256="0" * 64)
            fields["dependencies"] = []
            selection(home, ["compose-b"])
        elif name == "payload-symlink-parent":
            (package / "alias").symlink_to(package, target_is_directory=True)
            fields["payload"] = "alias/payload.so"
        elif name == "resource-hardlink":
            os.link(package / "data.txt", package / "second.txt")
        write_manifest(package, fields)
        if name == "disabled":
            result = child(cases / ("result-" + name), probe, home)
            assert {row["mod"] for row in result["mod_events"]} == {"compose-b"}
        else:
            result = startup_error(cases / ("result-" + name), probe, home)
            if name not in ("duplicate-mod", "duplicate-config", "unknown-config", "payload-symlink-parent", "resource-hardlink"):
                assert result["diagnostic"]["mod_id"], name
        results.append(result)
    max_home = cases / "registration-max-table/profile"
    install(max_home, mods["a/max-table"])
    results.append(child(cases / "result-max-table", probe, max_home))
    registration = []
    for variant in INVALID:
        home = cases / ("registration-" + variant) / "profile"
        install(home, mods["a/" + variant])
        result = startup_error(cases / ("result-registration-" + variant), probe, home, native=True)
        assert sum(row["event"] == "constructor" for row in result["mod_events"]) == 1
        assert result["diagnostic"]["mod_id"] == "compose-a"
        registration.append(result)
    return {"preflight_cases": results, "actual_registration_cases": registration}


def pad_text(path, size):
    data = path.read_bytes()
    assert len(data) + 2 <= size
    path.write_bytes(data + b"#" + b" " * (size - len(data) - 2) + b"\n")
    assert path.stat().st_size == size


def limits(cases, probe, mods):
    mib = 1024 * 1024
    home = cases / "bounds/profile"
    original = {}
    for index in range(32):
        owner = "bound-" + str(index).zfill(2)
        package = install(home, mods["a/normal"], directory=owner, changes={"id": owner})
        with (package / "payload.so").open("ab") as output:
            output.truncate(8 * mib)
        fields = tomllib.loads((package / "mod.toml").read_text())
        fields.update(payload_size=8 * mib, payload_sha256=host.sha(package / "payload.so"))
        fields["contributions"] = [{"id": "h" + str(number), "kind": kind, "resource": CAPABILITY,
            "capability": COMPOSE} for number, kind in enumerate(("before", "around", "around", "after"))]
        fields["resources"] = []
        for number in range(2):
            resource_file = package / ("r" + str(number))
            with resource_file.open("wb") as output:
                output.truncate(mib)
            fields["resources"].append({"path": resource_file.name, "size": mib, "sha256": host.sha(resource_file)})
        write_manifest(package, fields)
        original[owner] = fields
    selection(home, list(original))
    first = home / "mods/bound-00"
    pad_text(first / "mod.toml", 64 * 1024)
    pad_text(home / "cm-runtime.toml", 64 * 1024)
    positive = plan_result(cases / "bounds-exact", probe, home)
    assert len(positive["plan"]["mods"]) == 32
    assert sum(len(value["contributions"]) for value in positive["plan"]["mods"].values()) == 128
    assert sum(len(value["resources"]) for value in positive["plan"]["mods"].values()) == 64
    originals = {path: path.read_bytes() for path in (first / "mod.toml", home / "cm-runtime.toml")}
    negative = []
    for name in ("packages", "contributions", "resources", "total-payload", "total-resource", "manifest", "config"):
        fields = copy.deepcopy(original["bound-00"])
        extra = home / "mods/extra"
        if name == "packages":
            extra.mkdir()
        elif name == "contributions":
            fields["contributions"].append({"id": "overflow", "kind": "before", "resource": CAPABILITY, "capability": COMPOSE})
        elif name == "resources":
            fields["resources"].append({"path": "overflow", "size": 0, "sha256": "0" * 64})
        elif name == "total-payload":
            fields["payload_size"] += 1
        elif name == "total-resource":
            fields["resources"][0]["size"] += 1
        if name in ("manifest", "config"):
            path = first / "mod.toml" if name == "manifest" else home / "cm-runtime.toml"
            path.write_bytes(originals[path] + b" ")
        elif name != "packages":
            write_manifest(first, fields)
        negative.append(startup_error(cases / ("bounds-plus-one-" + name), probe, home))
        for path, data in originals.items():
            path.write_bytes(data)
        if extra.exists():
            extra.rmdir()
    single = cases / "object-bounds/profile"
    package = install(single, mods["a/normal"])
    with (package / "payload.so").open("ab") as output:
        output.truncate(64 * mib)
    with (package / "data.txt").open("ab") as output:
        output.truncate(8 * mib)
    fields = tomllib.loads((package / "mod.toml").read_text())
    fields.update(payload_size=64 * mib, payload_sha256=host.sha(package / "payload.so"), version="v" * 128)
    fields["resources"][0].update(size=8 * mib, sha256=host.sha(package / "data.txt"))
    fields["id"] = "m" * 128
    fields["contributions"][0]["id"] = "h" * 128
    long_path = "/".join(["p" * 127] * 3 + ["f" * 128])
    assert len(long_path) == 512
    destination = package / long_path
    destination.parent.mkdir(parents=True)
    shutil.copyfile(package / "data.txt", destination)
    fields["resources"][0]["path"] = long_path
    write_manifest(package, fields)
    object_positive = plan_result(cases / "object-bounds-exact", probe, single)
    for name in ("payload", "resource", "mod-id", "contribution-id", "version", "path"):
        invalid = copy.deepcopy(fields)
        if name == "payload":
            invalid["payload_size"] += 1
        elif name == "resource":
            invalid["resources"][0]["size"] += 1
        elif name == "mod-id":
            invalid["id"] += "m"
        elif name == "contribution-id":
            invalid["contributions"][0]["id"] += "h"
        elif name == "version":
            invalid["version"] += "v"
        elif name == "path":
            invalid["resources"][0]["path"] += "x"
        write_manifest(package, invalid)
        negative.append(startup_error(cases / ("object-plus-one-" + name), probe, single))
    return {"set_exact_limits": positive, "object_exact_limits": object_positive, "limit_plus_one": negative}


def callback_matrix(cases, probe, mods, legacy):
    positives = []
    for name, variant, mixed, original in (
        ("normal", "normal", False, True), ("false-input", "normal", False, False),
        ("error-exact", "normal", False, True),
        ("short", "short", False, True), ("mixed-short", "short", True, True),
    ):
        home = cases / ("callback-" + name) / "profile"
        pair(home, mods, variant)
        if mixed:
            native_mod.install(home, Path(legacy["payload"]))
        result = child(cases / ("callback-result-" + name), probe, home,
            extra={"CM_PROBE_ORIGINAL": str(original).lower(),
                   "CM_COMPOSE_MODE": "compose-a:error-exact" if name == "error-exact" else ""})
        hook_contract(result, short=variant == "short", legacy=mixed)
        decision = next(row["detail"] for row in result["trace"] if row["event"] == "policy-decision")
        assert decision["original_parallel"] is original and decision["final_parallel"] is False
        if variant == "normal":
            completed = callback_keys(result, "around-complete")
            assert completed == ["compose-b::around", "compose-a::around"]
        positives.append(result)
    failures = []
    modes = (
        "compose-a:repeat", "compose-a:stale", "compose-a:wrong-thread",
        "compose-b:cross-owner", "compose-a:next-before", "compose-a:next-after",
        "compose-a:next-null-output", "compose-a:next-bad-header", "compose-a:next-error-cap",
        "compose-a:short-keep", "compose-a:before-fail", "compose-b:inner-fail",
        "compose-a:swallow-error,compose-b:inner-fail", "compose-a:after-fail",
        "compose-a:bad-decision", "compose-a:bad-header", "compose-a:bad-status",
        "compose-a:error-length", "compose-a:error-canary", "compose-a:output-canary",
        "compose-a:fake-cancel", "compose-a:callback-panic",
    )
    for index, mode in enumerate(modes):
        home = cases / ("callback-failure-" + str(index)) / "profile"
        pair(home, mods)
        result = child(cases / ("callback-failure-result-" + str(index)), probe, home,
            action="twice" if mode.endswith(":stale") else "policy", expected="nonzero",
            extra={"CM_COMPOSE_MODE": mode, "CM_TOKEN_FILE": str(home / "token.txt")})
        assert any(row["event"] == "policy-failed" for row in result["trace"]), mode
        starts = callback_keys(result, "hook-enter")
        # Stale case has a complete first invocation; inspect the final after pair.
        assert starts[-2:] == ["compose-a::after", "compose-b::after"], (mode, starts)
        assert [row["mod"] for row in result["mod_events"] if row["event"] == "release"] == ["compose-a", "compose-b"]
        failures.append(result)
    home = cases / "cancel-before/profile"
    pair(home, mods)
    initial_cancel = child(cases / "cancel-before-result", probe, home, action="cancel-before")
    assert not callback_keys(initial_cancel, "hook-enter")
    return {"policy_positive_cases": positives, "policy_failure_cases": failures, "cancel_before": initial_cancel}


def held_callback(cases, probe, mods, action):
    directory = cases / ("held-" + action)
    home = directory / "profile"
    pair(home, mods)
    listener = socket.socket(socket.AF_UNIX)
    path = directory / "callback.sock"
    listener.bind(str(path))
    listener.listen(1)
    listener.settimeout(30)
    env = {**os.environ, "CM_PROBE_ACTION": "policy" if action == "stuck" else action,
           "CM_COMPOSE_MODE": "compose-a:hold", "CM_FIXTURE_SOCKET": str(path),
           "CM_FIXTURE_EVENTS": str(directory / "mod-events.jsonl"),
           "CM_NATIVE_TRACE": str(directory / "trace.jsonl")}
    command = [*prefix(directory), str(probe), str(home)]
    with (directory / "stderr.log").open("w") as err:
        process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=err, text=True, start_new_session=True)
        connection = None
        output = ""
        try:
            connection, _ = listener.accept()
            connection.settimeout(30)
            assert connection.recv(100) == b"callback-entered\n"
            assert not any(row["event"] == "release" for row in native_mod.rows(directory / "mod-events.jsonl"))
            if action == "stuck":
                try:
                    process.wait(timeout=1)
                    raise AssertionError("Unreleased synchronous callback unexpectedly returned")
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            else:
                process.stdin.write("continue\n")
                process.stdin.flush()
                if action == "cancel-after":
                    output += read_line(process)
                    assert "cancel-recorded" in output
                else:
                    # Explicit stop observation before releasing the blocked callback.
                    deadline = time.monotonic() + 30
                    while not any(row["event"] == "stopping-requested" for row in native_mod.rows(directory / "trace.jsonl")):
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Drain did not request stopping")
                        time.sleep(0.01)
                connection.sendall(b"x")
                tail, _ = process.communicate(timeout=30)
                output += tail
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if connection is not None:
                connection.close()
            listener.close()
            (directory / "stdout.log").write_text(output)
            result = {"action": action, "command": command, "return_code": process.returncode,
                      "trace": native_mod.rows(directory / "trace.jsonl"),
                      "mod_events": native_mod.rows(directory / "mod-events.jsonl")}
            host.write(directory / "result.json", result)
    if action == "stuck":
        assert process.returncode == -signal.SIGKILL
        assert not any(row["event"] == "stopped" for row in result["trace"])
        result["classification"] = "synchronous-native-watchdog-process-failure"
    else:
        assert process.returncode == 0, (directory / "stderr.log").read_text()
        after = [row["detail"] for row in result["trace"] if row["event"] == "hook-enter" and row["detail"]["phase"] == "after"]
        assert len(after) == 2 and all(row["extra"]["outcome"] == (2 if action == "cancel-after" else 0) for row in after)
        assert [row["mod"] for row in result["mod_events"] if row["event"] == "release"] == ["compose-a", "compose-b"]
    result["audit"] = audit(directory)
    host.write(directory / "result.json", result)
    return result


def transactions(cases, probe, binary, mods):
    results = []
    for variant in ("init-fail", "release-fail"):
        home = cases / ("transaction-" + variant) / "profile"
        pair(home, mods, variant)
        directory = cases / ("transaction-result-" + variant)
        if variant == "init-fail":
            directory.mkdir(parents=True)
            result = native_mod.child_case(directory,
                [*prefix(directory), str(binary), "exec", "--skip-git-repo-check", "--json", "must never start"],
                home, expected="nonzero")
            assert not any(row["event"] in ("ready", "registration-commit") for row in result["trace"])
            assert "thread.started" not in (directory / "stdout.log").read_text()
            error = next(row["detail"] for row in result["trace"] if row["event"] == "startup-failed")
            assert error["stage"] == "init" and error["mod_id"] == "compose-a" and error["already_native_executed"]
            result["audit"] = audit(directory)
            assert result["audit"]["network_count"] == 0
        else:
            result = child(directory, probe, home, action="load", expected="nonzero")
            assert any(row["event"] == "ready" for row in result["trace"])
            assert not any(row["event"] == "stopped" for row in result["trace"])
        events = result["mod_events"]
        assert [row["mod"] for row in events if row["event"] == "init"] == ["compose-b", "compose-a"]
        assert [row["mod"] for row in events if row["event"] == "release"] == ["compose-a", "compose-b"]
        result["first_error_preserved"] = True
        host.write(directory / "result.json", result)
        results.append(result)
    return {"failed_transactions_and_release_continuation": results}


def business(cases, root, binary, mods, frozen):
    sys.path.insert(0, str(root / "fixtures/native-loader"))
    from core_acceptance import run_case
    controls = []
    for name, roles, restrictive in (
        ("empty", (), False), ("a", ("a",), False), ("b", ("b",), True),
        ("ab", ("a", "b"), True), ("disabled", ("a", "b"), False), ("removed", (), False),
        ("replacement", ("a", "b/replacement"), True),
        ("same-mod-next", ("a/nested-next", "b"), True),
    ):
        home = cases / ("business-" + name) / "profile"
        home.mkdir(parents=True)
        if name == "ab":
            pair(home, mods)
        else:
            for role in roles:
                install(home, mods[role if "/" in role else role + "/normal"])
            if name == "disabled":
                selection(home, [])
            if name == "removed":
                package = install(home, mods["b/normal"])
                shutil.rmtree(package)
        directory = cases / ("core-" + name)
        result = run_case(root, directory, binary, home, bool(roles) and name != "disabled",
                          restrictive=restrictive, command_prefix=prefix(directory))
        result["audit"] = audit(directory)
        trace = native_mod.rows(directory / "core-trace.jsonl")
        ready = next(row["detail"] for row in trace if row["event"] == "ready")
        assert ready["plan"]["host"]["executable_sha256"] == frozen["executable_sha256"]
        assert ready["plan"]["host"]["build_id"] == frozen["host_identity"]["host_build_id"]
        if name == "ab":
            for call_id in ("cm-a", "cm-b"):
                hook_contract({"trace": trace}, call_id=call_id)
            assert ready["plan"]["initialization_order"] == ["compose-b", "compose-a"]
        if name == "replacement":
            assert any(row["event"] == "hook-enter" and row["detail"]["contribution"] == "terminal" for row in trace)
        if name == "same-mod-next":
            for call_id in ("cm-a", "cm-b"):
                order = [key for key in callback_keys({"trace": trace}, "hook-enter", call_id)
                         if "::around" in key]
                assert order == ["compose-a::around", "compose-a::around-inner", "compose-b::around"], order
                assert callback_keys({"trace": trace}, "around-complete", call_id) == list(reversed(order))
        result["runtime_plan_sha256"] = ready["plan_sha256"]
        result["runtime_plan"] = ready["plan"]
        host.write(directory / "result.json", result)
        controls.append(result)
    failures_and_cancellation = []
    home = cases / "business-errors/profile"
    pair(home, mods)
    for scenario in ("callback-failure", "cancel-waiting", "cancel-executing"):
        directory = cases / ("core-" + scenario)
        result = run_case(root, directory, binary, home, True, scenario=scenario, expected_releases=2,
            extra_env={"CM_COMPOSE_MODE": "compose-a:before-fail" if scenario == "callback-failure" else ""})
        result["observation"] = "direct child for real SIGINT delivery; successful runtime selection audited separately"
        failures_and_cancellation.append(result)
    parallel_source = (root / host.HOST / "codex-rs/core/src/tools/parallel.rs").read_text()
    assert parallel_source.count("router.tool_supports_parallel(&call)") == 1
    assert parallel_source.count("cm_runtime::tool_policy::evaluate(") == 1
    return {"real_core_controls": controls, "real_core_failure_and_cancellation": failures_and_cancellation,
            "original_query": "one unchanged router.tool_supports_parallel query before the policy chain",
            "original_query_source_sha256": host.sha(root / host.HOST / "codex-rs/core/src/tools/parallel.rs"),
            "seam": "eligibility strategy chain; original RWLock and asynchronous handler remain Core-owned"}


def collect_lightweight(artifact, logs):
    evidence = artifact / "evidence"
    for path in evidence.rglob("*"):
        relative = path.relative_to(evidence)
        if not path.is_file() or path.is_symlink() or path.suffix not in {".json", ".jsonl", ".log"}:
            continue
        if {"profile", "business-profile", "home"}.intersection(relative.parts):
            continue
        data = (redact_syscalls(path.read_text()).encode("utf-8")
                if path.name == "syscalls.log" else path.read_bytes())
        data.decode("utf-8")
        assert b"\0" not in data and len(data) <= 16 * 1024 * 1024, str(relative)
        destination = logs / "acceptance-evidence" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    for name in ("acceptance.json", "p01-baseline-acceptance.json", "p02-baseline-acceptance.json"):
        if (artifact / name).is_file():
            shutil.copyfile(artifact / name, logs / name)


def main():
    require_hosted_linux()
    if os.environ.get("GITHUB_REPOSITORY") != "DSLZL/CM-build-linux-x64":
        raise RuntimeError("P03 runs only in the independent Linux x64 builder")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = Path(os.environ["CM_SOURCE_DIR"]).resolve()
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    evidence = artifact / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    acceptance = {"schema_version": 1, "task_id": "CM-P03", "target": TARGET, "status": "not_run",
                  "implementation_commit": host.git(root, "rev-parse", "HEAD"),
                  "checks": [{"id": check, "status": "not_run", "evidence": ["evidence/" + name]}
                             for check, name in CHECKS.items()]}
    host.write(artifact / "acceptance.json", acceptance)
    stage = "P01/P02 regressions"
    try:
        package, frozen, legacy, probe = native_mod.acceptance(root, logs, report_name="p02-baseline-acceptance.json")
        for name in ("p01-baseline-acceptance.json", "p02-baseline-acceptance.json"):
            assert host.read(artifact / name)["status"] == "pass"
        stage = "independent authors"
        mods = build_mods(root, logs, package, frozen)
        binary = package / "bin/codex"
        cases = evidence / "p03"
        common = {"source_repository": os.environ["CM_SOURCE_REPOSITORY"],
                  "source_sha": acceptance["implementation_commit"],
                  "workflow_repository": os.environ["GITHUB_REPOSITORY"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
                  "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                  "job": os.environ["GITHUB_JOB"], "target": TARGET,
                  "runner": host.read(logs / "run-metadata.json")["context"],
                  "host": frozen, "mods": mods, "legacy_mod": legacy,
                  "c_layout": json.loads((logs / "composition-c-layout.log").read_text()),
                  "rust_layout": host.build_log(logs, "host-test").relative_to(logs).as_posix() + ": linux_x64_composition_layout",
                  "selection_builds": 0, "release_ready": False}
        reports = {}
        stage = "determinism"
        reports["runtime-plan-determinism.json"] = determinism(cases, probe, mods)
        stage = "callbacks"
        callbacks = callback_matrix(cases, probe, mods, legacy)
        callbacks["held_callback_cases"] = [held_callback(cases, probe, mods, action)
                                             for action in ("cancel-after", "drain", "stuck")]
        stage = "locked input drift"
        reports["runtime-plan-drift.json"] = drift(cases, probe, binary, mods)
        stage = "exclusive conflict"
        reports["exclusive-hook-conflict.json"] = exclusive(cases, probe, mods)
        stage = "declarations and bounds"
        reports["runtime-conflict-matrix.json"] = declaration_matrix(cases, probe, mods)
        reports["runtime-conflict-matrix.json"]["boundaries"] = limits(cases, probe, mods)
        stage = "registration transaction"
        transaction = transactions(cases, probe, binary, mods)
        stage = "real Core"
        core = business(cases, root, binary, mods, frozen)
        assert callbacks.keys().isdisjoint(core)
        reports["hook-order-contract.json"] = {**callbacks, **core}
        transaction.update(core)
        transaction["consumer_boundary"] = "runtime process/network observations; P04 toolchain-free isolated consumer remains pending"
        reports["registration-transaction.json"] = transaction
        stage = "immutable provenance"
        assert host.sha(binary) == frozen["executable_sha256"]
        assert host.manifest_digest(host.manifest(package)) == frozen["package_manifest_sha256"]
        for receipt in mods.values():
            assert host.sha(Path(receipt["payload"])) == receipt["payload_sha256"]
        assert host.sha(Path(legacy["payload"])) == legacy["payload_sha256"]
        assert host.read(logs / "host-identity.json")["inputs"] == host.identity_inputs(root, logs)
        host.verify_sources(root, logs)
        assert set(reports) == set(CHECKS.values())
        for name, result in reports.items():
            assert common.keys().isdisjoint(result), "Report overwrites common provenance: " + name
            host.write(evidence / name, {"status": "pass", **common, **result})
        acceptance["status"] = "pass"
        for check in acceptance["checks"]:
            check.update(status="pass", command="python3 -B ci/scripts/runtime_composition.py")
        host.write(artifact / "acceptance.json", acceptance)
    except BaseException as error:
        acceptance.update(status="failed", failed_stage=stage, error=repr(error))
        host.write(artifact / "acceptance.json", acceptance)
        raise
    finally:
        try:
            collect_lightweight(artifact, logs)
        except BaseException as error:
            acceptance.update(status="failed", collection_error=repr(error))
            host.write(artifact / "acceptance.json", acceptance)
            host.write(logs / "acceptance.json", acceptance)
            raise


if __name__ == "__main__":
    main()
