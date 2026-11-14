#!/usr/bin/env python3
"""Hosted Windows PSEC mechanism gates; no product or full isolation qualification."""
import ctypes
from collections import Counter
from contextlib import ExitStack
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import ipaddress
import socket
import socketserver
import stat
import tempfile
import threading

import ci_progress
import record_run
from windows_x64_preflight import KEY, authority, exact_record, pe_fixture

SDK_REV = "6cd3d58f05d3447e67109cfb75e042803b843ca4"
SDK_LOCK_SHA = "60fce5417115280ff1ecf0a17934c2799d8e99a3a8d5c7d4cda56c8d3fb7dde9"
EXPORTS = ("CreateProcessSecurityEnvironment", "QueryProcessSecurityEnvironmentSupport",
           "CloseProcessSecurityEnvironment")


def surface_ready(value):
    if set(value) != {"api_set", "dll_loaded", "exports", "query_hresult", "support_flags", "winerror"}:
        raise RuntimeError("Unexpected native PSEC surface record")
    if any(type(value[key]) is not bool for key in ("api_set", "dll_loaded")) or \
            set(value["exports"]) != set(EXPORTS) or \
            any(type(item) is not bool for item in value["exports"].values()):
        raise RuntimeError("Invalid native PSEC surface types")
    for key, low, high in (("query_hresult", -(1 << 31), (1 << 31) - 1),
                           ("support_flags", 0, (1 << 64) - 1), ("winerror", 0, (1 << 32) - 1)):
        if value[key] is not None and (type(value[key]) is not int or not low <= value[key] <= high):
            raise RuntimeError("Invalid native PSEC numeric field: " + key)
    return value["api_set"] and value["dll_loaded"] and all(value["exports"].values()) and \
        value["query_hresult"] is not None and value["query_hresult"] >= 0 and \
        value["support_flags"] is not None and bool(value["support_flags"] & 1) and value["winerror"] is None


def native_surface():
    value = {"api_set": False, "dll_loaded": False, "exports": dict.fromkeys(EXPORTS, False),
             "query_hresult": None, "support_flags": None, "winerror": None}
    try:
        api_query = ctypes.WinDLL("api-ms-win-core-apiquery-l2-1-0.dll", winmode=0x800, use_last_error=True)
        implemented = api_query.IsApiSetImplemented
        implemented.argtypes, implemented.restype = [ctypes.c_char_p], ctypes.c_int32
        value["api_set"] = bool(implemented(b"api-win-appmodel-processmodel~securityenvironment"))
        if not value["api_set"]:
            return value
        model = ctypes.WinDLL("processmodel.dll", winmode=0x800, use_last_error=True)
        value["dll_loaded"] = True
        value["exports"] = {name: hasattr(model, name) for name in EXPORTS}
        if all(value["exports"].values()):
            query = model.QueryProcessSecurityEnvironmentSupport
            query.argtypes, query.restype = [ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int32
            flags = ctypes.c_uint64()
            value["query_hresult"] = query(ctypes.byref(flags))
            value["support_flags"] = flags.value
    except OSError as error:
        value["winerror"] = error.winerror
    except AttributeError:
        value["winerror"] = 127
    return value


def probe_record(text):
    return exact_record(text, {"gate": "native-psec-availability", "usable": True,
                               "deny_paths": True, "full_isolation": "not_run"})


def process_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized PSEC process fixture record")
    value = json.loads(text)
    pids = ("broker_pid", "child_pid", "descendant_pid")
    if not isinstance(value, dict) or any(type(value.get(name)) is not int or
            not 1 <= value[name] <= 0xFFFFFFFF for name in pids) or len({value[name] for name in pids}) != 3:
        raise RuntimeError("Invalid PSEC process identities")
    return exact_record(text, {**{name: value[name] for name in pids},
        "gate": "native-psec-process-file-control", "policy": "psec-only", "child_exit_code": 37,
        "descendant_exit_code": 38, "file_positive_count": 2, "child_read_error": 5,
        "child_write_open_error": 5, "descendant_read_error": 5, "descendant_write_open_error": 5,
        "protected_bytes_preserved": True, "ordinary_file_baselines": 2, "environment_allowlist_count": 5,
        "environment_canaries_absent": True, "inherited_handle_count": 0,
        "suspended_job_assignment_checked": True, "legacy_fallback": False,
        "network": "not_run", "full_isolation": "not_run"})


def network_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized PSEC network fixture record")
    value = json.loads(text)
    if not isinstance(value, dict) or value.get("gate") != "native-psec-provider-network-control" or \
            value.get("network") != "passed_provider_and_canary_controls":
        raise RuntimeError("Invalid PSEC network gate")
    base = {name: item for name, item in value.items() if name != "network_controls"}
    process_record(json.dumps({**base, "gate": "native-psec-process-file-control", "network": "not_run"}))
    controls = value.get("network_controls")
    if not isinstance(controls, dict) or set(controls) != {"child", "descendant"}:
        raise RuntimeError("Missing real child/descendant network controls")
    for record in controls.values():
        if not isinstance(record, dict) or set(record) != {"provider", "tcp_errors", "udp_errors",
                "audit_read_error", "audit_write_open_error"} or record["provider"] is not True or any(
                type(record[name]) is not int or record[name] != 5 for name in ("audit_read_error", "audit_write_open_error")):
            raise RuntimeError("Missing provider positive")
        for name in ("tcp_errors", "udp_errors"):
            errors = record[name]
            if type(errors) is not list or len(errors) != 3 or any(
                    not (type(error) is int and error in (10013, 10060) or
                         type(error) is str and error == "timed_out") for error in errors):
                raise RuntimeError("Incomplete network denial results")
    return value


def network_observation(events, config, value):
    expected = []
    for phase in ("before", "after"):
        for name, listener, host in (("provider", "provider", "127.0.0.1"),
                ("outside", "outside", config["host"]), ("loopback-port", "outside", "127.0.0.1"),
                ("loopback-address", "provider", "127.0.0.2")):
            expected.extend((
                {"event": "tcp_accept", "listener": listener, "local_host": host,
                 "local_port": config[listener + "_port"]},
                {"event": "tcp_request", "listener": listener, "request": f"GET /{phase}/{name} HTTP/1.0"}))
        for name, listener in (("outside", "outside"), ("loopback-port", "outside"), ("provider-udp", "provider")):
            expected.append({"event": "udp_receive", "listener": listener, "payload": phase + "/" + name})
    for role in ("child", "descendant"):
        expected.extend((
            {"event": "tcp_accept", "listener": "provider", "local_host": "127.0.0.1",
             "local_port": config["provider_port"]},
            {"event": "tcp_request", "listener": "provider",
             "request": f"GET /{role}/{value[role + '_pid']}/provider HTTP/1.0"}))
    if Counter(json.dumps(row, sort_keys=True) for row in events) != \
            Counter(json.dumps(row, sort_keys=True) for row in expected):
        raise RuntimeError("Network observer saw missing positives or forbidden/unmatched traffic")
    return {"ordinary_endpoint_baselines": 14, "provider_requests": 2, "tcp_accepts": 10,
        "udp_datagrams": 6, "forbidden_tcp_accepts": 0, "forbidden_udp_deliveries": 0,
        "exact_observation": True, "remote_internet": "not_run", "inbound_isolation": "not_run"}


def input_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized PSEC input fixture record")
    value = json.loads(text)
    if not isinstance(value, dict) or value.get("gate") != "native-psec-precompiled-input-control" or \
            not isinstance(value.get("input_baselines"), dict) or set(value["input_baselines"]) != {"before", "after"} or \
            not isinstance(value.get("network_controls"), dict) or set(value["network_controls"]) != {"child", "descendant"}:
        raise RuntimeError("Missing PSEC input gate identities/baselines")

    def check(record, expected):
        compiler_errors = record.get("compiler_creation_errors") if isinstance(record, dict) else None
        if type(compiler_errors) is not list or len(compiler_errors) != 9 or any(
                type(error) is not int or error not in ((2, 5) if expected == 5 and index % 3 == 1 else (expected,))
                for index, error in enumerate(compiler_errors)):
            raise RuntimeError("Invalid native compiler creation errors")
        exact_record(json.dumps(record), {"read_count": 6, "read_errors": [expected] * 6,
            "hardlink_creation_count": 3, "hardlink_creation_errors": [expected] * 3,
            "compiler_creation_count": 9, "compiler_creation_errors": compiler_errors, "compiler_executed": False})
        if any(type(error) is not int for name in ("read_errors", "hardlink_creation_errors")
                for error in record[name]):
            raise RuntimeError("Invalid native input error type")

    stripped = {}
    for role, record in value["network_controls"].items():
        if not isinstance(record, dict) or "inputs" not in record:
            raise RuntimeError("Missing real inherited input controls")
        check(record["inputs"], 5)
        stripped[role] = {name: item for name, item in record.items() if name != "inputs"}
    for baseline in value["input_baselines"].values():
        check(baseline, 0)
    base = {name: item for name, item in value.items() if name != "input_baselines"}
    network_record(json.dumps({**base, "gate": "native-psec-provider-network-control", "network_controls": stripped}))
    return value


def controlled_probe(directory, expected_sha):
    path = directory / "psec-probe.exe"
    if list(directory.iterdir()) != [path]:
        raise RuntimeError("Controlled runtime must contain exactly its precompiled probe")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_file_attributes", 0) & 0x400 or \
            hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
        raise RuntimeError("Runtime probe must be an independent regular file with its verified bytes")
    return {"path": str(path), "sha256": expected_sha, "bytes": info.st_size, "link_count": 1, "entry_count": 1}


def network_controls(run, probe, root, logs, *, inputs=None):
    response = b"HTTP/1.0 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\ncm-provider-ok"
    events, lock = [], threading.Lock()
    observer = {"status": "running"}
    audit = logs / "network-audit-canary.txt"
    with audit.open("xb") as stream:
        stream.write(b"psec-network-audit")

    with (logs / "network-events.jsonl").open("x", encoding="utf-8") as stream:
        def note(event):
            with lock:
                if len(events) >= 128:
                    raise RuntimeError("Network observer event limit exceeded")
                events.append(event)
                stream.write(json.dumps(event, sort_keys=True) + "\n")
                stream.flush()
                print("PSEC network observer: " + json.dumps(event, sort_keys=True), flush=True)

        class Tcp(socketserver.BaseRequestHandler):
            def handle(self):
                note({"event": "tcp_accept", "listener": self.server.role,
                    "local_host": self.request.getsockname()[0], "local_port": self.request.getsockname()[1]})
                self.request.settimeout(1)
                with self.request.makefile("rb") as source:
                    request = source.readline(1025)
                    if len(request) > 1024 or not request.endswith(b"\r\n") or source.readline(3) != b"\r\n":
                        raise RuntimeError("Invalid bounded network request")
                note({"event": "tcp_request", "listener": self.server.role,
                    "request": request[:-2].decode("ascii", errors="strict")})
                self.request.sendall(response)

        class Udp(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                note({"event": "udp_receive", "listener": self.server.role,
                    "payload": data.decode("ascii", errors="replace")})
                if not 1 <= len(data) <= 1024:
                    raise RuntimeError("Invalid bounded UDP canary")
                sock.sendto(data, self.client_address)

        def stop(server, thread):
            server.shutdown()
            thread.join(timeout=2)
            if thread.is_alive():
                raise RuntimeError("Network listener did not stop")

        try:
            hosts = [row[4][0] for row in socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, socket.SOCK_STREAM)
                if not (ipaddress.ip_address(row[4][0]).is_loopback or ipaddress.ip_address(row[4][0]).is_link_local or
                        ipaddress.ip_address(row[4][0]).is_unspecified)]
            if not hosts:
                raise RuntimeError("No non-loopback local IPv4 for ordinary canary")
            with ExitStack() as stack:
                servers = []
                for role in ("provider", "outside"):
                    tcp = stack.enter_context(socketserver.TCPServer(("0.0.0.0", 0), Tcp))
                    tcp.role = role
                    udp = stack.enter_context(socketserver.UDPServer(("0.0.0.0", tcp.server_address[1]), Udp))
                    udp.role = role
                    udp.max_packet_size = 1025
                    servers.extend((tcp, udp))
                config = {"host": hosts[0], "provider_port": servers[0].server_address[1],
                    "outside_port": servers[2].server_address[1], "audit_dir": str(logs)}
                if config["provider_port"] == config["outside_port"]:
                    raise RuntimeError("Provider and canary ports must differ")
                observer["config"] = config
                root.mkdir()
                if inputs is not None:
                    config["inputs"] = inputs
                    work = root / "work"
                    work.mkdir()
                    for index, target in enumerate(inputs["reads"]):
                        (work / f"read{index}-link").symlink_to(target)
                    for index, target in enumerate(inputs["tools"]):
                        (work / f"tool{index}-link.exe").symlink_to(target)
                if len(json.dumps(config).encode("utf-8")) > 4096:
                    raise RuntimeError("Oversized bounded PSEC fixture configuration")
                (root / "network.json").write_text(json.dumps(config), encoding="utf-8")
                (logs / "network-config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
                for server in servers:
                    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
                    thread.start()
                    stack.callback(stop, server, thread)

                def baseline(phase):
                    with ci_progress.stage("ordinary-network-" + phase):
                        with audit.open("r+b") as source:
                            if source.read() != b"psec-network-audit":
                                raise RuntimeError("Protected observer canary changed")
                        for name, host, port in (("provider", "127.0.0.1", config["provider_port"]),
                                ("outside", config["host"], config["outside_port"]),
                                ("loopback-port", "127.0.0.1", config["outside_port"]),
                                ("loopback-address", "127.0.0.2", config["provider_port"])):
                            with socket.create_connection((host, port), timeout=1) as client:
                                client.sendall(f"GET /{phase}/{name} HTTP/1.0\r\n\r\n".encode("ascii"))
                                with client.makefile("rb") as source:
                                    if source.read(1025) != response:
                                        raise RuntimeError("Ordinary TCP baseline failed: " + name)
                        for name, host, port in (("outside", config["host"], config["outside_port"]),
                                ("loopback-port", "127.0.0.1", config["outside_port"]),
                                ("provider-udp", "127.0.0.1", config["provider_port"])):
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                                client.settimeout(1)
                                payload = (phase + "/" + name).encode("ascii")
                                client.sendto(payload, (host, port))
                                if client.recvfrom(1025)[0] != payload:
                                    raise RuntimeError("Ordinary UDP baseline failed: " + name)
                        observer[phase + "_baseline"] = True

                baseline("before")
                try:
                    _, text = run("native-psec-provider-network-controls", [probe, "--network", root], 25)
                    value = (input_record if inputs is not None else network_record)(text)
                finally:
                    baseline("after")
            observer.update(network_observation(events, config, value), status="passed", audit_bytes_preserved=True)
            return value
        except BaseException:
            observer["status"] = "failed"
            raise
        finally:
            (logs / "network-observer.json").write_text(json.dumps(observer, indent=2) + "\n", encoding="utf-8")


def diagnose_exports():
    # Export presence after a failed gate cannot establish callable availability.
    names = (*EXPORTS, "Experimental_CreateProcessInSandbox", "Experimental_QuerySandboxSupport")
    value = {"diagnostic_only": True, "dll_loaded": False, "exports": dict.fromkeys(names),
             "winerror": None, "error": None, "callable_availability": "not_run"}
    try:
        model = ctypes.WinDLL("processmodel.dll", winmode=0x800, use_last_error=True)
        value["dll_loaded"] = True
        for name in names:
            value["exports"][name] = hasattr(model, name)
    except OSError as error:
        value["winerror"] = getattr(error, "winerror", None)
        value["error"] = {"type": type(error).__name__, "errno": error.errno, "message": str(error)}
    return value


def main(*, key=KEY):
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    authority(json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text()), entry, os.environ, key=key)
    target = entry["target"]
    stage = os.environ.get("CM_PREFLIGHT_STAGE")
    if stage not in ("isolation-availability", "isolation-process", "isolation-network", "isolation-inputs") or \
            Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Isolation probe requires its fixed stage and recorded source checkout")
    input_probe = stage == "isolation-inputs"
    network_probe = stage in ("isolation-network", "isolation-inputs")
    process_probe = stage in ("isolation-process", "isolation-network", "isolation-inputs")
    if process_probe and key != "windows-arm64":
        raise RuntimeError("Real PSEC process fixture requires native Windows ARM64")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Isolation text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running", "scope":
        "V01f-native-psec-precompiled-input-controls-only" if input_probe else
        "V01e-native-psec-provider-network-controls-only" if network_probe else
        "V01d-native-psec-process-file-controls-only" if process_probe else "V01b-native-isolation-availability-only",
        "platform": key, "target": target, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": os.environ["CM_REQUEST_ID"],
        "cache_mode": "none", "cache_writes": 0, "sdk_compiler_invoked": False,
        "product_build": "not_run", "qualification": "not_run", "full_isolation": "not_run",
        "dependency_search_attacks": "not_run", "full_cli_rust_v8_protoc": "not_run", "host_tui": "not_run",
        "platform_enabled": False, "release_ready": False}

    def run(label, args, timeout=30, codes=(0,)):
        values = [str(value) for value in args]
        with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"stage": label, "command": values, "cwd": str(Path.cwd())}) + "\n")
        result = ci_progress.run(logs, label, values, timeout)
        text = (logs / (label + ".log")).read_text(encoding="utf-8", errors="strict").strip()
        if result.returncode not in codes:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return result.returncode, text

    try:
        report["environment"] = {"os": platform.platform(), "python": platform.python_version(),
            "image_os": os.environ["ImageOS"], "image_version": os.environ["ImageVersion"]}
        with ci_progress.stage("native-psec-api-surface"):
            report["surface"] = native_surface()
            print("PSEC API surface: " + json.dumps(report["surface"], sort_keys=True), flush=True)
            if not surface_ready(report["surface"]):
                report["blocked_at"] = "api-surface-or-deny-path-support"
                report["export_diagnostics"] = diagnose_exports()
                print("Diagnostic exports (not callable availability): " +
                      json.dumps(report["export_diagnostics"], sort_keys=True), flush=True)
                raise RuntimeError("Native PSEC prerequisites unavailable; no SDK or CLI compilation")
        cl = Path(shutil.which("cl.exe") or "")
        tools = {"X64": ("hostx64", "x64"), "ARM64": ("hostarm64", "arm64")}[entry["runner_arch"]]
        if not cl.is_absolute() or not cl.is_file() or tuple(part.lower() for part in cl.parts[-3:]) != (*tools, "cl.exe"):
            raise RuntimeError("SDK probe requires the exact installed native MSVC tools for " + key)
        tool_identity = {name: os.environ.get(name) for name in
            ("VCToolsVersion", "WindowsSDKVersion", "WindowsSdkDir", "VCToolsInstallDir")}
        report["environment"].update(cl=str(cl), **tool_identity)
        if not all(tool_identity.values()):
            raise RuntimeError("SDK probe requires recorded MSVC/Windows SDK identity")
        with tempfile.TemporaryDirectory(prefix="cm-" + key + "-isolation-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory).resolve()
            sdk = temp / "mxc"
            run("sdk-init", ["git", "init", "--quiet", sdk])
            git = ["git", "-c", "core.autocrlf=false", "-C", sdk]
            run("sdk-fetch", [*git, "fetch", "--no-tags", "--depth=1", "https://github.com/microsoft/mxc.git", SDK_REV], 120)
            run("sdk-checkout", [*git, "checkout", "--quiet", "--detach", "FETCH_HEAD"])
            _, head = run("sdk-head", [*git, "rev-parse", "HEAD"])
            lock = sdk / "src/Cargo.lock"
            if head != SDK_REV or hashlib.sha256(lock.read_bytes()).hexdigest() != SDK_LOCK_SHA:
                raise RuntimeError("Fixed SDK commit or original lockfile mismatch")
            cfg = json.loads((root / ".github/cm-ci.json").read_text())
            toolchain = cfg["rust_toolchain"] + "-" + target
            name = "cm_native_psec_child" if process_probe else "cm_native_availability"
            fixture = root / "fixtures/native-loader" / (
                "windows-psec-child.rs" if process_probe else "windows-isolation-probe.rs")
            example = sdk / "src/backends/appcontainer/common/examples" / (name + ".rs")
            if example.exists():
                raise RuntimeError("Private SDK example name already exists upstream")
            example.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture, example)
            report["sdk"] = {"repository": "microsoft/mxc", "commit": head, "lock_sha256": SDK_LOCK_SHA,
                "cargo_config_sha256": hashlib.sha256((sdk / ".cargo/config.toml").read_bytes()).hexdigest(),
                "example_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(), "declared_license": "MIT",
                "toolchain": toolchain, "package": "appcontainer_common", "example": name}
            run("sdk-toolchain", ["rustup", "toolchain", "install", toolchain, "--profile", "minimal", "--component", "rustfmt"], 180)
            rust = ["rustup", "run", toolchain]
            _, report["rustc"] = run("sdk-rustc", [*rust, "rustc", "-Vv"])
            if "host: " + target not in report["rustc"].splitlines():
                raise RuntimeError("SDK probe compiler is not native " + key)
            _, report["cargo"] = run("sdk-cargo", [*rust, "cargo", "-V"])
            if process_probe:
                run("sdk-example-format-normalize", [*rust, "rustfmt", "--edition", "2021", example])
            run("sdk-example-format", [*rust, "rustfmt", "--check", "--edition", "2021", example])
            report["sdk"]["compiled_example_sha256"] = hashlib.sha256(example.read_bytes()).hexdigest()
            if process_probe:
                shutil.copyfile(example, logs / "compiled-psec-example.rs.txt")
            report["sdk_compiler_invoked"] = True
            previous = Path.cwd()
            try:
                os.chdir(sdk / "src")
                run("sdk-example-build", [*rust, "cargo", "build", "--locked", "--package", "appcontainer_common",
                    "--example", name, "--target", target, "--target-dir", temp / "target"], 360)
            finally:
                os.chdir(previous)
            if hashlib.sha256(lock.read_bytes()).hexdigest() != SDK_LOCK_SHA or \
                    hashlib.sha256(example.read_bytes()).hexdigest() != report["sdk"]["compiled_example_sha256"]:
                raise RuntimeError("SDK build changed the pinned lockfile or reviewed example")
            run("sdk-original-tree", [*git, "diff", "--exit-code"])
            probe = temp / "target" / target / "debug/examples" / (name + ".exe")
            report["native_probe"] = pe_fixture(probe.read_bytes(), False,
                expected_machine={"X64": 0x8664, "ARM64": 0xAA64}[entry["runner_arch"]])
            inputs, identities = None, []
            if input_probe:
                tools = [cl]
                for name in ("rustc", "cargo"):
                    _, path = run("sdk-" + name + "-path", ["rustup", "which", "--toolchain", toolchain, name])
                    tool = Path(path)
                    if not tool.is_absolute() or not tool.is_file() or tool.name.lower() != name + ".exe":
                        raise RuntimeError("Missing exact installed native tool: " + name)
                    tools.append(tool.resolve())
                cargo_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo").resolve()
                cached = list(cargo_home.glob("registry/src/*/serde-1.0.228/Cargo.toml"))
                if len(cached) != 1:
                    raise RuntimeError("Missing unique actual downloaded Cargo cache canary")
                reads = [root / "crates/cm/src/lib.rs", cached[0], sdk / "src/backends/appcontainer/common/Cargo.toml"]
                denied = [Path(os.environ["GITHUB_WORKSPACE"]), sdk, cargo_home,
                    Path(os.environ.get("RUSTUP_HOME") or Path.home() / ".rustup"),
                    Path(os.environ["ProgramFiles"]), Path(os.environ["ProgramFiles(x86)"]),
                    Path(os.environ["SystemRoot"]) / "Microsoft.NET", *(tool.parent for tool in tools)]
                if os.environ.get("RUNNER_TOOL_CACHE"):
                    denied.append(Path(os.environ["RUNNER_TOOL_CACHE"]))
                denied_roots = []
                for path in sorted({path.resolve() for path in denied if path.exists()}, key=lambda path: len(path.parts)):
                    if not any(path.is_relative_to(parent) for parent in denied_roots):
                        denied_roots.append(path)
                inputs = {"reads": [str(path.resolve(strict=True)) for path in reads],
                    "tools": [str(path) for path in tools], "deny_roots": sorted(str(path) for path in denied_roots)}
                for path in inputs["reads"] + inputs["tools"]:
                    source = Path(path)
                    if not source.is_file() or source.stat().st_size == 0:
                        raise RuntimeError("Ordinary input/tool canary is not a real nonempty file")
                    with source.open("rb") as stream:
                        identities.append({"path": path, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()})
                report["input_control_identities"] = identities
                report["input_control_spec"] = inputs
                runtime = temp / "runtime-inputs"
                runtime.mkdir()
                candidate = runtime / "psec-probe.exe"
                shutil.copyfile(probe, candidate)
                report["controlled_runtime_input"] = controlled_probe(runtime, report["native_probe"]["sha256"])
                admission = {"status": "running", "hardlink_attacks": [], "before_native_execution": True}
                report["runtime_admission"] = admission
                with ci_progress.stage("runtime-input-admission"):
                    for index, source in enumerate(inputs["reads"]):
                        alias = runtime / f"source-cache-hardlink-{index}"
                        os.link(source, alias)
                        try:
                            if not alias.samefile(source) or alias.stat().st_nlink < 2:
                                raise RuntimeError("Admission attack must be an actual outside hardlink")
                            try:
                                controlled_probe(runtime, report["native_probe"]["sha256"])
                            except RuntimeError as error:
                                if str(error) != "Controlled runtime must contain exactly its precompiled probe":
                                    raise
                                admission["hardlink_attacks"].append({"source": source,
                                    "same_file": True, "rejected": True, "reason": str(error)})
                            else:
                                raise RuntimeError("Source/cache hardlink runtime was accepted")
                        finally:
                            alias.unlink()
                        controlled_probe(runtime, report["native_probe"]["sha256"])
                    admission["status"] = "passed"
                probe = candidate
            if network_probe:
                result = network_controls(run, probe, temp / "network-controls", logs, inputs=inputs)
                for identity in identities:
                    with Path(identity["path"]).open("rb") as stream:
                        if hashlib.file_digest(stream, "sha256").hexdigest() != identity["sha256"]:
                            raise RuntimeError("Actual source/cache/tool bytes changed")
                report["native_input_controls" if input_probe else "native_provider_network_controls"] = result
                report["status"] = "passed_precompiled_input_controls_only" if input_probe else "passed_provider_network_controls_only"
            elif process_probe:
                _, text = run("native-psec-process-file-controls", [probe, "--broker", temp / "process-controls"], 25)
                report["native_process_file_controls"] = process_record(text)
                report["status"] = "passed_process_file_controls_only"
            else:
                code, text = run("native-psec-create-close", [probe], 20, codes=(0, 2))
                report["native_availability"] = json.loads(text)
                print("PSEC SDK availability: " + text, flush=True)
                probe_record(text)
                if code != 0:
                    raise RuntimeError("Native PSEC create/close/startup-info availability failed")
                report["status"] = "passed_availability_only"
    except BaseException:
        report["status"] = "failed"
        raise
    finally:
        (logs / (key + "-" + stage + ".json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Native PSEC mechanism passed; full isolation and product qualification remain NOT_RUN", flush=True)


def self_check():
    from types import SimpleNamespace
    from unittest.mock import Mock, patch

    good = {"api_set": True, "dll_loaded": True, "exports": dict.fromkeys(EXPORTS, True),
            "query_hresult": 0, "support_flags": 1, "winerror": None}
    assert surface_ready(good)
    assert surface_ready({**good, "support_flags": (1 << 63) | 1})
    for change in ({"api_set": False}, {"dll_loaded": False}, {"query_hresult": None},
                   {"query_hresult": -(1 << 31)}, {"support_flags": 0}, {"support_flags": None},
                   {"winerror": 127}, *({"exports": {**good["exports"], name: False}} for name in EXPORTS)):
        assert not surface_ready({**good, **change})
    for change in ({"support_flags": True}, {"support_flags": -1}, {"support_flags": 1 << 64},
                   {"query_hresult": True}, {"query_hresult": 1 << 31}, {"api_set": 1},
                   {"exports": {}}, {"extra": False}):
        try:
            surface_ready({**good, **change})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid PSEC surface record accepted")
    kernel = SimpleNamespace(IsApiSetImplemented=Mock(return_value=1))

    def query(flags):
        ctypes.cast(flags, ctypes.POINTER(ctypes.c_uint64)).contents.value = 1
        return 0

    model = SimpleNamespace(**{name: Mock() for name in EXPORTS})
    model.QueryProcessSecurityEnvironmentSupport.side_effect = query
    with patch.object(ctypes, "WinDLL", side_effect=[kernel, model], create=True) as load:
        assert native_surface() == good
        assert load.call_args_list[0].args == ("api-ms-win-core-apiquery-l2-1-0.dll",)
        assert load.call_args_list[1].args == ("processmodel.dll",)
        assert all(call.kwargs == {"winmode": 0x800, "use_last_error": True} for call in load.call_args_list)
        assert model.QueryProcessSecurityEnvironmentSupport.restype is ctypes.c_int32
    kernel.IsApiSetImplemented.return_value = 0
    with patch.object(ctypes, "WinDLL", return_value=kernel, create=True) as load:
        assert not surface_ready(native_surface())
        load.assert_called_once()
    kernel.IsApiSetImplemented.return_value = 1
    model.QueryProcessSecurityEnvironmentSupport.side_effect = lambda _: -(1 << 31)
    with patch.object(ctypes, "WinDLL", side_effect=[kernel, model], create=True):
        assert not surface_ready(native_surface())
    missing_dll = OSError("controlled missing DLL")
    missing_dll.winerror = 126
    with patch.object(ctypes, "WinDLL", side_effect=missing_dll, create=True):
        failed = native_surface()
        assert not surface_ready(failed) and failed["winerror"] == 126
    names = (*EXPORTS, "Experimental_CreateProcessInSandbox", "Experimental_QuerySandboxSupport")
    diagnostic_model = SimpleNamespace(**{name: Mock() for name in names})
    with patch.object(ctypes, "WinDLL", return_value=diagnostic_model, create=True) as load:
        diagnostics = diagnose_exports()
        load.assert_called_once_with("processmodel.dll", winmode=0x800, use_last_error=True)
        assert diagnostics == {"diagnostic_only": True, "dll_loaded": True,
            "exports": dict.fromkeys(names, True), "winerror": None, "error": None,
            "callable_availability": "not_run"}
        for name in names:
            getattr(diagnostic_model, name).assert_not_called()
    with patch.object(ctypes, "WinDLL", return_value=SimpleNamespace(**{names[0]: Mock()}), create=True):
        diagnostics = diagnose_exports()
        assert diagnostics["dll_loaded"] and diagnostics["winerror"] is None
        assert diagnostics["exports"] == {name: name == names[0] for name in names}
    for code in (126, 193):
        missing_dll.winerror = code
        with patch.object(ctypes, "WinDLL", side_effect=missing_dll, create=True):
            diagnostics = diagnose_exports()
            assert not diagnostics["dll_loaded"] and diagnostics["winerror"] == code
            assert diagnostics["exports"] == dict.fromkeys(names)
            assert diagnostics["diagnostic_only"] and diagnostics["callable_availability"] == "not_run"
            assert diagnostics["error"] == {"type": "OSError", "errno": None, "message": "controlled missing DLL"}
    with patch.object(ctypes, "WinDLL", side_effect=FileNotFoundError("controlled missing module"), create=True):
        diagnostics = diagnose_exports()
        assert not diagnostics["dll_loaded"] and diagnostics["winerror"] is None
        assert diagnostics["exports"] == dict.fromkeys(names)
        assert diagnostics["error"] == {"type": "FileNotFoundError", "errno": None,
                                        "message": "controlled missing module"}
    good_probe = {"gate": "native-psec-availability", "usable": True, "deny_paths": True, "full_isolation": "not_run"}
    probe_record(json.dumps(good_probe))
    for change in ({"usable": False}, {"deny_paths": False}, {"usable": 1},
                   {"full_isolation": "pass"}, {"extra": True}):
        try:
            probe_record(json.dumps({**good_probe, **change}))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Unavailable or unqualified PSEC accepted")
    process = {"gate": "native-psec-process-file-control", "policy": "psec-only", "broker_pid": 1,
        "child_pid": 2, "descendant_pid": 3, "child_exit_code": 37, "descendant_exit_code": 38,
        "file_positive_count": 2, "child_read_error": 5, "child_write_open_error": 5,
        "descendant_read_error": 5, "descendant_write_open_error": 5, "protected_bytes_preserved": True,
        "ordinary_file_baselines": 2, "environment_allowlist_count": 5, "environment_canaries_absent": True,
        "inherited_handle_count": 0, "suspended_job_assignment_checked": True, "legacy_fallback": False,
        "network": "not_run", "full_isolation": "not_run"}
    assert process_record(json.dumps(process)) == process
    for change in ({"broker_pid": 0}, {"child_pid": True}, {"descendant_pid": 1},
            {"descendant_pid": 1 << 32}, {"child_exit_code": True}, {"descendant_exit_code": 0},
            {"child_read_error": 0}, {"descendant_write_open_error": 0}, {"legacy_fallback": True},
            {"policy": "legacy"}, {"inherited_handle_count": False}, {"inherited_handle_count": 1},
            {"environment_allowlist_count": 4}, {"environment_canaries_absent": False},
            {"protected_bytes_preserved": False},
            {"network": "pass"}, {"full_isolation": "pass"}, {"extra": True}):
        try:
            process_record(json.dumps({**process, **change}))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Incomplete or unbound PSEC process control accepted")
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / "cm-worker-preflight.json").write_text("{}")
        for stage in ("isolation-process", "isolation-network", "isolation-inputs"):
            env = {"RUNNER_TEMP": directory, "CM_SOURCE_DIR": str(Path(__file__).resolve().parents[2]),
                "CM_PREFLIGHT_STAGE": stage}
            with patch.dict(os.environ, env), patch.object(record_run, "require_hosted_worker",
                    return_value={"target": "x86_64-pc-windows-msvc"}), patch(__name__ + ".authority"), \
                    patch.object(record_run, "record") as record:
                try:
                    main()
                except RuntimeError as error:
                    assert str(error) == "Real PSEC process fixture requires native Windows ARM64"
                else:
                    raise AssertionError("ARM64-only PSEC process gate accepted x64")
                record.assert_not_called()
    controls = {"provider": True, "tcp_errors": [10013, 10060, "timed_out"], "udp_errors": [10060] * 3,
        "audit_read_error": 5, "audit_write_open_error": 5}
    network = {**process, "gate": "native-psec-provider-network-control", "network": "passed_provider_and_canary_controls",
        "network_controls": {"child": controls, "descendant": controls}}
    assert network_record(json.dumps(network)) == network
    for change in ({"gate": "native-psec-process-file-control"}, {"child_pid": 3}, {"network": "not_run"},
            {"full_isolation": "pass"}, {"network_controls": {}},
            *({"network_controls": {"child": {**controls, **bad}, "descendant": controls}} for bad in
                ({"provider": 1}, {"provider": False}, {"tcp_errors": [0, 10060, 10060]},
                 {"tcp_errors": [True, 10060, 10060]}, {"tcp_errors": [10013.0, 10060, 10060]},
                 {"tcp_errors": ["unknown", 10060, 10060]}, {"udp_errors": [10060, 10060]},
                 {"udp_errors": [10054] * 3}, {"audit_read_error": 0}, {"audit_write_open_error": True},
                 {"extra": True})), {"extra": True}):
        try:
            network_record(json.dumps({**network, **change}))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Incomplete or unbound PSEC network control accepted")
    config = {"host": "10.0.0.2", "provider_port": 1234, "outside_port": 5678}
    events = []
    for phase in ("before", "after"):
        for listener, host, port, name in (("provider", "127.0.0.1", 1234, "provider"),
                ("outside", "10.0.0.2", 5678, "outside"), ("outside", "127.0.0.1", 5678, "loopback-port"),
                ("provider", "127.0.0.2", 1234, "loopback-address")):
            events.extend(({"event": "tcp_accept", "listener": listener, "local_host": host, "local_port": port},
                {"event": "tcp_request", "listener": listener, "request": f"GET /{phase}/{name} HTTP/1.0"}))
        for listener, name in (("outside", "outside"), ("outside", "loopback-port"), ("provider", "provider-udp")):
            events.append({"event": "udp_receive", "listener": listener, "payload": phase + "/" + name})
    for role, pid in (("child", 2), ("descendant", 3)):
        events.extend(({"event": "tcp_accept", "listener": "provider", "local_host": "127.0.0.1", "local_port": 1234},
            {"event": "tcp_request", "listener": "provider", "request": f"GET /{role}/{pid}/provider HTTP/1.0"}))
    assert len(events) == 26
    assert network_observation(events, config, network)["ordinary_endpoint_baselines"] == 14
    for bad_events, bad_config, bad_value in ((events[1:], config, network), (events + [events[0]], config, network),
            (events + [{"event": "tcp_accept", "listener": "outside", "local_host": "10.0.0.2", "local_port": 5678}], config, network),
            (events + [{"event": "udp_receive", "listener": "outside", "payload": "child/2/udp0"}], config, network),
            (events, {**config, "provider_port": 1235}, network), (events, config, {**network, "descendant_pid": 4}),
            ([{**events[0], "extra": True}, *events[1:]], config, network)):
        try:
            network_observation(bad_events, bad_config, bad_value)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Missing/extra/forbidden/unbound observer traffic accepted")
    denied_inputs = {"read_count": 6, "read_errors": [5] * 6,
        "hardlink_creation_count": 3, "hardlink_creation_errors": [5] * 3, "compiler_creation_count": 9,
        "compiler_creation_errors": [5] * 9, "compiler_executed": False}
    ordinary_inputs = {**denied_inputs, "read_errors": [0] * 6, "hardlink_creation_errors": [0] * 3,
        "compiler_creation_errors": [0] * 9}
    input_value = {**network, "gate": "native-psec-precompiled-input-control",
        "network_controls": {role: {**controls, "inputs": denied_inputs} for role in ("child", "descendant")},
        "input_baselines": {"before": ordinary_inputs, "after": ordinary_inputs}}
    assert input_record(json.dumps(input_value)) == input_value
    path_inputs = {**denied_inputs, "compiler_creation_errors": [5, 2, 5] * 3}
    path_value = {**input_value,
        "network_controls": {role: {**controls, "inputs": path_inputs} for role in ("child", "descendant")}}
    assert input_record(json.dumps(path_value)) == path_value
    for change in ({"gate": "native-psec-provider-network-control"}, {"input_baselines": {}},
            {"input_baselines": {"before": ordinary_inputs}}, {"child_pid": 3},
            {"input_baselines": {"before": {**ordinary_inputs, "read_errors": [False] * 6}, "after": ordinary_inputs}},
            {"input_baselines": {"before": {**ordinary_inputs, "compiler_creation_errors": [0, 2, 0] * 3},
                                 "after": ordinary_inputs}},
            *({"network_controls": {"child": {**controls, "inputs": {**denied_inputs, **bad}},
                                    "descendant": {**controls, "inputs": denied_inputs}}} for bad in
                ({"read_count": 5}, {"read_errors": [5] * 5}, {"read_errors": [0] * 6},
                 {"hardlink_creation_count": 2}, {"hardlink_creation_errors": [5] * 2},
                 {"hardlink_creation_errors": [0] * 3}, {"hardlink_creation_errors": [True] * 3},
                 {"compiler_creation_count": True}, {"compiler_creation_errors": [2] * 9},
                 {"compiler_creation_errors": [5, 3, 5] * 3}, {"compiler_creation_errors": [5, False, 5] * 3},
                 {"compiler_creation_errors": [5, 0x80070002, 5] * 3},
                 {"compiler_creation_errors": [5] * 8}, {"compiler_creation_errors": None},
                 {"compiler_executed": True}, {"extra": True})),
            {"network_controls": {"child": controls, "descendant": {**controls, "inputs": denied_inputs}}},
            {"extra": True}):
        try:
            input_record(json.dumps({**input_value, **change}))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Missing/allowed/incorrect input/tool controls accepted")
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        runtime = temp / "runtime"
        runtime.mkdir()
        candidate = runtime / "psec-probe.exe"
        candidate.write_bytes(b"precompiled-probe")
        expected = hashlib.sha256(candidate.read_bytes()).hexdigest()
        assert controlled_probe(runtime, expected)["entry_count"] == 1
        for attack in ("hash", "extra", "symlink", "hardlink"):
            if attack == "hash":
                candidate.write_bytes(b"changed")
            elif attack == "extra":
                (runtime / "source.rs").write_text("source")
            else:
                candidate.unlink()
                source = temp / (attack + ".exe")
                source.write_bytes(b"precompiled-probe")
                if attack == "symlink":
                    candidate.symlink_to(source)
                else:
                    os.link(source, candidate)
            try:
                controlled_probe(runtime, expected)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Untrusted runtime input accepted: " + attack)
            if attack == "extra":
                (runtime / "source.rs").unlink()
            if candidate.exists() or candidate.is_symlink():
                candidate.unlink()
            candidate.write_bytes(b"precompiled-probe")


if __name__ == "__main__":
    main()
