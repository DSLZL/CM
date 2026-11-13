"""Bounded Windows fixture loading/ConPTY controls; never product qualification."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import struct
import subprocess
import tempfile
import threading

import ci_progress
import record_run

KEY, TARGET = "windows-x64", "x86_64-pc-windows-msvc"
SOCKET_MODES = ("socket-ordinary", "socket-lpac", "socket-restricted")
PEER_MODES = ("peer-outside", "peer-ordinary", "peer-lpac", "peer-restricted")


def authority(policy, entry, env):
    expected = {"source_repository": "DSLZL/CM", "source_sha": env.get("CM_SOURCE_SHA"),
        "observed_source_default_sha": env.get("CM_SOURCE_SHA"), "source_default_branch": "main",
        "builder_repository": entry["repository"], "workflow_sha": env.get("GITHUB_WORKFLOW_SHA"),
        "worker_default_branch": "main", "request_id": env.get("CM_REQUEST_ID"),
        "platform": KEY, "target": TARGET, "cache_mode": "none", "execution_role": "platform_preflight",
        "build_kind": "qualification", "consumer_required": "false",
        "distribution_required": "false", "index_required": "false"}
    if (entry["key"] != KEY or any(policy.get(key) != value for key, value in expected.items())
            or env.get("CM_EXECUTION_ROLE") != "platform_preflight"
            or env.get("GITHUB_JOB") != "native-preflight" or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("CM_BUILD_KIND") != "qualification" or env.get("CM_HOST_ORIGIN")
            or any(env.get(key) != "none" for key in ("CM_CACHE_MODE", "ACTIONS_CACHE_MODE"))
            or env.get("GITHUB_WORKFLOW_REF") != entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main"):
        raise RuntimeError("Windows probe differs from its exact cache-none native preflight authority")


def pe_fixture(data, dll):
    if not 128 <= len(data) <= 32 * 1024 * 1024 or data[:2] != b"MZ":
        raise RuntimeError("Expected bounded native PE fixture")
    header = struct.unpack_from("<I", data, 60)[0]
    if not 64 <= header <= len(data) - 264 or data[header:header + 4] != b"PE\0\0":
        raise RuntimeError("Invalid PE fixture header")
    machine, count = struct.unpack_from("<HH", data, header + 4)
    optional, flags = struct.unpack_from("<HH", data, header + 20)
    if (machine != 0x8664 or not 1 <= count <= 32 or optional != 240
            or not flags & 2 or bool(flags & 0x2000) != dll
            or struct.unpack_from("<H", data, header + 24)[0] != 0x20B):
        raise RuntimeError("Wrong PE fixture architecture/kind")
    sections = header + 24 + optional
    if sections + count * 40 > len(data):
        raise RuntimeError("Truncated PE fixture section table")
    for offset in range(sections, sections + count * 40, 40):
        size, raw = struct.unpack_from("<II", data, offset + 16)
        attributes = struct.unpack_from("<I", data, offset + 36)[0]
        if (size and (raw < sections + count * 40 or raw > len(data) or size > len(data) - raw)
                or attributes & 0x20000000 and attributes & 0x80000000):
            raise RuntimeError("Invalid PE fixture section range/permissions")
    return {"format": "pe32+", "machine": machine, "dll": dll, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "scope": "fixture-header-and-section-bounds",
        "full_dependency_qualification": "not_run"}


def exact_record(text, expected):
    if len(text) > 8192:
        raise RuntimeError("Oversized native fixture record")
    value = json.loads(text)
    if (not isinstance(value, dict) or value != expected or set(value) != set(expected)
            or any(type(value[key]) is not type(item) for key, item in expected.items())):
        raise RuntimeError("Native fixture record differs from the required observation")
    return value


def terminal_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized ConPTY fixture record")
    value = json.loads(text)
    if not isinstance(value, dict) or type(value.get("output_bytes")) is not int or not 1 <= value["output_bytes"] < 65536:
        raise RuntimeError("Missing bounded ConPTY output")
    return exact_record(text, {"status": "pass", "gate": "ConPTY-control", "initial_columns": 96,
        "initial_rows": 28, "resized_columns": 120, "resized_rows": 40, "input": "Y",
        "child_exit_code": 0, "drain_error": 109, "output_bytes": value["output_bytes"], "full_host_tui": "not_run"})


def mutation_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized mutation fixture record")
    value = json.loads(text)
    errors = ("write_error", "delete_error", "replace_error", "rename_error", "parent_rename_error")
    if (not isinstance(value, dict) or any(type(value.get(key)) is not int
            or value[key] not in (5, 32) for key in errors) or value.get("write_error") != 32):
        raise RuntimeError("External mutation was not denied by the native pin")
    return exact_record(text, {**{key: value[key] for key in errors}, "native_executed": False})


def lpac_network_record(text):
    return exact_record(text, {"status": "pass", "gate": "lpac-internal-provider-network-control",
        "outside_token_checks": 3, "capability_count": 0, "ordinary_file_positive": True,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "lpac_opt_out_file_denied": True, "private_file_positive": True, "provider_http_positive": True,
        "outside_listener_positive": True, "outside_connect_error": 10013, "outside_unexpected_accepts": 0,
        "profile_deleted": True, "full_isolation": "not_run", "product": "not_run"})


def lpac_registry_record(text):
    return exact_record(text, {"status": "pass", "gate": "lpac-registry-read-network-control", "outside_token_checks": 3,
        "capability_count": 1, "capability": "registryRead", "ordinary_file_positive": True,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "lpac_opt_out_file_denied": True, "private_file_positive": True, "provider_http_positive": True,
        "outside_listener_positive": True, "outside_connect_error": 10013, "outside_unexpected_accepts": 0,
        "host_registry_baseline": True, "host_environment_read_error": 5, "host_environment_write_open_error": 5,
        "profile_deleted": True, "full_isolation": "not_run", "product": "not_run"})


def lpac_restricted_expected(*, network=False):
    expected = {"status": "pass", "gate": "lpac-restricted-registry-control",
        "outside_token_checks": 3, "outside_restricted_token_checks": 2,
        "restricting_sid_count": 3, "restricting_sid_policy": "world-users-private-nt",
        "private_sid_group_absence_checked": True, "private_sid_file_grants": 3,
        "private_sid_default_dacl_checked": True,
        "privilege_allowlist_checked": True, "capability_count": 1, "capability": "registryRead",
        "ordinary_file_positive": True, "environment_allowlist_count": 8,
        "environment_canary_not_inherited": True, "lpac_opt_out_file_denied": True,
        "private_file_positive": True, "child_winsock_startup_checks": 3,
        "host_registry_baseline": True, "host_environment_read_error": 5, "host_environment_write_open_error": 5,
        "profile_deleted": True, "network": "not_run", "full_isolation": "not_run", "product": "not_run"}
    if network:
        expected.update(gate="lpac-restricted-network-control", network="pass", provider_http_positive=True,
            outside_listener_positive=True, outside_connect_error=10013, outside_unexpected_accepts=0)
    return expected


def lpac_restricted_record(text, *, network=False):
    return exact_record(text, lpac_restricted_expected(network=network))


def restricted_appcontainer_record(text):
    expected = lpac_restricted_expected(network=True)
    expected.update(gate="restricted-appcontainer-network-control", capability_count=0,
        all_packages_file_denied=expected.pop("lpac_opt_out_file_denied"), all_application_packages_opt_out=False,
        outside_connect_error=10060, outside_denial_observation="bounded_timeout_3_seconds",
        outside_listener_post_positive=True)
    del expected["capability"]
    return exact_record(text, expected)


def restricted_appcontainer_files_record(text, *, policy="users"):
    if policy not in ("users", "restricted-code", "trusted-installer", "private-catalog", "private-catalog-network"):
        raise RuntimeError("Unknown file restriction SID policy")
    network = policy == "private-catalog-network"
    expected = lpac_restricted_expected(network=network)
    expected.update(gate="restricted-appcontainer-files-control", capability_count=0,
        all_packages_file_denied=expected.pop("lpac_opt_out_file_denied"), all_application_packages_opt_out=False,
        outside_file_baselines=6, file_path_checks=6, file_read_error=5,
        outside_compiler_creation_baselines=3, compiler_creation_checks=3, compiler_creation_error=5,
        source_cache_aliases_checked=True, compiler_executed=False)
    del expected["capability"]
    if policy == "restricted-code":
        expected.update(gate="restricted-code-appcontainer-files-control", restricting_sid_policy="world-restricted-code-private-nt")
    elif policy in ("trusted-installer", "private-catalog", "private-catalog-network"):
        expected.update(gate="restricted-installer-appcontainer-files-control",
            restricting_sid_policy="world-trusted-installer-private-nt", system_sid_group_absence_checked=True)
        if policy in ("private-catalog", "private-catalog-network"):
            expected.update(gate="restricted-installer-private-catalog-control",
                private_registry_view="winsock-catalog-only", catalog_copy_bounded=True,
                inherited_handle_count=2, inherited_catalog_write_denials=3,
                real_catalog_read_denials=6, private_catalog_read_checks=9,
                private_catalog_write_denials=2, private_catalog_dacl_denials=2,
                private_catalog_create_denials=2, private_catalog_deleted=True)
            if network:
                expected.update(gate="restricted-installer-private-network-control", outside_connect_error=10060,
                    outside_denial_observation="bounded_timeout_3_seconds", outside_listener_post_positive=True,
                    private_registry_view="winsock-catalog-startup-only", copied_registry_root_count=1,
                    real_hklm_restored_before_socket=True, restored_control_socket_positive=True,
                    real_catalog_read_denials=12)
    return exact_record(text, expected)


def lpac_socket_record(text, mode):
    if mode not in SOCKET_MODES or len(text) > 8192:
        raise RuntimeError("Invalid socket observation mode or record size")
    value = json.loads(text)
    if (not isinstance(value, dict) or type(value.get("socket_error")) is not int
            or value["socket_error"] not in (0, 10013)):
        raise RuntimeError("Missing bounded socket availability observation")
    return exact_record(text, {"status": "observed", "gate": "lpac-socket-availability-control",
        "mode": mode, "socket_error": value["socket_error"], "network": "not_run",
        "full_isolation": "not_run", "product": "not_run"})


def lpac_shared_peer_record(text, mode):
    if mode not in PEER_MODES or len(text) > 8192:
        raise RuntimeError("Invalid shared-peer observation mode or record size")
    value = json.loads(text)
    bounds = {"parent_peer_port": (1, 65535), "peer_address": (0, 0xFFFFFFFF), "peer_port": (0, 65535)}
    if (not isinstance(value, dict) or any(type(value.get(key)) is not int or not low <= value[key] <= high
            for key, (low, high) in bounds.items()) or type(value.get("direct_socket_error")) is not int
            or value["direct_socket_error"] not in (0, 10013)):
        raise RuntimeError("Missing bounded shared-peer observation")
    return exact_record(text, {"status": "observed", "gate": "lpac-shared-peer-observation", "mode": mode,
        "appcontainer": mode != "peer-outside", "lpac": mode in ("peer-lpac", "peer-restricted"),
        "outside_token_checks": 1, "outside_restricted_token_checks": int(mode == "peer-restricted"),
        "capability_count": int(mode in ("peer-lpac", "peer-restricted")), "inherited_handle_count": 2,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "file_controls_checked": True, "pid_bound_socket_share": True,
        "direct_socket_error": value["direct_socket_error"], "parent_peer_address": 2130706433,
        "parent_peer_port": value["parent_peer_port"], "peer_size": 16, "peer_family": 2,
        "peer_address": value["peer_address"], "peer_port": value["peer_port"], "profile_deleted": True,
        "http": "not_run", "network": "not_run", "full_isolation": "not_run", "product": "not_run"})


def lpac_socket_share_expected():
    return {"status": "pass", "gate": "lpac-socket-share-control",
        "outside_token_checks": 1, "outside_restricted_token_checks": 1,
        "restricting_sid_count": 3, "restricting_sid_policy": "world-users-private-nt",
        "private_sid_group_absence_checked": True, "private_sid_file_grants": 3,
        "private_sid_default_dacl_checked": True, "privilege_allowlist_checked": True,
        "capability_count": 1, "capability": "registryRead", "inherited_handle_count": 2,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "lpac_opt_out_file_denied": True, "private_file_positive": True, "host_registry_baseline": True,
        "host_environment_read_error": 5, "host_environment_write_open_error": 5,
        "direct_socket_error": 10013, "pid_bound_socket_share": True, "parent_child_http_positive": True,
        "profile_deleted": True, "network_qualification": "not_run", "full_isolation": "not_run", "product": "not_run"}


def lpac_socket_share_record(text):
    return exact_record(text, lpac_socket_share_expected())


def lpac_shared_transfer_record(text):
    if len(text) > 8192:
        raise RuntimeError("Oversized shared transfer record")
    value = json.loads(text)
    bounds = {"parent_peer_port": (1, 65535), "peer_address": (0, 0xFFFFFFFF), "peer_port": (0, 65535)}
    if (not isinstance(value, dict) or any(type(value.get(key)) is not int or not low <= value[key] <= high
            for key, (low, high) in bounds.items()) or (value["peer_address"], value["peer_port"])
            not in ((0, 0), (2130706433, value["parent_peer_port"]))):
        raise RuntimeError("Shared transfer peer metadata differs from the parent endpoint")
    expected = lpac_socket_share_expected()
    expected.update(gate="lpac-shared-transfer-control", parent_endpoint_checked=True,
        parent_peer_address=2130706433, peer_size=16, peer_family=2, **{key: value[key] for key in bounds})
    return exact_record(text, expected)


def diagnostic_child_pids(text):
    if len(text) > 65536:
        raise RuntimeError("Oversized native failure log")
    lines = [line for line in text.splitlines() if line.startswith("Native diagnostic child:")]
    rows = [re.fullmatch(r"Native diagnostic child: role=(control|provider|client); pid=([1-9][0-9]{0,9})", line)
        for line in lines]
    if not 1 <= len(rows) <= 3 or not all(rows):
        raise RuntimeError("Missing or malformed native diagnostic child identity")
    roles, pids = [row[1] for row in rows], [int(row[2]) for row in rows]
    if len(set(roles)) != len(rows) or len(set(pids)) != len(rows) or any(pid > 0xFFFFFFFF for pid in pids):
        raise RuntimeError("Duplicate or out-of-range native diagnostic child identity")
    return pids


@contextmanager
def registry_failure_trace(temp, logs, label, run, report):
    system = Path(os.environ["SystemRoot"]) / "System32"
    session = "CM-WX-Q-" + hashlib.sha256(str(temp).encode()).hexdigest()[:20]
    trace = temp / "registry.etl"
    state = {"diagnostic_only": True, "provider": "Microsoft-Windows-Kernel-Registry",
        "maximum_trace_megabytes": 8, "automatic_stop_seconds": 20,
        "automatic_stop_method": "controller-timer", "child_policy_changed": False}
    started = False
    timer = None

    def expire():
        try:
            state["deadline_stop_code"], _ = run("registry-trace-deadline-stop",
                [system / "logman.exe", "stop", session, "-ets"], 15, codes=None)
        except Exception as error:
            state["deadline_stop_error"] = type(error).__name__

    try:
        code, _ = run("registry-trace-start", [system / "logman.exe", "create", "trace", session,
            "-ets", "-p", state["provider"], "0xffffffffffffffff", "0xff", "-o", trace,
            "-f", "bincirc", "-max", "8"], 15, codes=None)
        state["start_code"], started = code, code == 0
        if started:
            timer = threading.Timer(20, expire)
            timer.daemon = True
            timer.start()
    except Exception as error:
        state["start_error"] = type(error).__name__
    try:
        yield
    finally:
        try:
            state["stop_code"], _ = run("registry-trace-stop",
                [system / "logman.exe", "stop", session, "-ets"], 15, codes=None)
        except Exception as error:
            state["stop_error"] = type(error).__name__
        if timer is not None:
            try:
                timer.cancel()
                timer.join(timeout=20)
                if timer.is_alive():
                    state["timer_cleanup_error"] = "still_alive"
            except Exception as error:
                state["timer_cleanup_error"] = type(error).__name__
        if started:
            try:
                failure = logs / (label + ".log")
                if (failure.is_file() and trace.is_file() and 0 < trace.stat().st_size <= 8 * 1024 * 1024
                        and "Native diagnostic child:" in failure.read_text(encoding="utf-8", errors="strict")):
                    pids = diagnostic_child_pids(failure.read_text(encoding="utf-8", errors="strict"))
                    script = temp / "read-registry-trace.ps1"
                    script.write_text(r'''param([string]$Trace,[string]$Output,[string]$TargetIds)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Diagnostics\Microsoft.PowerShell.Diagnostics.psd1') -ErrorAction Stop
if($TargetIds -notmatch '^[1-9][0-9]{0,9}(,[1-9][0-9]{0,9}){0,2}$'){throw 'Invalid child IDs'}
$ids=@($TargetIds.Split(',')|ForEach-Object{[long]$_})
$selected=@(Get-WinEvent -Path $Trace -Oldest -MaxEvents 20000 -ErrorAction Stop |
    Where-Object{$ids -contains [long]$_.ProcessId}|Select-Object -First 193)
$events=@($selected|Select-Object -First 192|ForEach-Object{
    $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}; $names=@()
    foreach($item in $xml.Event.EventData.Data){
        $name=[string]$item.Name
        if($names.Count -lt 32){$names+= $name.Substring(0,[Math]::Min($name.Length,64))}
        if($name -cin @('KeyName','RelativeName','Status','KeyObject','BaseObject','ObjectName','KeyHandle','DesiredAccess')){
            $value=[string]$item.'#text'; $fields[$name]=$value.Substring(0,[Math]::Min($value.Length,256))
        }
    }
    [pscustomobject]@{pid=$event.ProcessId;id=$event.Id;opcode=$event.Opcode;field_names=$names;fields=$fields}
})
$result=[pscustomobject]@{diagnostic_only=$true;child_pids=$ids;scan_limit=20000;selected_limit=192;truncated=($selected.Count -gt 192);events=$events}
$text=$result|ConvertTo-Json -Depth 8 -Compress
$utf8=New-Object Text.UTF8Encoding($false)
if($utf8.GetByteCount($text) -gt 524288){throw 'Oversized filtered trace'}
[IO.File]::WriteAllText($Output,$text,$utf8)
''', encoding="utf-8")
                    output = logs / "registry-trace-diagnostic.json"
                    state["extract_code"], _ = run("registry-trace-extract", [system / "WindowsPowerShell/v1.0/powershell.exe",
                        "-NoLogo", "-NoProfile", "-NonInteractive", "-File", script, "-Trace", trace,
                        "-Output", output, "-TargetIds", ",".join(map(str, pids))], 30, codes=None)
                    state["filtered_output_written"] = output.is_file()
            except Exception as error:
                state["decode_error"] = type(error).__name__
        report["registry_trace_diagnostic"] = state


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    authority(json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text()), entry, os.environ)
    mechanism = os.environ.get("CM_PREFLIGHT_STAGE", "loader-terminal")
    if mechanism not in ("loader-terminal", "lpac-network", "lpac-registry-read", "lpac-registry-restricted",
            "lpac-restricted-network", "lpac-socket-availability", "lpac-socket-share", "lpac-shared-peer-observation",
            "lpac-shared-transfer", "restricted-appcontainer-network", "restricted-appcontainer-files",
            "restricted-code-appcontainer-files", "restricted-installer-appcontainer-files", "restricted-installer-private-catalog",
            "restricted-installer-private-network"):
        raise RuntimeError("Unknown Windows native mechanism stage")
    socket_stage = mechanism == "lpac-socket-availability"
    socket_share_stage = mechanism == "lpac-socket-share"
    peer_stage = mechanism == "lpac-shared-peer-observation"
    transfer_stage = mechanism == "lpac-shared-transfer"
    ordinary_stage = mechanism == "restricted-appcontainer-network"
    restricted_code_stage = mechanism == "restricted-code-appcontainer-files"
    catalog_network_stage = mechanism == "restricted-installer-private-network"
    catalog_stage = catalog_network_stage or mechanism == "restricted-installer-private-catalog"
    installer_stage = catalog_stage or mechanism == "restricted-installer-appcontainer-files"
    files_stage = installer_stage or restricted_code_stage or mechanism == "restricted-appcontainer-files"
    restricted_network = catalog_network_stage or ordinary_stage or mechanism == "lpac-restricted-network"
    restricted = files_stage or transfer_stage or socket_share_stage or restricted_network or mechanism == "lpac-registry-restricted"
    registry = restricted or mechanism == "lpac-registry-read"
    lpac = peer_stage or socket_stage or registry or mechanism == "lpac-network"
    if Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Mechanism source must be the exact recorded source checkout")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Fixture text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running",
        "scope": "V01q-private-catalog-network-only" if catalog_network_stage else
            "V01p-private-catalog-files-only" if catalog_stage else
            "V01o-restricted-installer-files-only" if installer_stage else
            "V01n-restricted-code-files-only" if restricted_code_stage else
            "V01m-restricted-appcontainer-files-only" if files_stage else
            "V01l-restricted-appcontainer-network-only" if ordinary_stage else
            "V01k-shared-channel-transfer-only" if transfer_stage else
            "V01j-shared-peer-observations-only" if peer_stage else
            "V01i-shared-socket-fixture-only" if socket_share_stage else
            "V01h-socket-availability-fixture-only" if socket_stage else
            "V01g-restricted-network-fixture-only" if restricted_network else
            "V01f-private-sid-registry-fixture-only" if restricted else "V01d-system-dependency-fixture-only" if registry else
            "V01c-lpac-network-fixture-only" if lpac else "V01a-loader-terminal-fixtures-only",
        "platform": KEY, "target": TARGET, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": os.environ["CM_REQUEST_ID"],
        "cache_mode": "none", "cache_writes": 0, "product_build": "not_run", "qualification": "not_run",
        "isolation": "not_run", "rust_v8_protoc": "not_run", "dependency_search_attacks": "not_run",
        "platform_enabled": False, "release_ready": False, "controls": {}}

    def command(label, args):
        values = [str(value) for value in args]
        with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"stage": label, "command": values}) + "\n")
        return values

    def run(label, args, timeout=30, codes=(0,)):
        result = ci_progress.run(logs, label, command(label, args), timeout)
        text = (logs / (label + ".log")).read_text(encoding="utf-8", errors="replace")
        if codes is not None and result.returncode not in codes:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return result.returncode, text.strip()

    @contextmanager
    def interactive(label, args):
        with ci_progress.stage(label), (logs / (label + ".log")).open("w", encoding="utf-8") as stream:
            process = subprocess.Popen(command(label, args), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="strict")
            lines = queue.Queue()

            def read():
                try:
                    for line in process.stdout:
                        stream.write(line)
                        stream.flush()
                        lines.put(line)
                finally:
                    lines.put(None)

            reader = threading.Thread(target=read, daemon=True)
            reader.start()

            def receive():
                try:
                    value = lines.get(timeout=10)
                except queue.Empty as error:
                    raise RuntimeError(label + " native barrier timed out") from error
                if value is None:
                    raise RuntimeError(label + " ended before its native barrier")
                return value.strip()

            try:
                yield process, receive
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
                reader.join(timeout=5)
                if reader.is_alive():
                    raise RuntimeError(label + " native text reader failed to drain")
                process.stdin.close()
                process.stdout.close()

    try:
        with tempfile.TemporaryDirectory(prefix="cm-wx-mechanisms-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory).resolve()
            cl = Path(shutil.which("cl.exe") or "")
            if not cl.is_absolute() or not cl.is_file() or tuple(part.lower() for part in cl.parts[-3:]) != ("hostx64", "x64", "cl.exe"):
                raise RuntimeError("Missing exact native x64 MSVC compiler")
            sdk = {key: os.environ.get(key) for key in ("VCToolsVersion", "WindowsSDKVersion", "WindowsSdkDir", "VCToolsInstallDir")}
            if not all(sdk.values()) or not os.environ.get("ImageOS") or not os.environ.get("ImageVersion"):
                raise RuntimeError("Missing MSVC/SDK/hosted image identity")
            report["environment"] = {"os": platform.platform(), "python": platform.python_version(),
                "cl": str(cl), **sdk, "image_os": os.environ["ImageOS"], "image_version": os.environ["ImageVersion"]}
            source = root / "fixtures/native-loader" / ("windows-lpac-network.c" if lpac else "windows-preflight.c")
            probe, payload = temp / "native-probe.exe", temp / "sentinel.dll"
            flags = ["/nologo", "/Bv", "/std:c11", "/W4", "/WX", "/O2", "/MT", "/utf-8", "/TC"]
            libraries = ["bcrypt.lib", *(["userenv.lib", "advapi32.lib", "ws2_32.lib", "onecoreuap.lib"] if lpac else [])]
            if restricted_code_stage or installer_stage:
                flags.append("/DCM_DELAY_DIAGNOSTIC")
                libraries += ["delayimp.lib", *["/DELAYLOAD:" + name for name in
                    ("bcrypt.dll", "USERENV.dll", "ADVAPI32.dll", "WS2_32.dll", "api-ms-win-security-base-l1-2-2.dll")]]
            run("compile-native-probe", [cl, *flags, source, "/Fo" + str(temp / "probe.obj"),
                "/Fe" + str(probe), "/link", *libraries, "/INCREMENTAL:NO"], 120)
            if lpac:
                report["inputs"] = {"probe": pe_fixture(probe.read_bytes(), False)}
                run("probe-dependencies", [cl.with_name("dumpbin.exe"), "/nologo", "/dependents", probe])
                if socket_stage or peer_stage:
                    for mode in (PEER_MODES if peer_stage else SOCKET_MODES):
                        group = temp / mode
                        group.mkdir()
                        candidate = group / probe.name
                        shutil.copyfile(probe, candidate)
                        if hashlib.sha256(candidate.read_bytes()).hexdigest() != report["inputs"]["probe"]["sha256"]:
                            raise RuntimeError("Socket policy comparison changed its compiled fixture")
                        _, text = run("lpac-" + mode + "-control", [candidate, mode], 120)
                        parse = lpac_shared_peer_record if peer_stage else lpac_socket_record
                        report["controls"][mode] = parse(text, mode)
                    report["status"] = "observed_shared_peer_only" if peer_stage else "observed_socket_availability_only"
                    return
                label, mode, key, parse = {
                    "lpac-network": ("lpac-internal-provider-network-control", "run", "lpac_network", lpac_network_record),
                    "lpac-registry-read": ("lpac-registry-read-network-control", "registry-read", "lpac_registry_read", lpac_registry_record),
                    "lpac-registry-restricted": ("lpac-restricted-registry-control", "registry-restricted",
                        "lpac_registry_restricted", lpac_restricted_record),
                    "lpac-restricted-network": ("lpac-restricted-network-control", "restricted-network",
                        "lpac_restricted_network", lambda text: lpac_restricted_record(text, network=True)),
                    "lpac-socket-share": ("lpac-socket-share-control", "socket-share",
                        "lpac_socket_share", lpac_socket_share_record),
                    "lpac-shared-transfer": ("lpac-shared-transfer-control", "shared-transfer",
                        "lpac_shared_transfer", lpac_shared_transfer_record),
                    "restricted-appcontainer-network": ("restricted-appcontainer-network-control",
                        "restricted-appcontainer-network", "restricted_appcontainer_network", restricted_appcontainer_record),
                    "restricted-appcontainer-files": ("restricted-appcontainer-files-control",
                        "restricted-appcontainer-files", "restricted_appcontainer_files", restricted_appcontainer_files_record),
                    "restricted-code-appcontainer-files": ("restricted-code-appcontainer-files-control",
                        "restricted-code-appcontainer-files", "restricted_code_appcontainer_files",
                        lambda text: restricted_appcontainer_files_record(text, policy="restricted-code")),
                    "restricted-installer-appcontainer-files": ("restricted-installer-appcontainer-files-control",
                        "restricted-installer-appcontainer-files", "restricted_installer_appcontainer_files",
                        lambda text: restricted_appcontainer_files_record(text, policy="trusted-installer")),
                    "restricted-installer-private-catalog": ("restricted-installer-private-catalog-control",
                        "restricted-installer-private-catalog", "restricted_installer_private_catalog",
                        lambda text: restricted_appcontainer_files_record(text, policy="private-catalog")),
                    "restricted-installer-private-network": ("restricted-installer-private-network-control",
                        "restricted-installer-private-network", "restricted_installer_private_network",
                        lambda text: restricted_appcontainer_files_record(text, policy="private-catalog-network")),
                }[mechanism]
                args = [probe, mode]
                if files_stage:
                    group = temp / "files-control"
                    group.mkdir()
                    candidate = group / probe.name
                    shutil.copyfile(probe, candidate)
                    if hashlib.sha256(candidate.read_bytes()).hexdigest() != report["inputs"]["probe"]["sha256"]:
                        raise RuntimeError("File control changed its compiled fixture")
                    source_canary, cache_canary = root / "ci/source-files.txt", temp / "outside-cache.txt"
                    cache_canary.write_bytes(b"outside cache canary")
                    report["file_control_inputs"] = {name: {"path": str(path),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                        for name, path in (("source", source_canary), ("cache", cache_canary), ("compiler", cl))}
                    if restricted_code_stage or installer_stage:
                        system = Path(os.environ["SystemRoot"]) / "System32"
                        for name, path in (("source", source_canary), ("cache", cache_canary), ("compiler", cl),
                                *((name, system / (name + ".dll")) for name in
                                    ("bcrypt", "bcryptprimitives", "KERNEL32", "KernelBase", "ntdll",
                                        "USERENV", "ADVAPI32", "WS2_32"))):
                            run(name + "-permissions", [system / "icacls.exe", path])
                    args = [candidate, mode, source_canary, cache_canary, cl]
                if catalog_network_stage:
                    with registry_failure_trace(temp, logs, label, run, report):
                        _, text = run(label, args, 120)
                else:
                    _, text = run(label, args, 120)
                report["controls"][key] = parse(text)
                report["status"] = ("passed_bounded_file_tool_network_controls_only" if catalog_network_stage else
                    "passed_bounded_file_tool_controls_only" if files_stage else
                    "passed_bounded_shared_transfer_only" if transfer_stage else
                    "passed_bounded_shared_socket_only" if socket_share_stage else
                    "passed_bounded_registry_controls_only" if restricted and not restricted_network else
                    "passed_bounded_network_controls_only")
                return
            run("compile-sentinel-dll", [cl, *flags, "/DCM_PAYLOAD", "/LD", source,
                "/Fo" + str(temp / "payload.obj"), "/Fe" + str(payload), "/link",
                "/IMPLIB:" + str(temp / "sentinel.lib"), "/INCREMENTAL:NO"], 120)
            report["inputs"] = {"probe": pe_fixture(probe.read_bytes(), False), "payload": pe_fixture(payload.read_bytes(), True)}
            for name, path in (("probe", probe), ("payload", payload)):
                run(name + "-dependencies", [cl.with_name("dumpbin.exe"), "/nologo", "/dependents", path])
            digest = report["inputs"]["payload"]["sha256"]
            marker = temp / "constructor.marker"
            os.environ["CM_CONSTRUCTOR_MARKER"] = str(marker)
            for mode in ("writer", "mapping"):
                candidate = temp / ("retained-" + mode + ".dll")
                shutil.copyfile(payload, candidate)
                _, text = run("baseline-pin-" + mode, [probe, "pin-only", candidate])
                baseline = exact_record(text, {"status": "accepted", "gate": "pin", "native_executed": False})
                with interactive("retained-" + mode, [probe, "hold", mode, candidate]) as (holder, receive):
                    exact_record(receive(), {"status": "held", "native_executed": False})
                    with interactive("pin-with-retained-" + mode, [probe, "pin-held", candidate]) as (locker, locked):
                        text = locked()
                        pin_result = json.loads(text)
                        accepted = pin_result == {"status": "accepted", "gate": "pin", "native_executed": False}
                        holder.stdin.write("W"); holder.stdin.flush()
                        mutated = exact_record(receive(), {"status": "mutated", "written": 1, "native_executed": False})
                        if holder.wait(timeout=10) != 0:
                            raise RuntimeError("Retained writer/mapping control failed")
                        changed = hashlib.sha256(candidate.read_bytes()).hexdigest() != digest
                        if accepted:
                            locker.stdin.write("Q"); locker.stdin.flush()
                        code = locker.wait(timeout=10)
                report["controls"]["retained_" + mode] = {"pin_return_code": code, "pin_result": pin_result,
                    "baseline_pin": baseline, "writer_result": mutated, "backing_object_changed": changed,
                    "pin_held_during_mutation_if_accepted": accepted, "modified_native_executed": False}
                if not changed or marker.exists() or code != 2:
                    raise RuntimeError("Retained " + mode + " counterexample prevents fixed-handle qualification")
                exact_record(text, {"status": "rejected", "gate": "pin-file", "error": 32, "native_executed": False})
            baseline = temp / "unpinned"
            baseline.mkdir()
            baseline_file = baseline / "candidate.dll"
            shutil.copyfile(payload, baseline_file)
            (baseline / "candidate.dll.replacement").write_bytes(b"unlocked replacement control")
            _, text = run("unlocked-mutation-controls", [probe, "attack", baseline_file, baseline], codes=(2,))
            report["controls"]["unlocked_mutation"] = exact_record(text,
                {"write_error": 0, "delete_error": 0, "replace_error": 0, "rename_error": 0,
                 "parent_rename_error": 0, "native_executed": False})
            if marker.exists():
                raise RuntimeError("Unlocked mutation control executed a constructor")
            stage = temp / "pinned"
            stage.mkdir()
            candidate = stage / "candidate.dll"
            shutil.copyfile(payload, candidate)
            (stage / "candidate.dll.replacement").write_bytes(b"replacement must never be loaded")
            wrong = ("1" if digest[0] != "1" else "2") + digest[1:]
            _, text = run("wrong-hash-before-constructor", [probe, "load", candidate, wrong], codes=(2,))
            report["controls"]["wrong_hash"] = exact_record(text,
                {"status": "rejected", "gate": "payload-hash", "error": 13, "native_executed": False})
            if marker.exists():
                raise RuntimeError("Wrong hash executed a constructor")
            with interactive("verified-pin-and-load", [probe, "load", candidate, digest]) as (loader, receive):
                exact_record(receive(), {"status": "ready", "gate": "verified-pin", "native_executed": False})
                _, text = run("independent-write-delete-rename", [probe, "attack", candidate, stage])
                report["controls"]["external_mutation"] = mutation_record(text)
                if marker.exists() or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                    raise RuntimeError("Pinned fixture changed or executed before the load barrier")
                loader.stdin.write("L"); loader.stdin.flush()
                report["controls"]["pinned_load"] = exact_record(receive(), {"status": "pass",
                    "gate": "pinned-system-loader-control", "constructor_value": 41, "native_executed": True})
                if loader.wait(timeout=10) != 0 or marker.read_bytes() != b"constructor41":
                    raise RuntimeError("Missing actual constructor control")
            moved = temp / "unpinned-after-exit"
            stage.rename(moved)
            if hashlib.sha256((moved / candidate.name).read_bytes()).hexdigest() != digest:
                raise RuntimeError("Post-exit parent rename control changed its object")
            (moved / candidate.name).unlink()
            report["controls"]["rename_delete_after_loader_exit"] = "pass"
            _, text = run("conpty-input-resize-drain", [probe, "conpty"], 45)
            report["controls"]["conpty"] = terminal_record(text)
            if hashlib.sha256(payload.read_bytes()).hexdigest() != digest:
                raise RuntimeError("Original payload changed during controls")
            report["status"] = "passed_bounded_controls_only"
    except BaseException:
        report["status"] = "failed"
        raise
    finally:
        name = ("windows-x64-restricted-installer-private-network.json" if catalog_network_stage else
            "windows-x64-restricted-installer-private-catalog.json" if catalog_stage else
            "windows-x64-restricted-installer-appcontainer-files.json" if installer_stage else
            "windows-x64-restricted-code-appcontainer-files.json" if restricted_code_stage else
            "windows-x64-restricted-appcontainer-files.json" if files_stage else
            "windows-x64-restricted-appcontainer-network.json" if ordinary_stage else
            "windows-x64-lpac-shared-transfer.json" if transfer_stage else
            "windows-x64-lpac-shared-peer-observation.json" if peer_stage else
            "windows-x64-lpac-socket-share.json" if socket_share_stage else
            "windows-x64-lpac-socket-availability.json" if socket_stage else
            "windows-x64-lpac-restricted-network.json" if restricted_network else
            "windows-x64-lpac-registry-restricted.json" if restricted else "windows-x64-lpac-registry-read.json" if registry else
            "windows-x64-lpac-network.json" if lpac else "windows-x64-mechanisms.json")
        (logs / name).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Windows V01a fixture controls passed; isolation, full dependency closure and product qualification remain NOT_RUN", flush=True)


def self_check():
    from unittest.mock import patch
    import cm_platforms
    child = "Native diagnostic child: role=provider; pid=4294967295"
    assert diagnostic_child_pids(child) == [0xFFFFFFFF]
    assert diagnostic_child_pids(child + "\nNative diagnostic child: role=client; pid=123") == [0xFFFFFFFF, 123]
    for text in ("", "x" * 65537, child + "\n" + child, child.replace("provider", "unknown"),
            child.replace("4294967295", "4294967296"), child.replace("4294967295", "0"),
            child.replace("4294967295", "1;exit"), child + "\n" + child.replace("provider", "client")):
        try:
            diagnostic_child_pids(text)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid trace child identity accepted")
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"SystemRoot": "C:/Windows"}):
        temp = Path(directory)
        for start_code, stop_error, expired in ((0, False, False), (1, False, False), (0, True, False),
                (None, False, False), (0, False, True)):
            calls, report = [], {}

            def trace_run(label, args, timeout, codes=None):
                calls.append(label)
                if label == "registry-trace-start":
                    assert "-ets" in args and "-rf" not in args
                if start_code is None and label == "registry-trace-start":
                    raise OSError("diagnostic start failure")
                if stop_error and label == "registry-trace-stop":
                    raise OSError("diagnostic stop failure")
                return (start_code if label == "registry-trace-start" else 0), ""

            with patch.object(threading, "Timer") as timer_factory:
                timer_factory.return_value.is_alive.return_value = False
                if expired:
                    timer_factory.return_value.start.side_effect = lambda: timer_factory.call_args.args[1]()
                try:
                    with registry_failure_trace(temp, temp, "probe", trace_run, report):
                        raise RuntimeError("original native failure")
                except RuntimeError as error:
                    assert str(error) == "original native failure"
                else:
                    raise AssertionError("Optional trace hid the original native failure")
                if start_code == 0:
                    assert timer_factory.call_args.args[0] == 20
                    timer_factory.return_value.cancel.assert_called_once()
                    timer_factory.return_value.join.assert_called_once_with(timeout=20)
                else:
                    timer_factory.assert_not_called()
            assert calls == ["registry-trace-start", *(["registry-trace-deadline-stop"] if expired else []),
                "registry-trace-stop"]
            if expired:
                assert report["registry_trace_diagnostic"]["deadline_stop_code"] == 0
            assert report["registry_trace_diagnostic"]["child_policy_changed"] is False
            if stop_error:
                assert report["registry_trace_diagnostic"]["stop_error"] == "OSError"
            if start_code is None:
                assert report["registry_trace_diagnostic"]["start_error"] == "OSError"
    entry = cm_platforms.select(KEY)
    env = {"CM_SOURCE_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "b" * 40, "CM_REQUEST_ID": "windows-controls",
        "CM_EXECUTION_ROLE": "platform_preflight", "GITHUB_JOB": "native-preflight", "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main",
        "CM_BUILD_KIND": "qualification", "CM_CACHE_MODE": "none", "ACTIONS_CACHE_MODE": "none"}
    policy = {"source_repository": "DSLZL/CM", "source_sha": "a" * 40, "observed_source_default_sha": "a" * 40,
        "source_default_branch": "main", "builder_repository": entry["repository"], "workflow_sha": "b" * 40,
        "worker_default_branch": "main", "request_id": "windows-controls", "platform": KEY, "target": TARGET,
        "cache_mode": "none", "execution_role": "platform_preflight", "build_kind": "qualification",
        "consumer_required": "false", "distribution_required": "false", "index_required": "false"}
    authority(policy, entry, env)
    for changes in ({"GITHUB_JOB": "build-write"}, {"CM_CACHE_MODE": "write"}, {"ACTIONS_CACHE_MODE": "read"},
            {"GITHUB_REF": "refs/heads/other"}, {"CM_BUILD_KIND": "program"}, {"CM_HOST_ORIGIN": "{}"}):
        try:
            authority(policy, entry, {**env, **changes})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid Windows authority accepted")
    for field in policy:
        try:
            authority({**policy, field: "wrong"}, entry, env)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Changed Windows preflight identity accepted: " + field)
    for key in set(cm_platforms.load()["platforms"]) - {KEY}:
        try:
            authority(policy, cm_platforms.select(key), env)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Cross-platform native authority accepted")
    data = bytearray(1024)
    data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HH", data, 132, 0x8664, 1)
    struct.pack_into("<HHH", data, 148, 240, 0x2002, 0x20B)
    struct.pack_into("<II", data, 408, 512, 512)
    struct.pack_into("<I", data, 428, 0x60000020)
    assert pe_fixture(bytes(data), True)["machine"] == 0x8664
    for offset, format_string, value in ((60, "<I", 0xFFFFFFF0), (132, "<H", 0xAA64),
            (134, "<H", 99), (148, "<H", 239), (150, "<H", 2), (152, "<H", 0x10B),
            (408, "<I", 0xFFFFFF00), (412, "<I", 100), (428, "<I", 0xE0000020)):
        changed = bytearray(data); struct.pack_into(format_string, changed, offset, value)
        try:
            pe_fixture(bytes(changed), True)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Malformed PE fixture accepted")
    expected = {"status": "ready", "gate": "verified-pin", "native_executed": False}
    assert exact_record(json.dumps(expected), expected) == expected
    for changed in ({**expected, "native_executed": 0}, {**expected, "status": "pass"}, {**expected, "extra": True}):
        try:
            exact_record(json.dumps(changed), expected)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Forged native fixture record accepted")
    mutations = {key: 32 for key in ("write_error", "delete_error", "replace_error", "rename_error", "parent_rename_error")}
    mutations["native_executed"] = False
    assert mutation_record(json.dumps(mutations)) == mutations
    for changed in ({**mutations, "write_error": 0}, {**mutations, "replace_error": 2},
            {**mutations, "parent_rename_error": False}):
        try:
            mutation_record(json.dumps(changed))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Unproven external mutation rejection accepted")
    # Windows-only fixture inputs must not rebuild either qualified Linux Host.
    import retry
    module = Path(cm_platforms.__file__).read_text()
    recipe = "    env:\n      CM_TARGET: x86_64-unknown-linux-gnu\n    steps:\n"
    rows = b"100644 blob aaaa\tci/scripts/cm_platforms.py\x00"
    additions = b"".join(b"100644 blob bbbb\t" + path.encode() + b"\x00" for path in (
        "ci/worker-files-windows-x64.json", "ci/scripts/windows_x64_preflight.py",
        "fixtures/native-loader/windows-preflight.c", "ci/scripts/windows_isolation_preflight.py",
        "fixtures/native-loader/windows-isolation-probe.rs", "fixtures/native-loader/windows-lpac-network.c"))
    with patch.object(retry, "source", side_effect=lambda root, revision, path:
            module if path == "ci/scripts/cm_platforms.py" else recipe):
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            with patch.dict(os.environ, {"CM_TARGET": target}), patch.object(retry, "git", return_value=rows):
                baseline = retry.product_inputs(Path("."), "HEAD")
                with patch.object(retry, "git", return_value=rows + additions):
                    assert retry.product_inputs(Path("."), "HEAD") == baseline
                with patch.object(retry, "git", return_value=rows + additions + b"100644 blob cccc\tcrates/cm/src/lib.rs\x00"):
                    assert retry.product_inputs(Path("."), "HEAD") != baseline
    terminal = {"status": "pass", "gate": "ConPTY-control", "initial_columns": 96, "initial_rows": 28,
        "resized_columns": 120, "resized_rows": 40, "input": "Y", "child_exit_code": 0,
        "drain_error": 109, "output_bytes": 100, "full_host_tui": "not_run"}
    assert terminal_record(json.dumps(terminal)) == terminal
    for changed in ({**terminal, "output_bytes": True}, {**terminal, "child_exit_code": 1},
            {**terminal, "drain_error": 0}, {**terminal, "resized_rows": 28}, {**terminal, "full_host_tui": "pass"}):
        try:
            terminal_record(json.dumps(changed))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Incomplete ConPTY observation accepted")
    lpac = {"status": "pass", "gate": "lpac-internal-provider-network-control", "outside_token_checks": 3,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "capability_count": 0, "ordinary_file_positive": True, "lpac_opt_out_file_denied": True,
        "private_file_positive": True, "provider_http_positive": True, "outside_listener_positive": True,
        "outside_connect_error": 10013, "outside_unexpected_accepts": 0, "profile_deleted": True,
        "full_isolation": "not_run", "product": "not_run"}
    assert lpac_network_record(json.dumps(lpac)) == lpac
    changed = [{**lpac, key: value} for key, value in (("outside_token_checks", True), ("capability_count", 1),
        ("environment_allowlist_count", True), ("environment_allowlist_count", 0), ("environment_allowlist_count", 7),
        ("outside_connect_error", 10061), ("outside_connect_error", 10060), ("outside_unexpected_accepts", 1),
        ("profile_deleted", False), ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
    changed += [{**lpac, key: False} for key, value in lpac.items() if type(value) is bool]
    changed += [{key: value for key, value in lpac.items() if key != "provider_http_positive"}]
    for raw in [json.dumps(value) for value in changed] + ["[]", " " * 8193]:
        try:
            lpac_network_record(raw)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError("Incomplete or overclaimed LPAC network observation accepted")
    registry = {**lpac, "gate": "lpac-registry-read-network-control", "capability_count": 1,
        "capability": "registryRead", "host_registry_baseline": True,
        "host_environment_read_error": 5, "host_environment_write_open_error": 5}
    assert lpac_registry_record(json.dumps(registry)) == registry
    changed = [{**registry, key: value} for key, value in (("outside_token_checks", True),
        ("capability_count", 0), ("capability_count", 2), ("capability_count", True),
        ("capability", "internetClient"), ("capability", "registryread"),
        ("environment_allowlist_count", 7), ("environment_allowlist_count", True),
        ("outside_connect_error", 10061), ("outside_connect_error", 10060), ("outside_unexpected_accepts", 1),
        ("host_environment_read_error", 0), ("host_environment_read_error", 2), ("host_environment_read_error", True),
        ("host_environment_write_open_error", 0), ("host_environment_write_open_error", 2),
        ("host_environment_write_open_error", True), ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
    changed += [{**registry, key: False} for key, value in registry.items() if type(value) is bool]
    changed += [{key: value for key, value in registry.items() if key != omitted} for omitted in registry]
    for raw in [json.dumps(value) for value in changed] + [json.dumps(lpac), "[]", " " * 8193]:
        try:
            lpac_registry_record(raw)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError("Incomplete or overclaimed LPAC registry-read observation accepted")
    try:
        lpac_network_record(json.dumps(registry))
    except RuntimeError:
        pass
    else:
        raise AssertionError("Named capability accepted as the zero-capability mode")
    restricted = {"status": "pass", "gate": "lpac-restricted-registry-control",
        "outside_token_checks": 3, "outside_restricted_token_checks": 2,
        "restricting_sid_count": 3, "restricting_sid_policy": "world-users-private-nt",
        "private_sid_group_absence_checked": True, "private_sid_file_grants": 3,
        "private_sid_default_dacl_checked": True,
        "privilege_allowlist_checked": True, "capability_count": 1, "capability": "registryRead",
        "ordinary_file_positive": True, "environment_allowlist_count": 8,
        "environment_canary_not_inherited": True, "lpac_opt_out_file_denied": True,
        "private_file_positive": True, "child_winsock_startup_checks": 3,
        "host_registry_baseline": True, "host_environment_read_error": 5, "host_environment_write_open_error": 5,
        "profile_deleted": True, "network": "not_run", "full_isolation": "not_run", "product": "not_run"}
    assert lpac_restricted_record(json.dumps(restricted)) == restricted
    changed = [{**restricted, key: value} for key, value in (
        ("outside_token_checks", True), ("outside_restricted_token_checks", 0), ("outside_restricted_token_checks", True),
        ("restricting_sid_count", 0), ("restricting_sid_count", 2), ("restricting_sid_count", 4), ("restricting_sid_count", True),
        ("restricting_sid_policy", "world-users-owner"), ("restricting_sid_policy", "registryRead"),
        ("restricting_sid_policy", "world-users-package"),
        ("private_sid_file_grants", 0), ("private_sid_file_grants", 2),
        ("private_sid_file_grants", 4), ("private_sid_file_grants", True),
        ("private_sid_default_dacl_checked", 1),
        ("capability_count", 0), ("capability_count", 2), ("capability_count", True), ("capability", "internetClient"),
        ("environment_allowlist_count", 7), ("environment_allowlist_count", True),
        ("child_winsock_startup_checks", 0), ("child_winsock_startup_checks", True),
        ("host_environment_read_error", 0), ("host_environment_read_error", 2), ("host_environment_read_error", True),
        ("host_environment_write_open_error", 0), ("host_environment_write_open_error", 2),
        ("host_environment_write_open_error", True), ("network", "pass"), ("provider_http_positive", True),
        ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
    changed += [{**restricted, key: False} for key, value in restricted.items() if type(value) is bool]
    changed += [{key: value for key, value in restricted.items() if key != omitted} for omitted in restricted]
    for raw in [json.dumps(value) for value in changed] + [json.dumps(lpac), json.dumps(registry), "[]", " " * 8193]:
        try:
            lpac_restricted_record(raw)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError("Incomplete or overclaimed restricted-registry observation accepted")
    for parse in (lpac_network_record, lpac_registry_record):
        try:
            parse(json.dumps(restricted))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Restricted registry-only observation accepted as network qualification")
    network = {**restricted, "gate": "lpac-restricted-network-control", "network": "pass",
        "provider_http_positive": True, "outside_listener_positive": True,
        "outside_connect_error": 10013, "outside_unexpected_accepts": 0}
    assert lpac_restricted_record(json.dumps(network), network=True) == network
    changed = [{**network, key: value} for key, value in (("outside_connect_error", 0),
        ("outside_connect_error", 10060), ("outside_connect_error", 10061), ("outside_unexpected_accepts", 1),
        ("outside_unexpected_accepts", False), ("outside_restricted_token_checks", True),
        ("restricting_sid_count", 2), ("private_sid_file_grants", 2), ("private_sid_default_dacl_checked", 1),
        ("capability_count", 0), ("capability_count", True), ("capability", "internetClient"),
        ("host_environment_read_error", 0), ("host_environment_write_open_error", 0),
        ("network", "not_run"), ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
    changed += [{**network, key: False} for key, value in network.items() if type(value) is bool]
    changed += [{key: value for key, value in network.items() if key != omitted} for omitted in network]
    for raw in [json.dumps(value) for value in changed] + [json.dumps(restricted), json.dumps(registry),
            json.dumps(lpac), "[]", " " * 8193]:
        try:
            lpac_restricted_record(raw, network=True)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError("Incomplete or overclaimed restricted-network observation accepted")
    for parse in (lpac_network_record, lpac_registry_record, lpac_restricted_record):
        try:
            parse(json.dumps(network))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Restricted network observation accepted as another mode")
    ordinary = {**network, "gate": "restricted-appcontainer-network-control", "capability_count": 0,
        "all_packages_file_denied": True, "all_application_packages_opt_out": False,
        "outside_connect_error": 10060, "outside_denial_observation": "bounded_timeout_3_seconds",
        "outside_listener_post_positive": True}
    del ordinary["capability"], ordinary["lpac_opt_out_file_denied"]
    assert restricted_appcontainer_record(json.dumps(ordinary)) == ordinary
    changed = [{key: value for key, value in ordinary.items() if key != omitted} for omitted in ordinary]
    for key, value in ordinary.items():
        if type(value) is bool:
            changed += [{**ordinary, key: item} for item in (not value, int(value))]
        elif type(value) is int:
            changed += [{**ordinary, key: item} for item in (True, float(value), str(value), value + 1)]
    changed += [{**ordinary, key: value} for key, value in (("capability", "registryRead"),
        ("outside_connect_error", 10013), ("outside_connect_error", 10061), ("outside_connect_error", 0),
        ("outside_denial_observation", "access_denied"),
        ("gate", "lpac-restricted-network-control"), ("network", "not_run"),
        ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
    for raw in [json.dumps(value) for value in (*changed, lpac, registry, restricted, network)] + ["[]", " " * 8193]:
        try:
            restricted_appcontainer_record(raw)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError("Incomplete or overclaimed restricted AppContainer observation accepted")
    for parse in (lpac_network_record, lpac_registry_record, lpac_restricted_record,
            lambda text: lpac_restricted_record(text, network=True), lpac_socket_share_record, lpac_shared_transfer_record):
        try:
            parse(json.dumps(ordinary))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Restricted AppContainer observation accepted as an older mode")
    files = {**restricted, "gate": "restricted-appcontainer-files-control", "capability_count": 0,
        "all_packages_file_denied": True, "all_application_packages_opt_out": False,
        "outside_file_baselines": 6, "file_path_checks": 6, "file_read_error": 5,
        "outside_compiler_creation_baselines": 3, "compiler_creation_checks": 3, "compiler_creation_error": 5,
        "source_cache_aliases_checked": True, "compiler_executed": False}
    del files["capability"], files["lpac_opt_out_file_denied"]
    old_parsers = (lpac_network_record, lpac_registry_record, lpac_restricted_record,
        lambda text: lpac_restricted_record(text, network=True), restricted_appcontainer_record)
    file_records = (files, {**files, "gate": "restricted-code-appcontainer-files-control",
        "restricting_sid_policy": "world-restricted-code-private-nt"},
        {**files, "gate": "restricted-installer-appcontainer-files-control",
            "restricting_sid_policy": "world-trusted-installer-private-nt", "system_sid_group_absence_checked": True},
        {**files, "gate": "restricted-installer-private-catalog-control",
            "restricting_sid_policy": "world-trusted-installer-private-nt", "system_sid_group_absence_checked": True,
            "private_registry_view": "winsock-catalog-only", "catalog_copy_bounded": True,
            "inherited_handle_count": 2, "inherited_catalog_write_denials": 3,
            "real_catalog_read_denials": 6, "private_catalog_read_checks": 9,
            "private_catalog_write_denials": 2, "private_catalog_dacl_denials": 2,
            "private_catalog_create_denials": 2, "private_catalog_deleted": True},
        {**files, "gate": "restricted-installer-private-network-control",
            "restricting_sid_policy": "world-trusted-installer-private-nt", "system_sid_group_absence_checked": True,
            "private_registry_view": "winsock-catalog-startup-only", "catalog_copy_bounded": True,
            "copied_registry_root_count": 1, "real_hklm_restored_before_socket": True,
            "restored_control_socket_positive": True,
            "inherited_handle_count": 2, "inherited_catalog_write_denials": 3,
            "real_catalog_read_denials": 12, "private_catalog_read_checks": 9,
            "private_catalog_write_denials": 2, "private_catalog_dacl_denials": 2,
            "private_catalog_create_denials": 2, "private_catalog_deleted": True,
            "network": "pass", "provider_http_positive": True, "outside_listener_positive": True,
            "outside_connect_error": 10060, "outside_unexpected_accepts": 0,
            "outside_denial_observation": "bounded_timeout_3_seconds", "outside_listener_post_positive": True})
    file_parsers = (restricted_appcontainer_files_record,
        lambda text: restricted_appcontainer_files_record(text, policy="restricted-code"),
        lambda text: restricted_appcontainer_files_record(text, policy="trusted-installer"),
        lambda text: restricted_appcontainer_files_record(text, policy="private-catalog"),
        lambda text: restricted_appcontainer_files_record(text, policy="private-catalog-network"))
    for policy in ("", "other", True, None):
        try:
            restricted_appcontainer_files_record(json.dumps(files), policy=policy)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Unknown file restriction SID policy accepted")
    for record, parse in zip(file_records, file_parsers):
        assert parse(json.dumps(record)) == record
        changed = [{key: value for key, value in record.items() if key != omitted} for omitted in record]
        for key, value in record.items():
            if type(value) is bool:
                changed += [{**record, key: item} for item in (not value, int(value))]
            elif type(value) is int:
                changed += [{**record, key: item} for item in (True, float(value), str(value), value + 1, value - 1)]
        changed += [{**record, key: value} for key, value in (("status", "observed"),
            ("gate", "restricted-appcontainer-network-control"), ("restricting_sid_policy", "world-users-owner"),
            ("capability", "registryRead"), ("network", "not_run" if record["network"] == "pass" else "pass"),
            ("full_isolation", "pass"), ("product", "pass"),
            ("file_read_error", 0), ("compiler_creation_error", 0), ("compiler_creation_error", 2),
            ("private_registry_view", "real-hklm"), ("extra", True))]
        if record["network"] == "pass":
            previous = {key: value for key, value in record.items()
                if key not in ("copied_registry_root_count", "real_hklm_restored_before_socket",
                    "restored_control_socket_positive")}
            previous.update(private_registry_view="winsock-catalog-only", real_catalog_read_denials=6,
                private_catalog_read_checks=9, private_catalog_write_denials=2,
                private_catalog_dacl_denials=2, private_catalog_create_denials=2)
            changed.append(previous)
            changed.append({**previous, "private_registry_view": "winsock-catalog-and-ipv4-transport-only",
                "copied_registry_root_count": 3, "mapped_control_socket_positive": True,
                "private_catalog_read_checks": 15, "private_catalog_write_denials": 6,
                "private_catalog_dacl_denials": 6, "private_catalog_create_denials": 6})
        for raw in [json.dumps(value) for value in (*changed, lpac, registry, restricted, network, ordinary,
                *[other for other in file_records if other is not record])] + ["[]", " " * 8193]:
            try:
                parse(raw)
            except (RuntimeError, ValueError):
                pass
            else:
                raise AssertionError("Incomplete or overclaimed source/cache/compiler controls accepted")
        for other in (*old_parsers, lpac_socket_share_record, lpac_shared_transfer_record,
                *[other for other in file_parsers if other is not parse]):
            try:
                other(json.dumps(record))
            except RuntimeError:
                pass
            else:
                raise AssertionError("File/compiler controls accepted as another mode")
    old_parsers += file_parsers
    for mode in SOCKET_MODES:
        for error in (0, 10013):
            observed = {"status": "observed", "gate": "lpac-socket-availability-control",
                "mode": mode, "socket_error": error, "network": "not_run",
                "full_isolation": "not_run", "product": "not_run"}
            assert lpac_socket_record(json.dumps(observed), mode) == observed
            changed = [{**observed, key: value} for key, value in (("status", "pass"),
                ("gate", "lpac-restricted-network-control"), ("mode", "unknown"),
                ("socket_error", True), ("socket_error", False), ("socket_error", 0.0),
                ("socket_error", "10013"), ("socket_error", 10060), ("socket_error", 10061),
                ("network", "pass"), ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
            changed += [{key: value for key, value in observed.items() if key != omitted} for omitted in observed]
            for raw in [json.dumps(value) for value in changed] + [json.dumps(value)
                    for value in (lpac, registry, restricted, network)] + ["[]", " " * 8193]:
                try:
                    lpac_socket_record(raw, mode)
                except (RuntimeError, ValueError):
                    pass
                else:
                    raise AssertionError("Incomplete or overclaimed socket observation accepted")
            for other in (*[item for item in SOCKET_MODES if item != mode], "unknown"):
                try:
                    lpac_socket_record(json.dumps(observed), other)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Cross-policy socket observation accepted")
            for parse in old_parsers:
                try:
                    parse(json.dumps(observed))
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Socket observation accepted as network or registry qualification")
    shared = {"status": "pass", "gate": "lpac-socket-share-control",
        "outside_token_checks": 1, "outside_restricted_token_checks": 1,
        "restricting_sid_count": 3, "restricting_sid_policy": "world-users-private-nt",
        "private_sid_group_absence_checked": True, "private_sid_file_grants": 3,
        "private_sid_default_dacl_checked": True, "privilege_allowlist_checked": True,
        "capability_count": 1, "capability": "registryRead", "inherited_handle_count": 2,
        "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
        "lpac_opt_out_file_denied": True, "private_file_positive": True, "host_registry_baseline": True,
        "host_environment_read_error": 5, "host_environment_write_open_error": 5,
        "direct_socket_error": 10013, "pid_bound_socket_share": True, "parent_child_http_positive": True,
        "profile_deleted": True, "network_qualification": "not_run", "full_isolation": "not_run", "product": "not_run"}
    assert lpac_socket_share_record(json.dumps(shared)) == shared
    changed = [{key: value for key, value in shared.items() if key != omitted} for omitted in shared]
    changed += [{**shared, key: value} for key, value in (("status", "observed"),
        ("gate", "lpac-restricted-network-control"), ("restricting_sid_policy", "world-users-owner"),
        ("capability", "internetClient"), ("network_qualification", "pass"), ("full_isolation", "pass"),
        ("product", "pass"), ("outside_connect_error", 10013), ("provider_http_positive", True), ("extra", True))]
    for key, value in shared.items():
        if type(value) is bool:
            changed += [{**shared, key: item} for item in (False, 1)]
        elif type(value) is int:
            changed += [{**shared, key: item} for item in (True, float(value), str(value), value + 1, value - 1)]
    old_records = [lpac, registry, restricted, network] + [
        {"status": "observed", "gate": "lpac-socket-availability-control", "mode": mode,
            "socket_error": error, "network": "not_run", "full_isolation": "not_run", "product": "not_run"}
        for mode in SOCKET_MODES for error in (0, 10013)]
    for raw in [json.dumps(value) for value in changed + old_records] + ["[]", " " * 8193]:
        try:
            lpac_socket_share_record(raw)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError("Incomplete or overclaimed shared-socket observation accepted")
    for parse in (*old_parsers, *[lambda text, mode=mode: lpac_socket_record(text, mode) for mode in SOCKET_MODES]):
        try:
            parse(json.dumps(shared))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Shared parent/child socket control accepted as another qualification")
    for address, port in ((0, 0), (2130706433, 49151)):
        transferred = {**shared, "gate": "lpac-shared-transfer-control", "parent_endpoint_checked": True,
            "parent_peer_address": 2130706433, "parent_peer_port": 49151, "peer_size": 16, "peer_family": 2,
            "peer_address": address, "peer_port": port}
        assert lpac_shared_transfer_record(json.dumps(transferred)) == transferred
        changed = [{key: value for key, value in transferred.items() if key != omitted} for omitted in transferred]
        changed += [{**transferred, key: value} for key, value in (("gate", "lpac-socket-share-control"),
            ("status", "observed"), ("parent_peer_address", 0), ("parent_peer_port", 0),
            ("parent_peer_port", 65536), ("peer_address", -1), ("peer_address", 0x100000000),
            ("peer_port", -1), ("peer_port", 65536), ("peer_family", 23), ("peer_size", 28),
            ("network_qualification", "pass"), ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
        changed += [{**transferred, "peer_address": bad_address, "peer_port": bad_port}
            for bad_address, bad_port in ((0, 49151), (2130706433, 0), (2130706433, 49152), (1, 49151))]
        for key, value in transferred.items():
            if type(value) is bool:
                changed += [{**transferred, key: item} for item in (False, 1)]
            elif type(value) is int:
                changed += [{**transferred, key: item} for item in (True, float(value), str(value))]
                if key not in ("parent_peer_port", "peer_address", "peer_port"):
                    changed += [{**transferred, key: value + 1}, {**transferred, key: value - 1}]
        for raw in [json.dumps(value) for value in changed + old_records + [shared]] + ["[]", " " * 8193]:
            try:
                lpac_shared_transfer_record(raw)
            except (RuntimeError, ValueError):
                pass
            else:
                raise AssertionError("Incomplete, mismatched or overclaimed shared transfer accepted")
        for parse in (*old_parsers, lpac_socket_share_record,
                *[lambda text, mode=mode: lpac_socket_record(text, mode) for mode in SOCKET_MODES]):
            try:
                parse(json.dumps(transferred))
            except RuntimeError:
                pass
            else:
                raise AssertionError("Shared transfer accepted as an older qualification")
    for mode, appcontainer, lpac_mode, restricted_count, capability_count in (
            ("peer-outside", False, False, 0, 0), ("peer-ordinary", True, False, 0, 0),
            ("peer-lpac", True, True, 0, 1), ("peer-restricted", True, True, 1, 1)):
        for address, port in ((0, 0), (2130706433, 49152), (0xFFFFFFFF, 65535)):
            observed = {"status": "observed", "gate": "lpac-shared-peer-observation", "mode": mode,
                "appcontainer": appcontainer, "lpac": lpac_mode,
                "outside_token_checks": 1, "outside_restricted_token_checks": restricted_count,
                "capability_count": capability_count, "inherited_handle_count": 2,
                "environment_allowlist_count": 8, "environment_canary_not_inherited": True,
                "file_controls_checked": True, "pid_bound_socket_share": True, "direct_socket_error": 10013,
                "parent_peer_address": 2130706433, "parent_peer_port": 49151, "peer_size": 16, "peer_family": 2,
                "peer_address": address, "peer_port": port, "profile_deleted": True,
                "http": "not_run", "network": "not_run", "full_isolation": "not_run", "product": "not_run"}
            for error in (0, 10013):
                assert lpac_shared_peer_record(json.dumps({**observed, "direct_socket_error": error}), mode) == {
                    **observed, "direct_socket_error": error}
            changed = [{key: value for key, value in observed.items() if key != omitted} for omitted in observed]
            changed += [{**observed, key: value} for key, value in (("status", "pass"), ("mode", "unknown"),
                ("gate", "lpac-socket-share-control"), ("direct_socket_error", 10060), ("direct_socket_error", 10061),
                ("parent_peer_address", 0), ("parent_peer_port", 0), ("parent_peer_port", 65536),
                ("peer_size", 0), ("peer_family", 23), ("peer_address", -1), ("peer_address", 0x100000000),
                ("peer_port", -1), ("peer_port", 65536), ("http", "pass"), ("network", "pass"),
                ("full_isolation", "pass"), ("product", "pass"), ("extra", True))]
            for key, value in observed.items():
                if type(value) is bool:
                    changed += [{**observed, key: item} for item in (not value, int(value))]
                elif type(value) is int:
                    changed += [{**observed, key: item} for item in (True, float(value), str(value))]
            changed += [{**observed, key: observed[key] + 1} for key in (
                "outside_token_checks", "outside_restricted_token_checks", "capability_count", "inherited_handle_count",
                "environment_allowlist_count")]
            for raw in [json.dumps(value) for value in changed + old_records + [shared]] + ["[]", " " * 8193]:
                try:
                    lpac_shared_peer_record(raw, mode)
                except (RuntimeError, ValueError):
                    pass
                else:
                    raise AssertionError("Incomplete or overclaimed shared-peer observation accepted")
            for other in (*[item for item in PEER_MODES if item != mode], "unknown"):
                try:
                    lpac_shared_peer_record(json.dumps(observed), other)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Cross-policy shared-peer observation accepted")
            for parse in (*old_parsers, lpac_socket_share_record, lpac_shared_transfer_record,
                    *[lambda text, mode=mode: lpac_socket_record(text, mode) for mode in SOCKET_MODES]):
                try:
                    parse(json.dumps(observed))
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Shared-peer observation accepted as another qualification")
    print("Windows preflight authority, PE fixture and bounded native records self-check passed", flush=True)


if __name__ == "__main__":
    main()
