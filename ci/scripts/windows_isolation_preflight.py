#!/usr/bin/env python3
"""Hosted Windows PSEC availability gate; no product or isolation qualification."""
import ctypes
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import tempfile

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
    if os.environ.get("CM_PREFLIGHT_STAGE") != "isolation-availability" or \
            Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Isolation probe requires its fixed stage and recorded source checkout")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Isolation text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running", "scope": "V01b-native-isolation-availability-only",
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
            fixture = root / "fixtures/native-loader/windows-isolation-probe.rs"
            example = sdk / "src/backends/appcontainer/common/examples/cm_native_availability.rs"
            if example.exists():
                raise RuntimeError("Private SDK example name already exists upstream")
            example.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture, example)
            report["sdk"] = {"repository": "microsoft/mxc", "commit": head, "lock_sha256": SDK_LOCK_SHA,
                "cargo_config_sha256": hashlib.sha256((sdk / ".cargo/config.toml").read_bytes()).hexdigest(),
                "example_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(), "declared_license": "MIT",
                "toolchain": toolchain, "package": "appcontainer_common", "example": "cm_native_availability"}
            run("sdk-toolchain", ["rustup", "toolchain", "install", toolchain, "--profile", "minimal", "--component", "rustfmt"], 180)
            rust = ["rustup", "run", toolchain]
            _, report["rustc"] = run("sdk-rustc", [*rust, "rustc", "-Vv"])
            if "host: " + target not in report["rustc"].splitlines():
                raise RuntimeError("SDK probe compiler is not native " + key)
            _, report["cargo"] = run("sdk-cargo", [*rust, "cargo", "-V"])
            run("sdk-example-format", [*rust, "rustfmt", "--check", "--edition", "2021", example])
            report["sdk_compiler_invoked"] = True
            previous = Path.cwd()
            try:
                os.chdir(sdk / "src")
                run("sdk-example-build", [*rust, "cargo", "build", "--locked", "--package", "appcontainer_common",
                    "--example", "cm_native_availability", "--target", target, "--target-dir", temp / "target"], 360)
            finally:
                os.chdir(previous)
            if hashlib.sha256(lock.read_bytes()).hexdigest() != SDK_LOCK_SHA:
                raise RuntimeError("SDK build changed the pinned lockfile")
            run("sdk-original-tree", [*git, "diff", "--exit-code"])
            probe = temp / "target" / target / "debug/examples/cm_native_availability.exe"
            report["native_probe"] = pe_fixture(probe.read_bytes(), False,
                expected_machine={"X64": 0x8664, "ARM64": 0xAA64}[entry["runner_arch"]])
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
        (logs / (key + "-isolation-availability.json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Native PSEC availability passed; full isolation and product qualification remain NOT_RUN", flush=True)


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


if __name__ == "__main__":
    main()
