"""Observe native Windows ARM64 isolation API surfaces without building or creating a sandbox."""
import json
import os
from pathlib import Path
import platform
import struct
import sysconfig

import ci_progress
import record_run
from windows_isolation_preflight import EXPORTS, diagnose_exports, native_surface, surface_ready
from windows_x64_preflight import authority

KEY = "windows-arm64"
TARGET = "aarch64-pc-windows-msvc"


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    policy = json.loads((temporary / "cm-worker-preflight.json").read_text(encoding="utf-8"))
    authority(policy, entry, os.environ, key=KEY)
    if os.environ.get("CM_PREFLIGHT_STAGE") != "isolation-surface" or Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("ARM64 API observation requires its fixed stage and exact recorded source checkout")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(temporary):
        raise RuntimeError("ARM64 API text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    record_run.record(logs)
    report = {"schema_version": 1, "status": "running", "scope": "V01a-native-api-surface-only",
        "platform": KEY, "target": TARGET, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": os.environ["CM_REQUEST_ID"],
        "cache_mode": "none", "cache_writes": 0, "cache_deletes": 0, "cli_builds": 0,
        "sdk_compiler_invoked": False, "native_creation": "not_run", "full_isolation": "not_run",
        "qualification": "not_run", "product_build": "not_run", "platform_enabled": False, "release_ready": False,
        "environment": {"system": platform.system(), "machine": platform.machine(), "version": platform.version(),
            "python_version": platform.python_version(), "python_platform": sysconfig.get_platform(),
            "pointer_bits": struct.calcsize("P") * 8, "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion")}}
    try:
        with ci_progress.stage("windows-arm64-isolation-api-surface"):
            report["psec_surface"] = native_surface()
            report["psec_surface_ready"] = surface_ready(report["psec_surface"])
            report["export_diagnostic"] = diagnose_exports()
        report["status"] = "observed_surface_only"
    except Exception as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        (logs / "windows-arm64-isolation-surface.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Windows ARM64 API observation complete; callable sandbox, isolation and product qualification remain NOT_RUN", flush=True)


def self_check():
    import tempfile
    from unittest.mock import patch
    import cm_platforms

    entry = cm_platforms.select(KEY)
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory).resolve()
        env = {"RUNNER_TEMP": str(temp), "CM_CI_LOG_DIR": str(temp / "logs"),
            "CM_SOURCE_DIR": str(Path(__file__).resolve().parents[2]), "CM_PREFLIGHT_STAGE": "isolation-surface",
            "CM_SOURCE_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "b" * 40, "CM_REQUEST_ID": "arm64-surface",
            "CM_EXECUTION_ROLE": "platform_preflight", "GITHUB_JOB": "native-preflight", "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": entry["repository"] + "/.github/workflows/native-preflight.yml@refs/heads/main",
            "CM_BUILD_KIND": "qualification", "CM_CACHE_MODE": "none", "ACTIONS_CACHE_MODE": "none",
            "CM_PLATFORM": KEY, "CM_TARGET": TARGET, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
        policy = {"source_repository": "DSLZL/CM", "source_sha": "a" * 40, "observed_source_default_sha": "a" * 40,
            "source_default_branch": "main", "builder_repository": entry["repository"], "workflow_sha": "b" * 40,
            "worker_default_branch": "main", "request_id": "arm64-surface", "platform": KEY, "target": TARGET,
            "cache_mode": "none", "execution_role": "platform_preflight", "build_kind": "qualification",
            "consumer_required": "false", "distribution_required": "false", "index_required": "false"}
        (temp / "cm-worker-preflight.json").write_text(json.dumps(policy), encoding="utf-8")
        absent = {"api_set": False, "dll_loaded": False, "exports": dict.fromkeys(EXPORTS, False), "query_hresult": None,
            "support_flags": None, "winerror": None}
        with patch.dict(os.environ, env, clear=True), patch.object(record_run, "require_hosted_worker", return_value=entry), \
                patch.object(record_run, "record"), patch(__name__ + ".native_surface", return_value=absent) as query, \
                patch(__name__ + ".diagnose_exports", return_value={"diagnostic_only": True, "callable_availability": "not_run"}) as exports:
            main()
            observed = json.loads((temp / "logs/windows-arm64-isolation-surface.json").read_text(encoding="utf-8"))
            assert observed["status"] == "observed_surface_only" and observed["psec_surface_ready"] is False
            assert observed["psec_surface"] == absent and observed["export_diagnostic"]["callable_availability"] == "not_run"
            assert observed["cli_builds"] == 0 and observed["sdk_compiler_invoked"] is False
            assert observed["platform_enabled"] is False and observed["full_isolation"] == observed["qualification"] == "not_run"
            for changes in ({"CM_PREFLIGHT_STAGE": "loader-terminal"}, {"CM_SOURCE_DIR": str(temp)},
                    {"CM_CI_LOG_DIR": str(temp.parent / "outside")}, {"CM_PLATFORM": "windows-x64"}):
                query.reset_mock(); exports.reset_mock()
                with patch.dict(os.environ, changes):
                    try:
                        main()
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("Invalid ARM64 observation authority accepted")
                query.assert_not_called(); exports.assert_not_called()
            query.side_effect = OSError("read-only query failed")
            try:
                main()
            except OSError:
                pass
            else:
                raise AssertionError("ARM64 surface failure was hidden")
            failed = json.loads((temp / "logs/windows-arm64-isolation-surface.json").read_text(encoding="utf-8"))
            assert failed["status"] == "failed" and failed["error"]["type"] == "OSError"
    print("CM Windows ARM64 API observation self-check passed", flush=True)


if __name__ == "__main__":
    main()
