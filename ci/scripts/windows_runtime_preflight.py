#!/usr/bin/env python3
"""Actual native Windows runtime library gate; no CLI, helper or binary cache."""
import hashlib
import difflib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import ci_progress
import record_run
from linux_arm64_preflight import test_executables
from windows_x64_preflight import authority, pe_fixture

KEY = "windows-arm64"
TARGET = "aarch64-pc-windows-msvc"
GIT_CONFIG = {"GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_0": "core.autocrlf", "GIT_CONFIG_VALUE_0": "false",
    "GIT_CONFIG_KEY_1": "core.longpaths", "GIT_CONFIG_VALUE_1": "true",
    "GIT_CONFIG_KEY_2": "core.hooksPath", "GIT_CONFIG_VALUE_2": "NUL"}


def passed_tests(text):
    matches = re.findall(r"^test result: ok\. ([1-9][0-9]*) passed; 0 failed;", text, re.M)
    if len(matches) != 1:
        raise RuntimeError("Expected one successful nonempty native test result")
    return int(matches[0])


def formatting_patch(root, formatted):
    patch = []
    for package in ("cm", "cm-abi"):
        for original in sorted((root / "crates" / package).rglob("*.rs")):
            relative = original.relative_to(root)
            before = original.read_text(encoding="utf-8").splitlines(keepends=True)
            after = (formatted / relative).read_text(encoding="utf-8").splitlines(keepends=True)
            patch.extend(difflib.unified_diff(before, after,
                fromfile="a/" + relative.as_posix(), tofile="b/" + relative.as_posix()))
    return "".join(patch)


def main():
    root = Path(__file__).resolve().parents[2]
    entry = record_run.require_hosted_worker(enabled=False)
    policy = json.loads((Path(os.environ["RUNNER_TEMP"]) / "cm-worker-preflight.json").read_text())
    authority(policy, entry, os.environ, key=KEY)
    if os.environ.get("CM_PREFLIGHT_STAGE") != "runtime-library" or Path(os.environ["CM_SOURCE_DIR"]).resolve() != root:
        raise RuntimeError("Runtime library requires its exact reviewed stage and source")
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    if not logs.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise RuntimeError("Library text evidence must stay in runner temporary storage")
    logs.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "status": "running", "stage": "runtime-library",
        "scope": "actual cm-abi and complete cm-runtime library, not a projection fixture",
        "platform": KEY, "target": TARGET, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": os.environ["CM_REQUEST_ID"],
        "cache_mode": "none", "cache_writes": 0, "cache_deletes": 0, "cli_builds": 0,
        "v8_builds": 0, "protoc_builds": 0, "platform_enabled": False,
        "full_qualification": "not_run", "packaged_host": "not_run", "gates": {}}

    def run(label, args, timeout=60, *, cwd=root):
        previous = Path.cwd()
        try:
            os.chdir(cwd)
            values = [str(value) for value in args]
            with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"stage": label, "command": values, "cwd": str(cwd)}) + "\n")
            result = ci_progress.run(logs, label, values, timeout)
        finally:
            os.chdir(previous)
        text = (logs / (label + ".log")).read_text(encoding="utf-8", errors="strict")
        if result.returncode:
            raise RuntimeError(label + " failed; see " + label + ".log")
        return text

    try:
        if any(os.environ.get(name) for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTDOC",
                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CFLAGS", "CXXFLAGS", "CL", "_CL_", "CC", "CXX", "AR",
                "CC_aarch64_pc_windows_msvc", "AR_aarch64_pc_windows_msvc", "CFLAGS_aarch64_pc_windows_msvc",
                "CRATE_CC_NO_DEFAULTS", "CC_FORCE_DISABLE", "CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER")):
            raise RuntimeError("Library requires native baseline compilers without overrides")
        if any(os.environ.get(name) != value for name, value in GIT_CONFIG.items()):
            raise RuntimeError("Library source preparation requires the fixed per-process Git configuration")
        import host

        cfg = host.read(root / ".github/cm-ci.json")
        pin = host.read(root / host.ADAPTER / "source.json")
        if cfg["rust_toolchain"] != "1.95.0" or cfg["upstream"]["commit"] != pin["commit"] or host.TARGET != TARGET:
            raise RuntimeError("Library toolchain, target or upstream pins differ")
        report["source_sha256"] = {row["path"]: row["sha256"] for row in host.cm_manifest(root)}
        report["environment"] = {name: os.environ[name] for name in (
            "ImageOS", "ImageVersion", "VCToolsVersion", "WindowsSDKVersion", "VCToolsInstallDir", "WindowsSdkDir")}
        cl = Path(shutil.which("cl.exe") or "")
        if not cl.is_absolute() or tuple(part.lower() for part in cl.parts[-3:]) != ("hostarm64", "arm64", "cl.exe"):
            raise RuntimeError("Library requires installed native ARM64 MSVC")
        link = Path(shutil.which("link.exe") or "")
        if not link.is_absolute() or link.parent != cl.parent:
            raise RuntimeError("Library requires the matching installed native linker")
        tools = report["tools"] = {}
        for name, path in (("cl", cl), ("link", link), ("lib", cl.with_name("lib.exe"))):
            tools[name] = {"path": str(path), **pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)}
        with tempfile.TemporaryDirectory(prefix="cm-runtime-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temp = Path(directory).resolve()
            report["temporary_root"] = str(temp)
            toolchain = cfg["rust_toolchain"] + "-" + TARGET
            run("library-native-toolchain", ["rustup", "toolchain", "install", toolchain, "--profile", "minimal"], 180)
            run("library-native-components", ["rustup", "component", "add", "rustfmt", "clippy", "--toolchain", toolchain], 180)
            for name in ("rustc", "cargo", "rustfmt", "cargo-clippy", "clippy-driver"):
                path = Path(run("library-" + name + "-path", ["rustup", "which", "--toolchain", toolchain, name]).strip())
                tools[name] = {"path": str(path), **pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)}
            version = run("library-rustc-version", [tools["rustc"]["path"], "-Vv"])
            if "host: " + TARGET not in version.splitlines():
                raise RuntimeError("Library Rust compiler is not native ARM64")
            os.environ.update({"TEMP": str(temp), "TMP": str(temp),
                "CARGO_HOME": str(temp / "c"), "CARGO_TARGET_DIR": str(temp / "t"),
                "CARGO_INCREMENTAL": "0", "RUSTUP_TOOLCHAIN": toolchain, "RUSTC": tools["rustc"]["path"],
                "RUSTFLAGS": "-Ctarget-feature=+crt-static", "CC": str(cl), "AR": tools["lib"]["path"],
                "CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER": str(link)})
            with ci_progress.stage("library-fixed-source-prepare"):
                host.prepare(root, logs)
            tree = root / host.HOST
            provenance = host.read(logs / "host-source-provenance.json")
            if provenance["source_sha"] != report["source_sha"] or provenance["upstream_commit"] != pin["commit"]:
                raise RuntimeError("Library prepared source provenance differs")
            report["source_preparation"] = {"status": "pass", "upstream_commit": pin["commit"],
                "original_manifest_sha256": provenance["original_manifest_sha256"],
                "host_manifest_sha256": provenance["host_manifest_sha256"],
                "original_lock_sha256": provenance["original_lock_sha256"], "host_lock_sha256": provenance["host_lock_sha256"],
                "overlay_files": len(provenance["overlay"]), "production_host": False}
            identity = temp / "private-library-identity.json"
            host.write(identity, {"domain": "cm.native-mechanism-probe.v1", "target": TARGET,
                "host_build_id": "sha256:" + hashlib.sha256((report["source_sha"] + TARGET).encode()).hexdigest(),
                "host_api_version": pin["host_api_version"], "capabilities": pin["capabilities"],
                "abis": pin["abis"], "production_host": False})
            os.environ["CM_HOST_IDENTITY_JSON"] = str(identity)
            report["private_identity_sha256"] = host.sha(identity)
            report["gates"]["format"] = "pass"
            try:
                run("library-format-check", [tools["rustfmt"]["path"], "--edition", "2024", "--check",
                    root / "crates/cm/src/lib.rs", root / "crates/cm/build.rs", root / "crates/cm-abi/src/lib.rs"])
            except RuntimeError:
                report["gates"]["format"] = "failed"
                formatted = temp / "formatted"
                for package in ("cm", "cm-abi"):
                    shutil.copytree(root / "crates" / package, formatted / "crates" / package)
                run("library-format-candidate", [tools["rustfmt"]["path"], "--edition", "2024",
                    formatted / "crates/cm/src/lib.rs", formatted / "crates/cm/build.rs",
                    formatted / "crates/cm-abi/src/lib.rs"])
                (logs / "library-format.patch.log").write_text(formatting_patch(root, formatted), encoding="utf-8")
            cargo = [tools["cargo"]["path"]]
            common = ["--locked", "--target", TARGET, "--profile", "dev-small", "-p", "cm-abi", "-p", "cm-runtime", "--lib", "-j", "2"]
            run("library-clippy", [*cargo, "clippy", *common, "--tests", "--", "-D", "warnings"], 600, cwd=tree / "codex-rs")
            report["gates"]["actual_library_clippy"] = "pass"
            text = run("library-test-build", [*cargo, "test", *common, "--no-run", "--message-format=json"], 600, cwd=tree / "codex-rs")
            executables = test_executables(text, temp / "t")
            report["test_binaries"] = {name: pe_fixture(path.read_bytes(), False, expected_machine=0xAA64)
                for name, path in executables.items()}
            report["gates"]["actual_test_build"] = "pass"
            for name, scope in (("abi", ""), ("loader", "loader::"),
                    ("profile", "profile::tests::"), ("state", "state::tests::"),
                    ("manifest", "manifest::tests::"), ("package", "package::tests::"),
                    ("index", "index::"), ("mod-lock", "mod_lock::tests::"),
                    ("upgrade", "upgrade::tests::"), ("provenance", "provenance::"),
                    ("runtime", "runtime::tests::"), ("runtime-plan", "runtime_plan::tests::")):
                executable = executables["cm_abi" if name == "abi" else "cm_runtime"]
                args = [executable, *([scope] if scope else []), "--test-threads=1"]
                try:
                    report["gates"][name + "_tests"] = {"status": "pass",
                        "passed": passed_tests(run("library-" + name + "-tests", args, 180))}
                except RuntimeError as error:
                    report["gates"][name + "_tests"] = {"status": "failed", "error": str(error)}
            if any(pe_fixture(Path(row["path"]).read_bytes(), False, expected_machine=0xAA64) !=
                    {key: value for key, value in row.items() if key != "path"} for row in tools.values()):
                raise RuntimeError("Native library tools changed")
            if (host.manifest_digest(host.manifest(tree)) != provenance["host_manifest_sha256"] or
                    {row["path"]: row["sha256"] for row in host.cm_manifest(root)} != report["source_sha256"]):
                raise RuntimeError("Library source inputs changed during compilation")
            if report["gates"]["format"] != "pass":
                raise RuntimeError("Source requires the hosted formatting patch")
            if any(isinstance(value, dict) and value.get("status") != "pass" for value in report["gates"].values()):
                raise RuntimeError("Actual library test failures; see the individual suite logs")
            report.update(status="pass", tools_unchanged=True)
    except BaseException as error:
        report.update(status="failed", error=repr(error))
        raise
    finally:
        (logs / "windows-runtime-library.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def self_check():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "source"
        formatted = Path(directory) / "formatted"
        for tree, text in ((root, "fn main(){}\n"), (formatted, "fn main() {}\n")):
            (tree / "crates/cm/src").mkdir(parents=True)
            (tree / "crates/cm/src/lib.rs").write_text(text, encoding="utf-8")
        patch = formatting_patch(root, formatted)
        assert patch.startswith("--- a/crates/cm/src/lib.rs\n+++ b/crates/cm/src/lib.rs\n")
        assert "-fn main(){}\n+fn main() {}\n" in patch
    assert passed_tests("test result: ok. 17 passed; 0 failed; 2 ignored; 0 measured\n") == 17
    for text in ("", "test result: ok. 0 passed; 0 failed;", "test result: ok. 1 passed; 1 failed;",
            "test result: ok. 1 passed; 0 failed;\ntest result: ok. 1 passed; 0 failed;"):
        try:
            passed_tests(text)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Empty, failed or ambiguous test result accepted")
    script = ("import host, linux_ci\nfrom pathlib import Path\n"
        "assert host.TARGET == 'aarch64-pc-windows-msvc'\n"
        "try:\n linux_ci.load_config(Path.cwd())\n"
        "except RuntimeError as error:\n assert 'Unsupported native GNU Linux target' in str(error)\n"
        "else:\n raise AssertionError('Windows must not enter Linux production phases')\n")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run([sys.executable, "-B", "-c", script], cwd=root,
        env={**os.environ, "CM_TARGET": TARGET, "CM_PLATFORM": KEY, "PYTHONPATH": str(root / "ci/scripts")},
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    print("Windows actual library gate self-check: nonempty results and Linux execution guard passed")


if __name__ == "__main__":
    main()
