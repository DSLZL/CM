#!/usr/bin/env python3
"""M05 business acceptance inside the existing compiler-free namespace only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci/scripts"))
import ci_progress
import mod_manifest as packages
from mod_author import REPORTS

INPUTS = Path("/inputs")
WORK = Path("/work/m05")
PROFILE = Path("/profile/m05")
EVIDENCE = Path("/evidence/m05")
BINARY = INPUTS / "host/bin/codex"
SECRET = "CM_M05_DIAGNOSTIC_SECRET"


def helpers():
    path = Path(__file__).resolve().parents[1] / "managed-package/driver.py"
    spec = importlib.util.spec_from_file_location("cm_m05_managed", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.WORK, module.PROFILE, module.EVIDENCE = WORK, PROFILE, EVIDENCE / "management"
    module.OFFICIAL_PROFILE = INPUTS / "official/profile"
    return module, module.sdk_module()


def diagnostic(text):
    rows = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    assert rows and rows[-1].get("code") and rows[-1].get("stage"), "Missing structured CM diagnostic"
    value = rows[-1]
    assert SECRET not in json.dumps(value) and value["expected"] and value["actual"] and value["next_action"]
    assert value["origin"]["verified"] is False
    return value


@ci_progress.case("name")
def run(m, sdk, name, home, *, version="v1", managed=True, failure=False, sentinel=False,
        remote=False, native_executed=True):
    directory = EVIDENCE / name
    directory.mkdir(parents=True)
    provider = sdk.Provider(tool=version is not None, tool_name="native-mod__greet",
        expected_output={"version": version, "result": "hello from native-mod"})
    arguments = sdk.command(directory, provider.endpoint, "embedded", token=name)[1:]
    if remote:
        arguments[0:0] = ["--remote", provider.endpoint]
    command = m.launch_command(BINARY, home, arguments) if managed else [str(BINARY), *arguments]
    env = sdk.environment(home, directory)
    env["CM_REPLACEMENT_SENTINEL"] = str(directory / "constructor-sentinel")
    try:
        with (directory / "stdout.jsonl").open("w") as out, (directory / "stderr.log").open("w") as err:
            result = subprocess.run(command, env=env, cwd=directory, stdout=out, stderr=err, timeout=90)
        native = sdk.rows(directory / "native.jsonl")
        stderr = (directory / "stderr.log").read_text()
        assert SECRET not in stderr and SECRET not in (directory / "stdout.jsonl").read_text()
        record = {"command": command, "provider_endpoint": provider.endpoint,
            "return_code": result.returncode, "provider_requests": provider.requests,
            "provider_errors": provider.errors, "native_trace": native, "stderr": stderr}
        packages.write(directory / "result.json", record)
        assert (result.returncode != 0) is failure and not provider.errors, record
        if failure:
            assert not provider.requests and not any(row["event"] == "ready" for row in native)
            errors = [row["detail"] for row in native if row["event"] == "startup-failed"]
            assert errors and errors[-1]["already_native_executed"] is native_executed
            record["diagnostic"] = errors[-1]
        else:
            ready = next(row["detail"] for row in native if row["event"] == "ready")
            assert ready["plan"]["host"]["executable_sha256"] == packages.sha(BINARY)
            assert set(ready["plan"]["mods"]) == set(m.state(home)[1]["enabled"])
            assert any(row["event"] == "stopped" for row in native)
            requests = [row for row in provider.requests if row["purpose"] == "business"]
            assert requests and all("exec_command" in [tool.get("name") for tool in row["tools"]] for row in requests)
            assert all([tool.get("name") for tool in row["tools"]].count("native-mod__greet") ==
                int(version is not None) for row in requests)
            outputs = [json.loads(item["output"]) for row in requests for item in row["outputs"]]
            assert (any(value == {"version": version, "result": "hello from native-mod"} for value in outputs)
                if version is not None else not outputs)
            record["actual_mods"] = sorted(ready["plan"]["mods"])
        assert (directory / "constructor-sentinel").exists() is sentinel
        packages.write(directory / "result.json", record)
        return record
    finally:
        provider.close()


@ci_progress.case()
def update(m, sdk, receipt):
    home = PROFILE / "user"
    m.cm(home, "install", INPUTS / "mods/m02/lifecycle-audit/normal")
    m.cm(home, "install", INPUTS / "mods/m05/v1.cmod")
    before = m.state(home)[1]
    other = before["installed"]["lifecycle-audit"]
    path = Path(m.cm(home, "state", "path", "native-mod")["path"]) / "retained"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text("author-owned user data")
    path.chmod(0o600)
    data = path.read_bytes()
    first = run(m, sdk, "installed-v1", home)
    unchanged = m.state(home)
    rejected = m.cm(home, "replace", "native-mod", INPUTS / "mods/m05/v2.cmod", "--from", "0" * 64, success=False)
    assert m.state(home) == unchanged
    replaced = m.cm(home, "replace", "native-mod", INPUTS / "mods/m05/v2.cmod", "--from", before["installed"]["native-mod"])
    current = m.state(home)[1]
    assert current["installed"]["lifecycle-audit"] == other
    assert current["installed"]["native-mod"] != before["installed"]["native-mod"]
    state_path = Path(m.cm(home, "state", "path", "native-mod")["path"]) / "retained"
    assert state_path.read_bytes() == data
    second = run(m, sdk, "replaced-v2", home, version="v2")
    m.cm(home, "disable", "native-mod")
    disabled = run(m, sdk, "disabled-restart", home, version=None)
    m.cm(home, "enable", "native-mod")
    enabled = run(m, sdk, "enabled-restart", home, version="v2")
    m.cm(home, "remove", "native-mod")
    removed = run(m, sdk, "removed-restart", home, version=None)
    assert m.state(home)[1]["installed"]["lifecycle-audit"] == other and state_path.read_bytes() == data
    return {"v1": first, "v2": second, "wrong_old_digest": rejected, "replace": replaced,
        "disabled": disabled, "enabled": enabled, "removed": removed, "other_mod_content_sha256": other,
        "owned_data_retained": True, "author_builds": receipt["authors"],
        "builder_execution_audit": receipt.get("builder_execution_audit"),
        "qualification_controlled_update": receipt["build_kind"] == "qualification"}


def candidate(name, source=None):
    home = PROFILE / name
    package = home / "mods/native-mod"
    shutil.copytree(source or INPUTS / "mods/m05/v1", package)
    fields = tomllib.loads((package / "mod.toml").read_text())
    packages.selection(home, [fields["id"]])
    return home, package, fields


@ci_progress.case()
def failures(m, sdk, receipt):
    rows = []
    for name in ("abi", "capability", "dependency", "conflict", "target", "corrupt"):
        home, package, fields = candidate("reject-" + name)
        if name == "abi":
            fields["compat"].update(abi_minor_min=99, abi_minor_max=99)
        elif name == "capability":
            fields["compat"]["required_capabilities"].append("unsupported.feature.v1")
        elif name == "dependency":
            fields["dependencies"] = [{"id": "missing-mod", "version": "1.0.0"}]
        elif name == "conflict":
            shutil.copytree(INPUTS / "mods/m02/lifecycle-audit/normal", home / "mods/lifecycle-audit")
            fields["conflicts"] = ["lifecycle-audit"]
            packages.selection(home, ["native-mod", "lifecycle-audit"])
        elif name == "target":
            fields["binary"]["target"] = "aarch64-unknown-linux-gnu"
        else:
            (package / "payload.so").write_bytes(b"corrupt controlled package")
        fields["provenance"]["release_notes"] = SECRET
        packages.manifest(package, fields)
        result = packages.metadata(BINARY, home, ["doctor"], success=False,
            evidence=EVIDENCE / "failures" / (name + ".json"))
        value = result["output"]
        assert value["mod_id"] == "native-mod" and value["expected"] and value["next_action"]
        assert not value["already_native_executed"] and SECRET not in json.dumps(value)
        rows.append({"case": name, "expected_abi": {"major": 2, "minor": 2},
            "declared_compatibility": fields["compat"], "declared_target": fields["binary"]["target"], **result})
    home = PROFILE / "init-fail"
    m.cm(home, "install", INPUTS / "mods/m05/init-fail.cmod")
    initialized = run(m, sdk, "initialization-failure", home, failure=True, sentinel=False)
    # Initializers have run even though the independent constructor sentinel is absent.
    assert initialized["diagnostic"]["already_native_executed"]
    backend = run(m, sdk, "unsupported-backend", home, managed=False, failure=True, remote=True, native_executed=False)
    state_home = PROFILE / "state-incompatible"
    m.cm(state_home, "install", INPUTS / "mods/m05/v1.cmod")
    state_path = Path(m.cm(state_home, "state", "path", "native-mod")["path"])
    state_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    (state_path / "retained").write_text("state must survive rejected replacement")
    (state_path / "retained").chmod(0o600)
    before = m.state(state_home)
    breaking = WORK / "breaking-state"
    shutil.copytree(INPUTS / "mods/m05/v2", breaking)
    fields = tomllib.loads((breaking / "mod.toml").read_text())
    fields["state"]["schema"] = "incompatible-schema"
    packages.manifest(breaking, fields)
    state_error = m.cm(state_home, "replace", "native-mod", breaking, "--from",
        before[1]["installed"]["native-mod"], success=False)
    assert diagnostic(state_error["stderr"])["code"].startswith("state") and m.state(state_home) == before
    assert (state_path / "retained").read_text() == "state must survive rejected replacement"
    return {"author_compile": receipt["compile_failure"], "static_rejections": rows,
        "runtime_initialization": initialized, "unsupported_backend": backend, "state_rejection": state_error}


@ci_progress.case()
def metadata_boundary(m, sdk):
    home, package, fields = candidate("metadata", INPUTS / "mods/constructor-sentinel")
    fields["provenance"].update(repository="https://user:" + SECRET + "@invalid/?token=" + SECRET,
        release_notes=SECRET + "\u001b[2J", license=SECRET)
    packages.manifest(package, fields)
    (package / "postinstall.sh").write_text('#!/bin/sh\n: > "$CM_M05_INSTALL_SENTINEL"\n')
    (package / "postinstall.sh").chmod(0o755)
    before = m.protected_inventory(home)
    rows = []
    for command in ("list", "plan", "doctor"):
        result = packages.metadata(BINARY, home, [command], evidence=EVIDENCE / "metadata" / (command + ".json"),
            extra_env={"CM_REPLACEMENT_SENTINEL": str(EVIDENCE / "metadata-sentinel"),
                       "CM_NATIVE_TRACE": str(EVIDENCE / "metadata-native.jsonl"),
                       "CM_M05_INSTALL_SENTINEL": str(EVIDENCE / "installation-sentinel")})
        value = result["output"]
        assert SECRET not in json.dumps(value) and value["schema_version"] == 2
        if command != "list":
            assert value["qualification"]["verified"] is False
            assert value["projection"]["canonical"] is False and "plan" not in value
        assert m.protected_inventory(home) == before
        assert not (EVIDENCE / "metadata-sentinel").exists() and not (EVIDENCE / "metadata-native.jsonl").exists()
        assert not (EVIDENCE / "installation-sentinel").exists()
        rows.append({"command": command, **result})
    compatible = dict(fields["compat"])
    fields["compat"].update(abi_minor_min=99, abi_minor_max=99)
    packages.manifest(package, fields)
    before = m.protected_inventory(home)
    rejected = packages.metadata(BINARY, home, ["doctor"], success=False,
        evidence=EVIDENCE / "metadata/wrong-abi.json", extra_env={
            "CM_REPLACEMENT_SENTINEL": str(EVIDENCE / "metadata-sentinel")})
    assert SECRET not in json.dumps(rejected) and m.protected_inventory(home) == before
    assert not (EVIDENCE / "metadata-sentinel").exists()
    rows.append({"command": "doctor-wrong-abi", **rejected})
    fields["compat"] = compatible
    fields["provenance"].update(repository="https://github.com/DSLZL/CM", release_notes="constructor control", license="Apache-2.0")
    packages.manifest(package, fields)
    positive = run(m, sdk, "constructor-positive-control", home, managed=False, failure=True, sentinel=True)
    return {"commands": rows, "read_only_inventory_unchanged": True, "constructor_positive_control": positive,
        "installation_script_guard": packages.read(INPUTS / "fixture/m05-producer.json")["source_review"]}


@ci_progress.case()
def command_contract(m):
    results = []
    for args in (("--help",), ("cm", "--help"), ("cm", "launch", "--help")):
        result = subprocess.run([str(BINARY), *args], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0
        results.append({"command": [str(BINARY), *args], "return_code": result.returncode, "help": result.stdout})
    assert all(name in results[1]["help"] for name in ("install", "replace", "disable", "enable", "launch", "doctor"))
    return {"help": results, "compiler_paths_absent": all(shutil.which(name) is None for name in ("cargo", "rustc", "gcc", "cc", "ld")),
        "local_or_remote_build_fallback": False}


def matrix():
    WORK.mkdir()
    PROFILE.mkdir()
    EVIDENCE.mkdir()
    m, sdk = helpers()
    receipt = packages.read(INPUTS / "fixture/m05-producer.json")
    baseline = m.protected_inventory(INPUTS / "official")
    host_before = packages.sha(BINARY)
    updated = update(m, sdk, receipt)
    rejected = failures(m, sdk, receipt)
    boundary = metadata_boundary(m, sdk)
    contract = command_contract(m)
    assert contract["compiler_paths_absent"] and host_before == packages.sha(BINARY)
    assert m.protected_inventory(INPUTS / "official") == baseline
    if receipt["build_kind"] == "mod-only":
        assert receipt["builder_execution_audit"]["status"] == "pass"
        assert receipt["current_author_variants"] == ["v2"]
    reports = (updated, receipt["source_review"], rejected, updated, boundary,
        {**contract, "ci_blocked_checks": receipt["source_review"]["blocked_ci_checks"]})
    for name, report in zip(REPORTS, reports, strict=True):
        packages.write(Path("/evidence") / name, {"status": "behavior_pass", "result": report,
            "host_unchanged": True, "official_installation_unchanged": True})
    for path in (*EVIDENCE.rglob("*.json"), *EVIDENCE.rglob("*.jsonl"), *EVIDENCE.rglob("*.log")):
        assert SECRET not in path.read_text(errors="replace"), "Secret in exported M05 evidence"
    packages.write(EVIDENCE / "suite.json", {"status": "pass", "reports": list(REPORTS), "release_ready": False})


def self_check():
    value = {"stage": "preflight", "code": "abi", "expected": "ABI 2.2", "actual": {"minor": 99},
        "next_action": "Use a compatible precompiled Mod", "origin": {"verified": False}}
    assert diagnostic(json.dumps(value)) == value
    try:
        diagnostic("not a structured diagnostic")
    except AssertionError:
        pass
    else:
        raise AssertionError("Missing diagnostics accepted")


if __name__ == "__main__":
    {"matrix": matrix, "self-check": self_check}[sys.argv[1]]()
