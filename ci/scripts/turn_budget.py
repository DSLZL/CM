"""G02A author handoff; runtime cases run separately in the strict consumer."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib

from linux_ci import TARGET

OWNER = "org.example.turn-budget"
CAPABILITY = "core.turn_sampling_budget.v1"
CASES = ("counting", "reentry", "terminal", "scope", "cancellation-recovery", "plug-and-play")
REPORTS = tuple("budget-" + name + ".json" for name in CASES)
LEGACY_ORIGIN = {
    "run_id": 40902527878, "run_attempt": 1,
    "source_sha": "e089cb59f2c7773fbac2f1aa6c718ce1f02f55e5",
    "workflow_sha": "cd341f906b11c78416b4a04fc9c337a3c7598948",
    "request_id": "cm-m05-retry-20261029-r4-selective",
    "input_artifact_id": 12902766704,
    "input_artifact_sha256": "7c5c31ace5fb08567cae06efb417b693e352443ed42b141fee306d2320209b50",
    "consumer_artifact_id": 12909768461,
    "consumer_artifact_sha256": "719e1662f3c21e34cc3272b442218b9d4048d32c19e2bd600cd83631003a36a7",
    "receipt_artifact_id": 12909992360,
    "receipt_artifact_sha256": "03e977151cafa14155f64aac5aa70859f67f70e2dc60a6e6182c306faf48bdca",
}


def driver():
    path = Path(__file__).resolve().parents[2] / "fixtures/turn-budget/driver.py"
    spec = importlib.util.spec_from_file_location("cm_turn_budget_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(inputs, package, frozen, logs, authors, sdk):
    import host
    import mod_manifest
    from linux_ci import cargo_args, execute, load_config
    root = Path(os.environ["CM_SOURCE_DIR"])
    cfg = load_config(root)
    unit = {"manifest": "examples/mods/turn-budget/Cargo.toml", "packages": ["cm-turn-budget"], "features": []}
    source = root / "examples/mods/turn-budget"
    lock = source / "Cargo.lock"
    before = host.sha(lock)
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "g02a-turn-budget"
    assert not target.exists(), "Independent Mod target must start empty"
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    for phase in ("fmt", "clippy", "test", "build"):
        command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"] if phase == "fmt"
                   else cargo_args(unit, phase, cfg, cfg["build_profile"]))
        if phase == "clippy":
            command += ["--all-targets", "--", "-D", "warnings"]
        execute(root, logs, "g02a-author-" + phase, command, env)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", str(source / "Cargo.toml")], env=env, text=True))
    dependencies = {item["name"]: sorted(dep["name"] for dep in item["dependencies"]) for item in metadata["packages"]}
    assert dependencies["cm-sdk"] == ["cm-abi"] and dependencies["cm-abi"] == []
    assert dependencies["cm-turn-budget"] == ["cm-sdk", "serde", "serde_json"]
    assert set(dependencies) <= {"cm-abi", "cm-sdk", "cm-turn-budget", "serde", "serde_core", "serde_derive",
        "serde_json", "itoa", "memchr", "zmij", "proc-macro2", "quote", "syn", "unicode-ident"}
    assert host.sha(lock) == before
    destination = inputs / "mods/g02a/turn-budget"
    destination.mkdir(parents=True)
    payload = destination / "payload.so"
    shutil.copyfile(target / TARGET / cfg["build_profile"] / "libcm_turn_budget.so", payload)
    manifest = tomllib.loads((source / "mod.toml").read_text())
    manifest["binary"].update(size=payload.stat().st_size, sha256=host.sha(payload),
        glibc_min=mod_manifest.native_glibc_min(payload))
    manifest["provenance"]["revision"] = os.environ["CM_SOURCE_SHA"]
    mod_manifest.manifest(destination, manifest)
    archive = destination.with_suffix(".cmod")
    mod_manifest.zip_package(destination, archive)
    exports = subprocess.check_output(["nm", "-D", "--defined-only", str(payload)], text=True)
    assert re.search(r"\bT cm_mod_entry_v2$", exports, re.MULTILINE)
    identity = {"sources": host.manifest(root, [*source.rglob("*"),
        *(root / "crates/cm-sdk").rglob("*"), *(root / "crates/cm-abi").rglob("*")]),
        "lock_sha256": before, "dependencies": dependencies, "toolchain": cfg["rust_toolchain"],
        "target": TARGET, "profile": cfg["build_profile"], "flags": frozen["host_identity"]["inputs"]["flags"],
        "host_frozen_before_author_build": frozen["executable_sha256"], "initial_target_empty": True}
    author = {"status": "pass", "inputs": identity, "mod_build_id": "sha256:" + host.digest(identity),
        "payload_sha256": host.sha(payload), "manifest_sha256": host.sha(destination / "mod.toml"),
        "archive_sha256": host.sha(archive), "exports": exports}
    authors["g02a/turn-budget"] = author
    for relative in ("ci/scripts/turn_budget.py", "fixtures/turn-budget/driver.py"):
        path = inputs / "fixture" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, path)
    probe = native_probe(root, logs, inputs, frozen, sdk)
    legacy = legacy_host(inputs)
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    host.verify_sources(root, logs)
    result = {"status": "pass", "author": author, "private_core_probe": probe, "legacy_host": legacy,
        "host_rebuilt_after_freeze": False, "cases": list(CASES)}
    host.write(inputs / "fixture/g02a-producer.json", result)
    return result


def restore_legacy():
    import host
    import worker_policy as policy
    from linux_ci import load_config
    if load_config(Path(os.environ["CM_SOURCE_DIR"]))["task_id"] != "CM-G02A":
        return
    source, worker, _, workflow, _ = policy.identities()
    remote = policy.verify_origin(LEGACY_ORIGIN, source, worker, workflow)
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-g02a-legacy-reference"
    directory.mkdir()
    with policy.download_origin_archive(worker, remote["artifacts"]["receipt"], directory / "receipt.zip") as archive:
        receipt = policy.archive_json(archive, "worker-receipt.json")
    ci = policy.qualification_receipt(receipt, LEGACY_ORIGIN, remote["jobs"], source, worker)
    with policy.download_origin_archive(worker, remote["artifacts"]["input"], directory / "inputs.zip") as archive:
        assert archive.namelist() == ["runtime-inputs.tar"]
        with archive.open("runtime-inputs.tar") as stream, (directory / "inputs.tar").open("xb") as output:
            shutil.copyfileobj(stream, output)
    binary = directory / "codex"
    with tarfile.open(directory / "inputs.tar", "r:") as archive:
        metadata = archive.getmember("runtime-inputs/producer.json")
        member = archive.getmember("runtime-inputs/host/bin/codex")
        assert metadata.isfile() and metadata.size <= 16 * 1024 * 1024
        assert member.isfile() and 0 < member.size <= 1024 ** 3
        producer = json.load(archive.extractfile(metadata))
        with archive.extractfile(member) as stream, binary.open("xb") as output:
            shutil.copyfileobj(stream, output)
    binary.chmod(0o755)
    previous = producer["host"]
    assert producer["task_id"] == "CM-M05" and producer["m05"]["build_kind"] == "qualification"
    assert previous["host_identity"]["host_api_version"] == "0.6.0"
    assert CAPABILITY not in previous["host_identity"]["capabilities"]
    assert host.sha(binary) == previous["executable_sha256"]
    result = {"origin": LEGACY_ORIGIN, "ci": ci, "host": previous,
        "path": "/inputs/host/g02a-legacy/codex", "purpose": "pre-native metadata rejection only"}
    host.write(directory / "legacy-host.json", result)


def legacy_host(inputs):
    import host
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-g02a-legacy-reference"
    result = host.read(directory / "legacy-host.json")
    assert result["origin"] == LEGACY_ORIGIN
    assert host.sha(directory / "codex") == result["host"]["executable_sha256"]
    binary = inputs / "host/g02a-legacy/codex"
    binary.parent.mkdir()
    shutil.copyfile(directory / "codex", binary)
    binary.chmod(0o755)
    assert host.sha(binary) == result["host"]["executable_sha256"]
    host.write(inputs / "fixture/g02a-legacy-host.json", result)
    return result


def native_probe(root, logs, inputs, frozen, sdk):
    import host
    import mod_manifest
    from linux_ci import execute
    # M02 already compiled this exact instrumented executable; do not invoke Cargo again.
    previous = sdk["native_scope_probe"]
    binary = Path(previous["command"][0])
    assert host.sha(binary) == previous["binary_sha256"]
    home = Path(os.environ["RUNNER_TEMP"]) / "cm-g02a-native-profile"
    shutil.copytree(inputs / "mods/g02a/turn-budget", home / "mods" / OWNER)
    mod_manifest.write_toml(home / "cm-runtime.toml", {"format_version": 2, "enabled": [OWNER],
        "mods": {OWNER: {"policy": {"max_main_samples": 2,
            "session_sources": ["exec"], "request_kinds": ["turn"]}}}})
    report = inputs / "fixture/g02a-native-scopes.json"
    trace = inputs / "fixture/g02a-native-trace.jsonl"
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR") if key in os.environ}
    env.update(previous["test_environment"])
    env.update(CODEX_HOME=str(home), HOME=str(home / "home"),
        CM_BUDGET_PROBE_PROFILE=str(home), CM_BUDGET_PROBE_REPORT=str(report), CM_NATIVE_TRACE=str(trace))
    command = [str(binary), "--ignored", "--exact", "thread_manager::tests::cm_turn_budget_scopes", "--nocapture"]
    try:
        execute(root, logs, "g02a-native-probe", command, env)
    finally:
        for path in (report, trace):
            if path.is_file():
                shutil.copyfile(path, logs / path.name)
    scope = host.read(report)
    assert scope["status"] == "pass"
    for key in ("step_rebuild", "model_change", "same_object_reentry", "same_text_id_new_scope",
                "concurrent_limit", "unmatched_kind", "undeclared_isolated_default", "cancel_before_charge",
                "closed_scope_rejected", "shutdown"):
        assert scope[key] is True, key
    assert scope["persistent_recovery_error"] == "sampling_budget_recovery_unsupported"
    result = {"status": "pass", "scope_report": scope, "binary_sha256": host.sha(binary), "command": command,
        "fixture_source_sha256": host.sha(root / "fixtures/turn-budget/scope_probe.rs"),
        "instrumented_source_sha256": previous["native_fixture_source_manifest_sha256"],
        "test_environment": previous["test_environment"],
        "cli_executable_sha256": frozen["executable_sha256"], "separate_from_cli": True,
        "compilation_reused_from_m02": True, "consumer_replayed": False}
    host.write(inputs / "fixture/g02a-native-probe.json", result)
    return result


def produce():
    import runtime_consumer
    runtime_consumer.produce()


def self_check():
    from worker_policy import parse_origin
    assert parse_origin(LEGACY_ORIGIN) == LEGACY_ORIGIN
    assert len(CASES) == len(set(CASES)) == len(REPORTS) == 6
    root = Path(__file__).resolve().parents[2]
    manifest = tomllib.loads((root / "examples/mods/turn-budget/mod.toml").read_text())
    assert manifest["id"] == OWNER and manifest["compat"]["required_capabilities"] == [CAPABILITY]
    assert manifest["contributions"] == [{"id": "main-sampling", "kind": "sampling_budget",
        "capability": CAPABILITY, "resource": CAPABILITY}]
    assert manifest["config"]["defaults"] == {}
    driver().self_check()
    print(json.dumps({"g02a_handoff_self_check": "pass"}))


if __name__ == "__main__":
    {"produce": produce, "self-check": self_check, "restore-legacy": restore_legacy}[sys.argv[1]]()
