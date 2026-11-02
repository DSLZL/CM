"""G01 prepares exact-bound manifests from existing independent composition builds."""
import json
import os
from pathlib import Path
import shutil

REPORTS = ("hook-qualification-matrix.json", "exact-host-hook-binding.json",
           "prepared-slot-runtime.json", "hook-conflict-lifecycle.json",
           "unsupported-without-build-fallback.json")


def prepare(inputs, frozen, logs, authors):
    import host
    import mod_manifest
    import runtime_composition as composition
    from linux_ci import load_config, TARGET
    root = Path(os.environ["CM_SOURCE_DIR"])
    identity = frozen["host_identity"]
    mapping = identity["patch_map"]
    assert host.digest(mapping) == identity["patch_map_sha256"]
    parallel = root / host.HOST / "codex-rs/core/src/tools/parallel.rs"
    assert host.sha(parallel) == mapping["source_fingerprints"]["codex-rs/core/src/tools/parallel.rs"]
    assert parallel.read_text().count("router.tool_supports_parallel(&call)") == 1
    assert parallel.read_text().count("cm_runtime::tool_policy::evaluate(") == 1
    builds = host.read(logs / "composition-builds.json")
    packages = {}
    for role, variants in (("a", ("normal", "short", "replacement")), ("b", ("normal", "replacement"))):
        for variant in variants:
            key = role + "/" + variant
            receipt = builds[key]
            package = composition.install(inputs, receipt, directory="g01/" + key)
            record = mod_manifest.convert(package)
            record.pop("state", None)
            record["kind"] = "advanced_hook"
            record["compat"].update(host_api_min="0.10.0", exact_host={
                "build_id": identity["host_build_id"], "executable_sha256": frozen["executable_sha256"],
                "patch_map_sha256": identity["patch_map_sha256"]})
            mod_manifest.manifest(package, record)
            assert host.sha(package / "payload.so") == receipt["payload_sha256"]
            authors["g01/" + key] = receipt
            packages[key] = {"payload_sha256": receipt["payload_sha256"],
                "manifest_sha256": host.sha(package / "mod.toml"), "independent_build": receipt["mod_build_id"]}
    cfg = load_config(root)
    probe = Path(os.environ["CARGO_TARGET_DIR"]) / "host" / TARGET / cfg["build_profile"] / "examples/native_probe"
    destination = inputs / "probes/cm-hook-policy"
    destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(probe, destination)
    destination.chmod(0o755)
    legacy = inputs / "host/g02a-legacy/codex"
    previous = host.read(inputs / "fixture/g02a-legacy-host.json")
    assert host.sha(legacy) == previous["host"]["executable_sha256"] != frozen["executable_sha256"]
    for name in ("ci/scripts/runtime_hooks.py", "fixtures/runtime-hooks/driver.py"):
        path = inputs / "fixture" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, path)
    result = {"packages": packages, "patch_map_sha256": identity["patch_map_sha256"],
        "original_query_count": 1, "bridge_count": 1,
        "previous_host": {"path": "/inputs/host/g02a-legacy/codex", "origin": previous["origin"],
            "executable_sha256": host.sha(legacy)},
        "probe": {"path": "/inputs/probes/cm-hook-policy", "sha256": host.sha(destination),
            "separate_from_cli": True, "role": "policy continuation/lifetime supplement only"}}
    host.write(inputs / "fixture/g01-producer.json", result)
    return result


def reports(evidence, steps, audit):
    from mod_manifest import read, write
    from runtime_cases import GROUPS
    assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
    assert all(steps["g01-" + case]["status"] == "pass" for case in GROUPS["g01"])
    sdk_cases = ["m02-" + case for case in GROUPS["m02"]]
    assert all(steps[case]["status"] == "pass" for case in sdk_cases)
    matrix = read(evidence / REPORTS[0])
    matrix["qualification"] = {
        "stable_sdk": {"capability_status": "supported", "experiment_status": "pass", "evidence_cases": sdk_cases},
        "prepared_slots": {"status": "verified", "resource": "core.tool_parallel_eligibility.v1",
            "capability_status": "supported", "experiment_status": "pass",
            "evidence_cases": ["core-around", "core-short", "core-error", "restart-disabled"]},
        "verified_detour": {"capability_status": "unavailable", "experiment_status": "not_run", "implemented": False},
        "unverified_detour": {"capability_status": "unsupported", "experiment_status": "pass",
            "evidence_case": "unsupported-detour"},
        "arbitrary_layout_inline_async_signature": {"capability_status": "unsupported", "experiment_status": "pass",
            "rejection_cases": ["unsupported-layout", "unsupported-inline", "unsupported-async", "unsupported-signature"],
            "implemented": False}}
    matrix.update(arbitrary_source_L4=False, program_complete=False)
    matrix["native_trust"] = "same process privileges; abort, invalid pointers and stuck callbacks can terminate or hang Host"
    matrix["hot_unload"] = "unsupported; disabling takes effect in a fresh process"
    write(evidence / REPORTS[0], matrix)
    fallback = read(evidence / REPORTS[4])
    fallback.update(compiler_linker_jit_build_service_calls=0, build_fallback=False,
        audit_boundary=audit["boundary"] if "boundary" in audit else "fixed audited native fixtures; not a generic malicious-native JIT detector")
    write(evidence / REPORTS[4], fallback)


def self_check():
    from record_run import require_hosted_linux
    require_hosted_linux()
    import importlib.util
    import sys
    from unittest.mock import patch
    import mod_manifest
    import retry
    import runtime_cases
    root = Path(__file__).resolve().parents[2]
    before = retry.test_inputs(root, "HEAD")
    path = "fixtures/runtime-hooks/driver.py"
    with patch.object(sys, "path", [str(root / "fixtures/native-loader"), *sys.path]):
        spec = importlib.util.spec_from_file_location("cm_g01_report_check", root / path)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
    rejected = {"patch_map_sha256": {"error": "wrong digest"}}
    with patch.object(driver, "binding", return_value=driver.report(1, "patch_map_sha256", {"error": "missing"})):
        missing = driver.case_binding_map_missing()[1]
    assert runtime_cases.merge(rejected, missing) == {
        "patch_map_sha256": {"error": "wrong digest"}, "missing_patch_map_sha256": {"error": "missing"}}
    with patch.object(driver, "install"), patch.object(driver, "change"), patch.object(
            driver, "reject", return_value={"error": "wrong target"}):
        wrong_target = driver.case_binding_target()[1]
    assert wrong_target == {"wrong_target": {"error": "wrong target"}}
    assert "target" not in wrong_target, "Target identity belongs to consumer promotion"
    emitted = {}
    steps = {phase + "-" + case: {"status": "pass"} for phase in ("g01", "m02")
             for case in runtime_cases.GROUPS[phase]}
    with patch.object(mod_manifest, "read", side_effect=lambda path: {}), patch.object(
            mod_manifest, "write", side_effect=lambda path, value: emitted.__setitem__(path.name, value)):
        reports(root, steps, {"status": "pass", "compiler_linker_jit_build_service_calls": 0})
    assert "release_ready" not in emitted[REPORTS[0]], "Release status belongs to consumer promotion"
    assert emitted[REPORTS[0]]["arbitrary_source_L4"] is False
    assert emitted[REPORTS[4]]["build_fallback"] is False
    original = retry.source
    changed = original(root, "HEAD", path).replace("def case_binding_map():\n", "def case_binding_map():\n    assert False\n")
    assert changed != original(root, "HEAD", path)
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            changed if name == path else original(directory, revision, name)):
        after = retry.test_inputs(root, "HEAD")
    assert {name for name in before if before[name] != after[name]} == {"g01-binding-map"}
    changed = original(root, "HEAD", path).replace('    directory = EVIDENCE / "rejection"\n',
                              '    directory = EVIDENCE / "rejection"\n    assert False\n')
    assert changed != original(root, "HEAD", path)
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            changed if name == path else original(directory, revision, name)):
        after = retry.test_inputs(root, "HEAD")
    affected = {name for name in before if before[name] != after[name]}
    assert "g01-binding-map" in affected and "g01-core-around" not in affected
    assert all(name.startswith("g01-") for name in affected)
    closure = {"packages": {}, "files": [
        {"path": "inputs/mods/g01/a/normal/payload.so", "sha256": "one"},
        {"path": "inputs/probes/cm-hook-policy", "sha256": "one"}]}
    labels = ["g01-" + case for case in runtime_cases.GROUPS["g01"]]
    before = {name: retry.native_key(closure, name) for name in labels}
    closure["files"][1]["sha256"] = "two"
    affected = {name for name in labels if retry.native_key(closure, name) != before[name]}
    assert affected == {"g01-" + name for name in ("binding-drift", "next-repeat", "next-stale-owner", "next-thread", "cancel-before", "cancel-callback")}
    print("CM G01 independent function/helper/probe dependency checks passed", flush=True)


if __name__ == "__main__":
    if os.sys.argv[1] == "self-check":
        self_check()
    else:
        assert os.sys.argv[1] == "produce"
        from runtime_consumer import produce
        produce()
