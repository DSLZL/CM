#!/usr/bin/env python3
"""M04 independent Mod authors and compiler-free file-state acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPORTS = ("restart-disable-remove.json", "empty-set-restart.json", "mod-state-retention.json",
           "precompiled-state-rollback.json", "migration-interruption.json", "runtime-dependency-ownership.json")
VARIANTS = {"v1": "1", "compatible": "1", "v2": "2"}
CHECKS = ("versioned_generation_does_not_reinterpret_legacy_state",
          "bounded_snapshot_preserves_bytes_modes_and_unrelated_owner",
          "links_special_files_and_unowned_paths_are_rejected_before_cleanup",
          "copy_budget_and_replaced_inputs_fail_without_touching_source",
          "replaced_lock_inode_cannot_bypass_a_live_lease",
          "cleanup_failure_keeps_precise_retry_scope_and_snapshot_copy",
          "cleanup_retry_accepts_only_remaining_owned_headers",
          "restore_interruption_preserves_active_view_and_checkpoint_before_retry",
          "checkpoint_binding_and_data_corruption_are_rejected_before_publication",
          "enospc_during_restore_preserves_source_and_active_view",
          "managed_removed_configuration_is_inert_and_unmanaged_remains_strict",
          "state_live_process_lease_is_released_by_sigkill",
          "helper_exec_does_not_inherit_the_state_lease",
          "descriptor_is_unchanged_before_commit_and_truthful_after_rename")


def driver():
    path = Path(__file__).resolve().parents[2] / "fixtures/state/driver.py"
    spec = importlib.util.spec_from_file_location("cm_m04_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(inputs, package, frozen, logs, authors):
    import host
    import mod_manifest
    import runtime_sdk
    from linux_ci import TARGET, cargo_args, execute, load_config
    root = Path(os.environ["CM_SOURCE_DIR"])
    cfg = load_config(root)
    unit = {"manifest": "fixtures/mods/example-tool/Cargo.toml",
            "packages": ["cm-example-tool-fixture"], "features": []}
    lock = root / "fixtures/mods/example-tool/Cargo.lock"
    lock_sha = host.sha(lock)
    source_paths = [root / unit["manifest"], lock, root / "fixtures/mods/example-tool/src/lib.rs",
                    root / "fixtures/runtime-sdk/fixture.rs",
                    *[p for directory in ("cm-abi", "cm-sdk") for p in (root / "crates" / directory).rglob("*") if p.is_file()]]
    for variant, version in VARIANTS.items():
        target = Path(os.environ["CARGO_TARGET_DIR"]) / ("m04-" + variant)
        assert not target.exists(), "State Mod author target must start empty"
        flags = {"CM_FILE_STATE_VERSION": version, "CM_FILE_STATE_BUILD": variant}
        env = {**os.environ, **flags, "CARGO_TARGET_DIR": str(target)}
        for phase in ("fmt", "clippy", "test", "build"):
            command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"] if phase == "fmt"
                       else cargo_args(unit, phase, cfg, cfg["build_profile"]))
            if phase == "clippy":
                command += ["--all-targets", "--", "-D", "warnings"]
            execute(root, logs, "m04-" + variant + "-" + phase, command, env)
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
            "--manifest-path", str(root / unit["manifest"])], env=env, text=True))
        dependencies = sorted(item["name"] for item in metadata["packages"])
        assert dependencies == ["cm-abi", "cm-example-tool-fixture", "cm-sdk"]
        assert host.sha(lock) == lock_sha
        destination = inputs / "mods/m04" / variant
        destination.mkdir(parents=True)
        payload = destination / "payload.so"
        shutil.copyfile(target / TARGET / cfg["build_profile"] / "libcm_example_tool_fixture.so", payload)
        fields = runtime_sdk.fields("example-tool", payload)
        fields["version"] = "2.0.0" if variant == "v2" else "1.0.0"
        fields["compat"]["host_api_min"] = "0.6.0"
        fields["compat"]["required_capabilities"].append("state.files.v1")
        fields["state"]["version"] = int(version)
        fields["config"] = {"schema_version": 1, "schema": {"type": "object", "additionalProperties": False,
            "properties": {"mode": {"type": "string", "enum": ["basic", "new"] if variant == "v2" else ["basic"]}}},
            "defaults": {"mode": "basic"}}
        mod_manifest.manifest(destination, fields)
        mod_manifest.zip_package(destination, destination.with_suffix(".cmod"))
        exports = subprocess.check_output(["nm", "-D", "--defined-only", str(payload)], text=True)
        assert re.search(r"\bT cm_mod_entry_v2$", exports, re.MULTILINE), exports
        identity = {"sources": host.manifest(root, source_paths), "compile_env": flags, "variant": variant,
            "dependencies": dependencies, "lock_sha256": lock_sha, "target": TARGET,
            "profile": cfg["build_profile"], "toolchain": frozen["host_identity"]["inputs"]["toolchain"],
            "flags": frozen["host_identity"]["inputs"]["flags"], "initial_target_empty": True,
            "host_frozen_before_author_build": frozen["executable_sha256"]}
        authors["m04/" + variant] = {"inputs": identity, "mod_build_id": "sha256:" + host.digest(identity),
            "payload_sha256": host.sha(payload), "manifest_sha256": host.sha(destination / "mod.toml"),
            "exports": exports}
    assert len({authors["m04/" + variant]["payload_sha256"] for variant in VARIANTS}) == 3
    audit = inputs / "mods/m04/audit"
    shutil.copytree(inputs / "mods/m02/lifecycle-audit/normal", audit)
    import tomllib
    fields = tomllib.loads((audit / "mod.toml").read_text())
    fields["compat"]["required_capabilities"].append("state.files.v1")
    fields["compat"]["host_api_min"] = "0.6.0"
    mod_manifest.manifest(audit, fields)
    log = host.build_log(logs, "host-test")
    text = log.read_text()
    assert all(name + " ... ok" in text for name in CHECKS), "M04 precise state tests did not run"
    for source in ("ci/scripts/runtime_state.py", "fixtures/state/driver.py"):
        destination = inputs / "fixture" / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source, destination)
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    mod_manifest.write(inputs / "fixture/m04-producer.json", {"status": "pass", "precise_unit_checks": CHECKS,
        "host_test_log_sha256": host.sha(log), "unit_binary_is_published_host": False,
        "host_executable_sha256": frozen["executable_sha256"], "authors": {variant: authors["m04/" + variant] for variant in VARIANTS}})


def self_check():
    assert len(REPORTS) == len(set(REPORTS)) == 6
    assert len(CHECKS) == len(set(CHECKS))
    assert VARIANTS == {"v1": "1", "compatible": "1", "v2": "2"}
    driver().self_check()
    print(json.dumps({"m04_state_handoff_self_check": "pass"}))


if __name__ == "__main__":
    {"produce": lambda: __import__("runtime_consumer").produce(),
     "matrix": lambda: driver().matrix(), "self-check": self_check}[sys.argv[1]]()
