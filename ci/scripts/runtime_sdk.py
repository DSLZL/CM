#!/usr/bin/env python3
"""M02 native author builds and runtime-only consumer entry point."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

TARGET = "x86_64-unknown-linux-gnu"
REPORTS = ("runtime-sdk-dependencies.json", "runtime-adapter-wiring.json", "runtime-registry-scopes.json",
           "runtime-name-collisions.json", "opaque-handle-scopes.json", "async-abi-cancellation.json",
           "restart-and-library-lifetime.json")
NEGATIVE = ("short-tail", "null-runtime", "runtime-short", "runtime-minor", "runtime-reserved",
            "null-dispatch", "null-cancel", "null-release", "null-array", "stride", "count", "reserved",
            "undeclared", "reserved-name", "foreign-owner", "duplicate-name", "duplicate-id",
            "invalid-utf8", "duplicate-route", "descriptor-short", "too-many")
CAPABILITIES = ("runtime.lifecycle.v1", "runtime.tool.v1", "runtime.context_section.v1")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def fields(owner, payload):
    import mod_manifest
    lifecycle = owner == "lifecycle-audit"
    contributions = ([{"id": "audit", "kind": "lifecycle", "capability": CAPABILITIES[0],
                       "resource": owner + "__events"}] if lifecycle else [
        {"id": "echo", "kind": "tool", "capability": CAPABILITIES[1], "resource": owner + "__echo"},
        {"id": "context", "kind": "context_section", "capability": CAPABILITIES[2], "resource": owner + "__context"}])
    old = {"format_version": 2, "id": owner, "version": "0.1.0", "payload": "payload.so",
        "payload_size": payload.stat().st_size, "payload_sha256": sha(payload), "target": TARGET,
        "abi_major": 2, "abi_minor": 2, "required_capabilities": sorted({item["capability"] for item in contributions}),
        "dependencies": [], "contributions": contributions}
    mod_manifest.manifest(payload.parent, old)
    value = mod_manifest.convert(payload.parent)
    value["compat"]["host_api_min"] = "0.5.0"
    value["provenance"]["revision"] = os.environ["CM_SOURCE_SHA"]
    mod_manifest.manifest(payload.parent, value)
    return value


def native_probe(root, logs, inputs, package, frozen):
    import host
    import mod_manifest
    from linux_ci import execute, load_config
    cfg = load_config(root)
    probe = Path(os.environ["RUNNER_TEMP"]) / "cm-m02-native-probe-source"
    shutil.copytree(root / host.HOST, probe, ignore=shutil.ignore_patterns(".git", "target"))
    core = probe / "codex-rs/core"
    test_source = root / "fixtures/runtime-sdk/host_scopes.rs"
    shutil.copyfile(test_source, core / "src/cm_runtime_native.rs")
    with (core / "src/thread_manager_tests.rs").open("a") as stream:
        stream.write('\ninclude!("cm_runtime_native.rs");\n')
    manifest = core / "Cargo.toml"
    text = manifest.read_text()
    assert text.count("[dev-dependencies]\n") == 1
    manifest.write_text(text.replace("[dev-dependencies]\n",
        '[dev-dependencies]\ncm-host-adapter = { path = "../cm-host-adapter" }\n', 1))
    lock = probe / "codex-rs/Cargo.lock"
    text = lock.read_text()
    pattern = r'(\[\[package\]\]\nname = "codex-core"\n.*?dependencies = \[\n)(.*?)(\n\])'
    match = re.search(pattern, text, re.DOTALL)
    assert match and '"cm-host-adapter"' not in match[2]
    dependencies = sorted([*match[2].splitlines(), ' "cm-host-adapter",'])
    lock.write_text(text[:match.start(2)] + "\n".join(dependencies) + text[match.end(2):])
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "m02-native-probe"
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    command = ["cargo", "test", "--locked", "--manifest-path", str(probe / "codex-rs/Cargo.toml"),
        "--target", TARGET, "--profile", cfg["test_profile"], "--package", "codex-core", "--lib",
        "--no-run", "--message-format=json"]
    execute(root, logs, "m02-native-probe-build", command, env)
    artifacts = []
    for line in (logs / "m02-native-probe-build.log").read_text().splitlines():
        if not line.startswith("{"):
            continue
        event = json.loads(line)
        if event.get("reason") == "compiler-artifact" and event.get("executable") and event.get("profile", {}).get("test"):
            artifacts.append(event["executable"])
    assert len(set(artifacts)) == 1, artifacts
    binary = Path(artifacts[0])
    home = Path(os.environ["RUNNER_TEMP"]) / "cm-m02-native-profile"
    for owner in ("lifecycle-audit", "example-tool"):
        destination = home / "mods" / owner
        shutil.copytree(inputs / "mods/m02" / owner / "normal", destination)
    mod_manifest.selection(home, ["lifecycle-audit", "example-tool"])
    report = inputs / "fixture/m02-native-scopes.json"
    events = inputs / "fixture/m02-native-events.jsonl"
    trace = inputs / "fixture/m02-native-trace.jsonl"
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR") if key in os.environ}
    env.update(CODEX_HOME=str(home), HOME=str(home / "home"), CM_RUNTIME_PROBE_PROFILE=str(home),
        CM_RUNTIME_PROBE_REPORT=str(report), CM_RUNTIME_EVENTS=str(events), CM_NATIVE_TRACE=str(trace),
        CM_RUNTIME_MODE="handles")
    run = [str(binary), "--ignored", "--exact", "thread_manager::tests::cm_runtime_native_scopes", "--nocapture"]
    execute(root, logs, "m02-native-probe", run, env)
    evidence = read(report)
    assert evidence["status"] == "pass"
    rows = [json.loads(line) for line in events.read_text().splitlines()]
    starts = [row for row in rows if row["event"] == "dispatch" and row["kind"] == 1]
    assert len(starts) == 3, starts
    parent, child, explicit = starts
    assert all(row["thread_before"] == 0 for row in starts)
    assert parent["mod_scope"] == child["mod_scope"] != explicit["mod_scope"]
    assert explicit["mod_before"] == 0 and child["mod_before"] > parent["mod_before"]
    assert len({row["thread_scope"] for row in starts}) == 3
    for row in (parent, child):
        before = rows[:rows.index(row)]
        assert any(item["owner"] == "host-builtin" and item["thread"] == row["thread"] for item in before)
    assert sum(row["event"] == "userdata-release" for row in rows) == 2
    collisions = [json.loads(line) for line in trace.read_text().splitlines()]
    collisions = [row for row in collisions if row["event"] == "runtime-registration-failed"]
    assert {row["detail"]["resource"] for row in collisions} >= {"example-tool__echo", "example-tool__context"}, collisions
    host.verify_sources(root, logs)
    assert sha(package / "bin/codex") == frozen["executable_sha256"]
    result = {"status": "pass", "scope_report": evidence, "events": "m02-native-events.jsonl",
        "trace": "m02-native-trace.jsonl", "binary_sha256": sha(binary), "command": run,
        "fixture_source_sha256": sha(test_source), "host_build_id": frozen["host_identity"]["host_build_id"],
        "cli_executable_sha256": frozen["executable_sha256"],
        "native_fixture_source_manifest_sha256": host.manifest_digest(host.manifest(probe)),
        "independent_registry_state_verified": True, "inherited_mod_state_shared": True,
        "new_thread_state_verified": True, "builtin_before_mod": True}
    write(inputs / "fixture/m02-native-probe.json", result)
    return result


def prepare(inputs, package, authors):
    import host
    from linux_ci import cargo_args, execute, load_config
    root = Path(os.environ["CM_SOURCE_DIR"])
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    cfg = load_config(root)
    frozen = read(Path(os.environ["CM_CI_ARTIFACT_DIR"]) / "evidence/host-baseline-build.json")
    assert sha(package / "bin/codex") == frozen["executable_sha256"]
    dependencies = {}
    for owner in ("lifecycle-audit", "example-tool"):
        unit = {"manifest": "fixtures/mods/" + owner + "/Cargo.toml",
            "packages": ["cm-" + owner + "-fixture"], "features": []}
        lock = root / Path(unit["manifest"]).with_name("Cargo.lock")
        before = sha(lock)
        for variant in (("normal",) if owner == "lifecycle-audit" else ("normal", *NEGATIVE)):
            target = Path(os.environ["CARGO_TARGET_DIR"]) / ("m02-" + owner + "-" + variant)
            assert not target.exists(), "Mod author target must start empty"
            env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CM_RUNTIME_VARIANT": variant}
            current = {**unit, "features": [] if variant == "normal" else ["negative"]}
            for phase in (("fmt", "clippy", "test", "build") if variant == "normal" else ("build",)):
                command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"] if phase == "fmt"
                           else cargo_args(current, phase, cfg, cfg["build_profile"]))
                if phase == "clippy":
                    command += ["--all-targets", "--", "-D", "warnings"]
                execute(root, logs, "m02-" + owner + "-" + variant + "-" + phase, command, env)
            metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
                "--manifest-path", str(root / unit["manifest"])], env=env, text=True))
            names = sorted(item["name"] for item in metadata["packages"])
            assert names == sorted(["cm-abi", "cm-sdk", "cm-" + owner + "-fixture"])
            dependencies[owner] = names
            assert sha(lock) == before
            destination = inputs / "mods/m02" / owner / variant
            destination.mkdir(parents=True)
            shutil.copyfile(target / TARGET / cfg["build_profile"] / ("libcm_" + owner.replace("-", "_") + "_fixture.so"),
                destination / "payload.so")
            fields(owner, destination / "payload.so")
            identity = {"sources": host.manifest(root, [root / unit["manifest"], lock,
                root / ("fixtures/mods/" + owner + "/src/lib.rs"), root / "fixtures/runtime-sdk/fixture.rs",
                *[path for path in (root / "crates/cm-sdk").rglob("*") if path.is_file()],
                *[path for path in (root / "crates/cm-abi").rglob("*") if path.is_file()]]),
                "variant": variant, "dependencies": names, "lock_sha256": before,
                "toolchain": frozen["host_identity"]["inputs"]["toolchain"],
                "flags": frozen["host_identity"]["inputs"]["flags"], "profile": cfg["build_profile"], "target": TARGET,
                "host_frozen_before_author_build": frozen["executable_sha256"], "initial_target_empty": True}
            exports = subprocess.check_output(["nm", "-D", "--defined-only", str(destination / "payload.so")], text=True)
            assert re.search(r"\bT cm_mod_entry_v2$", exports, re.MULTILINE), exports
            authors["m02/" + owner + "/" + variant] = {"inputs": identity,
                "mod_build_id": "sha256:" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
                "payload_sha256": sha(destination / "payload.so"), "exports": exports}
    binary = Path(os.environ["RUNNER_TEMP"]) / "cm-m02-layout"
    execute(root, logs, "m02-c-layout-build", ["cc", "-std=c11", str(root / "fixtures/runtime-sdk/layout.c"), "-o", str(binary)])
    execute(root, logs, "m02-c-layout", [str(binary)])
    layout = read(logs / "m02-c-layout.log")
    assert layout["v22_all_sizes_alignments_offsets"] and layout["unchanged_v21_prefix"]
    for source in ("ci/scripts/runtime_sdk.py", "fixtures/runtime-sdk/driver.py"):
        destination = inputs / "fixture" / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source, destination)
    host_inventory = read(package / "dependency-inventory.json")["packages"]
    assert not any(item["name"] in ("cm-lifecycle-audit-fixture", "cm-example-tool-fixture") for item in host_inventory)
    sdk = next(item for item in host_inventory if item["name"] == "cm-sdk")
    adapter = next(item for item in host_inventory if item["name"] == "cm-host-adapter")
    assert sdk and adapter
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", str(root / host.HOST / "codex-rs/Cargo.toml")], text=True))
    packages = {item["name"]: item for item in metadata["packages"] if item["id"] in metadata["workspace_members"]}
    edges = {name: sorted({item["name"] for item in packages[name]["dependencies"]})
        for name in ("cm-abi", "cm-sdk", "cm-runtime", "cm-host-adapter", "codex-core", "codex-app-server")}
    assert edges["cm-abi"] == [] and edges["cm-sdk"] == ["cm-abi"]
    assert "cm-host-adapter" not in edges["codex-core"] and "cm-runtime" in edges["codex-core"]
    assert "cm-host-adapter" in edges["codex-app-server"]
    assert not any(name in packages for name in ("cm-lifecycle-audit-fixture", "cm-example-tool-fixture"))
    assert not set(edges["cm-host-adapter"]) & {"codex-core", "codex-core-api", "codex-tui", "cm-sdk"}
    wiring = (root / host.HOST / "codex-rs/app-server/src/extensions.rs").read_text()
    assert wiring.count("cm_host_adapter::append(&mut builder);") == 1
    assert wiring.index("cm_host_adapter::append(&mut builder);") < wiring.index("Arc::new(builder.build())")
    assert "linux_x64_layout_and_unchanged_prefixes ... ok" in host.build_log(logs, "host-test").read_text()
    probe = native_probe(root, logs, inputs, package, frozen)
    result = {"status": "pass", "independent_mod_dependencies": dependencies, "c_layout": layout,
        "host_sdk_package": sdk, "host_adapter_package": adapter, "host_links_concrete_mods": False,
        "workspace_dependency_edges": edges, "composition_root_sha256": sha(root / host.HOST / "codex-rs/app-server/src/extensions.rs"),
        "native_scope_probe": probe, "negative_variants": list(NEGATIVE),
        "current_host_test_log_sha256": sha(host.build_log(logs, "host-test"))}
    write(inputs / "fixture/m02-producer.json", result)
    return result


def self_check():
    assert len(REPORTS) == len(set(REPORTS)) == 7
    assert len(NEGATIVE) == len(set(NEGATIVE))
    from linux_ci import build_commands
    commands = build_commands({"id": "host", "manifest": "Cargo.toml", "packages": ["codex-cli"]},
        {"build_profile": "dev-small", "test_profile": "dev-small", "clippy_profile": "dev-small"})
    for phase in ("fmt", "clippy"):
        for package in ("codex-core", "codex-app-server"):
            assert any(commands[phase][index:index + 2] == ["--package", package]
                for index in range(len(commands[phase]) - 1))
    assert "codex-core" not in commands["test"] and "codex-app-server" not in commands["test"]
    root = Path(__file__).resolve().parents[2]
    pin = read(root / "adapters/codex-e4568a3/source.json")
    identity_test = (root / "crates/cm/src/host_identity.rs").read_text()
    stage = re.search(r'assert_eq!\(identity\["stage"\], ("[^"]*")\);', identity_test)
    capabilities = re.search(r'identity\["capabilities"\],\s*serde_json::json!\((\[.*?\])\)', identity_test, re.DOTALL)
    assert stage and json.loads(stage[1]) == pin["stage"], "Embedded identity test stage differs from the pinned Host contract"
    assert capabilities and json.loads(capabilities[1]) == pin["capabilities"], "Embedded identity test capabilities differ from the pinned Host contract"
    directory = root / "fixtures/runtime-sdk"
    import importlib.util
    spec = importlib.util.spec_from_file_location("cm_m02_driver", directory / "driver.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.self_check()
    print(json.dumps({"m02_runtime_handoff_self_check": "pass"}))


def produce():
    import runtime_consumer
    runtime_consumer.produce()


def matrix():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fixtures/runtime-sdk"))
    import driver
    driver.matrix()


if __name__ == "__main__":
    {"produce": produce, "matrix": matrix, "self-check": self_check}[sys.argv[1]]()
