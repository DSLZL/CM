"""G03 independent C author build and seven strict runtime checkpoints."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

from linux_ci import TARGET

OWNER = "org.example.tool-concurrency"
CAPABILITY = "core.turn_tool_concurrency.v1"
CASES = ("value-flow", "steer", "leaf-bound", "lock-domains", "cancellation", "backend-scope", "plug-and-play")
REPORTS = tuple("concurrency-" + case + ".json" for case in CASES)
CORE_PROBES = (
    "thread_manager::tests::cm_concurrency_probe::cm_tool_concurrency_core",
    "session::turn_input::tests::cm_tool_concurrency_steer",
    "thread_manager::tests::cm_tool_concurrency_backend",
)


def driver():
    path = Path(__file__).resolve().parents[2] / "fixtures/tool-concurrency/driver.py"
    spec = importlib.util.spec_from_file_location("cm_concurrency_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(inputs, package, frozen, logs, authors, sdk):
    import host
    import mod_manifest
    from linux_ci import cargo_args, execute, load_config
    root = Path(os.environ["CM_SOURCE_DIR"])
    cfg = load_config(root)
    from acceptance_cache import run
    run(root, logs, "g03-local-backend-contract")
    contract_log = Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"]) / "g03-local-backend-contract.log"
    assert "1 passed; 0 failed" in contract_log.read_text(), "Local backend contract test did not execute"
    source = root / "examples/mods/tool-concurrency"
    unit = {"manifest": "examples/mods/tool-concurrency/Cargo.toml",
            "packages": ["cm-tool-concurrency"], "features": []}
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "g03-tool-concurrency"
    assert not target.exists(), "C author build requires an empty independent target"
    before = host.sha(source / "Cargo.lock")
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    for phase in ("fmt", "clippy", "test", "build"):
        command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"] if phase == "fmt"
                   else cargo_args(unit, phase, cfg, cfg["build_profile"]))
        if phase == "clippy":
            command += ["--all-targets", "--", "-D", "warnings"]
        execute(root, logs, "concurrency-author-" + phase, command, env)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", str(source / "Cargo.toml")], env=env, text=True))
    dependencies = {item["name"]: sorted(dep["name"] for dep in item["dependencies"]) for item in metadata["packages"]}
    assert dependencies["cm-sdk"] == ["cm-abi"] and dependencies["cm-abi"] == []
    assert dependencies["cm-tool-concurrency"] == ["cm-sdk", "serde", "serde_json"]
    assert not any(name.startswith(("codex-", "cm-host")) or name == "cm-runtime" for name in dependencies)
    assert host.sha(source / "Cargo.lock") == before
    destination = inputs / "mods/g03/tool-concurrency"
    destination.mkdir(parents=True)
    payload = destination / "payload.so"
    shutil.copyfile(target / TARGET / cfg["build_profile"] / "libcm_tool_concurrency.so", payload)
    manifest = tomllib.loads((source / "mod.toml").read_text())
    manifest["binary"].update(size=payload.stat().st_size, sha256=host.sha(payload),
        glibc_min=mod_manifest.native_glibc_min(payload))
    manifest["provenance"]["revision"] = os.environ["CM_SOURCE_SHA"]
    mod_manifest.manifest(destination, manifest)
    archive = destination.with_suffix(".cmod")
    mod_manifest.zip_package(destination, archive)
    exports = subprocess.check_output(["nm", "-D", "--defined-only", str(payload)], text=True)
    assert re.search(r"\bT cm_mod_entry_v2$", exports, re.MULTILINE)
    preflight = Path(os.environ["RUNNER_TEMP"]) / "concurrency-author-plan"
    shutil.copytree(destination, preflight / "mods" / OWNER)
    mod_manifest.write_toml(preflight / "cm-runtime.toml", {"format_version": 2, "enabled": [OWNER]})
    mod_manifest.metadata(package / "bin/codex", preflight, ["plan"],
        evidence=logs / "concurrency-author-manifest.json")
    identity = {"sources": host.manifest(root, [*source.rglob("*"),
        *(root / "crates/cm-sdk").rglob("*"), *(root / "crates/cm-abi").rglob("*")]),
        "lock_sha256": before, "dependencies": dependencies, "toolchain": cfg["rust_toolchain"],
        "target": TARGET, "profile": cfg["build_profile"], "flags": frozen["host_identity"]["inputs"]["flags"],
        "host_frozen_before_author_build": frozen["executable_sha256"], "initial_target_empty": True}
    author = {"status": "pass", "inputs": identity, "mod_build_id": "sha256:" + host.digest(identity),
        "payload_sha256": host.sha(payload), "manifest_sha256": host.sha(destination / "mod.toml"),
        "archive_sha256": host.sha(archive), "exports": exports}
    authors["g03/tool-concurrency"] = author
    # The already-built M02 probe includes the new private cases. Never ask Cargo for it twice.
    native = sdk["native_scope_probe"]
    binary = Path(native["command"][0])
    assert host.sha(binary) == native["binary_sha256"]
    probe = inputs / "probes/cm-concurrency-core"
    probe.parent.mkdir(exist_ok=True)
    shutil.copy2(binary, probe)
    probe.chmod(0o755)
    backend_probe = inputs / "probes/cm-concurrency-backend"
    shutil.copy2(inputs / "probes/cm-review-tui", backend_probe)
    backend_probe.chmod(0o755)
    for relative in ("ci/scripts/tool_concurrency.py", "fixtures/tool-concurrency/driver.py"):
        path = inputs / "fixture" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, path)
    helper = package / "bin/codex-code-mode-host"
    models = host.read(root / host.HOST / "codex-rs/models-manager/models.json")
    for model in models["models"]:
        if model["slug"] == "gpt-5.4":
            model["tool_mode"] = None
    host.write(inputs / "fixture/concurrency-models.json", models)
    result = {"status": "pass", "author": author, "cases": list(CASES),
        "local_backend_contract": {"status": "pass", "check": "g03-local-backend-contract"},
        "probe": {"path": "/inputs/probes/cm-concurrency-core", "sha256": host.sha(probe),
            "source_sha256": native["native_fixture_source_manifest_sha256"],
            "names": list(CORE_PROBES), "test_environment": native["test_environment"],
            "separate_from_cli": True, "compilation_reused_from_m02": True},
        "backend_probe": {"path": "/inputs/probes/cm-concurrency-backend", "sha256": host.sha(backend_probe),
            "names": ["app_server_session::cm_concurrency_backend_probe::cm_tool_concurrency_backend_rejection"],
            "test_environment": native["test_environment"], "separate_from_cli": True,
            "compilation_reused_from_review": True},
        "code_mode_helper": {"path": "/inputs/host/bin/codex-code-mode-host", "sha256": host.sha(helper),
            "transport": "grpc+stdio://", "purpose": "normal Code Mode business cells only"},
        "host_rebuilt_after_freeze": False, "original_a": host.read(inputs / "fixture/g02a-producer.json")["author_origin"],
        "parent_abc_handoff": {"payload": "mods/g03/tool-concurrency/payload.so",
            "archive": "mods/g03/tool-concurrency.cmod", "author": author, "parent_acceptance": "not_run"}}
    host.write(inputs / "fixture/concurrency-producer.json", result)
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    host.verify_sources(root, logs)
    return result


def produce():
    import runtime_consumer
    runtime_consumer.produce()


def self_check():
    from retry import Checkpoints, PHASES, projection
    import tempfile
    import runtime_consumer
    assert list(CASES) == [label.removeprefix("concurrency-") for label in PHASES if label.startswith("concurrency-")]
    root = Path(__file__).resolve().parents[2]
    text = (root / "fixtures/tool-concurrency/driver.py").read_text()
    names = tuple(case.replace("-", "_") for case in CASES)
    original = {name: projection(text, (name,)) for name in names}
    changed = text.replace('report("steer",', 'report("steer-changed",', 1)
    assert projection(changed, ("steer",)) != original["steer"]
    assert all(projection(changed, (name,)) == original[name] for name in names if name != "steer")
    manifest = tomllib.loads((root / "examples/mods/tool-concurrency/mod.toml").read_text())
    assert manifest["id"] == OWNER and manifest["compat"]["required_capabilities"] == [CAPABILITY]
    runtime_consumer.check_code_mode_classification()
    checkpoint = object.__new__(Checkpoints)
    checkpoint.reports = {"concurrency-" + case: ["concurrency-" + case + ".json"] for case in CASES}
    for case in CASES:
        label = "concurrency-" + case
        assert checkpoint.owns(label, Path("concurrency") / case / "run/native.jsonl")
        assert checkpoint.owns(label, Path(label + ".json"))
        assert all(not checkpoint.owns(label, Path("concurrency") / other / "run/native.jsonl")
            for other in CASES if other != case)
        assert not checkpoint.owns("consumer-matrix", Path("concurrency") / case / "run/native.jsonl")
    with tempfile.TemporaryDirectory() as temporary:
        fixture = Path(temporary)
        producer = {"concurrency": {}}
        executions = []
        for key, filename in (("probe", "cm-concurrency-core"), ("backend_probe", "cm-concurrency-backend")):
            path = "/inputs/probes/" + filename
            binary = fixture / "rootfs" / path.lstrip("/")
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(filename.encode())
            name = CORE_PROBES[0] if key == "probe" else "app_server_session::cm_concurrency_backend_probe::cm_tool_concurrency_backend_rejection"
            producer["concurrency"][key] = {"path": path, "sha256": runtime_consumer.sha(binary),
                "separate_from_cli": True, "names": [name]}
            executions.append('1 execve("' + path + '", ["' + path + '", "--ignored", "--exact", "' + name + '"], 0x0) = 0')
        runtime_consumer.write(fixture / "rootfs/inputs/producer.json", producer)
        assert len(runtime_consumer.bind_concurrency_probes(executions, fixture)) == 2
        for invalid in (executions[:1] + [executions[1].replace("--exact", "--list")],
                        [executions[0].replace(CORE_PROBES[0], "unbound-test"), executions[1]]):
            try:
                runtime_consumer.bind_concurrency_probes(invalid, fixture)
            except AssertionError:
                pass
            else:
                raise AssertionError("Unbound probe test accepted")
        binary.write_bytes(b"changed probe")
        try:
            runtime_consumer.bind_concurrency_probes(executions, fixture)
        except AssertionError:
            pass
        else:
            raise AssertionError("Unsealed probe accepted")


if __name__ == "__main__":
    {"produce": produce, "self-check": self_check}[sys.argv[1]]()
