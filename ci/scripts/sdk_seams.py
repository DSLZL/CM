"""G06 independent SDK authors and bounded acceptance assembly."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPORTS = ("sdk-abi-contract.json", "sdk-original-continuation.json", "sdk-async-lifetime.json",
    "sdk-slot-order.json", "sdk-stream-boundary.json", "sdk-command-ui-bridge.json", "sdk-independent-binaries.json")
VARIANTS = ("v1", "v2", "replacement")
CAPABILITIES = ("core.tool_continuation.v1", "core.response_stream_observe.v1", "cli.command.v1", "tui.command.v1")


def recipes(root):
    from linux_ci import TARGET, load_config
    cfg = load_config(root)
    target = Path(os.environ["CARGO_TARGET_DIR"])
    result = {}
    for owner in ("a", "b"):
        for variant in VARIANTS:
            label = "g06-sdk-" + owner + "-" + variant
            directory = target / label
            result[label] = {"cwd": str(root), "command": [sys.executable, "-B", "ci/scripts/sdk_seams.py", "build", label],
                "target_directory": str(directory), "binary": "cm_sdk_seams_" + owner,
                "artifact_path": str(directory / TARGET / cfg["build_profile"] / ("libcm_sdk_seams_" + owner + ".so"))}
    label = "g06-c-abi"
    result[label] = {"cwd": str(root),
        "command": ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "fixtures/sdk-seams/abi.c", "-ldl", "-o", str(target / label)],
        "target_directory": str(target / "g06-c-target"), "binary": label, "artifact_path": str(target / label)}
    return result


def author_inputs(root, label):
    import host
    if label == "g06-c-abi":
        paths = [root / "fixtures/sdk-seams/abi.c", *(root / "crates/cm-abi/include").rglob("*.h")]
    else:
        _, _, owner, variant = label.split("-")
        paths = [path for directory in (root / ("fixtures/mods/sdk-seams-" + owner), root / "crates/cm-sdk", root / "crates/cm-abi")
                 for path in directory.rglob("*") if path.suffix in (".rs", ".toml", ".lock")]
        paths.append(root / "fixtures/sdk-seams/fixture.rs")
    result = {"sources": host.manifest(root, [path for path in paths if path.is_file()]),
        "recipe": recipes(root)[label]}
    if label != "g06-c-abi":
        from retry import projection
        result["builder_sha256"] = projection((root / "ci/scripts/sdk_seams.py").read_text(), ("recipes", "build"))
        result["cargo_recipe_sha256"] = projection((root / "ci/scripts/linux_ci.py").read_text(), ("cargo_args",))
    return result


def build(root, logs, label):
    from linux_ci import TARGET, cargo_args, execute, load_config
    cfg = load_config(root)
    _, _, owner, variant = label.split("-")
    features = ["version2"] if variant == "v2" else ["replacement"] if variant == "replacement" else []
    unit = {"manifest": "fixtures/mods/sdk-seams-" + owner + "/Cargo.toml", "packages": ["cm-sdk-seams-" + owner],
        "features": features}
    target = Path(os.environ["CARGO_TARGET_DIR"])
    assert not target.exists(), "Independent author target must start empty"
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    execute(root, logs, label + "-shared-fmt", ["rustfmt", "--edition", "2024", "--check", "fixtures/sdk-seams/fixture.rs"], env)
    for phase in ("fmt", "clippy", "test", "build"):
        command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"] if phase == "fmt"
            else cargo_args(unit, phase, cfg, cfg["build_profile"]))
        if phase == "clippy":
            command += ["--all-targets", "--", "-D", "warnings"]
        execute(root, logs, label + "-" + phase, command, env)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", unit["manifest"]], cwd=root, env=env, text=True))
    assert sorted(item["name"] for item in metadata["packages"]) == ["cm-abi", "cm-sdk", "cm-sdk-seams-" + owner]
    assert (target / TARGET / cfg["build_profile"] / ("libcm_sdk_seams_" + owner + ".so")).is_file()


def manifest(owner, variant, payload):
    import host
    import mod_manifest
    name = "sdk-" + owner
    contributions = [
        {"id": "around", "kind": "tool_replacement" if variant == "replacement" else "tool_around",
         "capability": CAPABILITIES[0], "resource": "exec_command"},
        {"id": "stream", "kind": "response_stream", "capability": CAPABILITIES[1], "resource": CAPABILITIES[1]},
        {"id": "cli", "kind": "cli_command", "capability": CAPABILITIES[2], "resource": name + "__hello"},
        {"id": "tui", "kind": "tui_command", "capability": CAPABILITIES[3], "resource": name + "__notice"}]
    return {"format_version": 3, "id": name, "version": "0.2.0" if variant == "v2" else "0.1.0", "kind": "sdk",
        "binary": {"path": "payload.so", "size": payload.stat().st_size, "sha256": host.sha(payload),
            "target": "x86_64-unknown-linux-gnu", "entry": "cm_mod_entry_v2", "glibc_min": mod_manifest.native_glibc_min(payload), "cpu": "x86-64"},
        "compat": {"abi_major": 2, "abi_minor_min": 3, "abi_minor_max": 3,
            "host_api_min": "0.11.0", "required_capabilities": list(CAPABILITIES)},
        "dependencies": [], "conflicts": [], "contributions": contributions, "resources": [],
        "commands": {"version": 1, "entries": [
            {"id": "cli", "name": name + "__hello", "help": "Independent SDK greeting", "input": "optional", "section": "cli", "route": 3},
            {"id": "tui", "name": name + "__notice", "help": "Show one bounded SDK notice", "input": "optional", "section": "tui", "route": 4}]},
        "provenance": {"repository": "https://github.com/DSLZL/CM", "revision": os.environ["CM_SOURCE_SHA"],
            "license": "Apache-2.0", "release_notes": "Independent ABI 2.3 author; no installer build"}}


def prepare(root, inputs, package, frozen, logs, authors):
    import acceptance_cache
    import host
    import mod_manifest
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    receipts = {}
    for owner in ("a", "b"):
        for variant in VARIANTS:
            label = "g06-sdk-" + owner + "-" + variant
            destination = inputs / "mods/g06" / owner / variant
            destination.mkdir(parents=True)
            payload = acceptance_cache.run(root, logs, label, destination / "payload.so")
            mod_manifest.manifest(destination, manifest(owner, variant, payload))
            receipt = host.read(Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"]) / label / "build.json")
            exports = subprocess.check_output(["nm", "-D", "--defined-only", str(payload)], text=True)
            assert " cm_mod_entry_v2" in exports
            record = {"inputs": receipt["inputs"], "origin": receipt["origin"], "payload_sha256": host.sha(payload),
                "mod_build_id": "sha256:" + host.digest(receipt["inputs"]), "exports": exports,
                "host_frozen_before_author_build": frozen["executable_sha256"], "host_linked": False}
            authors["g06/" + owner + "/" + variant] = record
            receipts[owner + "/" + variant] = record
    probe = acceptance_cache.run(root, logs, "g06-c-abi", inputs / "probes/cm-sdk-c-abi")
    probe.chmod(0o755)
    for relative in ("ci/scripts/sdk_seams.py", "fixtures/sdk-seams/driver.py"):
        destination = inputs / "fixture" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    value = {"authors": receipts, "c_probe_sha256": host.sha(probe), "host_sha256": frozen["executable_sha256"],
        "scope": "exec_command continuation, metadata-only response ACK, finite CLI input and UI notice",
        "private_core_probe": "/inputs/probes/cm-concurrency-core", "private_tui_probe": "/inputs/probes/cm-review-tui"}
    host.write(inputs / "fixture/g06-producer.json", value)
    regression_log = logs / "m02-example-tool-normal-test.log"
    assert "cross_owner_probe_cancellation ... ok" in regression_log.read_text(), "Original shutdown regression did not run"
    regression = {"status": "pass", "scenarios": ["active-foreign-wrong-owner", "owned-request-cancelled",
        "foreign-cancel-with-owner-active-rejected", "unexpected-ok-rejected", "unexpected-stale-rejected", "unexpected-invalid-rejected"],
        "log": regression_log.name, "log_sha256": host.sha(regression_log),
        "source_sha256": host.sha(root / "fixtures/runtime-sdk/fixture.rs"), "origin": acceptance_cache.origin(),
        "boundary": "producer unit regression with exact Host service responses; consumer continuation race is separate"}
    host.write(inputs / "fixture/g06-shutdown-regression.json", regression)
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    return value


def reports(evidence, steps, audit):
    from runtime_cases import GROUPS
    import mod_manifest
    assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
    assert all(steps["g06-" + case]["status"] == "pass" for case in GROUPS["g06"])
    for name in REPORTS:
        value = mod_manifest.read(evidence / name)
        value.update(supported_scope="finite ABI 2.3 experimental seams", arbitrary_provider_rewrite=False,
            hot_unload=False, program_complete=False)
        mod_manifest.write(evidence / name, value)


def self_check():
    from record_run import require_hosted_linux
    require_hosted_linux()
    import runtime_cases
    assert len(REPORTS) == len(set(REPORTS)) == 7
    assert runtime_cases.function("cancel-before", "g06") == "case_cancel_before"
    assert runtime_cases.function("cli-help", "g06") == "case_cli_help"
    for case in runtime_cases.GROUPS["g06"]:
        mods, probes = runtime_cases.g06_native_dependencies(case)
        assert len(mods) == len(set(mods)) and len(probes) == len(set(probes)), case
    assert runtime_cases.g06_native_dependencies("tool-base") == ((), [])
    assert runtime_cases.g06_native_dependencies("cli-help") == (("inputs/mods/g06/a/v1/",), [])
    from retry import projection
    source = Path(__file__).read_text()
    entries = ("recipes", "build")
    before = projection(source, entries)
    assert before == projection(source.replace("arbitrary_provider_rewrite=False", "arbitrary_provider_rewrite=True"), entries)
    changed = source.replace('for phase in ("fmt", "clippy", "test", "build"):', 'for phase in ("fmt", "test", "build"):')
    assert changed != source and before != projection(changed, entries)


if __name__ == "__main__":
    from record_run import require_hosted_linux
    require_hosted_linux()
    root = Path(os.environ["CM_SOURCE_DIR"])
    if sys.argv[1] == "build":
        build(root, Path(os.environ["CM_CI_LOG_DIR"]), sys.argv[2])
    elif sys.argv[1] == "produce":
        import runtime_consumer
        runtime_consumer.produce()
    else:
        assert sys.argv[1] == "self-check"
        self_check()
