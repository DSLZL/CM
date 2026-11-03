"""Cache linked acceptance executables and build checks, never runtime results."""
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

import host
from linux_ci import TARGET, cargo_args, execute, load_config

PROTOCOL = 2
LEGACY_PROTOCOL_SHA256 = "4940eeb1711c2de08990dd7e3f2a8b96a350194780f1a9c2c07d3dfe6dd83361"


def recipes(root):
    cfg = load_config(root)
    unit = cfg["units"][0]
    core = ["cargo", "test", "--locked", "--manifest-path", unit["manifest"],
            "--target", TARGET, "--profile", cfg["test_profile"], "-p", "codex-core", "--lib",
            "--no-run", "--message-format=json"]
    runtime = {**unit, "packages": ["cm-runtime"]}
    target = Path(os.environ["CARGO_TARGET_DIR"])
    specs = {
        "host-core-baseline-build": (root, core, target / "host", "codex_core"),
        "mod-adapter-clippy": (root, cargo_args({**unit, "packages": ["codex-core", "codex-exec"]},
            "clippy", cfg, cfg["clippy_profile"]) + ["--lib", "--", "-D", "warnings"], target / "host", None),
        "mod-host-abi-probe-build": (root, cargo_args(runtime, "build", cfg, cfg["build_profile"]) +
            ["--example", "native_probe", "--message-format=json"], target / "host", "native_probe"),
        "mod-pinned-snapshot-build": (root, cargo_args(runtime, "test", cfg, cfg["test_profile"]) +
            ["--lib", "--no-run", "--message-format=json"], target / "host", "cm_runtime"),
    }
    if cfg["task_id"] in ("CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06"):
        probe = Path(os.environ["RUNNER_TEMP"]) / "cm-m02-native-probe-source"
        specs["m02-native-probe-build"] = (probe, ["cargo", "test", "--locked", "--manifest-path",
            "codex-rs/Cargo.toml", "--target", TARGET, "--profile", cfg["test_profile"],
            "--package", "codex-core", "--lib", "--no-run", "--message-format=json"],
            target / "m02-native-probe", "codex_core")
    if cfg["task_id"] in ("CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06"):
        probe = Path(os.environ["RUNNER_TEMP"]) / "cm-review-tui-probe-source"
        specs["review-tui-probe-build"] = (probe, ["cargo", "test", "--locked", "--manifest-path",
            "codex-rs/Cargo.toml", "--target", TARGET, "--profile", cfg["test_profile"],
            "-p", "codex-tui", "--lib", "--no-run", "--message-format=json"],
            target / "review-tui-probe", "codex_tui")
    if cfg["task_id"] in ("CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06"):
        specs["g03-local-backend-contract"] = (root, cargo_args({**unit, "packages": ["codex-app-server"]},
            "test", cfg, cfg["test_profile"]) + ["--lib", "cm_tool_concurrency_origin_tests::", "--", "--nocapture"],
            target / "host", None)
    result = {label: {"cwd": str(cwd), "command": command, "target_directory": str(target), "binary": binary}
              for label, (cwd, command, target, binary) in specs.items()}
    if cfg["task_id"] == "CM-G06":
        import sdk_seams
        result.update(sdk_seams.recipes(root))
    return result


def identify(root, logs):
    specs = recipes(root)
    selected = json.loads(os.environ.get("CM_PROBE_BUILD_TARGETS", "[]"))
    if selected:
        specs = {label: specs[label] for label in selected}
    legacy = {"schema_version": 1, "host": host.read(logs / "host-identity.json"),
              "recipes": specs, "cache_protocol_sha256": LEGACY_PROTOCOL_SHA256}
    if "m02-native-probe-build" in specs:
        from runtime_sdk import native_probe_source
        probe = native_probe_source(root)
        legacy["instrumented_source_sha256"] = host.manifest_digest(host.manifest(probe))
    if "review-tui-probe-build" in specs:
        from review_before_send import native_probe_source
        legacy["review_instrumented_source_sha256"] = host.manifest_digest(host.manifest(native_probe_source(root)))
    compatibility = host.read(logs / "build-identity.json")["compatibility"]
    compiler = {"target": compatibility["target"],
        "toolchain": {"declared": load_config(root)["rust_toolchain"],
                      "rustc": compatibility["rustc"], "cargo": compatibility["cargo"]},
        "profiles": compatibility["requested_profiles"],
        "flags": {**compatibility["flags"], **{key: os.environ.get(key) for key in ("CARGO_INCREMENTAL", "RUSTC_WRAPPER")}},
        "cargo_configuration": compatibility["identity_files"],
        "native_tools": {name: {key: value for key, value in tool.items() if key != "path"}
                         for name, tool in compatibility["native"].items()},
        "native": host.read(root / host.ADAPTER / "inputs/native.json")}
    if load_config(root)["task_id"] == "CM-G06":
        import sdk_seams
        legacy["sdk_author_inputs"] = {label: sdk_seams.author_inputs(root, label)
                                       for label in specs if label.startswith("g06-")}
        legacy["sdk_compiler"] = {key: value for key, value in compiler.items() if key != "cargo_configuration"}
    inputs = {"schema_version": PROTOCOL, "recipes": specs, "legacy": legacy,
              "targets": target_inputs(legacy, compiler)}
    host.write(logs / "acceptance-build-inputs.json", inputs)
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write("legacy_acceptance_key=cm-acceptance-build-v1-" + TARGET + "-" + host.digest(legacy) + "\n")
        for label, value in inputs["targets"].items():
            stream.write(label.replace("-", "_") + "=cm-acceptance-build-v2-" + TARGET + "-" + label + "-" + host.digest(value) + "\n")


def target_inputs(legacy, compiler=None):
    private_sources = {"m02-native-probe-build": "instrumented_source_sha256",
                       "review-tui-probe-build": "review_instrumented_source_sha256"}
    changed_compiler = compiler is not None and compiler != {
        key: legacy["host"]["inputs"][key] for key in compiler}
    return {label: {"schema_version": PROTOCOL, "host": legacy["host"], "recipes": {label: recipe},
                   **({"instrumented_source_sha256": legacy[private_sources[label]],
                       **({"compiler": compiler} if changed_compiler else {})} if label in private_sources else {})}
            for label, recipe in legacy["recipes"].items() if not label.startswith("g06-")} | {
        label: {"schema_version": PROTOCOL, "recipes": {label: recipe},
                "author": legacy["sdk_author_inputs"][label], "compiler": legacy["sdk_compiler"]}
        for label, recipe in legacy["recipes"].items() if label.startswith("g06-")}


def origin():
    return {key: os.environ[key] for key in ("CM_SOURCE_REPOSITORY", "CM_SOURCE_SHA", "GITHUB_REPOSITORY",
            "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")}


def verify(cache, inputs):
    assert not cache.is_symlink() and not (cache / "build.json").is_symlink()
    receipt = host.read(cache / "build.json")
    files = [entry for entry in host.manifest(cache) if entry["path"] != "build.json"]
    expected = {label + ".log" for label in inputs["recipes"]}
    expected.update(label + ".bin" for label, recipe in inputs["recipes"].items() if recipe["binary"])
    assert receipt["inputs"] == inputs and receipt["files"] == files, "Acceptance cache inputs or bytes changed"
    assert {entry["path"] for entry in files} == expected and all(entry["mode"] != "120000" for entry in files)
    producer = receipt["origin"]
    assert producer["CM_SOURCE_REPOSITORY"] == os.environ["CM_SOURCE_REPOSITORY"]
    assert producer["GITHUB_REPOSITORY"] == os.environ["GITHUB_REPOSITORY"]
    assert all(re.fullmatch(r"[0-9a-f]{40}", producer[key]) for key in ("CM_SOURCE_SHA", "GITHUB_WORKFLOW_SHA"))
    assert all(re.fullmatch(r"[1-9][0-9]*", producer[key]) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    assert producer["GITHUB_JOB"] and set(receipt["checks"]) == set(inputs["recipes"])
    for label, recipe in inputs["recipes"].items():
        assert receipt["checks"][label]["recipe"] == recipe and receipt["checks"][label]["return_code"] == 0
    return receipt


def restore(root, logs):
    cache = Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"])
    assert not cache.is_symlink()
    inputs = host.read(logs / "acceptance-build-inputs.json")
    legacy = verify(cache / "legacy", inputs["legacy"]) if (cache / "legacy/build.json").is_file() else None
    state = {"schema_version": PROTOCOL, "targets": {}, "checks": {},
             "note": "Compilation and checks have independent receipts; runtime checkpoints are separate"}
    reused = logs / "reused-acceptance-build"
    reused.mkdir(exist_ok=True)
    for label, value in inputs["targets"].items():
        directory = cache / label
        migrated = False
        if not directory.exists() and legacy and value == target_inputs(inputs["legacy"])[label]:
            directory.mkdir(parents=True)
            for suffix in (".log", *((".bin",) if value["recipes"][label]["binary"] else ())):
                shutil.copy2(cache / "legacy" / (label + suffix), directory / (label + suffix))
            host.write(directory / "build.json", {"inputs": value, "origin": legacy["origin"],
                "checks": {label: legacy["checks"][label]}, "files": host.manifest(directory)})
            migrated = True
        receipt = verify(directory, value) if directory.exists() else None
        state["targets"][label] = {"status": "hit" if receipt else "miss", "migrated": migrated,
            "origin": receipt["origin"] if receipt else None, "reason": "verified_target" if receipt else "no_target_cache"}
        if receipt:
            state["checks"].update(receipt["checks"])
            shutil.copyfile(directory / (label + ".log"), reused / (label + ".log"))
            host.write(reused / (label + ".json"), receipt)
        print("CM acceptance build cache:", label, state["targets"][label]["status"], flush=True)
    hits = sum(item["status"] == "hit" for item in state["targets"].values())
    state["status"] = "hit" if hits == len(inputs["targets"]) else "partial" if hits else "miss"
    host.write(logs / "acceptance-build-cache.json", state)


def run(root, logs, label, destination=None):
    inputs = host.read(logs / "acceptance-build-inputs.json")
    recipe = recipes(root)[label]
    assert recipe == inputs["recipes"][label], "Acceptance build command changed after sealing"
    value = inputs["targets"][label]
    if "instrumented_source_sha256" in value:
        assert host.manifest_digest(host.manifest(Path(recipe["cwd"]))) == value["instrumented_source_sha256"]
    state = host.read(logs / "acceptance-build-cache.json")
    cache = Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"]) / label
    binary = cache / (label + ".bin")
    if (cache / "build.json").is_file():
        started = time.monotonic()
        original = verify(cache, value)
        reused = logs / "reused-acceptance-build"
        reused.mkdir(exist_ok=True)
        shutil.copyfile(cache / (label + ".log"), reused / (label + ".log"))
        host.write(reused / (label + ".json"), original)
        print("CM CI: reuse", label, "from run", original["origin"]["GITHUB_RUN_ID"], flush=True)
        event = {"phase": label, "command": recipe["command"], "cwd": recipe["cwd"], "return_code": 0,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "log": "reused-acceptance-build/" + label + ".log", "compilation": "reused", "origin": original["origin"]}
        with (logs / "phase-results.jsonl").open("a") as stream:
            stream.write(json.dumps(event) + "\n")
    else:
        cache.mkdir(parents=True, exist_ok=True)
        execute(Path(recipe["cwd"]), logs, label, recipe["command"],
                {**os.environ, "CARGO_TARGET_DIR": recipe["target_directory"]})
        shutil.copyfile(logs / (label + ".log"), cache / (label + ".log"))
        if recipe["binary"]:
            if "artifact_path" in recipe:
                shutil.copy2(recipe["artifact_path"], binary)
            else:
                artifacts = [event["executable"] for line in (logs / (label + ".log")).read_text().splitlines()
                    if line.startswith("{") and (event := json.loads(line)).get("reason") == "compiler-artifact"
                    and event.get("executable") and event["target"]["name"] == recipe["binary"]]
                assert len(set(artifacts)) == 1, artifacts
                shutil.copy2(artifacts[0], binary)
        state["checks"][label] = {"recipe": recipe, "return_code": 0}
        host.write(cache / "build.json", {"inputs": value, "origin": origin(),
            "checks": {label: state["checks"][label]},
            "files": [entry for entry in host.manifest(cache) if entry["path"] != "build.json"]})
        verify(cache, value)
        host.write(logs / "acceptance-build-cache.json", state)
    if destination is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, destination)
        return destination
    return binary if recipe["binary"] else None


def save(root, logs):
    cache = Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"])
    inputs = host.read(logs / "acceptance-build-inputs.json")
    receipts = {}
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for label, value in inputs["targets"].items():
            complete = (cache / label / "build.json").is_file()
            if complete:
                receipts[label] = verify(cache / label, value)
            output.write("save_" + label.replace("-", "_") + "=" + str(complete).lower() + "\n")
    host.write(logs / "acceptance-build-receipt.json", {"schema_version": PROTOCOL, "targets": receipts,
        "incomplete": sorted(set(inputs["targets"]) - receipts.keys())})


def self_check():
    import tempfile
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as directory:
        cache = Path(directory) / "cache"
        legacy_cache = cache / "legacy"
        legacy_cache.mkdir(parents=True)
        logs = Path(directory) / "logs"
        logs.mkdir()
        recipe = {"binary": None, "command": ["cargo", "clippy"],
                  "cwd": str(cache), "target_directory": str(cache / "target")}
        legacy = {"host": {"host_build_id": "frozen"},
                  "recipes": {"check": recipe, "other": recipe}}
        inputs = {"recipes": legacy["recipes"], "legacy": legacy, "targets": target_inputs(legacy)}
        for label in legacy["recipes"]:
            (legacy_cache / (label + ".log")).write_text("passed\n")
        env = {"CM_SOURCE_REPOSITORY": "DSLZL/CM", "CM_SOURCE_SHA": "a" * 40,
            "GITHUB_REPOSITORY": "DSLZL/CM-build-linux-x64", "GITHUB_WORKFLOW_SHA": "b" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "build",
            "GITHUB_OUTPUT": str(Path(directory) / "outputs")}
        with patch.dict(os.environ, {**env, "CM_ACCEPTANCE_BUILD_CACHE_DIR": str(cache)}):
            receipt = {"inputs": legacy, "origin": origin(), "checks": {
                label: {"recipe": value, "return_code": 0} for label, value in legacy["recipes"].items()},
                "files": host.manifest(legacy_cache)}
            host.write(legacy_cache / "build.json", receipt)
            host.write(logs / "acceptance-build-inputs.json", inputs)
            restore(cache, logs)
            assert all(item["migrated"] for item in host.read(logs / "acceptance-build-cache.json")["targets"].values())
            shutil.rmtree(legacy_cache)
            shutil.rmtree(cache / "other")
            restore(cache, logs)
            state = host.read(logs / "acceptance-build-cache.json")
            assert state["status"] == "partial" and state["targets"]["check"]["status"] == "hit"
            with patch.object(sys.modules[__name__], "recipes", return_value=inputs["recipes"]), \
                    patch.object(sys.modules[__name__], "execute", side_effect=AssertionError("Cache hit rebuilt")):
                assert run(cache, logs, "check") is None
            save(cache, logs)
            assert host.read(logs / "acceptance-build-receipt.json")["incomplete"] == ["other"]
            assert "save_check=true" in Path(env["GITHUB_OUTPUT"]).read_text()
            assert "save_other=false" in Path(env["GITHUB_OUTPUT"]).read_text()
            # A missing target executes independently; completed siblings remain reusable.
            def compile_check(_root, destination, label, _command, _env):
                (destination / (label + ".log")).write_text("current check passed\n")
            with patch.object(sys.modules[__name__], "recipes", return_value=inputs["recipes"]), \
                    patch.object(sys.modules[__name__], "execute", side_effect=compile_check) as compiler:
                run(cache, logs, "other")
                run(cache, logs, "other")
                assert compiler.call_count == 1
            save(cache, logs)
            assert not host.read(logs / "acceptance-build-receipt.json")["incomplete"]
            target = cache / "check"
            receipt = host.read(target / "build.json")
            for change in (lambda: (target / "check.log").write_text("tampered"),
                           lambda: receipt["origin"].update(GITHUB_RUN_ID="invalid"),
                           lambda: receipt["checks"]["check"].update(return_code=1),
                           lambda: receipt["inputs"].update(changed=True)):
                (target / "check.log").write_text("passed\n")
                candidate = json.loads(json.dumps(receipt))
                change()
                host.write(target / "build.json", receipt)
                try:
                    verify(target, inputs["targets"]["check"])
                except (AssertionError, KeyError):
                    pass
                else:
                    raise AssertionError("Invalid acceptance cache accepted")
                receipt = candidate
            private = {**legacy, "recipes": {**legacy["recipes"], "m02-native-probe-build": recipe,
                       "review-tui-probe-build": recipe}, "instrumented_source_sha256": "core-v1",
                       "review_instrumented_source_sha256": "tui-v1"}
            before = target_inputs(private)
            for field, label in (("instrumented_source_sha256", "m02-native-probe-build"),
                                 ("review_instrumented_source_sha256", "review-tui-probe-build")):
                after = target_inputs({**private, field: "changed"})
                assert {name for name in before if before[name] != after[name]} == {label}
            compiler = {"toolchain": {"rustc": "current"}, "flags": {"CFLAGS": "current"}, "native": {"libc": "current"}}
            private["host"] = {**private["host"], "inputs": compiler}
            before = target_inputs(private)
            assert target_inputs(private, compiler) == before
            for field in compiler:
                after = target_inputs(private, {**compiler, field: "changed"})
                assert {name for name in before if before[name] != after[name]} == {
                    "m02-native-probe-build", "review-tui-probe-build"}
            drift_cache = Path(directory) / "drift-cache"
            (drift_cache / "legacy").mkdir(parents=True)
            for label in private["recipes"]:
                (drift_cache / "legacy" / (label + ".log")).write_text("passed\n")
            host.write(drift_cache / "legacy/build.json", {"inputs": private, "origin": origin(),
                "checks": {label: {"recipe": value, "return_code": 0} for label, value in private["recipes"].items()},
                "files": host.manifest(drift_cache / "legacy")})
            host.write(logs / "acceptance-build-inputs.json", {"legacy": private,
                "targets": target_inputs(private, {**compiler, "native": "changed"})})
            with patch.dict(os.environ, {"CM_ACCEPTANCE_BUILD_CACHE_DIR": str(drift_cache)}):
                restore(cache, logs)
            state = host.read(logs / "acceptance-build-cache.json")["targets"]
            assert {label for label, value in state.items() if value["migrated"]} == {"check", "other"}
            assert state["m02-native-probe-build"]["status"] == state["review-tui-probe-build"]["status"] == "miss"
            authors = {**private, "recipes": {name: recipe for name in ("g06-sdk-a-v1", "g06-sdk-b-v1", "g06-c-abi")},
                "sdk_author_inputs": {name: {"sources": name} for name in ("g06-sdk-a-v1", "g06-sdk-b-v1", "g06-c-abi")},
                "sdk_compiler": compiler}
            before = target_inputs(authors)
            assert target_inputs({**authors, "host": {"host_build_id": "different-host"}}) == before
            changed = json.loads(json.dumps(authors))
            changed["sdk_author_inputs"]["g06-sdk-a-v1"]["sources"] = "only-author-a-changed"
            assert {name for name in before if before[name] != target_inputs(changed)[name]} == {"g06-sdk-a-v1"}


if __name__ == "__main__":
    if sys.argv[1] == "self-check":
        self_check()
    else:
        host.require_hosted_linux()
        root = Path(os.environ["CM_SOURCE_DIR"]).resolve()
        logs = Path(os.environ["CM_CI_LOG_DIR"])
        {"identity": identify, "restore": restore, "save": save}[sys.argv[1]](root, logs)
