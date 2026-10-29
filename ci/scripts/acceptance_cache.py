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
    if cfg["task_id"] in ("CM-M02", "CM-M03", "CM-M04", "CM-M05"):
        probe = Path(os.environ["RUNNER_TEMP"]) / "cm-m02-native-probe-source"
        specs["m02-native-probe-build"] = (probe, ["cargo", "test", "--locked", "--manifest-path",
            "codex-rs/Cargo.toml", "--target", TARGET, "--profile", cfg["test_profile"],
            "--package", "codex-core", "--lib", "--no-run", "--message-format=json"],
            target / "m02-native-probe", "codex_core")
    return {label: {"cwd": str(cwd), "command": command, "target_directory": str(target), "binary": binary}
            for label, (cwd, command, target, binary) in specs.items()}


def identify(root, logs):
    specs = recipes(root)
    inputs = {"schema_version": 1, "host": host.read(logs / "host-identity.json"),
              "recipes": specs, "cache_protocol_sha256": host.sha(Path(__file__))}
    if "m02-native-probe-build" in specs:
        from runtime_sdk import native_probe_source
        probe = native_probe_source(root)
        inputs["instrumented_source_sha256"] = host.manifest_digest(host.manifest(probe))
    host.write(logs / "acceptance-build-inputs.json", inputs)
    key = "cm-acceptance-build-v1-" + TARGET + "-" + host.digest(inputs)
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write("acceptance_key=" + key + "\n")


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
    receipt = verify(cache, inputs) if cache.exists() else None
    host.write(logs / "acceptance-build-cache.json", {"status": "hit" if receipt else "miss",
        "origin": receipt["origin"] if receipt else None, "checks": receipt["checks"] if receipt else {},
        "note": "Only compilation/checks reused; every current-source runtime test runs again"})
    if receipt:
        shutil.copytree(cache, logs / "reused-acceptance-build", ignore=shutil.ignore_patterns("*.bin"))
    print("CM acceptance build cache:", "hit" if receipt else "miss", flush=True)


def run(root, logs, label, destination=None):
    inputs = host.read(logs / "acceptance-build-inputs.json")
    recipe = recipes(root)[label]
    assert recipe == inputs["recipes"][label], "Acceptance build command changed after sealing"
    if label == "m02-native-probe-build":
        assert host.manifest_digest(host.manifest(Path(recipe["cwd"]))) == inputs["instrumented_source_sha256"]
    state = host.read(logs / "acceptance-build-cache.json")
    cache = Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"])
    binary = cache / (label + ".bin")
    if state["status"] == "hit":
        started = time.monotonic()
        original = host.read(cache / "build.json")
        assert original["inputs"] == inputs and original["checks"][label]["recipe"] == recipe
        for name in (label + ".log", *([binary.name] if recipe["binary"] else [])):
            entry = next(entry for entry in original["files"] if entry["path"] == name)
            assert host.sha(cache / name) == entry["sha256"]
        print("CM CI: reuse", label, "from run", original["origin"]["GITHUB_RUN_ID"], flush=True)
        event = {"phase": label, "command": recipe["command"], "cwd": recipe["cwd"], "return_code": 0,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "log": "reused-acceptance-build/" + label + ".log", "compilation": "reused", "origin": original["origin"]}
        with (logs / "phase-results.jsonl").open("a") as stream:
            stream.write(json.dumps(event) + "\n")
    else:
        cache.mkdir(exist_ok=True)
        execute(Path(recipe["cwd"]), logs, label, recipe["command"],
                {**os.environ, "CARGO_TARGET_DIR": recipe["target_directory"]})
        shutil.copyfile(logs / (label + ".log"), cache / (label + ".log"))
        if recipe["binary"]:
            artifacts = [event["executable"] for line in (logs / (label + ".log")).read_text().splitlines()
                if line.startswith("{") and (event := json.loads(line)).get("reason") == "compiler-artifact"
                and event.get("executable") and event["target"]["name"] == recipe["binary"]]
            assert len(set(artifacts)) == 1, artifacts
            shutil.copy2(artifacts[0], binary)
        state["checks"][label] = {"recipe": recipe, "return_code": 0}
        host.write(logs / "acceptance-build-cache.json", state)
    if destination is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, destination)
        return destination
    return binary if recipe["binary"] else None


def save(root, logs):
    cache = Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"])
    inputs = host.read(logs / "acceptance-build-inputs.json")
    state = host.read(logs / "acceptance-build-cache.json")
    if state["status"] == "miss":
        assert set(state["checks"]) == set(inputs["recipes"]), "Incomplete acceptance compilation"
        host.write(cache / "build.json", {"inputs": inputs, "origin": origin(),
            "checks": state["checks"], "files": host.manifest(cache)})
    verify(cache, inputs)
    shutil.copyfile(cache / "build.json", logs / "acceptance-build-receipt.json")


def self_check():
    import tempfile
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as directory:
        cache = Path(directory) / "cache"
        cache.mkdir()
        logs = Path(directory) / "logs"
        logs.mkdir()
        inputs = {"recipes": {"check": {"binary": None, "command": ["cargo", "clippy"],
            "cwd": str(cache), "target_directory": str(cache / "target")}}}
        (cache / "check.log").write_text("passed\n")
        env = {"CM_SOURCE_REPOSITORY": "DSLZL/CM", "CM_SOURCE_SHA": "a" * 40,
            "GITHUB_REPOSITORY": "DSLZL/CM-build-linux-x64", "GITHUB_WORKFLOW_SHA": "b" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "build"}
        with patch.dict(os.environ, {**env, "CM_ACCEPTANCE_BUILD_CACHE_DIR": str(cache)}):
            receipt = {"inputs": json.loads(json.dumps(inputs)), "origin": origin(), "checks": {
                "check": {"recipe": inputs["recipes"]["check"], "return_code": 0}}, "files": host.manifest(cache)}
            host.write(cache / "build.json", receipt)
            verify(cache, inputs)
            host.write(logs / "acceptance-build-inputs.json", inputs)
            restore(cache, logs)
            with patch.object(sys.modules[__name__], "recipes", return_value=inputs["recipes"]), \
                    patch.object(sys.modules[__name__], "execute", side_effect=AssertionError("Cache hit rebuilt")):
                assert run(cache, logs, "check") is None
            for change in (lambda: (cache / "check.log").write_text("tampered"),
                           lambda: receipt["origin"].update(GITHUB_RUN_ID="invalid"),
                           lambda: receipt["checks"]["check"].update(return_code=1),
                           lambda: receipt["inputs"].update(changed=True)):
                (cache / "check.log").write_text("passed\n")
                candidate = json.loads(json.dumps(receipt))
                change()
                host.write(cache / "build.json", receipt)
                try:
                    verify(cache, inputs)
                except (AssertionError, KeyError):
                    pass
                else:
                    raise AssertionError("Invalid acceptance cache accepted")
                receipt = candidate


if __name__ == "__main__":
    if sys.argv[1] == "self-check":
        self_check()
    else:
        host.require_hosted_linux()
        root = Path(os.environ["CM_SOURCE_DIR"]).resolve()
        logs = Path(os.environ["CM_CI_LOG_DIR"])
        {"identity": identify, "restore": restore, "save": save}[sys.argv[1]](root, logs)
