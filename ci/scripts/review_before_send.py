"""G02B builds the author Mod and a separate private TUI probe; never runtime results."""
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

OWNER = "org.example.review-before-send"
CAPABILITY = "tui.submit_review.v1"
CASES = ("nondestructive", "invalidation", "key-events", "entry-coverage", "queue-lifecycle", "plug-and-play")
REPORTS = tuple("review-" + case + ".json" for case in CASES)
REFERENCE_ORIGIN = {
    "run_id": 40961308903, "run_attempt": 1,
    "source_sha": "a2645a6448f1b9e4bfcd8887f2bc71efff248261",
    "workflow_sha": "6b39025f2e75d53330f414bee570dc5859ed49f3",
    "request_id": "cm-g02a-qual-20261030-r12",
    "input_artifact_id": 12931726243,
    "input_artifact_sha256": "587519daa1c0c24d15049dfe61913771885eacdea308c8d875f71758bb7df87a",
    "consumer_artifact_id": 12935244323,
    "consumer_artifact_sha256": "142fd47caf00a81c1f3143bec26e934e610f44d140b6b6d6b068e41775938ca6",
    "receipt_artifact_id": 12935708523,
    "receipt_artifact_sha256": "04b0b0ae43ac78679304dffdd258ac69dd26cd32971746da941cb0ec7f952ce3",
}


def driver():
    path = Path(__file__).resolve().parents[2] / "fixtures/review-before-send/driver.py"
    spec = importlib.util.spec_from_file_location("cm_review_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def restore_reference():
    import host
    import worker_policy as policy
    from linux_ci import load_config
    if load_config(Path(os.environ["CM_SOURCE_DIR"]))["task_id"] not in ("CM-G02B", "CM-G03"):
        return
    source, worker, _, workflow, _ = policy.identities()
    remote = policy.verify_origin(REFERENCE_ORIGIN, source, worker, workflow)
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-review-reference"
    directory.mkdir()
    with policy.download_origin_archive(worker, remote["artifacts"]["receipt"], directory / "receipt.zip") as archive:
        receipt = policy.archive_json(archive, "worker-receipt.json")
    policy.qualification_receipt(receipt, REFERENCE_ORIGIN, remote["jobs"], source, worker)
    with policy.download_origin_archive(worker, remote["artifacts"]["input"], directory / "inputs.zip") as archive:
        assert archive.namelist() == ["runtime-inputs.tar"]
        with archive.open("runtime-inputs.tar") as stream, (directory / "inputs.tar").open("xb") as output:
            shutil.copyfileobj(stream, output)
    names = {
        "producer.json", "input-manifest.json", "fixture/g02a-producer.json", "fixture/g02a-legacy-host.json",
        "mods/g02a/turn-budget/mod.toml", "mods/g02a/turn-budget/payload.so", "mods/g02a/turn-budget.cmod",
        "host/bin/codex", "host/g02a-legacy/codex",
    }
    seen = set()
    with tarfile.open(directory / "inputs.tar", "r:") as archive:
        for member in archive:
            relative = member.name.removeprefix("runtime-inputs/")
            if relative not in names:
                continue
            assert member.name == "runtime-inputs/" + relative and relative not in seen
            assert member.isfile() and 0 < member.size <= 1024 ** 3
            seen.add(relative)
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as stream, path.open("xb") as output:
                shutil.copyfileobj(stream, output)
            path.chmod(member.mode & 0o777)
    assert seen == names
    manifest = host.read(directory / "input-manifest.json")
    for name in names - {"input-manifest.json"}:
        record = next(row for row in manifest["files"] if row["path"] == name)
        assert host.sha(directory / name) == record["sha256"]
    prior = host.read(directory / "producer.json")
    assert prior["task_id"] == "CM-G02A" and prior["host"]["host_identity"]["host_api_version"] == "0.7.0"
    assert host.sha(directory / "host/bin/codex") == prior["host"]["executable_sha256"]
    assert host.sha(directory / "mods/g02a/turn-budget/payload.so") == "15d82581a1762dea416873e5af1f1d8551e1557827ea40481c355ecbc0efc2cf"
    legacy = Path(os.environ["RUNNER_TEMP"]) / "cm-g02a-legacy-reference"
    legacy.mkdir()
    shutil.copyfile(directory / "host/g02a-legacy/codex", legacy / "codex")
    (legacy / "codex").chmod(0o755)
    shutil.copyfile(directory / "fixture/g02a-legacy-host.json", legacy / "legacy-host.json")
    host.write(directory / "reference.json", {"origin": REFERENCE_ORIGIN, "host": prior["host"],
        "author": prior["authors"]["g02a/turn-budget"]})


def inherit_budget(inputs, package, frozen, logs, authors, sdk):
    import host
    import turn_budget
    reference = Path(os.environ["RUNNER_TEMP"]) / "cm-review-reference"
    previous = host.read(reference / "fixture/g02a-producer.json")
    shutil.copytree(reference / "mods/g02a", inputs / "mods/g02a")
    authors["g02a/turn-budget"] = host.read(reference / "reference.json")["author"]
    for relative in ("ci/scripts/turn_budget.py", "fixtures/turn-budget/driver.py"):
        path = inputs / "fixture" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(os.environ["CM_SOURCE_DIR"]) / relative, path)
    result = {**previous, "private_core_probe": turn_budget.native_probe(
        Path(os.environ["CM_SOURCE_DIR"]), logs, inputs, frozen, sdk),
        "legacy_host": turn_budget.legacy_host(inputs), "author_reused": True,
        "author_origin": REFERENCE_ORIGIN, "host_rebuilt_after_freeze": False}
    host.write(inputs / "fixture/g02a-producer.json", result)
    return result


def native_probe_source(root):
    import host
    probe = Path(os.environ["RUNNER_TEMP"]) / "cm-review-tui-probe-source"
    if probe.exists():
        return probe
    shutil.copytree(root / host.HOST, probe, ignore=shutil.ignore_patterns(".git", "target"))
    tui = probe / "codex-rs/tui/src"
    for relative, anchor, replacement in (
        ("bottom_pane/chat_composer_history.rs", "#[derive(Clone)]\npub(crate) struct ChatComposerHistory",
         "#[derive(Clone, Debug)]\npub(crate) struct ChatComposerHistory"),
        ("bottom_pane/paste_burst.rs", "#[derive(Clone, Default)]\npub(crate) struct PasteBurst",
         "#[derive(Clone, Debug, Default)]\npub(crate) struct PasteBurst"),
        ("bottom_pane/chat_composer.rs",
         "        pending_paste_handling: PendingPasteHandling,\n    ) -> Option<(String, Vec<TextElement>)> {\n",
         "        pending_paste_handling: PendingPasteHandling,\n    ) -> Option<(String, Vec<TextElement>)> {\n"
         "        #[cfg(test)]\n"
         "        submit_review::CM_PREPARATION_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);\n"),
    ):
        path = tui / relative
        text = path.read_text()
        assert text.count(anchor) == 1
        path.write_text(text.replace(anchor, replacement))
    destination = tui / "bottom_pane/chat_composer/cm_review_probe.rs"
    shutil.copyfile(root / "fixtures/review-before-send/composer_probe.rs", destination)
    with (tui / "bottom_pane/chat_composer/submit_review.rs").open("a") as stream:
        stream.write('\n#[cfg(test)]\npub(super) static CM_PREPARATION_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\n')
        stream.write('\n#[cfg(test)]\n#[path = "cm_review_probe.rs"]\nmod cm_probe;\n')
    shutil.copyfile(root / "fixtures/review-before-send/dispatch_probe.rs", tui / "chatwidget/tests/cm_review_probe.rs")
    with (tui / "chatwidget/tests.rs").open("a") as stream:
        stream.write('\n#[path = "tests/cm_review_probe.rs"]\nmod cm_review_probe;\n')
    shutil.copyfile(root / "fixtures/review-before-send/app_probe.rs", tui / "app/tests/cm_review_probe.rs")
    with (tui / "app/tests.rs").open("a") as stream:
        stream.write('\n#[path = "tests/cm_review_probe.rs"]\nmod cm_review_probe;\n')
    from linux_ci import load_config
    if load_config(root)["task_id"] == "CM-G03":
        shutil.copyfile(root / "fixtures/tool-concurrency/backend_probe.rs", tui / "app_server_session/cm_concurrency_backend.rs")
        with (tui / "app_server_session.rs").open("a") as stream:
            stream.write('\n#[cfg(test)]\ninclude!("app_server_session/cm_concurrency_backend.rs");\n')
        responder = probe / "codex-rs/app-server/src/request_processors/initialize_processor.rs"
        text = responder.read_text()
        anchor = "        self.outgoing\n            .send_response(connection_request_id, response)"
        assert text.count(anchor) == 1
        text = text.replace(anchor, '''        let mut response = response;
        match std::env::var("CM_CONCURRENCY_BACKEND_FAULT").as_deref() {
            Ok("missing") => response.cm_tool_concurrency = None,
            Ok("wrong-build") => response.cm_tool_concurrency.as_mut().expect("CM backend").host_build_id = "wrong-build".into(),
            Ok("wrong-capability") => response.cm_tool_concurrency.as_mut().expect("CM backend").capability = "wrong-capability".into(),
            Ok("disabled") => response.cm_tool_concurrency.as_mut().expect("CM backend").provider_enabled = false,
            _ => {},
        }
''' + anchor)
        responder.write_text(text)
    return probe


def prepare(inputs, package, frozen, logs, authors, sdk):
    import host
    import mod_manifest
    from acceptance_cache import run
    from linux_ci import cargo_args, execute, load_config
    root = Path(os.environ["CM_SOURCE_DIR"])
    cfg = load_config(root)
    source = root / "examples/mods/review-before-send"
    unit = {"manifest": "examples/mods/review-before-send/Cargo.toml",
            "packages": ["cm-review-before-send"], "features": []}
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "g02b-review-before-send"
    assert not target.exists(), "B must be authored with an empty independent target"
    before = host.sha(source / "Cargo.lock")
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    for phase in ("fmt", "clippy", "test", "build"):
        command = (["cargo", "fmt", "--manifest-path", unit["manifest"], "--", "--check"] if phase == "fmt"
                   else cargo_args(unit, phase, cfg, cfg["build_profile"]))
        if phase == "clippy":
            command += ["--all-targets", "--", "-D", "warnings"]
        execute(root, logs, "review-author-" + phase, command, env)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", str(source / "Cargo.toml")], env=env, text=True))
    dependencies = {item["name"]: sorted(dep["name"] for dep in item["dependencies"]) for item in metadata["packages"]}
    assert dependencies["cm-sdk"] == ["cm-abi"] and dependencies["cm-abi"] == []
    assert dependencies["cm-review-before-send"] == ["cm-sdk", "serde", "serde_json"]
    assert not any(name.startswith("codex-") or name.startswith("cm-host") or name == "cm-runtime" for name in dependencies)
    assert host.sha(source / "Cargo.lock") == before
    destination = inputs / "mods/g02b/review-before-send"
    destination.mkdir(parents=True)
    payload = destination / "payload.so"
    shutil.copyfile(target / TARGET / cfg["build_profile"] / "libcm_review_before_send.so", payload)
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
        "payload_sha256": host.sha(payload), "archive_sha256": host.sha(archive), "exports": exports}
    authors["g02b/review-before-send"] = author
    fault_unit = {"manifest": "fixtures/review-before-send/native/Cargo.toml",
                  "packages": ["cm-review-fault-fixture"], "features": []}
    for phase in ("clippy", "build"):
        command = cargo_args(fault_unit, phase, cfg, cfg["build_profile"])
        if phase == "clippy":
            command += ["--all-targets", "--", "-D", "warnings"]
        execute(root, logs, "review-fault-" + phase, command, env)
    faults = inputs / "mods/g02b/faults"
    faults.mkdir()
    shutil.copyfile(target / TARGET / cfg["build_profile"] / "libcm_review_fault_fixture.so", faults / "payload.so")
    fault_manifest = tomllib.loads((destination / "mod.toml").read_text())
    fault_manifest["binary"].update(size=(faults / "payload.so").stat().st_size, sha256=host.sha(faults / "payload.so"),
        glibc_min=mod_manifest.native_glibc_min(faults / "payload.so"))
    mod_manifest.manifest(faults, fault_manifest)
    probe_source = native_probe_source(root)
    probe = inputs / "probes/cm-review-tui"
    probe.parent.mkdir(exist_ok=True)
    run(root, logs, "review-tui-probe-build", probe)
    probe.chmod(0o755)
    reference = Path(os.environ["RUNNER_TEMP"]) / "cm-review-reference"
    previous = inputs / "host/review-legacy/codex"
    previous.parent.mkdir()
    shutil.copyfile(reference / "host/bin/codex", previous)
    previous.chmod(0o755)
    for relative in ("ci/scripts/review_before_send.py", "fixtures/review-before-send/driver.py"):
        path = inputs / "fixture" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, path)
    result = {"status": "pass", "author": author, "cases": list(CASES),
        "probe": {"path": "/inputs/probes/cm-review-tui", "sha256": host.sha(probe),
            "source_sha256": host.manifest_digest(host.manifest(probe_source)),
            "production_cli_sha256": frozen["executable_sha256"], "separate_from_cli": True},
        "reference": host.read(reference / "reference.json"),
        "host_rebuilt_after_freeze": False, "a_recompiled": False}
    host.write(inputs / "fixture/review-producer.json", result)
    assert host.sha(package / "bin/codex") == frozen["executable_sha256"]
    host.verify_sources(root, logs)
    return result


def produce():
    import runtime_consumer
    runtime_consumer.produce()


def self_check():
    from retry import PHASES, projection
    from unittest.mock import patch
    import runtime_consumer
    assert list(CASES) == [label.removeprefix("review-") for label in PHASES if label.startswith("review-")]
    text = (Path(__file__).resolve().parents[2] / "fixtures/review-before-send/driver.py").read_text()
    names = ("nondestructive", "invalidation", "key_events", "entry_coverage", "queue_lifecycle", "plug_and_play")
    original = {name: projection(text, (name,)) for name in names}
    changed = text.replace('probe("nondestructive")', 'probe("nondestructive", changed=True)', 1)
    assert projection(changed, ("nondestructive",)) != original["nondestructive"]
    assert all(projection(changed, (name,)) == original[name] for name in names[1:])
    manifest = tomllib.loads((Path(__file__).resolve().parents[2] / "examples/mods/review-before-send/mod.toml").read_text())
    assert manifest["id"] == OWNER and manifest["compat"]["required_capabilities"] == [CAPABILITY]
    probe = {"path": "/inputs/probes/cm-review-tui", "sha256": "a" * 64, "separate_from_cli": True}
    producer = {"review": {"probe": probe, "cases": list(CASES)}}
    call = '1 execve("' + probe["path"] + '", ["' + probe["path"] + '", "--ignored", "--exact", ' \
        '"chatwidget::tests::cm_review_probe::cm_review_cli_image", "--nocapture"], 0x1) = 0'
    with patch.object(runtime_consumer, "read", return_value=producer), \
            patch.object(runtime_consumer, "sha", return_value=probe["sha256"]) as hashed:
        assert runtime_consumer.bind_review_probes([call], Path("/consumer")) == [probe["path"]]
        for invalid in (call.replace("cli_image", "unregistered"), call.replace('"--exact"', '"--list"'), call):
            if invalid == call:
                hashed.return_value = "b" * 64
            try:
                runtime_consumer.bind_review_probes([invalid], Path("/consumer"))
            except AssertionError:
                continue
            raise AssertionError("Unbound review probe accepted: " + invalid)


if __name__ == "__main__":
    {"produce": produce, "restore-reference": restore_reference, "self-check": self_check}[sys.argv[1]]()
