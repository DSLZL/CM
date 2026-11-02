"""G05 qualification data stays separate from the frozen H1 production package."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile

REPORTS = ("upgrade-candidate-integrity.json", "upgrade-compatibility-rejections.json",
    "upgrade-binary-reuse.json", "upgrade-exact-host-variants.json", "upgrade-state-and-labels.json")
BASELINE_FILE = "ci/g05-baseline.json"


def driver():
    path = Path(__file__).resolve().parents[2] / "fixtures/compatibility/driver.py"
    spec = importlib.util.spec_from_file_location("cm_upgrade_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def baseline_file():
    source = os.environ.get("CM_SOURCE_DIR")
    return Path(source) / BASELINE_FILE if source else Path(__file__).resolve().parents[2] / BASELINE_FILE


def restore_reference(*, producer=False):
    import worker_policy as policy
    from record_run import require_hosted_linux
    require_hosted_linux()
    path = baseline_file()
    if not path.exists():
        return
    if os.environ.get("CM_SOURCE_DIR"):
        from linux_ci import load_config
        if load_config(Path(os.environ["CM_SOURCE_DIR"]))["task_id"] != "CM-G05":
            return
    import runtime_consumer as host
    pin = host.read(path)
    source, worker, _, _, _ = policy.identities()
    assert (source, worker) == (pin["source_repository"], pin["worker_repository"])
    prefix = "repos/" + worker
    run = policy.api(prefix + "/actions/runs/" + str(pin["run_id"]))
    assert (run["run_attempt"], run["head_sha"], run["path"], run["event"], run["display_title"]) == (
        pin["run_attempt"], pin["workflow_sha"], ".github/workflows/build.yml", "workflow_dispatch",
        "CM Linux x64 / " + pin["request_id"])
    jobs = policy.receipt_jobs(prefix + "/actions/runs/" + str(pin["run_id"]) + "/attempts/1/jobs?per_page=100",
        ("build-write / linux-x64", "runtime-consumer"))
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-g05-reference"
    directory.mkdir()
    records = {}
    for key, label in (("product_artifact", "task-artifacts"), ("input_artifact", "runtime-inputs")):
        expected = pin[key]
        record = policy.api(prefix + "/actions/artifacts/" + str(expected["id"]))
        policy.artifact_binding(record, expected["id"], "cm-linux-x64-" + label + "-" + pin["request_id"] + "-1",
            expected["digest"], pin["run_id"])
        records[key] = record
    if producer:
        with policy.download_origin_archive(worker, records["product_artifact"], directory / "product.zip") as archive:
            evidence = policy.archive_json(archive, "evidence/host-baseline-build.json")
            assert evidence["executable_sha256"] == pin["executable_sha256"]
            assert evidence["host_identity"]["host_build_id"] == pin["host_build_id"]
        (directory / "product.zip").unlink()
    with policy.download_origin_archive(worker, records["input_artifact"], directory / "inputs.zip") as archive:
        assert archive.namelist() == ["runtime-inputs.tar"]
        with archive.open("runtime-inputs.tar") as stream, (directory / "inputs.tar").open("xb") as output:
            shutil.copyfileobj(stream, output)
    destination = directory / "selected"
    destination.mkdir()
    with tarfile.open(directory / "inputs.tar", "r:") as archive:
        policy.archive_members(archive.getmembers(), "runtime-inputs")

        def record(name):
            member = archive.getmember("runtime-inputs/" + name)
            assert member.isfile() and member.size <= 16 * 1024 * 1024
            return json.load(archive.extractfile(member))

        manifest = record("input-manifest.json")
        prior = record("producer.json")
        assert manifest["sha256"] == host.digest(manifest["files"])
        assert prior["provenance"]["CM_SOURCE_SHA"] == pin["source_sha"]
        assert prior["provenance"]["GITHUB_WORKFLOW_SHA"] == pin["workflow_sha"]
        assert prior["task_id"] == "CM-G01"
        inventory = record("host/cm-runtime-files.json")
        host_names = {"host/cm-runtime-files.json", *("host/" + item["path"] for item in inventory["files"])}
        selected = {item["path"]: item for item in manifest["files"] if item["path"] in host_names
            or item["path"] == "fixture/g04-producer.json"
            or item["path"].startswith(("mods/g02a/turn-budget/", "mods/g02b/review-before-send/", "mods/g01/a/normal/"))}
        assert host_names <= selected.keys()
        for name, expected in selected.items():
            member = archive.getmember("runtime-inputs/" + name)
            assert (member.isfile() or member.islnk()) and member.size <= 1024 ** 3
            assert "link" not in expected
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output)
            target.chmod(member.mode & 0o777)
            assert host.sha(target) == expected["sha256"]
    host_record = host.read(destination / "host/cm-host.json")
    assert (host_record["host_release_id"], host_record["host_build_id"], host_record["patch_map_sha256"],
        host.sha(destination / "host/bin/codex")) == tuple(pin[key] for key in
        ("host_release_id", "host_build_id", "patch_map_sha256", "executable_sha256"))
    for relative in ("mods/g02a/turn-budget", "mods/g02b/review-before-send", "mods/g01/a/normal"):
        assert (destination / relative / "mod.toml").is_file() and (destination / relative / "payload.so").is_file()
    host.write(destination / "reference.json", {"pin": pin, "files": selected, "original_input_manifest": manifest["sha256"],
        "authors": {key: value for key, value in prior["authors"].items() if key in
            ("g02a/turn-budget", "g02b/review-before-send", "g01/a/normal")},
        "host": prior["host"], "jobs": jobs, "product_archive_verified": producer})
    for name in ("inputs.zip", "inputs.tar"):
        (directory / name).unlink()
    print(json.dumps({"stage": "g05-baseline", "status": "pass", "host": pin["host_release_id"],
        "input_artifact": pin["input_artifact"], "reuploaded": False}), flush=True)


def prepare(inputs, frozen):
    import runtime_consumer as host
    from host import build_log
    root = Path(os.environ["CM_SOURCE_DIR"])
    reference = Path(os.environ["RUNNER_TEMP"]) / "cm-g05-reference/selected/reference.json"
    baseline = host.read(reference)
    assert baseline["product_archive_verified"] and frozen["executable_sha256"] != baseline["pin"]["executable_sha256"]
    for relative in (BASELINE_FILE, "ci/scripts/runtime_upgrade.py", "fixtures/compatibility/driver.py"):
        destination = inputs / "fixture" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    host.write(inputs / "fixture/g05-producer.json", baseline)
    checks = ("upgrade_commit_revalidates_source_at_publication",
        "upgrade_package_member_identity_detects_same_bytes_replacement",
        "upgrade_state_copy_has_fresh_identity_and_retains_unselected_owners",
        "upgrade_state_copy_faults_preserve_source_and_leave_no_active_candidate",
        "upgrade_state_busy_incompatible_and_changed_inputs_fail_closed",
        "descriptor_is_unchanged_before_commit_and_truthful_after_rename")
    log = build_log(Path(os.environ["CM_CI_LOG_DIR"]), "host-test")
    text = log.read_text()
    assert all(name + " ... ok" in text for name in checks), "G05 transaction tests did not pass"
    host.write(inputs / "fixture/g05-transaction-checks.json", {"tests": {name: "pass" for name in checks},
        "host_sha256": frozen["executable_sha256"], "log_sha256": host.sha(log),
        "origin": {key: os.environ[key] for key in ("CM_SOURCE_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")},
        "unit_binary_is_published_host": False, "test_only_faults": True})
    return {"baseline": baseline, "original_packages_rebuilt": False, "implicit_build_fallback": False}


def mount_reference(inputs, root, system):
    import runtime_consumer as host
    reference = Path(os.environ["RUNNER_TEMP"]) / "cm-g05-reference/selected"
    prior = host.read(reference / "reference.json")
    expected = host.read(inputs / "fixture/g05-producer.json")
    assert prior["pin"] == expected["pin"] and prior["files"] == expected["files"]
    for name, entry in prior["files"].items():
        assert host.sha(reference / name) == entry["sha256"]
    inventory = host.read(reference / "host/cm-runtime-files.json")
    current = host.read(inputs / "host/cm-runtime-files.json")
    closure = {}
    audits = (host.read(inputs / "fixture/g04-producer.json"), host.read(reference / "fixture/g04-producer.json"))
    for audit in audits:
        assert audit["status"] == "pass"
        for name, item in audit["libraries"].items():
            assert name not in closure or closure[name] == item["sha256"], "Host system closure conflict"
            closure[name] = item["sha256"]
            assert host.sha(Path(name)) == item["sha256"], "Audited Host system library changed"
            system(name)
    for name in {*current["system_files"], *inventory["system_files"]}:
        assert isinstance(name, str) and name in closure, "Unqualified Host system dependency"
        system(name)
    shutil.copytree(reference, root / "inputs/upgrade-baseline")


def reports(evidence, steps, audit):
    from datetime import datetime, timezone
    from mod_manifest import read, write
    from runtime_cases import GROUPS
    assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
    assert all(steps["g05-" + case]["status"] == "pass" for case in GROUPS["g05"])
    dynamic = read(evidence / REPORTS[1])["cases"]["declared-function-table"]["dynamic_contract_cases"]
    assert all(steps[label]["status"] == "pass" for label in dynamic)
    for name in REPORTS:
        value = read(evidence / name)
        assert value["status"] == "behavior_pass" and value.get("cases")
        value.update(program_complete=False, native_sandbox=False, implicit_build_fallback=False)
        if name == REPORTS[1]:
            value["dynamic_function_table_checks"] = {label: {key: row for key, row in steps[label].items()
                if key != "audit"} for label in dynamic}
        if name == REPORTS[2]:
            value["verified_pairs"] = [{**{key: row[key] for key in ("host", "host_receipt", "lock_sha256",
                "config_sha256", "state_contracts", "original_packages_after")},
                "case": case, "verified": True,
                "execution": {key: item for key, item in steps["g05-" + case].items() if key != "audit"}}
                for case, row in value["cases"].items() if case.startswith("reuse-")]
            assert len(value["verified_pairs"]) == 6
            value["qualification_recorded_at"] = datetime.now(timezone.utc).isoformat()
            value["qualification_inheritance"] = False
        write(evidence / name, value)


def self_check():
    from record_run import require_hosted_linux
    require_hosted_linux()
    from unittest.mock import patch
    import tempfile
    import runtime_cases
    import retry
    root = Path(__file__).resolve().parents[2]
    module = driver()
    assert len(REPORTS) == 5 and len(set(REPORTS)) == 5
    assert set(runtime_cases.GROUPS["g05"]) == set(module.CASES)
    assert all(callable(getattr(module, runtime_cases.function(case, "g05"))) for case in module.CASES)
    texts = {path: retry.source(root, "HEAD", path) for path in retry.RUNTIME_FILES if not path.endswith("ci_progress.py")}
    entry = "fixtures/compatibility/driver.py"
    a, b = "case_check_only", "case_candidate_success"
    before = runtime_cases.closure(texts, [(entry, "matrix")], {entry: a})
    changed = dict(texts)
    changed[entry] = changed[entry].replace("def " + b + "():", "def " + b + "():\n    assert True")
    assert runtime_cases.closure(changed, [(entry, "matrix")], {entry: a}) == before
    changed[entry] = texts[entry].replace("def " + a + "():", "def " + a + "():\n    assert True")
    assert runtime_cases.closure(changed, [(entry, "matrix")], {entry: a}) != before
    labels = ["g05-" + case for case in module.CASES]
    closure = {"packages": {}, "files": [{"path": path, "sha256": "before"} for path in (
        "inputs/upgrade-baseline/mods/g02a/turn-budget/payload.so",
        "inputs/mods/m02/example-tool/null-runtime/payload.so", "fixture/g05-transaction-checks.json")]}
    native = {label: retry.native_key(closure, label) for label in labels}
    closure["files"][0]["sha256"] = "after"
    assert {label for label in labels if retry.native_key(closure, label) != native[label]} == {
        "g05-" + case for case in ("check-only", "candidate-success", "labels-tamper", "variant-identity",
            "reuse-a-h0", "reuse-a-h1", "reuse-ab-h0", "reuse-ab-h1")}
    closure["files"][0]["sha256"] = "before"
    closure["files"][1]["sha256"] = "after"
    assert all(retry.native_key(closure, label) == native[label] for label in labels)
    closure["files"][2]["sha256"] = "after"
    assert {label for label in labels if retry.native_key(closure, label) != native[label]} == {
        "g05-" + case for case in module.CASES if case.startswith(("candidate-fault-", "source-drift-"))
        or case in ("state-copy", "source-busy")}
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory, \
            patch.object(module, "EVIDENCE", Path(directory) / "evidence"), \
            patch.object(module, "WORK", Path(directory) / "work"), \
            patch.object(module, "PROFILE", Path(directory) / "profile"), \
            patch.object(module, "case_check_only", return_value={"self_check": True}), \
            patch.object(runtime_cases, "enter"), patch.object(runtime_cases, "finish") as finish:
        module.matrix("check-only")
        emitted = finish.call_args.args[2]
        assert len(emitted) == 5 and all(row == {"cases": {"check-only": {"self_check": True}}} for row in emitted)
    try:
        runtime_cases.merge({"cases": {"same": 1}}, {"cases": {"same": 2}})
    except AssertionError:
        pass
    else:
        raise AssertionError("Conflicting report keys were accepted")
    print(json.dumps({"g05_self_check": "pass", "cases": len(module.CASES)}))


if __name__ == "__main__":
    action = sys.argv[1]
    if action == "produce":
        import runtime_consumer
        runtime_consumer.produce()
    elif action == "restore-reference":
        restore_reference(producer="--producer" in sys.argv[2:])
    elif action == "self-check":
        self_check()
    else:
        raise SystemExit("Unknown upgrade qualification command")
