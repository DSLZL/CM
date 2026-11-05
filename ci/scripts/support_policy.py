"""S02 qualification metadata; never part of a native compiler recipe."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import tomllib
from mod_manifest import read, write, sha

REPORTS = ("runtime-version-policy.json", "stable-abi-evidence.json", "zero-mod-host-baseline.json",
    "runtime-policy-cases.json", "runtime-golden-support.json")
POLICY = "fixtures/compatibility-policy/policy.json"
SCHEMA = "schemas/support-matrix.schema.json"


def reference(evidence, relative):
    path = evidence / relative
    assert path.is_file() and not path.is_symlink()
    return {"path": relative, "sha256": sha(path), "size": path.stat().st_size}


def validate(value, identities, environment, steps, audit, schema, evidence=None):
    """Validate this closed matrix format, including evidence semantics JSON Schema cannot express."""
    assert set(value) == set(schema["required"]) and value["schema_version"] == 1
    assert value["task_id"] == "CM-S02" and value["status"] == "pass" and value["release_ready"] is False
    assert datetime.fromisoformat(value["generated_at"]).utcoffset() is not None
    assert value["qualification"] and value["production_origin"]
    assert value["rows"] and len({row["id"] for row in value["rows"]}) == len(value["rows"])
    definition = schema["$defs"]["row"]
    for row in value["rows"]:
        assert set(row) == set(definition["required"])
        for key in ("level", "maturity", "kind"):
            assert row[key] in definition["properties"][key]["enum"]
        assert isinstance(row["id"], str) and row["id"] and isinstance(row["scope"], str) and row["scope"]
        assert isinstance(row["interfaces"], list) and row["interfaces"] and all(isinstance(item, str) for item in row["interfaces"])
        assert isinstance(row["exclusions"], list) and all(isinstance(item, str) for item in row["exclusions"])
        assert row["identity"] == identities[row["id"]] and row["environment"] == environment
        assert row["evidence"] and len({entry["path"] for entry in row["evidence"]}) == len(row["evidence"])
        for entry in row["evidence"]:
            assert set(entry) == {"path", "sha256", "size"}
            path = Path(entry["path"])
            assert not path.is_absolute() and ".." not in path.parts and path.as_posix() == entry["path"]
            assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) and type(entry["size"]) is int and entry["size"] > 0
            if evidence is not None:
                assert entry == reference(evidence, entry["path"]), "Evidence bytes changed"
        if row["level"] == "platform-verified":
            assert row["not_run_reason"] is None
            assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
            assert row["kind"] != "boundary" and row["steps"]
            for label, item in row["steps"].items():
                assert item == {key: field for key, field in steps[label].items() if key != "audit"}
                assert item["status"] == "pass" and item["origin"], "Missing actual execution"
        else:
            assert isinstance(row["not_run_reason"], str) and row["not_run_reason"]


def label_self_check(schema_path):
    import tempfile
    schema = read(schema_path)
    environment = {"target": "x86_64-unknown-linux-gnu", "image": "fixture"}
    identities = {"fixture": {"host_sha256": "a" * 64}}
    steps = {"native": {"status": "pass", "origin": {"run_id": 1}}}
    audit = {"status": "pass", "compiler_linker_jit_build_service_calls": 0}
    value = {"schema_version": 1, "task_id": "CM-S02", "status": "pass", "release_ready": False,
        "generated_at": "2026-11-05T00:00:00+00:00", "qualification": {"run_id": 2}, "production_origin": {"run_id": 1},
        "rows": [{"id": "fixture", "level": "platform-verified", "maturity": "experimental", "kind": "sdk",
            "scope": "finite test", "identity": identities["fixture"], "environment": environment,
            "interfaces": ["2.3"], "steps": steps, "evidence": [{"path": "native.json", "sha256": "b" * 64, "size": 1}],
            "exclusions": ["stable ABI promotion"], "not_run_reason": None}]}
    validate(value, identities, environment, steps, audit, schema)
    for field, changed in (("identity", {"host_sha256": "c" * 64}), ("environment", {"image": "other"}),
            ("level", "verified"), ("steps", {}), ("kind", "boundary"), ("evidence", [])):
        invalid = deepcopy(value)
        invalid["rows"][0][field] = changed
        try:
            validate(invalid, identities, environment, steps, audit, schema)
        except (AssertionError, KeyError):
            pass
        else:
            raise AssertionError("Unjustified qualification accepted: " + field)
    for changed in ({"status": "failed", "origin": {"run_id": 1}},
            {"status": "pass", "origin": {}}, {"status": "not_run"}):
        invalid = deepcopy(value)
        invalid["rows"][0]["steps"] = {"native": changed}
        try:
            validate(invalid, identities, environment, {"native": changed}, audit, schema)
        except (AssertionError, KeyError):
            pass
        else:
            raise AssertionError("Failed/partial evidence accepted")
    try:
        validate(value, identities, environment, steps, {**audit, "compiler_linker_jit_build_service_calls": 1}, schema)
    except AssertionError:
        pass
    else:
        raise AssertionError("Native build was accepted as zero-build")
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        path = directory / "native.json"
        write(path, {"status": "behavior_pass"})
        bound = deepcopy(value)
        bound["rows"][0]["evidence"] = [reference(directory, path.name)]
        validate(bound, identities, environment, steps, audit, schema, directory)
        path.write_text("{}")
        try:
            validate(bound, identities, environment, steps, audit, schema, directory)
        except AssertionError:
            pass
        else:
            raise AssertionError("Changed report bytes inherited qualification")


def reports(evidence, inputs, validation, closure, steps, audit, common):
    import runtime_cases
    import mod_manifest
    import runtime_sdk
    import runtime_state
    import runtime_hooks
    import sdk_seams
    producer = read(inputs / "producer.json")
    schema = read(inputs / "fixture" / SCHEMA)
    policy = read(inputs / "fixture" / POLICY)
    assert set(policy["cases"]) == set(runtime_cases.GROUPS["s02"])
    environment = {"target": producer["target"], "runner": validation["consumer_environment"],
        "rootfs_sha256": closure["sha256"]}
    host = {"metadata": read(inputs / "host/cm-host.json"), "executable_sha256": sha(inputs / "host/bin/codex"),
        "inventory": read(inputs / "host/cm-runtime-files.json"),
        "inventory_sha256": sha(inputs / "host/cm-runtime-files.json"), "production": producer["host"]}
    paths = {"a": "g02a/turn-budget", "b": "g02b/review-before-send", "c": "g03/tool-concurrency"}
    mods = {}
    for name, relative in paths.items():
        directory = inputs / "mods" / relative
        mods[name] = {"manifest": tomllib.loads((directory / "mod.toml").read_text()),
            "manifest_sha256": sha(directory / "mod.toml"), "payload_sha256": sha(directory / "payload.so")}
    baseline = read(inputs / "fixture/g05-producer.json")
    rows, identities = [], {}

    def row(name, scope, labels, reports, roles=(), maturity="stable", kind="sdk", interfaces=("2.2",)):
        assert labels and all(steps[label]["status"] == "pass" for label in labels)
        identity = {"host": host, "mods": {role: mods[role] for role in roles}}
        native_group = {"stable-abi": "m02", "experimental-seams": "g06", "exact-host": "g01"}.get(name)
        if native_group:
            identity["fixture_packages"] = {path.parent.relative_to(inputs).as_posix(): {
                "manifest": tomllib.loads(path.read_text()), "manifest_sha256": sha(path),
                "payload_sha256": sha(path.parent / "payload.so")}
                for path in sorted((inputs / "mods" / native_group).rglob("mod.toml"))}
            assert identity["fixture_packages"]
        if name == "upgrade-h0-h1":
            identity["baseline"] = baseline
        identities[name] = identity
        references = []
        for report in reports:
            document = read(evidence / report)
            assert document["status"] in ("pass", "behavior_pass")
            references.append(reference(evidence, report))
        rows.append({"id": name, "level": "platform-verified", "maturity": maturity, "kind": kind,
            "scope": scope, "identity": identity, "environment": environment, "interfaces": list(interfaces),
            "steps": {label: {key: item for key, item in steps[label].items() if key != "audit"} for label in labels},
            "evidence": references, "exclusions": policy["cases"]["boundaries"]["unsupported"], "not_run_reason": None})

    def phase(name):
        return [label for label in steps if label.startswith(name + "-")]

    row("stable-abi", "Existing v1/2.0/2.1/2.2 layout, lifetime and refusal contracts",
        phase("p04") + phase("m01") + phase("m02") + phase("m04") + ["s02-versions", "s02-contracts"],
        ["s02/contracts/reports.json", "s02/versions/reports.json", *mod_manifest.REPORTS, *runtime_sdk.REPORTS, *runtime_state.REPORTS],
        interfaces=("1.0", "2.0", "2.1", "2.2"))
    row("empty-disabled", "Same H, fresh Embedded exec, builtin tool/provider; installed A disabled",
        ["s02-zero-mod", "s02-disable"], ["s02/zero-mod/reports.json", "s02/disable/reports.json"])
    empty = read(evidence / "s02/zero-mod/reports.json")["reports"][REPORTS[2]]["zero_mod"]["run"]
    disabled = read(evidence / "s02/disable/reports.json")["reports"][REPORTS[2]]["disabled_restart"]["run"]
    assert (empty["host_sha256"], empty["original_count"], empty["return_code"]) == (
        disabled["host_sha256"], disabled["original_count"], disabled["return_code"])
    assert len(empty["provider_requests"]) == len(disabled["provider_requests"]) > 0
    for role, phase_name in (("a", "g02a"), ("b", "review"), ("c", "concurrency")):
        row(role, "Finite " + role.upper() + " suite on the current H", phase(phase_name),
            [("budget-" if role == "a" else "review-" if role == "b" else "concurrency-")
                + label.removeprefix(phase_name + "-") + ".json" for label in phase(phase_name)], (role,))
    row("abc", policy["cases"]["abc"]["scope"], ["s02-abc"], ["s02/abc/reports.json"], ("a", "b", "c"))
    row("upgrade-h0-h1", policy["cases"]["boundaries"]["upgrade"], phase("g05") + ["s02-boundaries", "s02-conflict"],
        ["upgrade-binary-reuse.json", "upgrade-compatibility-rejections.json", "upgrade-state-and-labels.json"],
        interfaces=("2.2", "manifest/protocol/state negotiation"))
    row("experimental-seams", "Finite G06 suites; no stable promotion", phase("g06"),
        ["s02/labels/reports.json", *sdk_seams.REPORTS], maturity="experimental", interfaces=("2.3", "nested runtime 2.2"))
    row("exact-host", "G01 prepared slots on exact H; unknown shapes refused", phase("g01"),
        ["s02/boundaries/reports.json", *runtime_hooks.REPORTS], kind="exact-host", interfaces=("exact build ID / ELF / map",))
    identities["deferred"] = {"unsupported": policy["cases"]["boundaries"]["unsupported"]}
    rows.append({"id": "deferred", "level": "declared", "maturity": "experimental", "kind": "boundary",
        "scope": "Explicit support exclusions", "identity": identities["deferred"], "environment": environment,
        "interfaces": ["outside this GNU Linux x64 qualification"], "steps": {},
        "evidence": [reference(evidence, "s02/boundaries/reports.json")],
        "exclusions": policy["cases"]["boundaries"]["unsupported"],
        "not_run_reason": "No native qualification for these excluded platforms or features"})
    matrix = {"schema_version": 1, "task_id": "CM-S02", "status": "pass",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "qualification": {key: common[key] for key in ("provenance", "consumer_job", "input_manifest_sha256", "rootfs_sha256")},
        "production_origin": validation["production_origin"], "rows": rows, "release_ready": False}
    validate(matrix, identities, environment, steps, audit, schema, evidence)
    write(evidence / "support-matrix.json", matrix)
    matrix_ref = reference(evidence, "support-matrix.json")
    for name in REPORTS:
        value = read(evidence / name)
        assert value["status"] == "behavior_pass"
        value.update(support_matrix=matrix_ref, support_line="GNU Linux x64", maintenance_years=None,
            program_complete=False, hot_unload=False, native_sandbox=False)
        write(evidence / name, value)


def self_check():
    from record_run import require_hosted_linux
    require_hosted_linux()
    import runtime_cases
    root = Path(__file__).resolve().parents[2]
    assert len(REPORTS) == len(set(REPORTS)) == 5
    assert set(read(root / POLICY)["cases"]) == set(runtime_cases.GROUPS["s02"])
    label_self_check(root / SCHEMA)
    print(json.dumps({"s02_self_check": "pass", "cases": len(runtime_cases.GROUPS["s02"])}))


if __name__ == "__main__":
    assert sys.argv[1:] == ["self-check"]
    self_check()
