#!/usr/bin/env python3
"""Finite S02 cases; native work runs only in the disconnected consumer."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tomllib

sys.path.insert(0, "/fixture/ci/scripts")
import ci_progress
import mod_manifest
import runtime_cases
import support_policy

INPUTS = Path("/inputs")
WORK = Path("/work")
PROFILE = Path("/profile")
EVIDENCE = Path("/evidence")
BINARY = INPUTS / "host/bin/codex"


def module(relative):
    path = Path("/fixture/fixtures") / relative
    spec = importlib.util.spec_from_file_location("cm_support_" + path.parent.name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def policy(case):
    return mod_manifest.read(Path("/fixture/fixtures/compatibility-policy/policy.json"))["cases"][case]


def report(index, key, value):
    rows = [{} for _ in support_policy.REPORTS]
    rows[index] = {key: value}
    return rows


def case_versions():
    value = {**policy("versions"), "support_line": mod_manifest.TARGET}
    assert value["maintenance_years"] is None and not value["semver_implies_compatibility"]
    assert value["stable_abi"] == ["1.0", "2.0", "2.1", "2.2"] and value["experimental_abi"] == ["2.3"]
    assert len(value["dimensions"]) == len(set(value["dimensions"])) == 9
    assert set(value["dimensions"]) == {"artifact", "host_api", "abi", "capability", "manifest", "protocol", "state", "target", "hook"}
    schema = mod_manifest.read(Path("/fixture/schemas/support-matrix.schema.json"))
    assert schema["properties"]["task_id"] == {"const": "CM-S02"}
    assert False, "CM-MP-LA V05 controlled single-case failure"
    return report(0, "independent_version_dimensions", value)


def case_contracts():
    value = policy("contracts")
    identity = mod_manifest.read(INPUTS / "host/cm-host.json")
    sections = value["sections"]
    assert {row["abi"] for row in sections} == {"1.0", "2.0", "2.1", "2.2"}
    assert len({row["id"] for row in sections}) == len(sections)
    for row in [*sections, value["experimental"]]:
        assert row["contract"] in value["contracts"] and row["host_size"] > 0 and row["mod_size"] > 0
    # Native layout, lifetime and rejection checks remain separate, hashed baseline cases.
    return report(1, "section_contract_inventory", {"inventory": value, "host_metadata": identity})


def empty_run(home, directory):
    seams = module("sdk-seams/driver.py")
    value = seams.real(home, directory)
    assert value["original_count"] == 1 and not value["mods"]
    assert not any(row["event"] in ("dlopen-start", "entry-start", "init-start") for row in value["native"])
    ready = [row["detail"] for row in value["native"] if row["event"] == "ready"]
    assert len(ready) == 1 and ready[0]["mod_count"] == 0 and not ready[0]["plan"]["mods"]
    assert mod_manifest.sha(BINARY) == value["host_sha256"]
    return value


def case_zero_mod():
    mod_manifest.selection(PROFILE, [])
    return report(2, "zero_mod", {"scope": policy("zero-mod"), "run": empty_run(PROFILE, EVIDENCE / "exec")})


def case_disable():
    owner = "org.example.turn-budget"
    shutil.copytree(INPUTS / "mods/g02a/turn-budget", PROFILE / "mods" / owner)
    mod_manifest.selection(PROFILE, [owner])
    enabled = module("sdk-seams/driver.py").real(PROFILE, EVIDENCE / "enabled")
    assert any(row["event"] == "runtime-request" and row["detail"]["event_kind"] == 12 for row in enabled["native"])
    mod_manifest.selection(PROFILE, [])
    before = mod_manifest.sha(PROFILE / "mods" / owner / "payload.so")
    value = empty_run(PROFILE, EVIDENCE / "restart")
    assert before == mod_manifest.sha(PROFILE / "mods" / owner / "payload.so")
    return report(2, "disabled_restart", {"scope": policy("disable"), "installed_payload_sha256": before,
        "enabled_process": enabled, "run": value})


def case_abc():
    value = policy("abc")
    budget = module("turn-budget/driver.py")
    management = EVIDENCE / "management"
    for relative in ("m02/lifecycle-audit/normal", "m02/example-tool/normal", "g02a/turn-budget",
            "g02b/review-before-send", "g03/tool-concurrency"):
        budget.cm(PROFILE, management, "install", INPUTS / "mods" / relative)
    mod_manifest.write_toml(PROFILE / "cm-runtime.toml", {"format_version": 2, "enabled": [],
        "mods": {"org.example.turn-budget": {"policy": budget.policy(value["budget"])}}})
    budget.cm(PROFILE, management, "lock")
    review = module("review-before-send/driver.py")
    terminal = review.Terminal("s02", "abc", PROFILE, directory=EVIDENCE / "tui")
    try:
        terminal.review("CM_M02_support-abc")
        terminal.send(b"\r\t\r")
        terminal.quiet()
        assert not budget.admissions(terminal.directory)
        terminal.provider.tool = True
        terminal.send("y")
        terminal.wait(lambda: terminal.managed.tui_message_visible(terminal.output, "support-abc"), "ABC tool reply")
        terminal.wait_turns()
        requests = budget.business_requests(terminal.provider)
        assert len(requests) == 2 and not terminal.provider.errors
        admissions = budget.admissions(terminal.directory)
        turns = {row["turn"] for row in admissions}
        charges = {turn: budget.charged(budget.admissions(terminal.directory, turn)) for turn in turns}
        assert list(charges.values()).count([1, 2]) == 1, charges
        kinds = {row["detail"]["event_kind"] for row in terminal.native() if row["event"] == "runtime-request"}
        assert {12, 13, 14} <= kinds, kinds
        assert len(terminal.reviews()) == 1
    except BaseException:
        terminal.close(False)
        raise
    else:
        terminal.close(True)
    return report(4, "finite_same_process_abc", {"scope": value, "charges": charges,
        "event_kinds": sorted(kinds), "process": mod_manifest.read(terminal.directory / "result.json")})


def case_conflict():
    owner = "org.example.turn-budget"
    for name in (owner, "other-budget"):
        shutil.copytree(INPUTS / "mods/g02a/turn-budget", PROFILE / "mods" / name)
    path = PROFILE / "mods/other-budget/mod.toml"
    fields = tomllib.loads(path.read_text())
    fields["id"] = "other-budget"
    mod_manifest.write_toml(path, fields)
    mod_manifest.selection(PROFILE, [owner, "other-budget"])
    seams = module("sdk-seams/driver.py")
    value = seams.command(PROFILE, ["cm", "--home", PROFILE, "plan"], EVIDENCE / "plan", good=False)
    seams.no_native(value)
    assert owner in value["stderr"] and "other-budget" in value["stderr"], value
    diagnostic = next(json.loads(line) for line in value["stderr"].splitlines() if line.startswith("{"))
    assert diagnostic["already_native_executed"] is False and diagnostic["field"]
    assert diagnostic["code"] == "exclusive_conflict", diagnostic
    return report(3, "exclusive_resource_conflict", {"scope": policy("conflict"), "rejection": value})


def case_labels():
    value = policy("labels")
    support_policy.label_self_check(Path("/fixture/schemas/support-matrix.schema.json"))
    assert value["changed_bytes_inherit"] is False
    return report(4, "evidence_label_refusals", value)


def case_boundaries():
    value = policy("boundaries")
    if runtime_cases.historical_hosts():
        baseline = mod_manifest.read(INPUTS / "upgrade-baseline/reference.json")
        assert baseline["qualification"]["ci"]["production_origin"]
        assert baseline["pin"]["executable_sha256"] != mod_manifest.sha(BINARY)
    else:
        baseline = runtime_cases.deferred_check("s02-boundaries/legacy-upgrade")
    assert not value["release_ready"]
    return report(3, "upgrade_and_hook_boundaries", {"scope": value, "original_reference": baseline})


@ci_progress.case()
def matrix(case):
    runtime_cases.enter(globals(), "s02", case)
    WORK.mkdir(parents=True)
    PROFILE.mkdir(parents=True)
    EVIDENCE.mkdir(parents=True)
    runtime_cases.finish("s02", case, globals()[runtime_cases.function(case, "s02")](), support_policy.REPORTS)


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "matrix"
    matrix(sys.argv[2])
