#!/usr/bin/env python3
"""Independent upgrade transactions against the real retained and current Hosts."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci/scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native-loader"))
import ci_progress
import core_acceptance as core
import mod_manifest
import runtime_cases
from runtime_upgrade import REPORTS

INPUTS = Path("/inputs")
BASELINE = INPUTS / "upgrade-baseline"
OLD = BASELINE / "host/bin/codex"
NEW = INPUTS / "host/bin/codex"
WORK = Path("/work")
PROFILE = Path("/profile")
EVIDENCE = Path("/evidence")
CASES = runtime_cases.GROUPS["g05"]
A = "org.example.turn-budget"
B = "org.example.review-before-send"


def module(relative):
    path = Path(__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location("cm_upgrade_" + path.parent.name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(path):
    result = {}
    for item in sorted(path.rglob("*")):
        metadata = item.lstat()
        name = item.relative_to(path).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            result[name] = {"link": os.readlink(item)}
        elif stat.S_ISREG(metadata.st_mode):
            result[name] = {"sha256": sha(item), "mode": stat.S_IMODE(metadata.st_mode), "links": metadata.st_nlink}
        elif not stat.S_ISDIR(metadata.st_mode):
            result[name] = {"special": stat.S_IFMT(metadata.st_mode)}
    return result


def cm(home, *args, binary=OLD, success=True):
    return module("turn-budget/driver.py").cm(home, EVIDENCE / "management", *args, binary=binary, success=success)


def generation(home):
    active = json.loads((home / "cm-profile.json").read_text())
    value = json.loads((home / "store/generations" / active["generation"]).read_text())
    return active, value


def change_generation(home, update):
    active, value = generation(home)
    update(value)
    data = canonical(value)
    digest = hashlib.sha256(data).hexdigest()
    path = home / "store/generations" / digest
    path.write_bytes(data)
    path.chmod(0o600)
    active["generation"] = digest
    (home / "cm-profile.json").write_bytes(canonical(active))


def install(*, roles=(), state=False, hook=False):
    home = PROFILE / "old"
    packages = ([INPUTS / "mods/m04/audit", INPUTS / "mods/m04/v1.cmod"] if state else
        [] if hook else [INPUTS / "mods/m02/lifecycle-audit/normal", INPUTS / "mods/m02/example-tool/normal"])
    packages += [BASELINE / "mods" / relative for role, relative in
        (("a", "g02a/turn-budget"), ("b", "g02b/review-before-send")) if role in roles]
    if hook:
        packages.append(BASELINE / "mods/g01/a/normal")
    for package in packages:
        cm(home, "install", package)
    if "a" in roles:
        mod_manifest.write_toml(home / "cm-runtime.toml", {"format_version": 2, "enabled": [],
            "mods": {A: {"policy": module("turn-budget/driver.py").policy(2)}}})
        cm(home, "lock")
    return home


def upgrade(home, *, candidate=None, check=False, variants=(), options=(), success=True):
    candidate = candidate or PROFILE / "candidate"
    before = inventory(home)
    was_active = (candidate / "cm-profile.json").exists()
    arguments = [*options, "upgrade", candidate, *(["--check"] if check else [])]
    for package in variants:
        arguments += ["--variant", package]
    value = cm(home, *arguments, binary=NEW, success=success)
    after = inventory(home)
    assert before == after, "Upgrade changed source profile, packages, locks or state"
    assert value["already_native_executed"] is False
    if success:
        assert value["declared_compatible"] and value["verified"] is False
        assert value["committed"] is (not check)
    elif candidate != home and not was_active and value["code"] != "committed_durability":
        assert not (candidate / "cm-profile.json").exists()
    return {"result": value, "source_before": before, "source_after": after}


def usable(home, *, binary=OLD, name="old-still-usable", state_action=None, value=None):
    sdk = module("runtime-sdk/driver.py")
    directory = EVIDENCE / name
    provider = sdk.Provider()
    client = None
    state_fixture = module("state/driver.py")
    try:
        with state_fixture.state_environment(sdk, state_action or "read", value):
            client = sdk.Client(directory, home, provider, mode="normal", binary=binary)
        thread = client.start()
        completed = client.turn(thread, name)
        assert completed["status"] == "completed"
        client.close()
        client = None
        rows = core.trace_rows(directory / "native.jsonl")
        ready = next(row["detail"] for row in rows if row["event"] == "ready")
        assert ready["plan"]["host"]["executable_sha256"] == sha(binary)
        assert not provider.errors
        return {"binary_sha256": sha(binary), "completed": completed, "provider_requests": provider.requests,
            "native_trace": rows, "file_state": sdk.rows(directory / "events.jsonl")}
    finally:
        if client:
            client.close()
        provider.close()


def variant(home, update, *, owner="example-tool", name="variant"):
    _, selected = generation(home)
    package = WORK / name
    shutil.copytree(home / "store/objects" / selected["installed"][owner], package)
    fields = tomllib.loads((package / "mod.toml").read_text())
    update(fields, package)
    mod_manifest.manifest(package, fields)
    return package


def rejected_variant(update, *, owner="example-tool", field=None, code=None, state=False, hook=False):
    home = install(state=state, hook=hook)
    if state:
        usable(home, state_action="write", value="old-state", name="old-state-write")
    package = variant(home, update, owner=owner)
    result = upgrade(home, variants=[package], check=True, success=False)
    error = result["result"]
    assert error["mod_id"] == owner, error
    if field:
        assert error["field"] == field, error
    if code:
        assert error["code"] == code, error
    assert not (PROFILE / "candidate").exists()
    result["old_business"] = usable(home) if not hook else {"old_hook_package_unchanged": True}
    return result


def case_check_only():
    home = install(roles=("a", "b"))
    before = inventory(home)
    checked = upgrade(home, check=True)
    assert inventory(home) == before and not (PROFILE / "candidate").exists()
    wrong = variant(home, lambda fields, _: fields["compat"]["required_capabilities"].append("core.unknown.v99"))
    rejected = upgrade(home, check=True, variants=[wrong], success=False)
    assert rejected["result"]["code"] == "unknown_capability"
    strict = cm(home, "doctor", binary=NEW, success=False)
    assert strict["code"] == "managed_profile", strict
    empty = PROFILE / "empty-check"
    empty.mkdir(mode=0o700)
    inode = empty.stat().st_ino
    empty_check = upgrade(home, candidate=empty, check=True)
    assert not list(empty.iterdir()) and empty.stat().st_ino == inode
    fields = tomllib.loads((home / "cm-runtime.toml").read_text())
    fields["profiles"] = {"limited": {"mods": {A: {"policy": module("turn-budget/driver.py").policy(1)}}}}
    mod_manifest.write_toml(home / "cm-runtime.toml", fields)
    options = ["--cm-profile", "limited", "--cm-set", A + ".policy.max_main_samples=3"]
    cm(home, *options, "lock")
    missing_options = upgrade(home, check=True, success=False)
    assert missing_options["result"]["code"] == "upgrade_source_lock"
    reproduced = upgrade(home, check=True, options=options)
    return {"checked": checked, "rejected": rejected, "ordinary_self_host_guard": strict,
        "empty_candidate_check": empty_check, "missing_source_options": missing_options,
        "reproduced_source_configuration": reproduced}


def case_candidate_success():
    home = install(roles=("a", "b"))
    cm(home, "disable", B)
    (home / "auth.json").write_text('{"fixture":"must stay in the old home"}')
    (home / "session-data").write_bytes(b"unrelated session fixture")
    _, old = generation(home)
    value = upgrade(home)
    active, new = generation(PROFILE / "candidate")
    assert new["installed"] == old["installed"] and new["enabled"] == old["enabled"]
    assert new["consumed"] == old["consumed"] and B not in new["enabled"]
    assert new["config_sha256"] == old["config_sha256"]
    assert active["host"]["executable_sha256"] == sha(NEW)
    assert active["host"]["executable_sha256"] != generation(home)[0]["host"]["executable_sha256"]
    for digest in old["installed"].values():
        assert inventory(home / "store/objects" / digest) == inventory(PROFILE / "candidate/store/objects" / digest)
    assert not (PROFILE / "candidate/auth.json").exists() and not (PROFILE / "candidate/session-data").exists()
    candidate_before = inventory(PROFILE / "candidate")
    refused = upgrade(home, success=False)
    assert refused["result"]["code"] == "upgrade_destination"
    assert inventory(PROFILE / "candidate") == candidate_before
    value["existing_candidate_refused"] = refused
    value["old_business"] = usable(home)
    return value


def case_candidate_dependency():
    return rejected_variant(lambda fields, _: fields.update(dependencies=[{"id": "missing-owner", "version": "^1"}]),
        code="missing_dependency")


def case_candidate_conflict():
    return rejected_variant(lambda fields, _: fields.update(conflicts=["lifecycle-audit"]), code="declared_conflict")


def source_drift(kind):
    home = install()
    active = (home / "cm-profile.json").read_bytes()
    changed = None
    original = None
    moved = None
    if kind == "descriptor":
        changed = home / "cm-profile.json"
        original = changed.read_bytes()
        changed.write_bytes(b"{}")
    elif kind == "lock":
        change_generation(home, lambda value: value.update(lock_sha256="0" * 64))
    elif kind == "config":
        changed = home / "cm-runtime.toml"
        changed.write_text("format_version=2\nenabled=[]\n")
    elif kind == "object":
        _, selected = generation(home)
        changed = home / "store/objects" / selected["installed"]["example-tool"] / "payload.so"
        original = changed.read_bytes()
        changed.write_bytes(original + b"tampered")
    elif kind == "package":
        value = json.loads(active)
        value["host"]["inventory_sha256"] = "0" * 64
        (home / "cm-profile.json").write_bytes(canonical(value))
    elif kind == "directory":
        moved = home.with_name("moved-source")
        home.rename(moved)
        home.symlink_to(moved, target_is_directory=True)
    result = upgrade(home, check=True, success=False)
    if moved:
        home.unlink()
        moved.rename(home)
    if changed:
        if original is None:
            changed.unlink()
        else:
            changed.write_bytes(original)
    (home / "cm-profile.json").write_bytes(active)
    result["old_business_after_controlled_fixture_restore"] = usable(home)
    result["stale_input_interleaving"] = transaction_proof("upgrade_commit_revalidates_source_at_publication")
    if kind == "package":
        result["same_bytes_package_inode_swap"] = transaction_proof("upgrade_package_member_identity_detects_same_bytes_replacement")
    return result


def case_source_drift_descriptor():
    return source_drift("descriptor")


def case_source_drift_lock():
    return source_drift("lock")


def case_source_drift_config():
    return source_drift("config")


def case_source_drift_object():
    return source_drift("object")


def case_source_drift_package():
    return source_drift("package")


def case_source_drift_directory():
    return source_drift("directory")


def transaction_proof(name):
    proof = mod_manifest.read(Path("/fixture/g05-transaction-checks.json"))
    assert proof["tests"][name] == "pass"
    assert proof["host_sha256"] == sha(NEW)
    return {"test": name, "status": "pass", "execution": "hosted Rust test; test-only fault/interleaving",
        "origin": proof["origin"], "log_sha256": proof["log_sha256"]}


def case_candidate_fault_copy():
    return transaction_proof("upgrade_state_copy_faults_preserve_source_and_leave_no_active_candidate")


def case_candidate_fault_enospc():
    return transaction_proof("upgrade_state_copy_faults_preserve_source_and_leave_no_active_candidate")


def case_candidate_fault_pre_rename():
    return transaction_proof("descriptor_is_unchanged_before_commit_and_truthful_after_rename")


def case_candidate_fault_post_rename_sync():
    return transaction_proof("descriptor_is_unchanged_before_commit_and_truthful_after_rename")


def case_source_busy():
    home = install(state=True)
    result = []
    for path in (home / ".cm-write.lock", home / "state/cm-files-v1/.lease"):
        with path.open("rb+") as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result.append(upgrade(home, check=True, success=False))
    assert all(row["result"]["code"] in ("managed_profile", "state_busy") for row in result)
    result.append(upgrade(home, check=True))
    return {"leases": result, "real_runtime_lease": transaction_proof("upgrade_state_busy_incompatible_and_changed_inputs_fail_closed")}


def case_destination_existing():
    home = install()
    destination = PROFILE / "candidate"
    destination.mkdir(mode=0o700)
    (destination / "preserve").write_bytes(b"not an empty profile")
    before = inventory(destination)
    rejected = upgrade(home, success=False)
    assert rejected["result"]["code"] == "upgrade_destination" and inventory(destination) == before
    overlap = upgrade(home, candidate=home, check=True, success=False)
    assert overlap["result"]["code"] == "upgrade_destination"
    return {"existing": rejected, "overlap": overlap}


def case_abi_major():
    return rejected_variant(lambda fields, _: fields["compat"].update(abi_major=99), field="compat.abi_major")


def case_abi_minor():
    return rejected_variant(lambda fields, _: fields["compat"].update(abi_minor_min=99, abi_minor_max=99), field="compat.abi_minor")


def case_declared_function_table():
    home = install()
    value = upgrade(home, check=True)
    assert value["result"]["verified"] is False
    return {"static": value, "dynamic_function_table_inspected": False,
        "dynamic_contract_cases": ["m02-rejections-null-runtime", "m02-rejections-runtime-short", "m02-rejections-stride"]}


def case_missing_capability():
    return rejected_variant(lambda fields, _: fields["compat"]["required_capabilities"].append("core.unknown.v99"),
        code="unknown_capability")


def case_protocol_resource():
    return rejected_variant(lambda fields, _: fields["contributions"][0].update(resource="runtime.tool.v999"),
        code="contribution_contract")


def case_target_cpu():
    home = install()
    rejected = {}
    for field, value in (("target", "aarch64-unknown-linux-gnu"), ("cpu", "x86-64-v4")):
        package = variant(home, lambda fields, _: fields["binary"].update({field: value}), name=field)
        rejected[field] = upgrade(home, check=True, variants=[package], success=False)
        assert rejected[field]["result"]["field"] == "binary." + field
    return {"rejections": rejected, "old_business": usable(home)}


def case_glibc():
    return rejected_variant(lambda fields, _: fields["binary"].update(glibc_min="99.0"), field="binary.glibc_min")


def case_native_dependency():
    def missing(fields, package):
        payload = package / "payload.so"
        data = payload.read_bytes()
        assert b"libc.so.6\0" in data
        payload.write_bytes(data.replace(b"libc.so.6\0", b"libz.so.0\0"))
        fields["binary"]["sha256"] = sha(payload)
    return rejected_variant(missing, code="installation")


def reuse(role, host):
    roles = ("a", "b") if role == "ab" else (role,)
    home = install(roles=roles)
    selected_binary = OLD
    candidate = None
    if host == "h1":
        candidate = upgrade(home)
        home = PROFILE / "candidate"
        selected_binary = NEW
    before = {key: inventory(BASELINE / "mods" / relative) for key, relative in
        (("a", "g02a/turn-budget"), ("b", "g02b/review-before-send")) if key in roles}
    observations = {}
    if roles == ("a",):
        sdk = module("runtime-sdk/driver.py")
        budget = module("turn-budget/driver.py")
        provider = budget.Provider(desired=2, held=True)
        directory = EVIDENCE / "budget-stdio"
        client = None
        try:
            client = sdk.Client(directory, home, provider, mode="async", binary=selected_binary)
            thread = client.start()
            turn = budget.begin(client, thread, "cancel-upgrade")
            provider.entered("cancel-upgrade")
            client.call("turn/interrupt", {"threadId": thread, "turnId": turn})
            provider.release.set()
            budget.complete(client, turn, "interrupted")
            assert budget.charged(budget.admissions(directory, turn)) == [1]
            later = client.turn(thread, "after-upgrade", release=True)
            assert budget.charged(budget.admissions(directory, later["turn"])) == [1, 2]
            client.close()
            client = None
            observations["stdio_budget_and_cancellation"] = {"cancelled": turn, "resumed": later,
                "admissions": budget.admissions(directory), "provider_requests": provider.requests}
        finally:
            if client:
                client.close()
            provider.close()
        provider = budget.Provider(desired=3)
        directory = EVIDENCE / "budget-exec"
        directory.mkdir(parents=True)
        try:
            command = [str(selected_binary), "cm", "--home", str(home), "launch", "--",
                *sdk.command(directory, provider.endpoint, "embedded", token="budget-exec")[1:]]
            process = subprocess.run(command, env=sdk.environment(home, directory), cwd=directory,
                capture_output=True, text=True, timeout=120)
            mod_manifest.write(directory / "result.json", {"command": command, "return_code": process.returncode,
                "provider_requests": provider.requests, "provider_errors": provider.errors})
            assert process.returncode != 0 and len(budget.business_requests(provider)) == 2
            assert not provider.errors and budget.charged(budget.admissions(directory)) == [1, 2]
            observations["exec_budget_enforced"] = {"return_code": process.returncode, "requests": provider.requests}
        finally:
            provider.close()
    if "b" in roles:
        review = module("review-before-send/driver.py")
        terminal = review.Terminal("g05", "review-upgrade", home, binary=selected_binary, directory=EVIDENCE / "tui")
        try:
            terminal.review("CM_M02_cancelled")
            terminal.quiet()
            terminal.send(b"\x1b")
            terminal.send(b"\x03")
            terminal.review("CM_M02_accepted")
            terminal.send(b"\r\t\r")
            terminal.quiet()
            if role == "ab":
                budget = module("turn-budget/driver.py")
                assert not budget.admissions(terminal.directory), "Cancelled review consumed the turn budget"
                terminal.provider.tool = True
                terminal.send("y")
                terminal.wait(lambda: terminal.managed.tui_message_visible(terminal.output, "accepted"),
                    "reviewed tool round trip")
                terminal.wait_turns()
                requests = budget.business_requests(terminal.provider)
                assert len(requests) == 2 and not terminal.provider.errors, (requests, terminal.provider.errors)
                assert all(row["token"] == "accepted" for row in requests), requests
                admissions = budget.admissions(terminal.directory)
                turns = {row["turn"] for row in admissions}
                charges = {turn: budget.charged(budget.admissions(terminal.directory, turn)) for turn in turns}
                assert list(charges.values()).count([1, 2]) == 1, charges
                assert all(not row["detail"].get("error") for row in admissions), admissions
                observations["tui_budget_and_cancelled_review"] = {"admissions": admissions, "charges": charges}
            else:
                terminal.complete("accepted")
            assert len(terminal.reviews()) == 2
        except BaseException:
            terminal.close(False)
            raise
        else:
            terminal.close(True)
        observations["tui_review_y_esc_exactly_once"] = mod_manifest.read(EVIDENCE / "tui/result.json")
    after = {key: inventory(BASELINE / "mods" / relative) for key, relative in
        (("a", "g02a/turn-budget"), ("b", "g02b/review-before-send")) if key in roles}
    assert before == after
    active, selected = generation(home)
    return {"host": host, "host_receipt": active["host"], "lock_sha256": selected["lock_sha256"],
        "config_sha256": selected["config_sha256"], "state_contracts": selected.get("state"),
        "original_packages_before": before, "original_packages_after": after,
        "reference": mod_manifest.read(BASELINE / "reference.json"), "candidate": candidate,
        "observations": observations, "static_verified_claim": False}


def case_reuse_a_h0():
    return reuse("a", "h0")


def case_reuse_a_h1():
    return reuse("a", "h1")


def case_reuse_b_h0():
    return reuse("b", "h0")


def case_reuse_b_h1():
    return reuse("b", "h1")


def case_reuse_ab_h0():
    return reuse("ab", "h0")


def case_reuse_ab_h1():
    return reuse("ab", "h1")


def case_exact_old():
    home = install(hook=True)
    value = upgrade(home, check=True, success=False)
    assert value["result"]["field"] == "compat.exact_host.build_id"
    return value


def case_exact_no_variant():
    home = install(hook=True)
    value = upgrade(home, success=False)
    assert value["result"]["field"] == "compat.exact_host.build_id"
    assert not (PROFILE / "candidate").exists()
    return value


def case_exact_variant():
    home = install(hook=True)
    authored = module("runtime-hooks/driver.py").install(WORK / "author-variant", ("a/normal",))
    explicit = authored / "mods/0-a-normal"
    assert sha(explicit / "payload.so") == sha(INPUTS / "mods/g01/a/normal/payload.so")
    before = inventory(explicit)
    result = upgrade(home, variants=[explicit])
    candidate = PROFILE / "candidate"
    directory = EVIDENCE / "actual-core"
    business = core.run_case(Path("/fixture"), directory, NEW, candidate, True, scenario="parallel",
        restrictive=True, expected_releases=1, sandboxed=True,
        cm_options=module("managed-package/driver.py").launch_command(NEW, candidate, [])[1:])
    trace = core.trace_rows(directory / "core-trace.jsonl")
    assert any(row["event"] == "hook-enter" and row["detail"]["mod"] == "compose-a" for row in trace)
    assert inventory(explicit) == before
    return {"transaction": result, "explicit_package": before, "actual_core": business,
        "config_fixture": tomllib.loads((explicit / "mod.toml").read_text())["config"],
        "author": mod_manifest.read(INPUTS / "producer.json")["authors"]["g01/a/normal"]}


def wrong_exact(field):
    home = install(hook=True)
    package = WORK / "author-variant"
    shutil.copytree(INPUTS / "mods/g01/a/normal", package)
    fields = tomllib.loads((package / "mod.toml").read_text())
    fields["compat"]["exact_host"][field] = ("sha256:" if field == "build_id" else "") + "0" * 64
    mod_manifest.manifest(package, fields)
    result = upgrade(home, check=True, variants=[package], success=False)
    assert result["result"]["field"] == "compat.exact_host." + field
    return result


def case_exact_wrong_build():
    return wrong_exact("build_id")


def case_exact_wrong_elf():
    return wrong_exact("executable_sha256")


def case_exact_wrong_map():
    return wrong_exact("patch_map_sha256")


def case_variant_identity():
    home = install()
    package = variant(home, lambda fields, _: fields.update(version="9.0.0"))
    mismatch = upgrade(home, check=True, variants=[package], success=False)
    unknown = upgrade(home, check=True, variants=[BASELINE / "mods/g02a/turn-budget"], success=False)
    valid = INPUTS / "mods/m02/example-tool/normal"
    duplicate = upgrade(home, check=True, variants=[valid, valid], success=False)
    assert all(row["result"]["code"] == "upgrade_variant" for row in (mismatch, unknown, duplicate))
    return {"version_mismatch": mismatch, "unknown_id": unknown, "duplicate_id": duplicate}


def state_path(home, owner="example-tool", binary=OLD):
    return Path(cm(home, "state", "path", owner, binary=binary)["path"])


def state_upgrade(*, remove=False):
    home = install(state=True)
    usable(home, state_action="write", value="old-state", name="old-state-write")
    if remove:
        cm(home, "remove", "lifecycle-audit")
    result = upgrade(home)
    candidate = PROFILE / "candidate"
    old = generation(home)[1]
    new = generation(candidate)[1]
    assert old["state"]["home_id"] != new["state"]["home_id"]
    assert old["state"]["tree"] != new["state"]["tree"]
    assert old["state"]["owners"] == new["state"]["owners"]
    for owner in old["state"]["owners"]:
        before = home / "state/cm-files-v1/trees" / old["state"]["tree"] / owner
        after = candidate / "state/cm-files-v1/trees" / new["state"]["tree"] / owner
        assert inventory(before) == inventory(after)
        for path in before.rglob("*"):
            if path.is_file():
                copy = after / path.relative_to(before)
                assert (path.stat().st_dev, path.stat().st_ino) != (copy.stat().st_dev, copy.stat().st_ino)
    return home, candidate, result


def case_state_copy():
    home, candidate, result = state_upgrade(remove=True)
    assert "lifecycle-audit" not in generation(candidate)[1]["installed"]
    assert "lifecycle-audit" in generation(candidate)[1]["state"]["owners"]
    result["candidate_business"] = usable(candidate, binary=NEW, name="candidate-state-read")
    result["old_business"] = usable(home, name="old-state-read")
    result["copy_isolation_test"] = transaction_proof("upgrade_state_copy_has_fresh_identity_and_retains_unselected_owners")
    return result


def case_state_reject_owner():
    return rejected_variant(lambda fields, _: fields["state"].update(owner="another-owner"), state=True,
        field="state")


def case_state_reject_schema():
    return rejected_variant(lambda fields, _: fields["state"].update(schema="other-schema"), state=True,
        code="state_compatibility")


def case_state_reject_version():
    return rejected_variant(lambda fields, _: fields["state"].update(version=2), state=True,
        code="state_compatibility")


def case_state_reject_unsafe_entry():
    home = install(state=True)
    state_path(home).joinpath("unsafe").symlink_to("/etc/passwd")
    value = upgrade(home, check=True, success=False)
    assert value["result"]["code"] == "state_ownership"
    return value


def case_state_reject_overflow():
    home = install(state=True)
    path = state_path(home) / "oversized"
    with path.open("wb") as stream:
        stream.truncate(1024 ** 3 + 1)
    path.chmod(0o600)
    value = upgrade(home, check=True, success=False)
    assert value["result"]["code"] == "state_budget"
    return value


def case_state_reject_pending_cleanup():
    home = install(state=True)
    def pending(value):
        view = value["state"]
        owner = view["owners"]["example-tool"]
        view["cleanups"]["example-tool"] = {"tree": view["tree"], "owner": "example-tool",
            "schema": owner["schema"], "version": owner["version"], "operation": "a" * 64}
    change_generation(home, pending)
    value = upgrade(home, check=True, success=False)
    assert value["result"]["code"] == "state_ownership"
    return value


def file_values(result):
    return [row["value"] for row in result["file_state"] if row["event"] == "file-state"]


def case_state_return():
    home, candidate, transaction = state_upgrade()
    changed = usable(candidate, binary=NEW, name="candidate-only-write", state_action="write", value="new-state")
    new_data = inventory(candidate / "state")
    old = usable(home, name="old-retained-read")
    assert "v1:old-state" in file_values(old), old
    assert "v1:new-state" in file_values(changed), changed
    assert inventory(candidate / "state") == new_data
    return {"transaction": transaction, "candidate_new_data": changed, "old_data": old, "inverse_copy": False}


def checkpoint_binding(field):
    home, candidate, result = state_upgrade()
    old_checkpoint = cm(home, "state", "checkpoint")
    own_checkpoint = cm(candidate, "state", "checkpoint", binary=NEW)
    namespace = candidate / "state/cm-files-v1/checkpoints"
    checkpoint = own_checkpoint
    if field == "home":
        source = home / "state/cm-files-v1/checkpoints" / old_checkpoint["checkpoint"]
        destination = namespace / old_checkpoint["checkpoint"]
        shutil.copytree(source, destination)
        checkpoint = old_checkpoint
        digest = old_checkpoint["checkpoint"]
    else:
        source = namespace / own_checkpoint["checkpoint"]
        record = json.loads((source / "checkpoint.json").read_text())
        if field == "host":
            record["host"] = generation(home)[0]["host"]
        elif field == "generation":
            record["generation"] = "0" * 64
        elif field == "config":
            record["config_sha256"] = "0" * 64
        elif field == "owners":
            record["owners"]["example-tool"]["version"] += 1
        data = canonical(record)
        digest = hashlib.sha256(data).hexdigest()
        destination = namespace / digest
        shutil.copytree(source, destination)
        (destination / "checkpoint.json").write_bytes(data)
    before = inventory(candidate)
    rejected = cm(candidate, "rollback", own_checkpoint["generation"], "--restore", digest, binary=NEW, success=False)
    assert rejected["code"] in ("state_checkpoint", "state_compatibility", "state_ownership")
    assert inventory(candidate) == before
    result["foreign_checkpoint"] = checkpoint
    result["rejected_binding"] = {"field": field, "error": rejected}
    return result


def case_state_checkpoint_home():
    return checkpoint_binding("home")


def case_state_checkpoint_host():
    return checkpoint_binding("host")


def case_state_checkpoint_generation():
    return checkpoint_binding("generation")


def case_state_checkpoint_config():
    return checkpoint_binding("config")


def case_state_checkpoint_owners():
    return checkpoint_binding("owners")


def case_labels_tamper():
    home = install(roles=("a", "b"))
    clean = upgrade(home, check=True)
    assert clean["result"]["verified"] is False
    package = variant(home, lambda fields, _: fields["provenance"].update(verified=True), owner=A)
    forged = upgrade(home, check=True, variants=[package], success=False)
    assert forged["result"]["already_native_executed"] is False
    _, selected = generation(home)
    assert selected["lock_sha256"] == clean["result"]["source_lock_sha256"]
    return {"declaration": clean, "untrusted_verified_field": forged, "qualification_inheritance": False}


@ci_progress.case()
def matrix(case):
    runtime_cases.enter(globals(), "g05", case)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    PROFILE.mkdir(parents=True, exist_ok=True)
    value = globals()[runtime_cases.function(case, "g05")]()
    runtime_cases.finish("g05", case, [{"cases": {case: value}} for _ in REPORTS], REPORTS)


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "matrix"
    matrix(sys.argv[2])
