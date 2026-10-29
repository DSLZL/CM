#!/usr/bin/env python3
"""Actual precompiled Host/Mod state behavior in the strict runtime consumer."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci/scripts"))
import ci_progress
import managed_package
import mod_manifest
import runtime_state

INPUTS = Path("/inputs")
WORK = Path("/work/m04")
PROFILE = Path("/profile/m04")
EVIDENCE = Path("/evidence/m04")
BINARY = INPUTS / "host/bin/codex"
OWNER = "example-tool"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def current(m, home):
    active, generation = m.state(home)
    return json.loads(active)["generation"], generation


def namespace(home):
    return home / "state/cm-files-v1"


def state_root(m, home):
    return namespace(home) / "trees" / current(m, home)[1]["state"]["tree"]


def own(m, home, owner=OWNER):
    view = current(m, home)[1]["state"]
    contract = view["owners"][owner]
    return state_root(m, home) / owner / contract["schema"] / str(contract["version"])


def private_file(path, data):
    with path.open("wb") as stream:
        stream.write(data)
    path.chmod(0o600)


def setup(m, home, variant="v1"):
    m.cm(home, "install", INPUTS / "mods/m04/audit")
    m.cm(home, "install", INPUTS / "mods/m04" / (variant + ".cmod"))
    private_file(own(m, home, "lifecycle-audit") / "unrelated", b"other-owner-preserved")
    before = m.protected_inventory(home)
    path = m.cm(home, "state", "path", OWNER)
    assert Path(path["path"]) == own(m, home) and Path(path["root"]) == state_root(m, home)
    assert not path["already_native_executed"] and m.protected_inventory(home) == before


def rejected(m, home, *args, code=None):
    before = m.state(home)
    result = m.cm(home, *args, success=False)
    errors = [json.loads(line) for line in result["stderr"].splitlines() if line.startswith("{")]
    assert errors, result
    if code:
        assert errors[0]["code"] == code, result
    assert m.state(home) == before, "Rejected operation changed active generation"
    return {"command": result["command"], "return_code": result["return_code"], "error": errors[0]}


@ci_progress.case("name")
def startup_rejected(m, sdk, name, home, extra_env=None):
    directory = EVIDENCE / name
    directory.mkdir(parents=True)
    provider = sdk.Provider()
    command = sdk.command(directory, provider.endpoint, "embedded", token=name)
    env = sdk.environment(home, directory)
    env.update(extra_env or {})
    before = m.state(home)
    try:
        with (directory / "stdout.log").open("w") as out, (directory / "stderr.log").open("w") as err:
            result = subprocess.run(command, env=env, cwd=directory, stdout=out, stderr=err, timeout=45)
        events = sdk.rows(directory / "events.jsonl")
        native = sdk.rows(directory / "native.jsonl")
        assert result.returncode != 0 and not provider.requests
        assert not events and not any(row["event"] == "ready" for row in native), "Rejected startup ran a Mod"
        assert m.state(home) == before
        record = {"command": command, "provider_endpoint": provider.endpoint, "return_code": result.returncode,
            "diagnostic": (directory / "stderr.log").read_text(), "native_mod_callbacks": 0}
        m.write(directory / "result.json", record)
        return record
    finally:
        provider.close()


@contextmanager
def state_environment(sdk, operation="read", value=None, blob_bytes=None):
    original = sdk.environment

    def environment(*args, **kwargs):
        result = original(*args, **kwargs)
        result["CM_FILE_STATE_ACTION"] = operation
        if value is not None:
            result["CM_FILE_STATE_VALUE"] = value
        if blob_bytes is not None:
            result["CM_FILE_STATE_BLOB_BYTES"] = str(blob_bytes)
        return result

    sdk.environment = environment
    try:
        yield
    finally:
        sdk.environment = original


@ci_progress.case("name")
def business(m, sdk, name, home, *, operation="read", value=None, expected=None, build=None, blob_bytes=None, **kwargs):
    with state_environment(sdk, operation, value, blob_bytes):
        result = m.business(name, home, sdk, **kwargs)
    events = [row for row in sdk.rows(EVIDENCE / name / "events.jsonl") if row["event"] == "file-state"]
    if kwargs.get("tool", True):
        assert len(events) == 1 and events[0]["operation"] == operation, events
        if expected is not None:
            assert events[0]["value"] == expected, events
        if build is not None:
            assert events[0]["build"] == build, events
        outputs = [json.loads(output["output"]) for request in result["provider_requests"] for output in request["outputs"]]
        assert any(output["file_state"] == events[0]["value"] for output in outputs), "Disk value never reached the model"
    else:
        assert not events
    result["file_state_events"] = events
    m.write(EVIDENCE / name / "result.json", result)
    return result


def busy_operations(m, home, generation, checkpoint):
    return [rejected(m, home, *args, code="state_busy") for args in (
        ("state", "checkpoint"), ("rollback", generation, "--restore", checkpoint),
        ("state", "clean", OWNER, "--confirm", OWNER),
        ("replace", OWNER, INPUTS / "mods/m04/compatible", "--from", current(m, home)[1]["installed"][OWNER]))]


@ci_progress.case()
def restart_matrix(m, sdk):
    home = PROFILE / "restart"
    setup(m, home)
    private_file(home / "config.toml", b"# independent configuration retained\n")
    config_before = (home / "config.toml").read_bytes()
    initial = business(m, sdk, "state-write", home, operation="write", value="old-值", expected="v1:old-值", build="v1")
    readback = business(m, sdk, "state-second-process-read", home, expected="v1:old-值", build="v1")
    checkpoint = m.cm(home, "state", "checkpoint")
    generation = checkpoint["generation"]
    data = m.protected_inventory(state_root(m, home))
    changes = []
    busy = []

    def disable():
        changes.append(m.cm(home, "disable", OWNER))
        assert changes[-1]["restart_required"]
        busy.extend(busy_operations(m, home, generation, checkpoint["checkpoint"]))
        assert m.protected_inventory(state_root(m, home)) == data

    live = business(m, sdk, "live-exec", home, expected="v1:old-值", mutate=disable)
    restarted = business(m, sdk, "restart-only-b", home, tool=False)
    assert set(current(m, home)[1]["enabled"]) == {"lifecycle-audit"}
    removed = m.cm(home, "remove", OWNER)
    assert removed["restart_required"] and removed["data_preserved"]
    after_remove = business(m, sdk, "removed-only-b", home, tool=False)
    assert m.protected_inventory(state_root(m, home)) == data
    m.cm(home, "disable", "lifecycle-audit")
    empty = business(m, sdk, "empty-restart", home, tool=False)
    assert not sdk.rows(EVIDENCE / "empty-restart/events.jsonl"), "Empty selection called native Mod code"
    m.cm(home, "remove", "lifecycle-audit")
    empty_removed = business(m, sdk, "empty-removed", home, tool=False)
    assert not current(m, home)[1]["installed"]
    assert (home / "config.toml").read_bytes() == config_before
    return {"initial": initial, "read_in_new_process": readback, "live_exec": live, "busy": busy,
        "changes": changes, "restarted_only_b": restarted, "removed": removed, "after_remove": after_remove,
        "empty": empty, "empty_removed": empty_removed, "data_retained": True, "checkpoint": checkpoint}


@ci_progress.case()
def checkpoint_rejections(m, home, generation, checkpoint):
    source = namespace(home) / "checkpoints" / checkpoint
    rows = [rejected(m, home, "rollback", generation, "--restore", "0" * 64)]
    for name in ("truncated", "sha", "home", "host", "generation", "config", "owner", "schema", "version", "object", "data", "extra", "manifest-fifo", "manifest-public"):
        target = namespace(home) / "checkpoints" / ("negative-" + name)
        shutil.copytree(source, target)
        manifest = target / "checkpoint.json"
        document = json.loads(manifest.read_bytes())
        if name == "home":
            document["home_id"] = "f" * 64
        elif name == "host":
            document["host"]["executable_sha256"] = "f" * 64
        elif name in ("generation", "config"):
            document["generation" if name == "generation" else "config_sha256"] = "f" * 64
        elif name == "owner":
            document["owners"]["foreign"] = document["owners"].pop(OWNER)
        elif name in ("schema", "version", "object"):
            document["owners"][OWNER][{"schema": "schema", "version": "version", "object": "object_sha256"}[name]] = (
                99 if name == "version" else "foreign-schema" if name == "schema" else "f" * 64)
        elif name == "data":
            private_file(target / "data/example-tool/fixture-state/1/值 value.json", b"changed checkpoint")
        elif name == "extra":
            private_file(target / "data/unowned", b"foreign")
        raw = b"{" if name == "truncated" else canonical(document)
        manifest.write_bytes(raw)
        if name == "manifest-fifo":
            manifest.unlink()
            os.mkfifo(manifest, 0o600)
        elif name == "manifest-public":
            manifest.chmod(0o644)
        identity = "f" * 64 if name == "sha" else hashlib.sha256(raw).hexdigest()
        destination = target.with_name(identity)
        # An unchanged manifest with corrupted data deliberately has the original ID.
        if destination.exists():
            saved = source.with_name("saved-checkpoint")
            source.rename(saved)
        else:
            saved = None
        target.rename(destination)
        try:
            rows.append({"case": name, **rejected(m, home, "rollback", generation, "--restore", identity)})
        finally:
            shutil.rmtree(destination)
            if saved:
                saved.rename(source)
    return rows


@ci_progress.case()
def rollback_matrix(m, sdk):
    home = PROFILE / "rollback"
    setup(m, home)
    old = business(m, sdk, "rollback-v1-write", home, operation="write", value="checkpoint-old", expected="v1:checkpoint-old")
    checkpoint = m.cm(home, "state", "checkpoint")
    generation, checkpoint_id = checkpoint["generation"], checkpoint["checkpoint"]
    old_object = current(m, home)[1]["installed"][OWNER]
    conflicts = [rejected(m, home, "install", INPUTS / "mods/m04/compatible", code="installation_conflict"),
        rejected(m, home, "replace", OWNER, INPUTS / "mods/m04/compatible", "--from", "0" * 64, code="input_drift")]
    replacement = m.cm(home, "replace", OWNER, INPUTS / "mods/m04/compatible.cmod", "--from", old_object)
    compatible = business(m, sdk, "compatible-replace-read", home, expected="v1:checkpoint-old", build="compatible")
    m.cm(home, "rollback", generation)
    m.cm(home, "disable", OWNER)
    cleaned = m.cm(home, "state", "clean", OWNER, "--confirm", OWNER)
    assert cleaned["committed"] and not cleaned["cleanup_pending"] and cleaned["current_working_state_removed"]
    assert cleaned["checkpoints_preserved"]
    disabled_replacement = m.cm(home, "replace", OWNER, INPUTS / "mods/m04/v2.cmod", "--from", old_object)
    assert OWNER not in disabled_replacement["enabled"], "Replace implicitly enabled a disabled Mod"
    m.cm(home, "enable", OWNER)
    new = business(m, sdk, "rollback-v2-write", home, operation="write", value="new-format", expected="v2:new-format", build="v2")
    before = m.protected_inventory(state_root(m, home))
    incompatible = rejected(m, home, "rollback", generation, code="state_compatibility")
    negatives = checkpoint_rejections(m, home, generation, checkpoint_id)
    assert m.protected_inventory(state_root(m, home)) == before
    still_new = business(m, sdk, "after-rejected-rollback", home, expected="v2:new-format", build="v2")
    config = home / "cm-runtime.toml"
    mod_manifest.write_toml(config, {"format_version": 2, "enabled": [OWNER, "lifecycle-audit"], "mods": {OWNER: {"mode": "new"}}})
    bad_config = rejected(m, home, "rollback", generation, "--restore", checkpoint_id)
    mod_manifest.write_toml(config, {"format_version": 2, "enabled": [OWNER, "lifecycle-audit"], "mods": {OWNER: {"mode": "basic"}}})
    preserved_config = config.read_bytes()
    restored = m.cm(home, "rollback", generation, "--restore", checkpoint_id)
    assert restored["rollback_target"] == generation and restored["restored_checkpoint"] == checkpoint_id
    assert config.read_bytes() == preserved_config, "Rollback replaced current configuration"
    actual_old = business(m, sdk, "restored-v1-read", home, expected="v1:checkpoint-old", build="v1")
    assert (own(m, home, "lifecycle-audit") / "unrelated").read_bytes() == b"other-owner-preserved"
    delayed = startup_rejected(m, sdk, "delayed-obsolete-generation", home,
        {"CM_MANAGED_HOME": str(home), "CM_MANAGED_GENERATION": generation})
    forged = startup_rejected(m, sdk, "forged-state-environment", home, {"CM_MOD_STATE_ROOT": str(WORK)})
    cloned = PROFILE / "copied-home"
    shutil.copytree(home, cloned, symlinks=True)
    copied_home = rejected(m, cloned, "state", "checkpoint", code="state_ownership")
    descriptor = home / "cm-profile.json"
    original = descriptor.read_bytes()
    forged_host = json.loads(original)
    forged_host["host"]["executable_sha256"] = "f" * 64
    descriptor.write_bytes(canonical(forged_host))
    try:
        wrong_host = rejected(m, home, "state", "checkpoint")
    finally:
        descriptor.write_bytes(original)
    return {"home": str(home), "generation": generation, "checkpoint": checkpoint_id, "old": old,
        "replacement": replacement, "compatible_read": compatible, "conflicts": conflicts, "cleaned": cleaned,
        "disabled_replacement": disabled_replacement, "new": new, "incompatible": incompatible,
        "checkpoint_rejections": negatives, "new_after_rejection": still_new, "current_config_rejection": bad_config,
        "restored": restored, "actual_old_mod_read": actual_old, "delayed_generation": delayed,
        "forged_environment": forged, "copied_home": copied_home, "different_host_binding": wrong_host}


@ci_progress.case()
def public_failures(m, sdk):
    home = PROFILE / "interruption"
    setup(m, home)
    business(m, sdk, "bounded-state-write", home, operation="write", value="durable", expected="v1:durable", blob_bytes=64 * 1024 * 1024)
    checkpoint = m.cm(home, "state", "checkpoint")
    args = ("rollback", checkpoint["generation"], "--restore", checkpoint["checkpoint"])
    rows = []
    for name, path in (("tree-write", namespace(home) / "trees"), ("generation-write", home / "store/generations"), ("active-write", home)):
        before = m.state(home)
        root_before = m.protected_inventory(state_root(m, home))
        path.chmod(0o500)
        try:
            result = m.cm(home, *args, success=False)
        finally:
            path.chmod(0o700)
        assert m.state(home) == before and m.protected_inventory(state_root(m, home)) == root_before
        rows.append({"case": name, "public_cli": result, "old_active_and_data_preserved": True})
    directory = EVIDENCE / "interrupted-restore"
    command = [str(BINARY), "cm", "--home", str(home), *args]
    before = m.state(home)
    directory.mkdir(parents=True)
    with (directory / "stdout.log").open("w") as out, (directory / "stderr.log").open("w") as err:
        process = subprocess.Popen(command, env=m.environment(directory), cwd=WORK, stdout=out, stderr=err, close_fds=True)
        try:
            sdk.core.await_barrier(lambda: bool(list((namespace(home) / "trees").glob(".restore.*.tmp"))), process,
                "public restore staging exists")
            process.send_signal(signal.SIGSTOP)
            assert m.state(home) == before
            racing_start = startup_rejected(m, sdk, "runtime-during-exclusive-restore", home)
            racing_manager = rejected(m, home, "state", "checkpoint")
            process.kill()
            assert process.wait(timeout=15) == -signal.SIGKILL
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=15)
    assert m.state(home) == before
    rows.append({"case": "SIGKILL-during-real-restore", "command": command, "return_code": process.returncode,
        "staging_loaded": False, "old_active_preserved": True, "runtime_during_exclusive_lease": racing_start,
        "second_real_manager_rejected": racing_manager})
    restored = m.cm(home, *args)
    recovered = business(m, sdk, "read-after-interruption", home, expected="v1:durable")
    m.cm(home, "disable", OWNER)
    old_root = state_root(m, home)
    old_root.chmod(0o500)
    try:
        pending = m.cm(home, "state", "clean", OWNER, "--confirm", OWNER)
    finally:
        old_root.chmod(0o700)
    assert pending["committed"] and pending["cleanup_pending"] and not pending["current_working_state_removed"]
    retry = m.cm(home, "state", "clean", OWNER, "--confirm", OWNER)
    assert retry["retry"] and retry["cleanup_operation"] == pending["cleanup_operation"]
    assert not retry["cleanup_pending"] and retry["current_working_state_removed"]
    assert not (old_root / OWNER).exists()
    assert (namespace(home) / "checkpoints" / checkpoint["checkpoint"]).is_dir()
    assert (own(m, home, "lifecycle-audit") / "unrelated").read_bytes() == b"other-owner-preserved"
    return {"public_failures": rows, "retry_restore": restored, "actual_mod_read": recovered,
        "committed_cleanup_pending": pending, "cleanup_retry": retry}


@ci_progress.case()
def stdio_leases(m, sdk):
    home = PROFILE / "stdio"
    setup(m, home)
    business(m, sdk, "stdio-initial-write", home, operation="write", value="stdio", expected="v1:stdio")
    checkpoint = m.cm(home, "state", "checkpoint")
    results = []
    for mode in ("async", "noncooperative", "sigkill"):
        m.cm(home, "enable", OWNER)
        directory = EVIDENCE / ("stdio-" + mode)
        provider = sdk.Provider()
        with state_environment(sdk):
            client = sdk.Client(directory, home, provider, mode="async" if mode == "sigkill" else mode)
        try:
            thread = client.start()
            before = client.mappings("before")
            if mode == "sigkill":
                client.call("turn/start", {"threadId": thread, "input": [{"type": "text", "text": "CM_M02_sigkill", "text_elements": []}]})
                sdk.core.await_barrier(lambda: any(row["event"] == "worker-entered" for row in sdk.rows(directory / "events.jsonl")),
                    client.process, "actual native worker before SIGKILL")
                turn = None
            else:
                turn = client.turn(thread, "stdio-" + mode, interrupt=mode == "noncooperative", release=mode == "async")
            if mode == "noncooperative":
                sdk.core.await_barrier(lambda: any(row["event"] == "runtime-scope-failed" and row["detail"]["error"]["code"] == "runtime"
                    and row["detail"]["error"]["already_native_executed"] is True
                    for row in sdk.rows(directory / "native.jsonl")), client.process, "actual pinned request before state operation")
            m.cm(home, "disable", OWNER)
            busy = busy_operations(m, home, checkpoint["generation"], checkpoint["checkpoint"])
            if mode == "async":
                lease = namespace(home) / ".lease"
                saved_lease = lease.with_name("held-lease")
                lease.rename(saved_lease)
                private_file(lease, b"")
                try:
                    busy.append(rejected(m, home, "state", "checkpoint", code="state_ownership"))
                finally:
                    lease.unlink()
                    saved_lease.rename(lease)
            assert client.mappings("after-disable") == before, "Live process unloaded or replaced a native library"
            if mode == "sigkill":
                client.process.kill()
                assert client.process.wait(timeout=15) == -signal.SIGKILL
            client.close(failure=mode != "async")
            if mode == "noncooperative":
                lifetime = sdk.settled(directory, pinned=True)
            elif mode == "async":
                lifetime = sdk.settled(directory)
                sdk.business_evidence(provider)
            else:
                lifetime = {"forced_process_exit": True}
        finally:
            if client.process.poll() is None:
                client.process.kill()
                client.process.wait(timeout=15)
            provider.close()
        after_exit = m.cm(home, "state", "checkpoint")
        results.append({"mode": mode, "turn": turn, "busy_while_alive": busy, "lifetime": lifetime,
            "checkpoint_after_real_exit": after_exit})
    return results


@ci_progress.case()
def ownership(m, sdk):
    home = PROFILE / "ownership"
    setup(m, home)
    declarations = []
    for kind in ("missing-state", "wrong-owner", "dot-schema", "parent-schema", "abi1"):
        package = WORK / ("invalid-declaration-" + kind)
        shutil.copytree(INPUTS / "mods/m04/v1", package)
        fields = tomllib.loads((package / "mod.toml").read_text())
        if kind == "missing-state":
            fields.pop("state")
        elif kind == "wrong-owner":
            fields["state"]["owner"] = "lifecycle-audit"
        elif kind in ("dot-schema", "parent-schema"):
            fields["state"]["schema"] = "." if kind == "dot-schema" else ".."
        else:
            fields["compat"].update(abi_major=1, abi_minor_min=0, abi_minor_max=0)
            fields["binary"]["entry"] = "cm_mod_entry_v1"
        mod_manifest.manifest(package, fields)
        declarations.append({"case": kind, **rejected(m, home, "install", package, code="manifest_parse")})
    business(m, sdk, "ownership-write", home, operation="write", value="owned", expected="v1:owned")
    private_file(home / "config.toml", b"# user configuration is not owned Mod data\n")
    mod_manifest.write_toml(home / "cm-runtime.toml", {"format_version": 2,
        "enabled": [OWNER, "lifecycle-audit"], "mods": {OWNER: {"mode": "basic"}}})
    config_before = {name: (home / name).read_bytes() for name in ("config.toml", "cm-runtime.toml")}
    # Hard-link counterexamples must stay within the same consumer bind mount.
    external = PROFILE / "external"
    external.mkdir(mode=0o700)
    private_file(external / "preserve", b"outside-state")
    external_before = m.protected_inventory(external)
    m.cm(home, "disable", OWNER)
    illegal_ids = [rejected(m, home, "state", "clean", name, "--confirm", name) for name in
        (".", "..", "../lifecycle-audit", str(external), "example-tool-prefix", "用户 空格")]
    illegal_ids.append(rejected(m, home, "state", "clean", OWNER, "--confirm", "wrong-owner"))
    directory = own(m, home)
    negatives = []
    for kind in ("symlink", "hardlink", "fifo", "socket", "sparse-budget", "depth", "path-length", "entries"):
        path = directory / "bad"
        listener = None
        if kind == "symlink":
            path.symlink_to(external / "preserve")
        elif kind == "hardlink":
            os.link(external / "preserve", path)
            assert path.stat().st_nlink == 2
        elif kind == "fifo":
            os.mkfifo(path, 0o600)
        elif kind == "socket":
            listener = socket.socket(socket.AF_UNIX)
            # Bind a short name before moving the real socket into the deep state tree.
            socket_path = PROFILE / "ownership-socket"
            listener.bind(str(socket_path))
            socket_path.rename(path)
            assert path.is_socket()
        elif kind == "sparse-budget":
            private_file(path, b"")
            with path.open("wb") as stream:
                stream.truncate(1024 * 1024 * 1024 + 1)
        elif kind == "depth":
            leaf = path
            for _ in range(17):
                leaf.mkdir(mode=0o700)
                leaf /= "nested"
        elif kind == "path-length":
            path.mkdir(mode=0o700)
            (path / ("a" * 245)).mkdir(mode=0o700)
            (path / ("a" * 245) / ("b" * 245)).mkdir(mode=0o700)
        else:
            path.mkdir(mode=0o700)
            for index in range(4096):
                private_file(path / str(index), b"")
        try:
            negatives.append({"case": kind, **rejected(m, home, "state", "clean", OWNER, "--confirm", OWNER)})
            assert m.protected_inventory(external) == external_before
            assert (directory / "值 value.json").read_bytes() == b"v1:owned"
        finally:
            if listener:
                listener.close()
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
    dependency = WORK / "dependent-audit"
    shutil.copytree(INPUTS / "mods/m04/audit", dependency)
    fields = tomllib.loads((dependency / "mod.toml").read_text())
    fields["dependencies"] = [{"id": OWNER, "version": "^1"}]
    mod_manifest.manifest(dependency, fields)
    m.cm(home, "enable", OWNER)
    m.cm(home, "replace", "lifecycle-audit", dependency, "--from", current(m, home)[1]["installed"]["lifecycle-audit"])
    depends = [rejected(m, home, action, OWNER) for action in ("disable", "remove")]
    depends.append(rejected(m, home, "state", "clean", OWNER, "--confirm", OWNER))
    m.cm(home, "remove", "lifecycle-audit")
    m.cm(home, "remove", OWNER)
    assert (directory / "值 value.json").read_bytes() == b"v1:owned"
    retained_config = (home / "config.toml").read_bytes() if (home / "config.toml").exists() else None
    receipt = m.cm(home, "state", "clean", OWNER, "--confirm", OWNER)
    assert receipt["current_working_state_removed"] and receipt["checkpoints_preserved"]
    assert (own(m, home, "lifecycle-audit") / "unrelated").read_bytes() == b"other-owner-preserved"
    assert retained_config == ((home / "config.toml").read_bytes() if (home / "config.toml").exists() else None)
    assert all((home / name).read_bytes() == raw for name, raw in config_before.items())
    assert m.protected_inventory(external) == external_before
    return {"invalid_file_state_declarations": declarations,
        "illegal_owner_ids": illegal_ids, "unsafe_state_entries": negatives, "dependency_rejections": depends,
        "removed_owner_cleanup": receipt, "unrelated_owner_and_external_preserved": True}


def self_check():
    assert canonical({"值": 1, "a": True}) == '{"a":true,"值":1}'.encode()
    assert Path("example-tool/fixture-state/1/值 value.json").parts == ("example-tool", "fixture-state", "1", "值 value.json")
    assert len(runtime_state.REPORTS) == 6


def matrix():
    for directory in (WORK, PROFILE, EVIDENCE):
        directory.mkdir(parents=True, mode=0o700)
    m = managed_package.driver()
    m.WORK, m.PROFILE, m.EVIDENCE = WORK, PROFILE, EVIDENCE
    m.OFFICIAL_PROFILE = WORK / "official-profile"
    shutil.copytree(INPUTS / "official/profile", m.OFFICIAL_PROFILE, symlinks=True)
    sdk = m.sdk_module()
    frozen = m.sha(BINARY)
    authored = m.read(Path("/fixture/m04-producer.json"))
    assert authored["status"] == "pass" and authored["host_executable_sha256"] == frozen
    official_before = m.protected_inventory(INPUTS / "official")
    writable_official_before = m.protected_inventory(m.OFFICIAL_PROFILE)
    missing = PROFILE / "query-missing"
    m.cm(missing, "state", "path", OWNER, success=False)
    assert not missing.exists(), "Read-only state query created a managed home"
    restarted = restart_matrix(m, sdk)
    rolled = rollback_matrix(m, sdk)
    interrupted = public_failures(m, sdk)
    stdio = stdio_leases(m, sdk)
    tui_home = PROFILE / "tui"
    setup(m, tui_home)
    business(m, sdk, "tui-initial-write", tui_home, operation="write", value="tui", expected="v1:tui")
    tui_checkpoint = m.cm(tui_home, "state", "checkpoint")
    tui_busy = []

    def tui_disable():
        m.cm(tui_home, "disable", OWNER)
        tui_busy.extend(busy_operations(m, tui_home, tui_checkpoint["generation"], tui_checkpoint["checkpoint"]))

    tui = business(m, sdk, "actual-tui", tui_home, expected="v1:tui", tui=True, mutate=tui_disable)
    m.cm(tui_home, "state", "checkpoint")
    owned = ownership(m, sdk)
    assert m.protected_inventory(INPUTS / "official") == official_before
    assert m.protected_inventory(m.OFFICIAL_PROFILE) == writable_official_before
    assert m.sha(BINARY) == frozen
    b_payload = INPUTS / "mods/m04/audit/payload.so"
    assert m.sha(b_payload) == m.sha(INPUTS / "mods/m02/lifecycle-audit/normal/payload.so")
    reports = (
        {"restart_behavior": restarted, "stdio_leases": stdio, "actual_tui": tui, "tui_busy": tui_busy},
        {"empty_selected_set": restarted["empty"], "empty_installed_set": restarted["empty_removed"],
         "old_native_mappings_preserved_until_exit": True, "mod_callbacks_after_empty_restart": 0},
        {"read_after_process_restart": restarted["read_in_new_process"], "default_disable_remove_preserves_data": True,
         "explicit_cleanup": owned["removed_owner_cleanup"], "cleanup_pending_retry": interrupted["cleanup_retry"]},
        {"precompiled_rollback": rolled, "host_compiled_for_mod_changes": False},
        {"public_cli_interruption": interrupted, "precise_internal_tests": authored,
         "internal_fault_binary_is_published_host": False},
        {"ownership": owned, "official_and_unrelated_profiles_unchanged": True,
         "unchanged_b_payload_sha256": m.sha(b_payload)},
    )
    for name, report in zip(runtime_state.REPORTS, reports):
        m.write(Path("/evidence") / name, {"status": "behavior_pass", "frozen_host_sha256": frozen, **report})
    m.write(EVIDENCE / "suite.json", {"status": "pass", "reports": list(runtime_state.REPORTS), "frozen_host_sha256": frozen})
