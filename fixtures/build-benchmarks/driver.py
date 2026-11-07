#!/usr/bin/env python3
"""Fresh process measurements against one frozen Host, inside the offline rootfs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time

sys.path.insert(0, "/fixture/ci/scripts")
import ci_progress
import mod_manifest

INPUTS = Path("/inputs")
BINARY = INPUTS / "host/bin/codex"
OWNERS = {"A": "org.example.turn-budget", "B": "org.example.review-before-send", "C": "org.example.tool-concurrency"}
PACKAGES = {"A": "g02a/turn-budget", "B": "g02b/review-before-send", "C": "g03/tool-concurrency"}
HELPERS = ("lifecycle-audit", "example-tool")


def module(relative):
    path = Path("/fixture/fixtures") / relative
    spec = importlib.util.spec_from_file_location("cm_s04_" + path.parent.name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def files(directory):
    return [{"path": str(path.relative_to(directory)), "mode": path.lstat().st_mode & 0o777, **({"link": os.readlink(path)} if path.is_symlink() else
        {"sha256": mod_manifest.sha(path), "size": path.stat().st_size})}
        for path in sorted(directory.rglob("*")) if path.is_file() or path.is_symlink()]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def select_state(home, directory, enabled, state):
    budget = module("turn-budget/driver.py")
    managed = module("managed-package/driver.py")
    if not (home / "cm-profile.json").exists():
        for relative in ("m02/lifecycle-audit/normal", "m02/example-tool/normal", *PACKAGES.values()):
            budget.cm(home, directory, "install", INPUTS / "mods" / relative)
        mod_manifest.write_toml(home / "cm-runtime.toml", {"format_version": 2, "enabled": [],
            "mods": {OWNERS["A"]: {"policy": budget.policy(4)}}})
        budget.cm(home, directory, "lock")
        (home / "s04-retained-user-data.txt").write_text("CM-S04 retained user data\n")
    retained = mod_manifest.sha(home / "s04-retained-user-data.txt")
    current = managed.state(home)[1]
    wanted = {OWNERS[role] for role in enabled} | (set(HELPERS) if enabled else set())
    for owner in sorted(set(current["enabled"]) - wanted):
        budget.cm(home, directory, "disable", owner)
    for owner in sorted(wanted - set(current["enabled"])):
        budget.cm(home, directory, "enable", owner)
    if state.startswith("remove-"):
        owner = OWNERS[state.removeprefix("remove-")]
        before = files(home / "state") if (home / "state").exists() else []
        budget.cm(home, directory, "remove", owner)
        assert (files(home / "state") if (home / "state").exists() else []) == before, "Removing a Mod deleted retained user state"
    assert mod_manifest.sha(home / "s04-retained-user-data.txt") == retained, "A management operation changed retained user data"
    current = managed.state(home)[1]
    assert set(current["enabled"]) == wanted
    frozen = {mod_manifest.sha(INPUTS / "mods" / path / "payload.so") for path in
        (*PACKAGES.values(), "m02/lifecycle-audit/normal", "m02/example-tool/normal")}
    for payload in (home / "store/objects").rglob("payload.so"):
        assert mod_manifest.sha(payload) in frozen, "Installed payload differs from the frozen original"
    return current


class Monitor:
    def __init__(self, directory):
        self.directory = directory
        self.times, self.rows, self.rss = {}, [], []
        self.stop = threading.Event()
        self.process = None
        self.error = None
        self.thread = threading.Thread(target=self.observe, daemon=True)

    def spawn(self, popen, command, *args, **kwargs):
        assert command[0] == str(BINARY) and command[1:3] == ["cm", "--home"]
        assert re.fullmatch(r"/profile/s04/block-[123]", command[3])
        self.times["spawn"] = time.monotonic_ns()
        self.process = popen(command, *args, **kwargs)
        self.thread.start()
        return self.process

    def observe(self):
        try:
            self.poll()
        except BaseException as error:
            self.error = repr(error)

    def poll(self):
        sdk = module("runtime-sdk/driver.py")
        while not self.stop.wait(0.005):
            now = time.monotonic_ns()
            rows = sdk.rows(self.directory / "native.jsonl")
            for row in rows[len(self.rows):]:
                self.times.setdefault("first_native_observed", now)
                if row["event"] == "ready":
                    self.times.setdefault("ready_observed", now)
                if row["event"] == "dlopen-start":
                    self.times.setdefault("first_dlopen_observed", now)
                    self.times["last_dlopen_start_observed"] = now
            self.rows = rows
            try:
                status = (Path("/proc") / str(self.process.pid) / "status").read_text()
                value = re.search(r"^VmHWM:\s+(\d+) kB$", status, re.MULTILINE)
                if value:
                    self.rss.append({"observed_ns": now, "vmhwm_kib": int(value[1])})
            except FileNotFoundError:
                self.times.setdefault("exit", time.monotonic_ns())
                return
            if self.process.poll() is not None:
                self.times.setdefault("exit", time.monotonic_ns())
                return

    def finish(self):
        assert self.process.poll() is not None, "Host is still running at the end of a sample"
        self.thread.join(timeout=5)
        self.stop.set()
        assert not self.thread.is_alive()
        assert self.error is None and "exit" in self.times, self.error


def check_a(terminal):
    budget = module("turn-budget/driver.py")
    admissions = budget.admissions(terminal.directory)
    turns = {row["turn"] for row in admissions}
    charges = {turn: budget.charged(budget.admissions(terminal.directory, turn)) for turn in turns}
    assert list(charges.values()).count([1, 2]) == 1, charges
    assert any(row["event"] == "runtime-request" and row["detail"]["event_kind"] == 12 for row in terminal.native())
    return {"budget_charges": charges}


def check_b(terminal):
    assert len(terminal.reviews()) == 1
    assert any(row["event"] == "runtime-request" and row["detail"]["event_kind"] == 13 for row in terminal.native())
    return {"independent_y_required": True, "review_count_before_shutdown": 1}


def check_c(terminal):
    native = terminal.native()
    assert any(row["event"] == "runtime-request" and row["detail"]["event_kind"] == 14 for row in native)
    selected = [row["detail"] for row in native if row["event"] == "tool-concurrency-turn"]
    assert selected and any(row.get("effective") == 2 for row in selected), selected
    return {"concurrency_decisions": selected}


def metrics(monitor, native, enabled):
    times = monitor.times
    assert all(key in times for key in ("spawn", "first_native_observed", "ready_observed", "business_complete", "exit")), times
    assert times["spawn"] <= times["first_native_observed"] <= times["ready_observed"] <= times["business_complete"] <= times["exit"]
    return {"clock": "time.monotonic_ns", "timestamps_ns": times,
        "startup_seconds": (times["ready_observed"] - times["spawn"]) / 1e9,
        "business_seconds": (times["business_complete"] - times["ready_observed"]) / 1e9,
        "lifetime_seconds": (times["exit"] - times["spawn"]) / 1e9,
        "dlopen": {"status": "observed", "first_start_to_ready_seconds": (times["ready_observed"] - times["first_dlopen_observed"]) / 1e9,
            "pure_dlopen_latency": {"status": "unavailable", "reason": "frozen Host has start events but no dlopen completion timestamps"},
            "method": "external native-event polling; includes initialization, resolution and tracing overhead"} if enabled else
            {"status": "not_applicable", "reason": "empty active Mod set; no dlopen event"},
        "peak_rss": {"status": "available", "value": max(row["vmhwm_kib"] for row in monitor.rss), "unit": "KiB",
            "method": "exact Host PID /proc/PID/status VmHWM sampled every 5ms", "pid": monitor.process.pid,
            "children": "excluded", "lifetime_peak_exact": False, "limitation": "peak after the final successful proc read may be missed",
            "raw": monitor.rss} if monitor.rss else {"status": "unavailable", "reason": "Host exited before a VmHWM read"},
        "observer": {"poll_milliseconds": 5, "strace_present": True, "native_event_count": len(native)}}


def save_profile(home, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, "w:gz") as archive:
        archive.add(home, arcname="profile")
    return {"sha256": mod_manifest.sha(target), "files_sha256": digest(files(home)), "archive": target.name}


def relocate_profile_identity(home):
    identity_path = home / "state/cm-files-v1/identity.json"
    if not identity_path.exists():
        return None
    info = identity_path.lstat()
    assert identity_path.is_file() and not identity_path.is_symlink() and info.st_nlink == 1
    assert info.st_uid == os.geteuid() and not info.st_mode & 0o7077 and info.st_size <= 4096
    before = identity_path.read_bytes()
    identity = json.loads(before)
    fields = {kind + "_" + field for kind in ("home", "state", "lease") for field in ("device", "inode")}
    assert set(identity) == {"schema_version", "domain", "home_id", *fields}
    assert type(identity["schema_version"]) is int and identity["schema_version"] == 1 and identity["domain"] == "cm.state-home.v1"
    assert re.fullmatch(r"[0-9a-f]{64}", identity["home_id"])
    assert all(type(identity[key]) is int and 0 <= identity[key] < 2 ** 64 for key in fields)
    assert before == json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    for kind, path in (("home", home), ("state", identity_path.parent), ("lease", identity_path.parent / ".lease")):
        info = path.lstat()
        assert not path.is_symlink() and info.st_uid == os.geteuid() and not info.st_mode & 0o7077
        assert (path.is_dir() if kind != "lease" else path.is_file() and info.st_nlink == 1)
        identity[kind + "_device"], identity[kind + "_inode"] = info.st_dev, info.st_ino
    # Only this digest-verified fixture is relocated; Host ownership checks remain unchanged.
    identity_path.write_bytes(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode())
    return {"before": json.loads(before), "after": identity,
        "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": mod_manifest.sha(identity_path)}


def restore_profile(home, archive, expected):
    assert re.fullmatch(r"/profile/s04/block-[123]", str(home))
    assert mod_manifest.sha(archive) == expected["sha256"]
    temporary = home.parent / (home.name + "-restore")
    assert not temporary.exists()
    temporary.mkdir()
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        assert len(members) <= 8192 and sum(member.size for member in members) <= 256 * 1024 ** 2
        for member in members:
            name = Path(member.name)
            assert not name.is_absolute() and name.parts[0] == "profile" and ".." not in name.parts
            assert member.isdir() or member.isfile() or member.issym()
            assert not member.mode & 0o7000
        links = [member for member in stream.getmembers() if member.issym()]
        for member in links:
            name = Path(member.name)
            assert name.parts[0] == "profile" and ".." not in name.parts and not name.is_absolute()
            assert member.linkname == str(BINARY), "Unregistered profile alias"
        stream.extractall(temporary, members=[member for member in stream.getmembers() if not member.issym()], filter="data")
        for member in members:
            if member.isdir() or member.isfile():
                (temporary / member.name).chmod(member.mode & 0o777)
        for member in links:
            target = temporary / member.name
            assert target.parent.resolve().is_relative_to(temporary.resolve())
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(member.linkname)
    assert digest(files(temporary / "profile")) == expected["files_sha256"]
    relocation = relocate_profile_identity(temporary / "profile")
    if home.exists():
        shutil.rmtree(home)
    (temporary / "profile").rename(home)
    temporary.rmdir()
    return {"archive_sha256": expected["sha256"], "files_sha256_before_relocation": expected["files_sha256"],
        "files_sha256_after_relocation": digest(files(home)), "state_identity_relocation": relocation}


def run_sample(block, state, method, checks):
    enabled, name = state["enabled"], state["id"]
    home = Path("/profile/s04") / ("block-" + str(block))
    directory = Path("/evidence/s04") / ("block-" + str(block)) / name
    checkpoint = Path("/work/s04-checkpoints") / ("block-" + str(block)) / name
    previous = Path("/work/s04-previous") / ("block-" + str(block)) / name
    source = mod_manifest.read(Path("/fixture/s04-context.json"))
    slot = "runtime/" + str(block) + "/" + name
    frozen = files(INPUTS / "host") + files(INPUTS / "mods")
    sample = {"schema_version": 1, "task_id": "CM-S04", "slot": slot, "block": block, "state": name,
        "status": "failed", "measurement_reused": False, "execution_origin": source["origin"],
        "report_origin": source["origin"], "fingerprint": method, "sample_id": digest([source["origin"], slot]),
        "production_origin": source["production_origin"], "enabled": enabled, "helper_mods": list(HELPERS) if enabled else []}
    management = Path("/evidence/s04-management") / str(block) / name
    prior = mod_manifest.read(previous / "sample.json") if (previous / "sample.json").is_file() else None
    if prior and prior["status"] == "pass" and prior["fingerprint"] == method:
        restored = restore_profile(home, previous / "after.tar.gz", prior["profile_after"])
        sample = {**prior, "measurement_reused": True, "report_origin": source["origin"], "profile_restore": restored}
        mod_manifest.write(directory / "sample.json", sample)
        for filename in ("before.tar.gz", "after.tar.gz"):
            checkpoint.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(previous / filename, checkpoint / filename)
        mod_manifest.write(checkpoint / "sample.json", sample)
        return sample
    if prior and prior["status"] == "pass" and prior["fingerprint"]["inputs"] == method["inputs"]:
        sample["profile_restore"] = restore_profile(home, previous / "before.tar.gz", prior["profile_before"])
        generation = module("managed-package/driver.py").state(home)[1]
        assert set(generation["enabled"]) == {OWNERS[role] for role in enabled} | (set(HELPERS) if enabled else set())
    else:
        generation = select_state(home, management, enabled, name)
    sample["profile_before"] = save_profile(home, checkpoint / "before.tar.gz")
    review = module("review-before-send/driver.py")
    monitor = Monitor(directory)
    original_popen = review.subprocess.Popen
    terminal = None
    try:
        review.subprocess.Popen = lambda argv, *args, **kwargs: monitor.spawn(original_popen, argv, *args, **kwargs)
        try:
            terminal = review.Terminal("s04", "benchmark", home, reviewed="B" in enabled, directory=directory,
                launch_args=("--tool-concurrency", "2") if "C" in enabled else ())
        finally:
            review.subprocess.Popen = original_popen
        assert terminal.identity["pid"] == monitor.process.pid and terminal.identity["executable_sha256"] == mod_manifest.sha(BINARY)
        token = "s04-" + str(block) + "-" + name.lower()
        terminal.provider.tool = bool(enabled)
        if "B" in enabled:
            terminal.review("CM_M02_" + token)
            terminal.send(b"\r\t\r")
            terminal.quiet()
            assert not module("turn-budget/driver.py").admissions(directory)
            terminal.send("y")
        else:
            terminal.send("CM_M02_" + token)
            time.sleep(0.2)
            terminal.send(b"\r")
        terminal.wait(lambda: terminal.managed.tui_message_visible(terminal.output, token), "S04 actual business response")
        terminal.wait_turns()
        monitor.times["business_complete"] = time.monotonic_ns()
        assert not terminal.provider.errors
        actual = module("turn-budget/driver.py").business_requests(terminal.provider)
        assert len(actual) == (2 if enabled else 1)
        sample["behavior"] = {"provider_requests": len(actual), **{key: value for check in checks for key, value in check(terminal).items()}}
        ready = [row["detail"] for row in terminal.native() if row["event"] == "ready"]
        assert len(ready) == 1 and set(ready[0]["plan"]["mods"]) == set(generation["enabled"])
        sample["runtime_lock"] = ready[0]["plan"]
        descriptor, generation_bytes = module("managed-package/driver.py").state(home)
        sample["runtime_generation"] = {"descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
            "generation_sha256": json.loads(descriptor)["generation"], "structured_sha256": digest(generation_bytes), "content": generation_bytes}
        if not enabled:
            assert not any(row["event"] in ("dlopen-start", "entry-start", "init-start") for row in terminal.native())
        terminal.close(True)
        monitor.finish()
        sample["metrics"] = metrics(monitor, terminal.native(), enabled)
        sample["profile_after"] = save_profile(home, checkpoint / "after.tar.gz")
        assert files(INPUTS / "host") + files(INPUTS / "mods") == frozen
        sample["retained_user_data_sha256"] = mod_manifest.sha(home / "s04-retained-user-data.txt")
        sample.update(status="pass", original_files_unchanged=True, frozen_files_sha256=digest(frozen))
    except BaseException as error:
        sample.update(status="failed", failure={"type": type(error).__name__, "reason": str(error)})
        try:
            if terminal and terminal.process.poll() is None:
                terminal.close(False)
            if monitor.process:
                monitor.finish()
        except BaseException as cleanup_error:
            sample["cleanup_failure"] = repr(cleanup_error)
        raise
    finally:
        mod_manifest.write(directory / "sample.json", sample)
        mod_manifest.write(checkpoint / "sample.json", sample)
    return sample


def run_block(block):
    definition = mod_manifest.read(Path("/fixture/ci/benchmarks/runtime-loading.json"))
    assert block in definition["blocks"]
    context = mod_manifest.read(Path("/fixture/s04-context.json"))
    methods = context["methods"][str(block)]
    failures = []
    for state in definition["states"]:
        checks = [check for role, check in (("A", check_a), ("B", check_b), ("C", check_c)) if role in state["enabled"]]
        try:
            with ci_progress.stage("s04/runtime/" + str(block) + "/" + state["id"]):
                run_sample(block, state, methods[state["id"]], checks)
        except Exception as error:
            failures.append({"state": state["id"], "reason": str(error)})
            path = Path("/evidence/s04") / ("block-" + str(block)) / state["id"] / "sample.json"
            if not path.exists():
                slot = "runtime/" + str(block) + "/" + state["id"]
                mod_manifest.write(path, {"schema_version": 1, "task_id": "CM-S04", "slot": slot,
                    "block": block, "state": state["id"], "status": "failed", "failure": str(error),
                    "sample_id": digest([context["origin"], slot]), "execution_origin": context["origin"],
                    "report_origin": context["origin"], "fingerprint": methods[state["id"]], "measurement_reused": False})
    assert not failures, failures


def verify_frozen_host():
    signed = module("distribution-provenance/driver.py")
    bootstrap = mod_manifest.read(Path("/fixture/s01-bootstrap/identity.json"))
    policy = mod_manifest.read(Path("/fixture/crates/cm/src/distribution-policy.json"))
    assert bootstrap["archive_sha256"] == policy["verifier"]["archive_sha256"]
    assert mod_manifest.sha(Path("/fixture/s01-bootstrap/gh")) == bootstrap["binary_sha256"]
    verified = signed.verified_subject("cm-host")
    for row in mod_manifest.read(INPUTS / "distribution/cm-host/assets.json"):
        path = INPUTS / "host" / row["path"]
        actual = hashlib.sha256(os.readlink(path).encode()).hexdigest() if path.is_symlink() else mod_manifest.sha(path)
        assert actual == row["sha256"], "Frozen Host asset differs from its signed original"
    context = mod_manifest.read(Path("/fixture/s04-context.json"))
    assert mod_manifest.sha(BINARY) == context["host_sha256"]
    mod_manifest.write(Path("/evidence/s04-current-verification.json"), verified)


if __name__ == "__main__":
    if sys.argv[1:] == ["verify"]:
        verify_frozen_host()
    else:
        assert len(sys.argv) == 3 and sys.argv[1] == "block"
        Path("/profile/s04").mkdir(parents=True, exist_ok=True)
        run_block(int(sys.argv[2]))
