#!/usr/bin/env python3
"""Independent cases against H, plus a separately frozen private TUI probe."""
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import termios
import threading
import time
import tomllib
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci/scripts"))
import ci_progress
import mod_manifest

INPUTS = Path("/inputs")
BINARY = INPUTS / "host/bin/codex"
OWNER = "org.example.review-before-send"


def module(relative):
    path = Path(__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location("cm_review_" + path.parent.name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def install(home, enabled=True):
    sdk = module("runtime-sdk/driver.py")
    sdk.install(home)
    shutil.copytree(INPUTS / "mods/g02b/review-before-send", home / "mods" / OWNER)
    mod_manifest.write_toml(home / "cm-runtime.toml", {"format_version": 2,
        "enabled": ["lifecycle-audit", "example-tool", *([OWNER] if enabled else [])]})


def probe(case, *, changed=False):
    assert not changed
    directory = Path("/evidence/review") / case / "probe"
    directory.mkdir(parents=True)
    names = ["bottom_pane::chat_composer::submit_review::cm_probe::cm_review_" + case.replace("-", "_")]
    names += ["chatwidget::tests::cm_review_probe::cm_review_" + name for name in {
        "entry-coverage": ["programmatic", "admission"], "queue-lifecycle": ["queue"],
    }.get(case, [])]
    if case == "entry-coverage":
        names.append("app::tests::cm_review_probe::cm_review_programmatic_events")
    sdk = module("runtime-sdk/driver.py")
    for index, name in enumerate(names):
        run = directory / str(index)
        run.mkdir()
        home = Path("/profile/review") / case / ("probe-" + str(index))
        install(home)
        env = sdk.environment(home, run)
        env["CM_REVIEW_PROBE_PROFILE"] = str(home)
        image = home / "review.png"
        def chunk(kind, data):
            return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))
        image.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))
        env["CM_REVIEW_IMAGE"] = str(image)
        command = [str(INPUTS / "probes/cm-review-tui"), "--ignored", "--exact", name, "--nocapture"]
        with (run / "stdout.log").open("w") as out, (run / "stderr.log").open("w") as err:
            result = subprocess.run(command, env=env, cwd=run, stdout=out, stderr=err, timeout=90)
        write(run / "result.json", {"command": command, "return_code": result.returncode,
            "probe_sha256": sha(INPUTS / "probes/cm-review-tui"), "production_cli_sha256": sha(BINARY)})
        assert result.returncode == 0, (name, (run / "stderr.log").read_text(), (run / "stdout.log").read_text())
        assert "1 passed" in (run / "stdout.log").read_text(), "Exact probe name did not execute"
    return names


class Terminal:
    def __init__(self, case, name, home, *, reviewed=True, launch_args=()):
        self.sdk = module("runtime-sdk/driver.py")
        self.managed = module("managed-package/driver.py")
        self.directory = Path("/evidence/review") / case / name
        self.directory.mkdir(parents=True)
        self.home, self.reviewed = home, reviewed
        self.empty_launch_argv = not launch_args
        self.provider = self.sdk.Provider(tool=False)
        arguments = self.sdk.command(self.directory, self.provider.endpoint, "embedded", token=name)[1:]
        (home / "config.toml").write_text(self.managed.tui_configuration(arguments, self.directory))
        self.env = self.sdk.environment(home, self.directory)
        self.env["TERM"] = "xterm-256color"
        self.command = self.managed.launch_command(BINARY, home, list(launch_args))
        master, slave = pty.openpty()
        self.master, self.output = master, bytearray()
        self.reader_error = None
        self.stop = threading.Event()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))

        def child_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.process = subprocess.Popen(self.command, env=self.env, cwd=self.directory,
            stdin=slave, stdout=slave, stderr=slave, close_fds=True, preexec_fn=child_terminal)
        os.close(slave)

        def drain():
            try:
                while not self.stop.is_set():
                    if not select.select([master], [], [], 0.1)[0]:
                        continue
                    try:
                        block = os.read(master, 65536)
                    except OSError:
                        break
                    if not block:
                        break
                    self.output.extend(block)
                    assert len(self.output) <= 8 * 1024 * 1024, "PTY output limit"
                    if b"\x1b[6n" in block:
                        os.write(master, b"\x1b[1;1R")
            except BaseException as error:
                self.reader_error = str(error)

        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()
        self.identity = None
        try:
            self.wait(lambda: any(row["event"] == "backend-selected" for row in self.native()), "Embedded TUI")
            self.identity = self.managed.identity(self.process, sha(BINARY))
        except BaseException:
            self.close(False)
            raise

    def native(self):
        return self.sdk.rows(self.directory / "native.jsonl")

    def wait(self, predicate, label):
        self.sdk.core.await_barrier(predicate, self.process, label)
        assert self.reader_error is None, self.reader_error

    def send(self, value):
        os.write(self.master, value.encode() if isinstance(value, str) else value)

    def reviews(self):
        return [row for row in self.native() if row["event"] == "tui-review-required"]

    def review(self, text=None, key=b"\r"):
        before = len(self.reviews())
        if text is not None:
            self.send(text)
            time.sleep(0.2)
        self.send(key)
        self.wait_review(before)

    def wait_review(self, index):
        self.wait(lambda: len(self.reviews()) > index, "native review prepared")
        prepared = self.reviews()[index]["detail"]
        self.wait(lambda: any(row["event"] == "tui-review-ready"
            and row["detail"]["actor"] == prepared["actor"]
            and row["detail"]["review_id"] == prepared["review_id"]
            for row in self.native()), "UI review ready for independent Y")

    def quiet(self):
        before = len(self.provider.requests)
        time.sleep(0.35)
        assert len(self.provider.requests) == before == 0, "Business started before explicit Y"

    def complete(self, token):
        self.send("y")
        self.wait(lambda: self.managed.tui_message_visible(self.output, token), "reviewed provider response")
        requests = [row for row in self.provider.requests if row["purpose"] == "business"]
        assert len(requests) == 1 and not self.provider.errors, (requests, self.provider.errors)
        assert any("CM_M02_" + token in self.sdk.text_values(row["input"]) for row in requests)

    def close(self, success):
        try:
            listener = None
            if success:
                listener = self.managed.tui_mcp_listener(self.process.pid)
                assert any(item.get("name") == "mcp__codex_worktrees"
                    for row in self.provider.requests for item in row["tools"])
                if self.reviewed:
                    self.review("/quit")
                    self.send("y")
                else:
                    self.send("/quit")
                    time.sleep(0.2)
                    self.send(b"\r")
                assert self.process.wait(timeout=45) == 0
                assert any(row["event"] == "stopped" for row in self.native()), "Native runtime did not drain"
            write(self.directory / "result.json", {"command": self.command,
                "return_code": self.process.poll(), "provider_endpoint": self.provider.endpoint,
                "provider_requests": self.provider.requests, "provider_errors": self.provider.errors,
                "identity": self.identity, "tui": True, "empty_launch_argv": self.empty_launch_argv,
                "tui_mcp_listener": listener, "review_count": len(self.reviews())})
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=10)
            self.stop.set()
            self.reader.join(timeout=5)
            os.close(self.master)
            (self.directory / "pty.log").write_text(bytes(self.output).decode(errors="replace"))
            self.provider.close()


@contextmanager
def terminal(case, name, *, home=None, enabled=True, launch_args=()):
    if home is None:
        home = Path("/profile/review") / case / name
        directory = Path("/evidence/review") / case / ("management-" + name)
        for owner in ("lifecycle-audit", "example-tool"):
            cm(home, directory, "install", INPUTS / "mods/m02" / owner / "normal")
        if enabled:
            cm(home, directory, "install", INPUTS / "mods/g02b/review-before-send.cmod")
    process = Terminal(case, name, home, reviewed=enabled, launch_args=launch_args)
    try:
        yield process
    except BaseException:
        process.close(False)
        raise
    else:
        process.close(True)


def report(case, checks):
    write(Path("/evidence/review") / case / "suite.json", {"status": "pass", "checks": checks})
    write(Path("/evidence") / ("review-" + case + ".json"), {"status": "behavior_pass", "checks": checks,
        "case": case, "frozen_cli_sha256": sha(BINARY), "runtime_build_requests": 0})


@ci_progress.case()
def nondestructive():
    native = probe("nondestructive")
    with terminal("nondestructive", "full-draft") as tui:
        tui.review("CM_M02_full-draft 中文 " + "x" * 1500)
        tui.quiet()
        tui.complete("full-draft")
    report("nondestructive", {"first_submit_no_business": True, "full_private_draft_probe": native})


@ci_progress.case()
def invalidation():
    native = probe("invalidation")
    with terminal("invalidation", "edited") as tui:
        tui.review("CM_M02_old")
        tui.quiet()
        tui.send(b"\x1b")
        tui.send(b"\x03")
        tui.review("CM_M02_edited")
        tui.quiet()
        tui.complete("edited")
        request = next(row for row in tui.provider.requests if row["purpose"] == "business")
        assert "CM_M02_old" not in tui.sdk.text_values(request["input"])
    report("invalidation", {"escaped_and_edited_draft_requires_new_review": True, "probe": native})


@ci_progress.case()
def key_events():
    native = probe("key-events")
    with terminal("key-events", "independent-y") as tui:
        tui.review("CM_M02_independent-y")
        tui.send(b"\r\t\r")
        tui.quiet()
        tui.complete("independent-y")
    report("key-events", {"legacy_terminal_independent_y": True, "release_repeat_and_single_delivery": native})


@ci_progress.case()
def entry_coverage():
    native = probe("entry-coverage")
    with terminal("entry-coverage", "command") as tui:
        tui.review("/status")
        tui.quiet()
        tui.send(b"\x1b\x03")
        tui.review("CM_M02_command")
        tui.complete("command")
    image = Path("/profile/review/entry-coverage/probe-0/review.png")
    with terminal("entry-coverage", "cli-image",
            launch_args=["--image", str(image), "--", "CM_M02_cli-image"]) as tui:
        tui.wait_review(0)
        tui.quiet()
        tui.send(b"\r\t\r")
        tui.quiet()
        tui.complete("cli-image")
        request = next(row for row in tui.provider.requests if row["purpose"] == "business")
        assert "input_image" in tui.sdk.text_values(request["input"])
        assert "data:image/" in tui.sdk.text_values(request["input"])
    report("entry-coverage", {"commands_not_dispatched_before_y": True,
        "cli_initial_prompt_and_image_reviewed": True, "startup_and_programmatic": native})


@ci_progress.case()
def queue_lifecycle():
    native = probe("queue-lifecycle")
    with terminal("queue-lifecycle", "queue") as tui:
        tui.review("CM_M02_queue", key=b"\t")
        tui.quiet()
        tui.complete("queue")
    report("queue-lifecycle", {"queue_admission_requires_review": True, "shared_delivery_and_rewrite_probe": native})


def cm(home, directory, *arguments, binary=BINARY, success=True):
    return module("turn-budget/driver.py").cm(home, directory, *arguments, binary=binary, success=success)


def protocol_cases():
    sdk = module("runtime-sdk/driver.py")
    results = []
    for mode in ("false", "extra", "malformed", "error", "complete-error", "panic", "duplicate", "stale", "cancel", "deadline", "late"):
        directory = Path("/evidence/review/plug-and-play") / ("fault-" + mode)
        directory.mkdir(parents=True)
        home = Path("/profile/review/plug-and-play") / ("fault-" + mode)
        install(home)
        shutil.copyfile(INPUTS / "mods/g02b/faults/payload.so", home / "mods" / OWNER / "payload.so")
        shutil.copyfile(INPUTS / "mods/g02b/faults/mod.toml", home / "mods" / OWNER / "mod.toml")
        env = sdk.environment(home, directory)
        env.update(CM_REVIEW_PROBE_PROFILE=str(home), CM_REVIEW_FAULT=mode,
            CM_REVIEW_FAULT_LOG=str(directory / "fault.jsonl"))
        command = [str(INPUTS / "probes/cm-review-tui"), "--ignored", "--exact",
            "bottom_pane::chat_composer::submit_review::cm_probe::cm_review_protocol", "--nocapture"]
        with (directory / "stdout.log").open("w") as out, (directory / "stderr.log").open("w") as err:
            result = subprocess.run(command, env=env, cwd=directory, stdout=out, stderr=err, timeout=90)
        write(directory / "result.json", {"command": command, "return_code": result.returncode, "mode": mode})
        assert result.returncode == 0, (mode, (directory / "stdout.log").read_text(), (directory / "stderr.log").read_text())
        rows = sdk.rows(directory / "fault.jsonl")
        assert any(row["event"] == "ui-only-scopes" for row in rows), rows
        expected_release = 0 if mode in ("error", "panic") else 1
        assert len([row for row in rows if row["event"] == "request-release"]) == expected_release, rows
        if expected_release == 0:
            native = sdk.rows(directory / "native.jsonl")
            assert any(row["event"] == "runtime-ui-failed" and row["detail"].get("mod_id") == OWNER
                and row["detail"].get("resource") == "tui.submit_review.v1"
                and (row["detail"].get("native_status") or 0) > 0 for row in native), native
            assert any(row["event"] == "release-failed" and row["detail"].get("mod_id") == OWNER
                and row["detail"]["code"] == "runtime" for row in native), native
            assert not any(row["event"] == "userdata-released" and row["detail"]["mod"] == OWNER
                for row in native), "Nonquiescent request userdata was released"
        if mode in ("duplicate", "stale", "late"):
            assert any(row["event"] == mode + "-completion" and row["code"] != 0 for row in rows), rows
        results.append({"mode": mode, "callbacks": rows})
    return results


@ci_progress.case()
def plug_and_play():
    native = probe("plug-and-play")
    protocols = protocol_cases()
    case = "plug-and-play"
    home = Path("/profile/review") / case / "managed"
    directory = Path("/evidence/review") / case / "management"
    frozen = sha(BINARY)
    cm(home, directory, "install", INPUTS / "mods/g02b/review-before-send.cmod")
    with terminal(case, "enabled", home=home) as tui:
        tui.review("CM_M02_enabled")
        tui.quiet()
        tui.complete("enabled")
    cm(home, directory, "disable", OWNER)
    with terminal(case, "disabled", home=home, enabled=False) as tui:
        tui.send("CM_M02_disabled")
        time.sleep(0.2)
        tui.send(b"\r")
        tui.wait(lambda: tui.managed.tui_message_visible(tui.output, "disabled"), "unmodified submission")
        assert not tui.reviews()
    cm(home, directory, "enable", OWNER)
    sdk = module("runtime-sdk/driver.py")
    provider = sdk.Provider(tool=False)
    try:
        arguments = sdk.command(directory, provider.endpoint, "embedded", token="unsupported-exec")[1:]
        rejected_exec = cm(home, directory, "launch", "--", *arguments, success=False)
        rejected_stdio = cm(home, directory, "launch", "--", "app-server", "--listen", "stdio://", success=False)
        assert rejected_exec["stage"] == rejected_stdio["stage"] == "backend"
        assert not provider.requests, "Unsupported backend opened business"
    finally:
        provider.close()
    stable = (home / "cm-profile.json").read_bytes()
    conflict = Path("/work/review-conflict")
    shutil.copytree(INPUTS / "mods/g02b/review-before-send", conflict)
    manifest = tomllib.loads((conflict / "mod.toml").read_text())
    manifest["id"] = "org.example.conflicting-review"
    mod_manifest.manifest(conflict, manifest)
    rejected = cm(home, directory, "install", conflict, success=False)
    assert rejected["code"] == "exclusive_conflict" and (home / "cm-profile.json").read_bytes() == stable
    old = INPUTS / "host/review-legacy/codex"
    old_home = Path("/profile/review") / case / "old-host"
    rejected_old = cm(old_home, directory, "install", INPUTS / "mods/g02b/review-before-send.cmod",
        binary=old, success=False)
    assert rejected_old["code"] == "manifest_parse", rejected_old
    manifest["contributions"][0]["kind"] = "lifecycle"
    mod_manifest.manifest(conflict, manifest)
    assert cm(old_home, directory, "install", conflict, binary=old, success=False)["code"] == "compatibility"
    manifest["compat"]["host_api_min"] = "0.7.0"
    mod_manifest.manifest(conflict, manifest)
    assert cm(old_home, directory, "install", conflict, binary=old, success=False)["code"] == "unknown_capability"
    cm(home, directory, "remove", OWNER)
    with terminal(case, "removed", home=home, enabled=False) as tui:
        tui.send("CM_M02_removed")
        time.sleep(0.2)
        tui.send(b"\r")
        tui.wait(lambda: tui.managed.tui_message_visible(tui.output, "removed"), "removed B baseline")
        assert not tui.reviews()
    assert sha(BINARY) == frozen
    report(case, {"managed_install_disable_enable_remove": True, "old_host_rejected_before_native": rejected_old,
        "exclusive_conflict": rejected, "host_bytes_unchanged": True, "probe": native, "protocol_cases": protocols})


if __name__ == "__main__":
    {"nondestructive": nondestructive, "invalidation": invalidation, "key-events": key_events,
     "entry-coverage": entry_coverage, "queue-lifecycle": queue_lifecycle, "plug-and-play": plug_and_play}[sys.argv[1]]()
