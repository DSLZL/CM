#!/usr/bin/env python3
"""Atomic S03 CLI cases in the compiler-free private runtime rootfs."""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, "/fixture/ci/scripts")
import binary_index
from cm_platforms import linux_native
import ci_progress
import distribution_provenance as distribution
import runtime_cases

INPUTS = Path("/inputs")
WORK = Path("/work")
PROFILE = Path("/profile")
EVIDENCE = Path("/evidence")
BINARY = INPUTS / "host/bin/codex"
CATALOG = Path("/fixture/s01-proofs/index")
_counter = 0


def report(index, key, value):
    rows = [{} for _ in binary_index.REPORTS]
    rows[index] = {key: value}
    return rows


def case_data(case):
    value = distribution.read(Path("/fixture/fixtures/binary-index/cases.json"))["cases"][case]
    assert value["target"] == "native"
    return {**value, "target": binary_index.TARGET}


def state(home=None):
    home = home or PROFILE
    path = home / "cm-profile.json"
    if not path.exists():
        return None
    raw = path.read_bytes()
    return raw, (home / "store/generations" / json.loads(raw)["generation"]).read_bytes()


def command(*arguments, good=True, code=None, home=None, metadata=True):
    global _counter
    _counter += 1
    home = home or PROFILE
    directory = EVIDENCE / ("command-" + str(_counter))
    directory.mkdir(mode=0o700, parents=True)
    argv = [str(BINARY), "cm", "--home", str(home), *map(str, arguments)]
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(WORK), "CODEX_HOME": str(home),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GH_NO_UPDATE_NOTIFIER": "1",
        "CM_SEAMS_EVENTS": str(directory / "events.jsonl"), "CM_NATIVE_TRACE": str(directory / "native.jsonl"),
        "CM_REPLACEMENT_SENTINEL": str(directory / "constructor")}
    started = time.monotonic()
    result = subprocess.run(argv, env=environment, cwd=WORK, capture_output=True, text=True, timeout=145)
    value = {"command": argv, "return_code": result.returncode, "stdout": result.stdout,
        "stderr": result.stderr, "duration_seconds": time.monotonic() - started,
        "host_sha256": distribution.sha(BINARY)}
    distribution.write(directory / "result.json", value)
    assert (result.returncode == 0) == good, value
    if code:
        errors = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
        assert errors and errors[-1]["code"] == code, value
        assert errors[-1]["already_native_executed"] is False, value
    if metadata:
        assert not (directory / "events.jsonl").exists() and not (directory / "constructor").exists()
        assert not any((WORK / name).exists() for name in ("install-script-executed", "proc-macro-executed"))
    return json.loads(result.stdout) if good else value


def catalog(name="catalog", root=CATALOG):
    destination = WORK / "origin"
    if not destination.exists():
        shutil.copytree(root, destination)
    for suffix in (".json", ".json.bundle.jsonl"):
        shutil.copyfile(root / (name + suffix), destination / ("current" + suffix))
    return destination / "current.json"


def selections(*owners):
    return tuple(argument for owner in (owners or ("sdk-a",)) for argument in ("--mod", owner + "@0.1.0"))


def plan(source, *owners, offline=False, good=True, code=None):
    output = WORK / ("plan-" + str(_counter + 1) + ".json")
    result = command("index", "plan", "--source", source, *selections(*owners), "--out", output,
        *(("--offline",) if offline else ()), good=good, code=code)
    return output, result


def install(path, offline=False, good=True, code=None):
    return command("index", "install", "--plan", path, *(("--offline",) if offline else ()), good=good, code=code)


def rejected_archive(case):
    source = catalog(case.removeprefix("archive-"))
    before = state()
    _, result = plan(source, good=False)
    errors = [json.loads(line) for line in result["stderr"].splitlines() if line.startswith("{")]
    assert errors and errors[-1]["code"] in ("manifest_parse", "installation"), result
    assert errors[-1]["code"] not in ("distribution_signature", "index_checksum"), result
    assert state() == before and not (WORK / "escaped").exists()
    return report(2, case.replace("-", "_"), {"scope": case_data(case), "rejection": result})


class Origin:
    def __init__(self, mode="normal", tls=False):
        self.mode, self.requests = mode, []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(self.path)
                if owner.mode == "size":
                    self.send_response(200)
                    self.send_header("Content-Length", str(4 * 1024 * 1024 + 1))
                    self.end_headers()
                elif owner.mode == "timeout":
                    self.send_response(200)
                    self.send_header("Content-Length", "10")
                    self.end_headers()
                    owner.stopped.wait(25)
                elif owner.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:1/forbidden")
                    self.end_headers()
                elif owner.mode == "loop":
                    self.send_response(302)
                    self.send_header("Location", "/current.json")
                    self.end_headers()
                else:
                    path = self.path.lstrip("/")
                    if not path or any(part in ("", ".", "..") for part in path.split("/")):
                        self.send_error(404)
                        return
                    target = WORK / "origin" / path
                    if not target.is_file():
                        self.send_error(404)
                        return
                    data = target.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

            def log_message(self, *_arguments):
                pass

        self.stopped = threading.Event()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain("/fixture/binary-index-tls/cert.pem", "/fixture/binary-index-tls/key.pem")
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.endpoint = "http://127.0.0.1:" + str(self.server.server_address[1]) + "/current.json"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_error):
        self.stopped.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        distribution.write(EVIDENCE / ("http-" + self.mode + ".json"), {"endpoint": self.endpoint, "requests": self.requests})


def case_index_envelope():
    source = catalog()
    data = source.read_bytes()
    value = json.loads(data)
    results = []
    for raw in (data[:-1], data[:-1] + b',"records":[]}', distribution.canonical(value | {"execute": "shell"})):
        source.write_bytes(raw)
        results.append(command("index", "list", "--source", source, good=False, code="index_envelope"))
    assert state() is None
    return report(0, "closed_envelope", {"scope": case_data("index-envelope"), "rejections": results})


def case_identity_conflict():
    source = catalog()
    command("index", "list", "--source", source)
    catalog("identity-conflict")
    result = command("index", "list", "--source", source, good=False, code="index_identity_conflict")
    assert state() is None
    return report(0, "same_version_rebinding", {"scope": case_data("identity-conflict"), "rejection": result})


def case_namespace():
    result = command("index", "list", "--source", catalog("namespace"), good=False, code="index_namespace")
    return report(0, "namespace_binding", {"scope": case_data("namespace"), "rejection": result})


def case_source_proof():
    source = catalog()
    raw = source.read_bytes()
    value = json.loads(raw)
    value["source"]["repository_id"] = 1
    source.write_bytes(distribution.canonical(value))
    wrong = command("index", "list", "--source", source, good=False)
    source.write_bytes(raw)
    source.with_name(source.name + ".bundle.jsonl").write_bytes(b"{}")
    bad = command("index", "list", "--source", source, good=False)
    return report(0, "first_party_signature", {"scope": case_data("source-proof"), "rejections": [wrong, bad]})


def case_read_only():
    source = catalog()
    with Origin() as origin:
        listing = command("index", "list", "--source", origin.endpoint)
        assert origin.requests == ["/current.json", "/current.json.bundle.jsonl"]
        _, preview = plan(origin.endpoint)
        assert not preview["committed"] and not preview["already_native_executed"]
    assert state() is None and not (PROFILE / "state").exists()
    return report(1, "read_only_discovery", {"scope": case_data("read-only"), "list": listing, "preview": preview})


def case_missing_target():
    with Origin() as origin:
        catalog("missing-target")
        _, result = plan(origin.endpoint, good=False, code="index_missing_target")
        assert origin.requests == ["/current.json", "/current.json.bundle.jsonl"]
    assert state() is None
    return report(1, "missing_target", {"scope": case_data("missing-target"), "rejection": result})


def case_http_size():
    with Origin("size") as origin:
        result = command("index", "list", "--source", origin.endpoint, good=False, code="index_size")
    return report(1, "bounded_http_size", {"scope": case_data("http-size"), "rejection": result})


def case_http_redirect():
    results = []
    for mode in ("redirect", "loop"):
        with Origin(mode) as origin:
            results.append(command("index", "list", "--source", origin.endpoint, good=False))
            assert len(origin.requests) <= 4
    return report(1, "same_origin_redirect_bound", {"scope": case_data("http-redirect"), "rejections": results})


def case_http_timeout():
    with Origin("timeout") as origin:
        result = command("index", "list", "--source", origin.endpoint, good=False)
        assert result["duration_seconds"] < 24
    return report(1, "bounded_http_deadline", {"scope": case_data("http-timeout"), "rejection": result})


def case_http_tls():
    with Origin(tls=True) as origin:
        result = command("index", "list", "--source", origin.endpoint.replace("http:", "https:"), good=False, code="index_http")
        assert not origin.requests, "Untrusted TLS certificate reached HTTP application data"
    return report(1, "tls_is_required", {"scope": case_data("http-tls"), "rejection": result})


def case_archive_traversal():
    return rejected_archive("archive-traversal")


def case_archive_absolute():
    return rejected_archive("archive-absolute")


def case_archive_symlink():
    return rejected_archive("archive-symlink")


def case_archive_duplicate():
    return rejected_archive("archive-duplicate")


def case_archive_case_collision():
    return rejected_archive("archive-case-collision")


def case_archive_entry_limit():
    return rejected_archive("archive-entry-limit")


def case_archive_byte_limit():
    return rejected_archive("archive-byte-limit")


def case_archive_checksum():
    source = catalog()
    row = distribution.read(source)["records"][0]
    archive = source.parent / row["archive"]["path"]
    archive.write_bytes(b"not even a ZIP")
    _, result = plan(source, good=False, code="index_checksum")
    assert state() is None
    return report(2, "checksum_before_zip", {"scope": case_data("archive-checksum"), "rejection": result})


def case_plan_exact():
    source = catalog()
    path, preview = plan(source)
    saved = distribution.read(path)
    assert saved["selections"] == ["sdk-a@0.1.0"] and state() is None
    assert preview["plan_projection"]["candidate_contents"] == {"sdk-a": distribution.read(source)["records"][0]["object_sha256"]}
    assert not preview["support"]["sdk-a"]["platform_verified"]
    committed = install(path)
    assert committed["committed"] and state() is not None
    return report(3, "exact_plan_commit", {"scope": case_data("plan-exact"), "preview": preview, "commit": committed})


def case_plan_order():
    source = catalog()
    _, left = plan(source, "sdk-a", "sdk-b")
    _, right = plan(source, "sdk-b", "sdk-a")
    assert left["plan_sha256"] == right["plan_sha256"] and left["lock_sha256"] == right["lock_sha256"]
    assert state() is None
    assert not left["committed"] and not right["committed"]
    return report(3, "order_independent_lock", {"scope": case_data("plan-order"), "left": left, "right": right})


def case_plan_dependency():
    _, result = plan(catalog("dependency"), good=False, code="missing_dependency")
    assert state() is None
    return report(3, "dependency_rejection", {"scope": case_data("plan-dependency"), "rejection": result})


def case_plan_exclusive():
    _, result = plan(catalog("exclusive"), "sdk-a", "sdk-b", good=False, code="exclusive_conflict")
    assert state() is None
    return report(3, "exclusive_rejection", {"scope": case_data("plan-exclusive"), "rejection": result})


def case_plan_drift():
    source = catalog()
    path, _ = plan(source)
    current, _ = plan(source)
    install(current)
    before = state()
    assert before is not None
    result = install(path, good=False, code="input_drift")
    assert state() == before
    return report(3, "generation_drift", {"scope": case_data("plan-drift"), "rejection": result})


def case_transaction_fault():
    source = catalog()
    path, _ = plan(source, "sdk-a", "sdk-b")
    saved = distribution.read(path)
    row = next(row for row in distribution.read(source)["records"] if row["id"] == "sdk-b")
    payload = PROFILE / "store/objects" / row["object_sha256"] / row["declarations"]["binary"]["path"]
    payload.write_bytes(b"fault after preview")
    before = state()
    result = install(path, offline=True, good=False)
    assert state() == before and saved["selections"] == ["sdk-a@0.1.0", "sdk-b@0.1.0"]
    return report(3, "batch_is_not_partially_committed", {"scope": case_data("transaction-fault"), "rejection": result})


def case_support_forgery():
    source = catalog()
    value = distribution.read(source)
    value["records"][0]["platform_verified"] = True
    source.write_bytes(distribution.canonical(value))
    result = command("index", "list", "--source", source, good=False, code="index_envelope")
    return report(4, "untrusted_verification_label", {"scope": case_data("support-forgery"), "rejection": result})


def case_support_exact():
    source = catalog()
    _, preview = plan(source)
    assert preview["support"]["sdk-a"] == {"origin_verified": True, "declared_compatible": True,
        "platform_verified": False, "reason": "qualification_missing"}
    context = distribution.read(Path("/fixture/context.json"))
    import platform
    libc_name, libc_version = platform.libc_ver()
    assert libc_name == "glibc" and context["image_os"] == "ubuntu24"
    claim = {"plan": preview["plan_projection"], "conditions": {"backend": "Embedded", "target": binary_index.TARGET,
        "cpu": linux_native()["cpu"], "glibc_version": libc_version, "mods": preview["plan_projection"]["candidate_contents"],
        "config_sha256": preview["plan_projection"]["config"]["sha256"],
        "state_contracts_sha256": preview["state_contracts_sha256"],
        "exclusions": ["native-sandbox", "other-platforms", "hot-unload", "release-readiness"]},
        "image_os": context["image_os"], "image_version": context["image_version"]}
    return report(4, "qualification_candidate", claim)


def case_support_update():
    source = catalog()
    path, _ = plan(source)
    install(path)
    old = state()
    catalog("update")
    output = WORK / "update-plan.json"
    preview = command("index", "plan", "--source", source, "--mod", "sdk-a@0.2.0", "--out", output)
    assert not preview["support"]["sdk-a"]["platform_verified"] and state() == old
    result = install(output)
    assert result["committed"] and state() != old
    return report(4, "new_version_no_inheritance", {"scope": case_data("support-update"), "preview": preview})


def case_offline_complete():
    source = catalog()
    path, _ = plan(source)
    shutil.rmtree(source.parent)
    listing = command("index", "list", "--source", source, "--offline")
    assert listing["offline"] and not listing["revocation_fresh"]
    result = install(path, offline=True)
    assert result["committed"]
    command("disable", "sdk-a")
    assert not json.loads(state()[1])["enabled"]
    return report(5, "offline_exact_install_disable", {"scope": case_data("offline-complete"), "list": listing, "install": result})


def case_offline_missing():
    source = catalog()
    command("index", "list", "--source", source)
    shutil.rmtree(source.parent)
    _, result = plan(source, offline=True, good=False, code="index_offline_missing")
    assert state() is None
    return report(5, "offline_missing_never_builds", {"scope": case_data("offline-missing"), "rejection": result})


def seams():
    path = Path("/fixture/fixtures/sdk-seams/driver.py")
    spec = importlib.util.spec_from_file_location("s03_seams", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def case_refresh_running():
    source = catalog()
    path, _ = plan(source)
    install(path)
    before = state()
    runtime = seams()
    # Refresh during the actual native request, before its provider completes the turn.
    def refresh(process, directory, provider):
        catalog("revoked")
        value = command("index", "list", "--source", source)
        assert value["records"][0]["status"] == "revoked" and state() == before
        assert process.poll() is None
        runtime.release_native(process, directory, provider)
    value = runtime.real(PROFILE, EVIDENCE / "running", on_wait=refresh)
    assert value["original_count"] == 1 and value["host_sha256"] == distribution.sha(BINARY)
    ready = [row["detail"]["plan"] for row in value["native"] if row["event"] == "ready"]
    assert len(ready) == 1 and ready[0]["candidate_contents"] == {"sdk-a": distribution.read(CATALOG / "catalog.json")["records"][0]["object_sha256"]}
    assert state() == before
    return report(5, "refresh_keeps_running_set", {"scope": case_data("refresh-running"), "run": value})


def case_revoked_record():
    source = catalog()
    command("index", "list", "--source", source)
    catalog("revoked")
    _, result = plan(source, good=False, code="index_revoked")
    assert state() is None
    return report(5, "signed_revocation", {"scope": case_data("revoked-record"), "rejection": result})


def proof():
    runtime_cases.enter(globals(), "s03", "support-exact")
    for directory in (WORK, PROFILE, EVIDENCE):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = Path("/fixture/s03-qualified/index")
    values = {}
    for name in ("exact", "host", "state", "environment"):
        home = PROFILE / name
        home.mkdir(mode=0o700)
        source = catalog("qualified-" + name, root)
        output = WORK / (name + "-plan.json")
        result = command("index", "plan", "--source", source, *selections(), "--out", output, home=home)
        label = result["support"]["sdk-a"]
        assert label["origin_verified"] and label["declared_compatible"]
        assert label["platform_verified"] == (name == "exact"), result
        values[name] = result
    source = catalog("qualified-exact", root)
    row = distribution.read(source)["records"][0]
    claim = source.parent / row["qualification"]["statement"]["path"]
    claim.write_bytes(claim.read_bytes()[:-1] + b" ")
    home = PROFILE / "forgery"
    home.mkdir(mode=0o700)
    forged = command("index", "plan", "--source", source, *selections(), "--out", WORK / "forged-plan.json",
        home=home, good=False, code="index_checksum")
    distribution.write(Path("/evidence/index-proof-consumer.json"), {"status": "pass", "platform_verified_positive": values["exact"],
        "signed_condition_negatives": {key: value for key, value in values.items() if key != "exact"},
        "forged_qualification": forged, "host_sha256": distribution.sha(BINARY), "release_ready": False})


def current_verification(qualified=False):
    path = Path("/fixture/fixtures/distribution-provenance/driver.py")
    spec = importlib.util.spec_from_file_location("s03_distribution", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = Path("/fixture/s03-qualified/index") if qualified else CATALOG
    groups = (("qualifications", "qualification-bundle.jsonl"), ("qualified", "qualified-index-bundle.jsonl")) if qualified else (
        ("negative-subjects", "negative-bundle.jsonl"), ("subjects", "index-bundle.jsonl"))
    values = {}
    for directory, bundle in groups:
        files = sorted((root / directory).glob("*.json"))
        assert files and len(files) <= 32
        verified = module.verified_subject("s03", receipt=files[0], bundle=root / bundle)
        subjects = {item["digest"].get("sha256") for row in verified["verified"]
            for item in row["verificationResult"]["statement"]["subject"]}
        assert {distribution.sha(path) for path in files} <= subjects
        signer = distribution.read(files[0])["signer"]
        assert all(distribution.read(path)["signer"] == signer for path in files)
        values[directory] = {"subjects": {path.name: distribution.sha(path) for path in files}, "verification": verified}
    distribution.write(Path("/evidence/s03-qualified-verification.json" if qualified else "/evidence/s03-current-verification.json"), values)


@ci_progress.case()
def matrix(case):
    runtime_cases.enter(globals(), "s03", case)
    for directory in (WORK, PROFILE, EVIDENCE):
        directory.mkdir(mode=0o700, parents=True)
    result = globals()[runtime_cases.function(case, "s03")]()
    runtime_cases.finish("s03", case, result, binary_index.REPORTS)


if __name__ == "__main__":
    if sys.argv[1:] == ["proof"]:
        proof()
    elif sys.argv[1:] in (["verify-current"], ["verify-qualified"]):
        current_verification(sys.argv[1] == "verify-qualified")
    else:
        assert len(sys.argv) == 3 and sys.argv[1] == "matrix"
        matrix(sys.argv[2])
