"""Runtime-only fixture. Standard library only; no build modules or source tree."""
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import tomllib

sys.path.insert(0, "/fixture/fixtures/native-loader")
import core_acceptance as core

INPUTS = Path("/inputs")
EVIDENCE = Path("/evidence")
WORK = Path("/work")
PROFILE = Path("/profile")
BINARY = INPUTS / "host/bin/codex"
BODY = "0123456789abcdef" * 256
LIMIT_CAP = "core.exec_output_limit.v1"


def write(path, value):
    core.write(path, value)


def read(path):
    return json.loads(path.read_text())


def tree(root):
    result = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        result.append({"path": path.relative_to(root).as_posix(), "mode": path.lstat().st_mode,
                       "sha256": core.sha(path) if path.is_file() else None,
                       "link": os.readlink(path) if path.is_symlink() else None})
    return result


def check_mounts(mounts, bind_roots):
    pseudo = {"/proc": "proc", "/dev": "tmpfs", "/tmp": "tmpfs", "/dev/pts": "devpts",
              **{"/dev/" + name: "devtmpfs" for name in ("null", "zero", "full", "random", "urandom", "tty")}}
    assert set(bind_roots) == {"/", "/profile", "/work", "/evidence"}
    seen = set()
    for mount in mounts:
        record, separator, filesystem = mount.partition(" - ")
        fields = record.split()
        assert separator and len(fields) >= 6 and filesystem.split(), mount
        decode = lambda value: re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)
        # The filesystem root identifies the backing bind; the mount point is the visible path.
        origin, point = map(decode, fields[3:5])
        options = set(fields[5].split(","))
        assert point not in seen, "Stacked consumer mount: " + point
        seen.add(point)
        if point in bind_roots:
            assert origin == bind_roots[point], "Unexpected bind source: " + mount
        else:
            kind = filesystem.split()[0]
            assert pseudo.get(point) == kind, "Unexpected consumer mount: " + mount
            assert origin == ("/" + Path(point).name if kind == "devtmpfs" else "/"), mount
        assert options.intersection({"ro", "rw"}) == ({"ro"} if point == "/" else {"rw"}), mount
    assert set(bind_roots) | {"/proc", "/dev", "/tmp"} <= seen


def environment(label):
    context = read(Path("/fixture/context.json"))
    namespaces = {name: os.readlink("/proc/self/ns/" + name) for name in context["outer_namespaces"]}
    status = Path("/proc/self/status").read_text()
    capabilities = dict(re.findall(r'^(Cap\w+):\s+(\w+)$', status, re.MULTILINE))
    descriptors = {}
    for name in os.listdir("/proc/self/fd"):
        try:
            descriptors[name] = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    routes = Path("/proc/net/route").read_text()
    interfaces = [line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    process_roots = {name: os.readlink("/proc/" + name + "/root") for name in os.listdir("/proc")
                     if name.isdigit() and Path("/proc/" + name + "/root").exists()}
    snapshot = {"namespaces": namespaces, "outer_namespaces": context["outer_namespaces"],
        "capabilities": capabilities, "fd": descriptors, "mountinfo": mounts, "routes": routes,
        "interfaces": interfaces, "process_roots": process_roots, "environment_keys": sorted(os.environ),
        "pid": os.getpid(), "root": os.readlink("/proc/self/root"), "cache_mode": context["cache_mode"],
        "expected_bind_roots": context["bind_roots"]}
    write(EVIDENCE / (label + "-environment.json"), snapshot)
    assert all(namespaces[name] != context["outer_namespaces"][name] for name in namespaces)
    assert os.getuid() == 1000 and os.getgid() == 1000
    assert all(int(capabilities[name], 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    assert all(int(name) <= 2 for name in descriptors), "Inherited nonstandard descriptor"
    assert snapshot["root"] == "/" and all(root == "/" for root in process_roots.values())
    assert not any(line.split()[1] == "00000000" for line in routes.splitlines()[1:])
    assert set(interfaces) == {"lo"}
    assert set(os.environ) <= {"PATH", "LANG", "LC_ALL", "TERM", "TMPDIR", "HOME", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"}
    check_mounts(mounts, context["bind_roots"])
    core.enable_input_digest_cache()
    for forbidden in ("/var/run/docker.sock", "/run/docker.sock", "/run/host", "/sys", "/etc/resolv.conf",
                      "/usr/bin/cargo", "/usr/bin/gcc", "/usr/bin/cc", "/usr/bin/ld", "/usr/bin/ssh"):
        assert not Path(forbidden).exists(), forbidden
    return snapshot


def probe():
    snapshot = environment("probe")
    context = read(Path("/fixture/context.json"))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(1)
    with socket.create_connection(listener.getsockname(), timeout=1) as client:
        connection, _ = listener.accept()
        with connection:
            client.sendall(b"internal-positive")
            assert connection.recv(64) == b"internal-positive"
    listener.close()
    negatives = []
    for address in (("127.0.0.1", context["canary_port"]), ("198.51.100.1", 443), ("1.1.1.1", 443)):
        try:
            with socket.create_connection(address, timeout=0.5):
                raise AssertionError("Outside path reachable: " + repr(address))
        except OSError as error:
            negatives.append({"address": address, "error": type(error).__name__, "errno": error.errno})
    try:
        socket.getaddrinfo("cm-outside-build-service.invalid", 443)
    except socket.gaierror as error:
        negatives.append({"dns": "cm-outside-build-service.invalid", "errno": error.errno})
    else:
        raise AssertionError("Unexpected external DNS resolution")
    write(EVIDENCE / "isolation-probes.json", {"status": "pass", "internal_positive": True,
        "negative_results": negatives, "actual_namespaces": snapshot["namespaces"]})


def install(home, selected):
    mods = home / "mods"
    if mods.exists():
        shutil.rmtree(mods)
    mods.mkdir(parents=True)
    for owner in selected:
        source = INPUTS / ("mods/a" if owner == "a" else "mods/b/normal")
        shutil.copytree(source, mods / owner)
    config = home / "cm-runtime.toml"
    if config.exists():
        config.unlink()


def business(name, home, owners, *, variant=None, requested_limit=10000, expected_limit=None):
    directory = EVIDENCE / name
    failure = variant is not None
    result = core.run_case(Path("/fixture"), directory, BINARY, home, bool(owners),
        scenario="output-limit-failure" if failure else "parallel", restrictive="a" in owners,
        expected_releases=len(owners), sandboxed=True, long_output=True, requested_limit=requested_limit)
    rows = core.trace_rows(directory / "core-trace.jsonl")
    ready = [row for row in rows if row["event"] == "ready"]
    assert len(ready) == 1 and ready[0]["detail"]["mod_count"] == len(owners)
    actual = sorted(ready[0]["detail"]["plan"]["mods"])
    expected = sorted({"a": "serial-fixture", "b": "output-fixture"}[owner] for owner in owners)
    assert actual == expected, (actual, expected)
    if "b" in owners:
        assert sum(row["event"] == "userdata-released" and row["detail"].get("mod") == "output-fixture" for row in rows) == 1
    limits = [row for row in rows if row["event"] == "output-limit-decision"]
    if failure:
        assert not any((directory / ("completed-" + label)).exists() for label in ("A", "B"))
        assert len(result["provider_requests"]) == 1
        assert sum(row["event"] == "registration-commit" for row in rows) == 1
        rejected = [row["detail"]["error"] for row in rows if row["event"] == "output-limit-failed"]
        assert rejected and all(error["resource"] == LIMIT_CAP and error["mod_id"] == "output-fixture" for error in rejected)
    else:
        assert len(limits) == 2
        original = 10000 if requested_limit is None else requested_limit
        assert all(row["detail"]["original_limit"] == original for row in limits)
        final = (expected_limit if expected_limit is not None else min(original, 256)) if "b" in owners and original else None
        assert all(row["detail"]["limit"] == final for row in limits)
        eligibility = {row["detail"]["call_id"]: row["detail"] for row in rows if row["event"] == "policy-decision"}
        for row in limits:
            assert all(row["detail"][key] == eligibility[row["detail"]["call_id"]][key] for key in ("thread_id", "turn_id"))
        outputs = result["provider_requests"][1]["outputs"]
        bodies = {}
        for output in outputs:
            value = output["output"]
            assert isinstance(value, str), "Unexpected provider output encoding"
            text = value
            bodies[output["call_id"]] = text
            label = output["call_id"][-1].upper()
            assert (directory / ("completed-" + label)).read_text() == "real-command-exit-0\n"
            if original == 0:
                assert BODY not in text, "Zero output request was enlarged"
            elif original < 5000 or ("b" in owners):
                assert BODY not in text and "truncat" in text.lower(), text
            else:
                assert BODY in text, "Original budget/output changed"
        if "b" in owners:
            callbacks = [row for row in rows if row["event"] == "output-limit-exit"]
            assert len(callbacks) == (4 if expected_limit is not None else 2)
            assert all(row["detail"]["context"]["mod"] == "output-fixture" for row in callbacks)
            if expected_limit is not None:
                for call_id in ("cm-a", "cm-b"):
                    assert [row["detail"]["limit"] for row in callbacks if row["detail"]["context"]["call_id"] == call_id] == [128, 256]
        else:
            assert not any(row["event"].startswith("output-limit-enter") for row in rows)
        result["provider_tool_bodies"] = bodies
    result.update(actual_loaded=actual, runtime_set_lock=ready[0]["detail"]["plan"],
                  ready_count=len(ready), commit_count=sum(row["event"] == "registration-commit" for row in rows),
                  requested_limit=requested_limit)
    write(directory / "result.json", result)
    return result


def toml_value(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(key + " = " + toml_value(item) for key, item in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    return json.dumps(value)


def change_manifest(package, change):
    path = package / "mod.toml"
    fields = tomllib.loads(path.read_text())
    change(fields)
    path.write_text("\n".join(key + " = " + toml_value(value) for key, value in fields.items()) + "\n")


def startup(name, home, binary=BINARY, *, remote=False, require_cm=True):
    directory = EVIDENCE / name
    directory.mkdir(parents=True)
    trace = directory / "native.jsonl"
    endpoint_hits = []

    class Endpoint(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            endpoint_hits.append(self.path)
            self.send_error(500)

        do_POST = do_GET

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    args = core.cli_arguments(binary, directory, "http://127.0.0.1:" + str(server.server_port), sandboxed=True)
    if remote:
        args[1:1] = ["--remote", "http://127.0.0.1:" + str(server.server_port)]
    env = {"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb", "TMPDIR": "/tmp",
           "CODEX_HOME": str(home), "HOME": str(directory / "home"), "CM_NATIVE_TRACE": str(trace),
           "CODEX_API_KEY": "cm-controlled-fixture-only", "OPENAI_API_KEY": "cm-controlled-fixture-only"}
    Path(env["HOME"]).mkdir()
    return_code = None
    try:
        with (directory / "stdout.jsonl").open("w") as out, (directory / "stderr.log").open("w") as err:
            result = subprocess.run(args, env=env, stdout=out, stderr=err, close_fds=True, timeout=45)
        return_code = result.returncode
        stderr = (directory / "stderr.log").read_text()
        rows = core.trace_rows(trace)
        report = {"command": args, "return_code": result.returncode, "trace": rows,
                  "endpoint_hits": endpoint_hits, "stderr": stderr,
                  "ready_count": sum(row["event"] == "ready" for row in rows),
                  "commit_count": sum(row["event"] == "registration-commit" for row in rows)}
        write(directory / "result.json", report)
        assert result.returncode != 0 and report["ready_count"] == 0 and report["commit_count"] == 0
        assert not endpoint_hits, "Rejected startup contacted a backend"
        if require_cm:
            assert "CM " in stderr, "Not a CM rejection"
        return report
    finally:
        if not (directory / "result.json").exists():
            write(directory / "result.json", {"status": "failed", "command": args, "return_code": return_code,
                "error": repr(sys.exc_info()[1]), "endpoint_hits": endpoint_hits,
                "stdout": "stdout.jsonl", "stderr": "stderr.log", "trace": trace.name})
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def matrix():
    env = environment("matrix")
    baseline = tree(INPUTS)
    official_before = tree(INPUTS / "official")
    producer = read(INPUTS / "producer.json")
    data = PROFILE / "mod-data"
    data.mkdir()
    for name in ("a", "b"):
        (data / name).write_text("retained-" + name)
    retained = tree(data)
    states = []
    for name, installed, selected in (("empty", (), ()), ("a", ("a",), ("a",)), ("b", ("b",), ("b",)),
                                      ("ab", ("a", "b"), ("a", "b")), ("remove-a", ("b",), ("b",)),
                                      ("disable-b", ("b",), ())):
        install(PROFILE, installed)
        if name == "disable-b":
            (PROFILE / "cm-runtime.toml").write_text("format_version = 1\nenabled = []\n")
        before = tree(INPUTS)
        result = business("states/" + name, PROFILE, selected)
        assert tree(INPUTS) == before == baseline and tree(data) == retained
        result.update(state=name, installed=list(installed), selected=list(selected),
            inputs_unchanged=True, data_retained=True, selection=(PROFILE / "cm-runtime.toml").read_text()
                if (PROFILE / "cm-runtime.toml").exists() else None)
        write(EVIDENCE / "states" / name / "result.json", result)
        states.append(result)
    # Compare the stable command body, retaining unmodified headers in raw results.
    stable = lambda text: text.split("\nOutput:\n", 1)[1]
    for label in ("cm-a", "cm-b"):
        assert stable(states[0]["provider_tool_bodies"][label]) == stable(states[1]["provider_tool_bodies"][label])
        assert stable(states[0]["provider_tool_bodies"][label]) == stable(states[5]["provider_tool_bodies"][label])
        assert all(stable(states[2]["provider_tool_bodies"][label]) == stable(states[index]["provider_tool_bodies"][label]) for index in (3, 4))
    known_success = tree(PROFILE / "mods")
    selection = (PROFILE / "cm-runtime.toml").read_bytes()
    failures = []
    for kind in ("conflict", "dependency", "abi", "target", "capability", "payload", "resource", "backend", "init-fail",
                 *producer["entry_invalid"]):
        candidate = WORK / "candidates" / kind
        install(candidate, ("a", "b"))
        package = candidate / "mods/b"
        if kind in producer["entry_invalid"] or kind == "init-fail":
            shutil.rmtree(package)
            shutil.copytree(INPUTS / "mods/b" / kind, package)
            if kind == "init-fail":
                change_manifest(package, lambda fields: fields.update(dependencies=[{"id": "serial-fixture", "version": "0.1.0"}]))
        elif kind == "payload":
            with (package / "payload.so").open("r+b") as stream:
                stream.write(b"broken")
        elif kind == "resource":
            change_manifest(package, lambda fields: fields.update(resources=[{"path": "missing.txt", "size": 1, "sha256": "0" * 64}]))
        elif kind != "backend":
            changes = {"conflict": {"conflicts": ["serial-fixture"]}, "abi": {"abi_minor": 99},
                "dependency": {"dependencies": [{"id": "missing-mod", "version": "0.1.0"}]},
                "target": {"target": "aarch64-unknown-linux-gnu"}, "capability": {"required_capabilities": ["unknown.capability"]}}
            change_manifest(package, lambda fields: fields.update(changes[kind]))
        report = startup("failures/" + kind, candidate, remote=kind == "backend")
        if kind not in ("backend", "conflict"):
            errors = [row["detail"] for row in report["trace"] if row["event"] == "startup-failed"]
            assert errors and errors[0]["resource"] == LIMIT_CAP and errors[0]["mod_id"] == "output-fixture"
        native = kind in producer["entry_invalid"] or kind == "init-fail"
        assert any(row["event"] == "dlopen-start" for row in report["trace"]) == native
        if kind == "init-fail":
            released = [index for index, row in enumerate(report["trace"]) if row["event"] == "userdata-released"]
            assert len(released) == 2 and report["trace"][released[0]]["detail"]["mod"] == "output-fixture"
            assert released[0] < next(index for index, row in enumerate(report["trace"]) if row["event"] == "release-start" and row["detail"]["mod"] == "serial-fixture") < released[1]
            assert [row["detail"]["mod"] for row in report["trace"] if row["event"] == "init-start"] == ["serial-fixture", "output-fixture"]
        failures.append({"case": kind, "result": report})
        assert tree(PROFILE / "mods") == known_success and (PROFILE / "cm-runtime.toml").read_bytes() == selection
        assert tree(data) == retained and tree(INPUTS) == baseline
        business("recoveries/startup-" + kind, PROFILE, ())
    for kind in ("missing-helper", "damaged-package", "missing-inventory"):
        candidate = WORK / "packages" / kind
        shutil.copytree(INPUTS / "host", candidate)
        if kind == "missing-helper":
            (candidate / "codex-resources/bwrap").unlink()
        elif kind == "missing-inventory":
            (candidate / "cm-runtime-files.json").unlink()
        else:
            with (candidate / "codex-path/rg").open("r+b") as stream:
                stream.write(b"damaged")
        report = startup("failures/" + kind, PROFILE, binary=candidate / "bin/codex")
        assert not report["trace"] and "CM package" in report["stderr"]
        failures.append({"case": kind, "result": report})
        business("recoveries/package-" + kind, PROFILE, ())
    for variant in producer["call_invalid"]:
        candidate = WORK / "callbacks" / variant
        install(candidate, ("b",))
        shutil.rmtree(candidate / "mods/b")
        shutil.copytree(INPUTS / "mods/b" / variant, candidate / "mods/b")
        failures.append({"case": variant, "result": business("callbacks/" + variant, candidate, ("b",), variant=variant)})
        assert tree(INPUTS) == baseline and tree(data) == retained
        business("recoveries/callback-" + variant, PROFILE, ())
    zero_cases = []
    for owner in ((), ("b",)):
        candidate = WORK / ("zero-" + str(len(owner)))
        install(candidate, owner)
        zero_cases.append(business("zero-" + str(len(owner)), candidate, owner, requested_limit=0))
    equal_home = WORK / "equal-limit"
    install(equal_home, ("b",))
    equal_case = business("equal-limit", equal_home, ("b",), requested_limit=128)
    minimum_home = WORK / "minimum-limit"
    install(minimum_home, ("b",))
    shutil.rmtree(minimum_home / "mods/b")
    shutil.copytree(INPUTS / "mods/b/two-limiters", minimum_home / "mods/b")
    minimum_case = business("minimum-limit", minimum_home, ("b",), expected_limit=128)
    default_home = WORK / "absent-default"
    install(default_home, ())
    default_case = business("absent-default", default_home, (), requested_limit=None)
    # A known successful selection is still usable after every failed candidate.
    recovery = business("recovery", PROFILE, ())
    assert tree(PROFILE / "mods") == known_success and tree(data) == retained and tree(INPUTS) == baseline
    reports = {
        "frozen-host-independent-mods.json": {"authors": producer["authors"], "host_link_inputs_contain_mods": False,
            "input_inventory_before": baseline, "input_inventory_after": tree(INPUTS), "selection_builds": 0},
        "zero-build-runtime-environment.json": {"environment": env, "probes": read(EVIDENCE / "isolation-probes.json"),
            "runtime_inputs": baseline, "build_modules_available": False, "cache_mode": "none"},
        "plug-and-play-matrix.json": {"states": states, "zero_request_cases": zero_cases,
            "equal_input_limit": equal_case, "multiple_limiters_minimum": minimum_case,
            "absent_default_request": default_case, "data_retained": retained},
        "runtime-package-integrity.json": {"absolute_cli": str(BINARY), "actual_elf_sha256": core.sha(BINARY),
            "embedded": True, "sandbox": "workspace-write/never; actual nested packaged bwrap and rg",
            "package_files": tree(INPUTS / "host"), "required_component_failures": [case for case in failures if "package" in case["case"] or "missing" in case["case"]]},
        "zero-build-failure-matrix.json": {"failures": failures, "known_selection_unchanged": True,
            "active_pointer": "absent in current runtime; candidates never overwrite known selection", "recovery": recovery},
        "empty-host-independent-install.json": {"empty_states": [states[0], states[5]], "official_before": official_before,
            "official_after": tree(INPUTS / "official"), "official_producer_manifest": producer["official"],
            "official_profile_setup": producer["official_profile_setup"],
            "maintained_source": producer["maintained_source"],
            "cm_inputs_unchanged": baseline == tree(INPUTS)},
    }
    reports["frozen-host-independent-mods.json"]["read_only_input_digest_reuse"] = core.input_digest_stats()
    for name, report in reports.items():
        write(EVIDENCE / name, {"status": "behavior_pass", **report})
    write(EVIDENCE / "suite.json", {"status": "pass", "reports": sorted(reports), "release_ready": False})


def missing_library():
    context = read(Path("/fixture/missing-library.json"))
    report = startup("failures/missing-library", PROFILE, require_cm=False)
    assert not report["trace"]
    assert Path(context["removed_library"]).name in report["stderr"]
    assert "CM package" in report["stderr"] or "error while loading shared libraries" in report["stderr"]
    write(EVIDENCE / "missing-library.json", {"status": "pass", "mutation": context, "result": report})


def recovery():
    environment("recovery")
    before = tree(INPUTS)
    result = business("recoveries/actual-missing-library", PROFILE, ())
    assert tree(INPUTS) == before
    write(EVIDENCE / "actual-missing-library-recovery.json", result)


if __name__ == "__main__":
    {"probe": probe, "matrix": matrix, "missing-library": missing_library, "recovery": recovery}[sys.argv[1]]()
