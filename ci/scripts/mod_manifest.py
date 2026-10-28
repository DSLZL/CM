#!/usr/bin/env python3
"""M01 actual-CLI acceptance; runtime matrix uses only the standard library and frozen inputs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import tomllib
import zipfile

import ci_progress

TARGET = "x86_64-unknown-linux-gnu"
CAP = "core.exec_output_limit.v1"
CANARIES = ("M01_OWN_SECRET", "M01_OTHER_SECRET", "M01_BAD_SECRET")
REPORTS = ("binary-mod-manifest.json", "runtime-lock-determinism.json", "manifest-rejection-matrix.json",
           "runtime-lock-integrity.json", "mod-config-contract.json", "metadata-only-resolution.json")


def redact(text):
    for secret in CANARIES:
        text = text.replace(secret, "<configuration redacted>")
    return text


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text())


def toml_value(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(json.dumps(key) + " = " + toml_value(v) for key, v in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    return json.dumps(value)


def write_toml(path, fields):
    text = "\n".join(json.dumps(k) + " = " + toml_value(v) for k, v in fields.items()) + "\n"
    assert tomllib.loads(text) == fields
    path.write_text(text, encoding="utf-8")
    return text


def manifest(package, fields):
    write_toml(package / "mod.toml", fields)


def native_glibc_min(payload):
    # Trusted author output only; user installation never executes readelf or ldd.
    text = subprocess.check_output(["readelf", "--version-info", str(payload)], text=True)
    versions = [tuple(map(int, value.split("."))) for value in re.findall(r"\bGLIBC_(\d+[.]\d+(?:[.]\d+)?)\b", text)]
    required = max(versions, default=(2, 2))
    # The manifest has major.minor precision: round patch requirements up.
    return f"{required[0]}.{required[1] + int(any(required[2:]))}"


def convert(package, *, configured=False):
    old = tomllib.loads((package / "mod.toml").read_text())
    if old["format_version"] == 3:
        value = old
    else:
        hooks = old.get("contributions", [{"id": old.get("contribution"), "kind": "legacy_filter",
            "capability": old["required_capabilities"][0], "resource": old["required_capabilities"][0]}])
        value = {"format_version": 3, "id": old["id"], "version": "1.2.3", "kind": "sdk",
            "binary": {"path": old["payload"], "size": old["payload_size"], "sha256": old["payload_sha256"],
                "target": TARGET, "entry": "cm_mod_entry_v" + str(old["abi_major"]),
                "glibc_min": native_glibc_min(package / old["payload"]), "cpu": "x86-64"},
            "compat": {"abi_major": old["abi_major"], "abi_minor_min": old["abi_minor"], "abi_minor_max": old["abi_minor"],
                "host_api_min": "0.4.0", "required_capabilities": old["required_capabilities"]},
            "dependencies": [], "conflicts": [], "contributions": hooks, "resources": old.get("resources", []),
            "state": {"owner": old["id"], "schema": "fixture-state", "version": 1, "preserve": True},
            "provenance": {"repository": "https://github.com/DSLZL/CM", "revision": "a" * 40,
                "release_notes": "Independent binary fixture; no installation scripts", "license": "Apache-2.0"}}
    if configured:
        value["config"] = {"schema_version": 1, "schema": {"type": "object", "additionalProperties": False,
            "required": ["limit", "token", "labels"], "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 512}, "token": {"type": "string", "minLength": 1},
                "labels": {"type": "array", "items": {"type": "string"}, "minItems": 1}}},
            "defaults": {"limit": 256, "token": "default-token", "labels": ["default", "keep"]}}
    manifest(package, value)
    return value


def zip_package(package, destination, *, reverse=False, method=zipfile.ZIP_DEFLATED, extra=()):
    files = sorted(path for path in package.rglob("*") if path.is_file())
    with zipfile.ZipFile(destination, "w", compression=method) as archive:
        for path in (reversed(files) if reverse else files):
            archive.writestr(path.relative_to(package).as_posix(), path.read_bytes())
        for name, data in extra:
            archive.writestr(name, data)


@ci_progress.case()
def metadata(binary, home, action, *, options=(), success=True, evidence=None, extra_env=None):
    home.mkdir(parents=True, exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb",
        "HOME": str(home.parent / "metadata-home"), "CODEX_HOME": str(home), **(extra_env or {})}
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run([str(binary), *options, "cm", *action], env=env, text=True, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired:
        raise RuntimeError("CM metadata command timed out") from None
    for secret in CANARIES:
        assert secret not in result.stdout and secret not in result.stderr, "Metadata output leaked a configuration value"
    assert (result.returncode == 0) == success, (action, result.returncode, result.stderr)
    value = json.loads(result.stdout) if success else next((json.loads(line) for line in result.stderr.splitlines() if line.startswith('{')), {})
    if success:
        assert value["already_native_executed"] is False
    else:
        assert value.get("already_native_executed") is False and value.get("code") and value.get("field"), result.stderr
    report = {"return_code": result.returncode, "output": value, "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()}
    if evidence:
        write(evidence, report)
    return report


def selection(home, enabled, *, configured=False):
    value = {"format_version": 2, "enabled": enabled}
    if configured:
        value.update(mods={"output-fixture": {"token": CANARIES[0], "limit": 224, "labels": ["user", "keep"]}},
            profiles={"review": {"mods": {"output-fixture": {"limit": 192, "labels": ["profile", "keep"]}}}})
    return write_toml(home / "cm-runtime.toml", value)


def install(home, inputs, *, configured=False, reverse=False, archive=False):
    home.mkdir(parents=True)
    (home / "mods").mkdir()
    roles = [("a", "serial-fixture"), ("b/config" if configured else "b/normal", "output-fixture")]
    if reverse:
        roles.reverse()
    for role, owner in roles:
        slot = ("00" if owner == "serial-fixture" else "99") if reverse else owner
        package = home / "mods" / slot
        prepared = {"a": "m01-a", "b/normal": "m01-b", "b/config": "m01-config"}[role]
        shutil.copytree(inputs / "mods" / (prepared if (inputs / "mods" / prepared).exists() else role), package)
        if tomllib.loads((package / "mod.toml").read_text())["format_version"] < 3:
            convert(package, configured=configured and owner == "output-fixture")
        if archive:
            zip_package(package, home / "mods" / (slot + ".cmod"), reverse=reverse,
                method=zipfile.ZIP_STORED if reverse else zipfile.ZIP_DEFLATED)
            shutil.rmtree(package)
    selection(home, ["output-fixture", "serial-fixture"], configured=configured)
    return home


def mutate(home, owner, change):
    for package in (home / "mods").iterdir():
        if package.is_dir():
            fields = tomllib.loads((package / "mod.toml").read_text())
            if fields["id"] == owner:
                change(fields)
                manifest(package, fields)
                return package
    raise AssertionError("Missing fixture owner")


@ci_progress.case()
def rejection_cases(work, inputs, binary, evidence):
    cases = {
        "version-conflict": lambda m: m.update(dependencies=[{"id": "serial-fixture", "version": ">=2.0.0"}]),
        "missing-dependency": lambda m: m.update(dependencies=[{"id": "missing", "version": "^1"}]),
        "duplicate-dependency": lambda m: m.update(dependencies=[{"id": "serial-fixture", "version": "^1"}] * 2),
        "self-dependency": lambda m: m.update(dependencies=[{"id": "output-fixture", "version": "^1"}]),
        "bad-range": lambda m: m.update(dependencies=[{"id": "serial-fixture", "version": "secret??"}]),
        "capability": lambda m: m["compat"].update(required_capabilities=["unknown.capability.v1"]),
        "api": lambda m: m["compat"].update(host_api_min="99.0.0"),
        "abi": lambda m: m["compat"].update(abi_minor_max=99),
        "entry": lambda m: m["binary"].update(entry="run_installer"),
        "cpu": lambda m: m["binary"].update(cpu="x86-64-v4"),
        "system": lambda m: m["binary"].update(glibc_min="99.0"),
        "target": lambda m: m["binary"].update(target="aarch64-unknown-linux-gnu"),
        "script": lambda m: m.update(postinstall="build.rs"),
        "source-only": lambda m: m.pop("binary"),
        "state-owner": lambda m: m["state"].update(owner="someone-else"),
        "digest": lambda m: m["binary"].update(sha256="0" * 64),
        "duplicate-id": lambda m: (m.update(id="serial-fixture"), m["state"].update(owner="serial-fixture")),
        "conflict": lambda m: m.update(conflicts=["serial-fixture"]),
    }
    rows = []
    for name, change in cases.items():
        home = install(work / name, inputs)
        mutate(home, "output-fixture", change)
        rows.append({"case": name, **metadata(binary, home, ["plan"], success=False, evidence=evidence / (name + ".json"))})
    for name in ("missing-payload", "ordinary-executable", "zip-executable", "directory-link", "directory-hardlink", "directory-special"):
        home = install(work / name, inputs)
        package = home / "mods/output-fixture"
        if name == "missing-payload":
            (package / "payload.so").unlink()
        elif name.endswith("executable"):
            shutil.copyfile("/usr/bin/env", package / "payload.so")
            mutate(home, "output-fixture", lambda m: m["binary"].update(size=(package / "payload.so").stat().st_size,
                sha256=sha(package / "payload.so")))
            if name == "zip-executable":
                zip_package(package, package.with_suffix(".cmod")); shutil.rmtree(package)
        elif name == "directory-link":
            (package / "alias").symlink_to("payload.so")
        elif name == "directory-hardlink":
            os.link(package / "payload.so", package / "alias")
        else:
            os.mkfifo(package / "pipe")
        result = metadata(binary, home, ["plan"], success=False)
        rows.append({"case": name, **result})
    home = install(work / "dependency-cycle", inputs)
    mutate(home, "output-fixture", lambda m: m.update(dependencies=[{"id": "serial-fixture", "version": "^1"}]))
    mutate(home, "serial-fixture", lambda m: m.update(dependencies=[{"id": "output-fixture", "version": "^1"}]))
    rows.append({"case": "dependency-cycle", **metadata(binary, home, ["plan"], success=False)})
    home = install(work / "prerelease", inputs)
    mutate(home, "serial-fixture", lambda m: m.update(version="1.2.3-rc.1"))
    mutate(home, "output-fixture", lambda m: m.update(dependencies=[{"id": "serial-fixture", "version": ">=1.0.0"}]))
    rows.append({"case": "prerelease", **metadata(binary, home, ["plan"], success=False)})
    mutate(home, "output-fixture", lambda m: m.update(dependencies=[{"id": "serial-fixture", "version": "=1.2.3-rc.1"}]))
    prerelease = metadata(binary, home, ["plan"])
    home = install(work / "optional", inputs)
    mutate(home, "output-fixture", lambda m: m.update(dependencies=[{"id": "missing", "version": "^1", "optional": True}]))
    optional = metadata(binary, home, ["plan"])
    mutate(home, "output-fixture", lambda m: m["dependencies"][0].update(id="serial-fixture", version=">=2"))
    rows.append({"case": "selected-optional-version", **metadata(binary, home, ["plan"], success=False)})
    home = install(work / "optional-disabled", inputs)
    mutate(home, "output-fixture", lambda m: m.update(dependencies=[{"id": "serial-fixture", "version": "^1", "optional": True}]))
    selection(home, ["output-fixture"])
    disabled = metadata(binary, home, ["plan"])
    assert disabled["output"]["plan"]["initialization_order"] == ["output-fixture"]
    selection(home, ["serial-fixture", "output-fixture"])
    selected_optional = metadata(binary, home, ["plan"])
    mutate(home, "serial-fixture", lambda m: m.update(version="1.2.3+author"))
    mutate(home, "output-fixture", lambda m: m["dependencies"][0].update(version=">=1.2.3, <2.0.0"))
    build_metadata = metadata(binary, home, ["plan"])
    # Around contributions reuse the P03 seam to exercise its separate graph.
    home = install(work / "hook-dangling", inputs)
    mutate(home, "output-fixture", lambda m: m.update(dependencies=[{"id": "absent", "version": "^1", "optional": True}]))
    mutate(home, "output-fixture", lambda m: m["contributions"][0].update(kind="before", capability="core.tool_parallel_eligibility.compose.v1",
        resource="core.tool_parallel_eligibility.v1", order_before=["absent::hook"]))
    mutate(home, "output-fixture", lambda m: m["compat"].update(abi_minor_min=0, abi_minor_max=0,
        required_capabilities=["core.tool_parallel_eligibility.compose.v1"]))
    rows.append({"case": "dangling-optional-contribution", **metadata(binary, home, ["plan"], success=False)})
    for name in ("hook-cycle", "exclusive"):
        home = install(work / name, inputs)
        for owner, other in (("serial-fixture", "output-fixture"), ("output-fixture", "serial-fixture")):
            def update(m):
                m["binary"]["entry"] = "cm_mod_entry_v2"
                m["compat"].update(abi_major=2, abi_minor_min=0, abi_minor_max=0,
                    required_capabilities=["core.tool_parallel_eligibility.compose.v1"])
                m["contributions"] = [{"id": "hook", "kind": "before" if name == "hook-cycle" else "replacement",
                    "resource": "core.tool_parallel_eligibility.v1", "capability": "core.tool_parallel_eligibility.compose.v1",
                    "order_before": [other + "::hook"] if name == "hook-cycle" else []}]
            mutate(home, owner, update)
        result = metadata(binary, home, ["plan"], success=False)
        assert result["output"]["graph"] == "contribution"
        rows.append({"case": name, **result})
    return {"rejected": rows, "optional_absent": optional, "optional_installed_disabled": disabled,
        "optional_selected_matching": selected_optional, "explicit_prerelease": prerelease, "build_metadata_intersection": build_metadata}


def zip_rejections(work, inputs, binary):
    source = install(work / "zip-source", inputs)
    package = source / "mods/output-fixture"
    rows = []
    for name in ("traversal", "absolute", "backslash", "depth", "duplicate", "file-directory", "symlink", "special", "encrypted", "method", "crc", "truncated", "local-name", "size", "entry-limit",
                 "implicit-entry-limit", "entry-byte-limit", "attachment-byte-limit", "total-byte-limit"):
        home = work / ("zip-" + name)
        (home / "mods").mkdir(parents=True)
        path = home / "mods/bad.cmod"
        extra = {"traversal": [("../escape", b"x")], "absolute": [("/escape", b"x")],
            "backslash": [("a\\b", b"x")], "duplicate": [("mod.toml", b"duplicate")], "file-directory": [("payload.so/", b"")],
            "depth": [("a/" * 16 + "file", b"x")],
            "entry-limit": [("entry-" + str(i), b"") for i in range(257)],
            "implicit-entry-limit": [("dir-" + str(i) + "/file", b"") for i in range(128)]}.get(name, ())
        zip_package(package, path, method=zipfile.ZIP_STORED, extra=extra)
        if name in ("entry-byte-limit", "attachment-byte-limit", "total-byte-limit"):
            with zipfile.ZipFile(path, "a", compression=zipfile.ZIP_DEFLATED) as z:
                if name == "entry-byte-limit": z.writestr("oversized", b"\0" * (64 * 1024 * 1024 + 1))
                elif name == "attachment-byte-limit": z.writestr("oversized", b"\0" * (8 * 1024 * 1024 + 1))
                else:
                    remaining = 128 * 1024 * 1024 + 1 - sum(p.stat().st_size for p in package.rglob("*") if p.is_file())
                    z.writestr("large-0", b"\0" * (64 * 1024 * 1024))
                    z.writestr("large-1", b"\0" * (remaining - 64 * 1024 * 1024))
        if name in ("symlink", "special"):
            with zipfile.ZipFile(path, "a") as z:
                entry = zipfile.ZipInfo("link"); entry.create_system = 3
                entry.external_attr = ((stat.S_IFLNK if name == "symlink" else stat.S_IFIFO) | 0o600) << 16
                z.writestr(entry, "payload.so")
        data = bytearray(path.read_bytes())
        central = data.find(b"PK\x01\x02")
        if name == "encrypted":
            struct.pack_into("<H", data, 6, 1); struct.pack_into("<H", data, central + 8, 1)
        elif name == "method":
            struct.pack_into("<H", data, 8, 99); struct.pack_into("<H", data, central + 10, 99)
        elif name == "crc":
            size = struct.unpack_from("<H", data, 26)[0]; extra_size = struct.unpack_from("<H", data, 28)[0]
            data[30 + size + extra_size] ^= 1
        elif name == "truncated": data = data[:-9]
        elif name == "local-name": data[30] ^= 1
        elif name == "size": struct.pack_into("<I", data, central + 24, 0x7fffffff)
        path.write_bytes(data)
        rows.append({"case": name, **metadata(binary, home, ["list"], success=False)})
    return rows


def lock_integrity(work, inputs, binary):
    rows = []
    for name in ("manifest", "payload", "resource", "attachment", "defaults", "schema", "source", "config", "profile", "parameters", "host", "host-build-id"):
        home = install(work / name, inputs, configured=True)
        options = ["--cm-profile", "review", "--cm-set", "output-fixture.limit=128"]
        package = home / "mods/output-fixture"
        if name == "resource":
            resource = package / "data.txt"; resource.write_text("original resource")
            mutate(home, "output-fixture", lambda m: m.update(resources=[{"path": "data.txt", "size": resource.stat().st_size, "sha256": sha(resource)}]))
        metadata(binary, home, ["lock"], options=options)
        lock = (home / "mod.lock").read_bytes()
        actual = binary
        if name == "manifest": (package / "mod.toml").write_bytes((package / "mod.toml").read_bytes() + b"\n")
        elif name == "payload":
            with (package / "payload.so").open("r+b") as stream: stream.write(b"bad!")
        elif name == "resource": (package / "data.txt").write_text("new resource")
        elif name == "attachment": (package / "inert-license.txt").write_text("new attachment")
        elif name == "defaults": mutate(home, "output-fixture", lambda m: m["config"]["defaults"].update(limit=255))
        elif name == "schema": mutate(home, "output-fixture", lambda m: m["config"]["schema"]["properties"]["limit"].update(maximum=511))
        elif name == "source": mutate(home, "output-fixture", lambda m: m["provenance"].update(revision="b" * 40))
        elif name == "config":
            p = home / "cm-runtime.toml"; p.write_bytes(p.read_bytes() + b"\n")
        elif name == "profile":
            p = home / "cm-runtime.toml"; fields = tomllib.loads(p.read_text())
            fields["profiles"]["review"]["mods"]["output-fixture"]["limit"] = 191; write_toml(p, fields)
        elif name == "parameters": options[-1] = "output-fixture.limit=129"
        elif name in ("host", "host-build-id"):
            actual = work / ("changed-" + name) / "codex"; actual.parent.mkdir(); shutil.copyfile(binary, actual); actual.chmod(0o755)
            if name == "host":
                with actual.open("ab") as stream: stream.write(b"different executable identity")
            else:
                before = json.loads(lock)["plan"]["host"]["build_id"].encode()
                after = b"sha256:" + (b"0" if before != b"sha256:" + b"0" * 64 else b"1") * 64
                data = actual.read_bytes(); assert before in data
                actual.write_bytes(data.replace(before, after))
                assert metadata(actual, home, ["plan"], options=options)["output"]["plan"]["host"]["build_id"] == after.decode()
        result = metadata(actual, home, ["lock", "--check"], options=options, success=False)
        assert (home / "mod.lock").read_bytes() == lock
        rows.append({"case": name, **result, "old_lock_preserved": True})
    home = install(work / "unsafe-lock", inputs)
    protected = home / "protected"; protected.write_text("preserved")
    (home / "mod.lock").symlink_to(protected)
    metadata(binary, home, ["lock"], success=False)
    assert protected.read_text() == "preserved" and (home / "mod.lock").is_symlink()
    (home / "mod.lock").unlink(); (home / "mod.lock").mkdir()
    metadata(binary, home, ["lock"], success=False)
    (home / "mod.lock").rmdir()
    metadata(binary, home, ["lock"])
    good = (home / "mod.lock").read_bytes()
    for data in (good.replace(b'"schema_version":1', b'"schema_version":99', 1),
                 good[:-1] + b',"schema_version":1}', good + b"\n"):
        (home / "mod.lock").write_bytes(data)
        metadata(binary, home, ["lock", "--check"], success=False)
        assert (home / "mod.lock").read_bytes() == data
    metadata(binary, home, ["lock"])
    assert (home / "mod.lock").read_bytes() == good and stat.S_IMODE((home / "mod.lock").stat().st_mode) == 0o600
    return {"mutations": rows, "unsafe_targets_rejected": True, "atomic_recovery": True}


def config_rejections(work, inputs, binary, evidence):
    cases = {
        "unknown-key": lambda m: m["config"]["defaults"].update(unknown=CANARIES[2]),
        "wrong-type": lambda m: m["config"]["defaults"].update(limit=CANARIES[2]),
        "unknown-schema": lambda m: m["config"]["schema"].update(**{"$ref": "https://example.invalid/schema"}),
        "required": lambda m: m["config"]["schema"]["required"].append("missing"),
        "abi1-config": lambda m: m.update(config=tomllib.loads((inputs / "mods/m01-config/mod.toml").read_text())["config"]),
    }
    rows = []
    for name, change in cases.items():
        home = install(work / name, inputs, configured=True)
        owner = "serial-fixture" if name == "abi1-config" else "output-fixture"
        if name == "abi1-config":
            assert tomllib.loads((home / "mods" / owner / "mod.toml").read_text())["compat"]["abi_major"] == 1
            metadata(binary, home, ["plan"], evidence=evidence / "abi1-config-baseline.json")
        package = mutate(home, owner, change)
        package.rename(home / "mods/opaque-slot")
        result = metadata(binary, home, ["plan"], success=False, evidence=evidence / (name + ".json"))
        assert result["output"]["mod_id"] == owner, (name, result["output"])
        assert result["output"]["field"].startswith("compat.abi_major" if name == "abi1-config" else "config"), (name, result["output"])
        rows.append({"case": name, **result})
    home = install(work / "invalid-selection", inputs, configured=True)
    (home / "cm-runtime.toml").write_text("format_version=2\nenabled=[]\nsecret=" + CANARIES[2])
    rows.append({"case": "invalid-selection", **metadata(binary, home, ["plan"], success=False,
        evidence=evidence / "invalid-selection.json")})
    home = install(work / "missing-effective-required", inputs, configured=True)
    mutate(home, "output-fixture", lambda m: m["config"]["defaults"].pop("token"))
    fields = tomllib.loads((home / "cm-runtime.toml").read_text()); fields["mods"]["output-fixture"].pop("token")
    write_toml(home / "cm-runtime.toml", fields)
    rows.append({"case": "missing-effective-required", **metadata(binary, home, ["plan"], success=False,
        evidence=evidence / "missing-effective-required.json")})
    home = install(work / "invalid-cli", inputs, configured=True)
    for index, value in enumerate(("output-fixture.limit=" + json.dumps(CANARIES[2]), "output-fixture.unknown=" + json.dumps(CANARIES[2]),
                  "output-fixture.limit=" + CANARIES[2], "missing.limit=2", "output-fixture.limit=nan", "output-fixture.limit=2020-01-01")):
        rows.append({"case": "invalid-cli", **metadata(binary, home, ["plan"], options=["--cm-set", value], success=False,
            evidence=evidence / ("invalid-cli-" + str(index) + ".json"))})
    return rows


def remote_rejection(binary, home):
    server = socket.socket(); server.bind(("127.0.0.1", 0)); server.listen(); server.settimeout(0.1)
    try:
        # A real endpoint remains listening for the entire actual CLI invocation.
        result = subprocess.run([str(binary), "--remote", "http://127.0.0.1:" + str(server.getsockname()[1]), "cm", "plan"],
            env={"PATH": "/usr/bin:/bin", "HOME": str(home), "CODEX_HOME": str(home)}, capture_output=True, text=True, timeout=90)
        assert result.returncode != 0 and "remote" in result.stderr.lower()
        try:
            client, _ = server.accept(); client.close()
        except socket.timeout:
            return {"return_code": result.returncode, "requests": 0}
        raise AssertionError("Metadata command contacted the remote endpoint")
    finally:
        server.close()


def matrix():
    assert os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
    sys.path.insert(0, "/fixture/fixtures/native-loader")
    import core_acceptance as core
    inputs = Path("/inputs"); binary = inputs / "host/bin/codex"
    evidence = Path("/evidence/m01"); work = Path("/work/m01"); work.mkdir()
    baseline = sha(binary)
    home = install(work / "configured", inputs, configured=True)
    other = home / "mods/other-mod"; shutil.copytree(inputs / "mods/m01-b", other)
    convert(other, configured=True)
    mutate(home, "output-fixture", lambda m: None)
    fields = tomllib.loads((other / "mod.toml").read_text()); fields["id"] = "other-mod"; fields["state"]["owner"] = "other-mod"
    fields["config"]["defaults"]["token"] = CANARIES[1]; manifest(other, fields)
    options = ["--cm-profile", "review", "--cm-set", "output-fixture.limit=128",
        "--cm-set", 'output-fixture.labels=["parameter"]']
    absent = metadata(binary, home, ["doctor"], options=options)
    assert absent["output"]["lock"] == "absent" and not (home / "mod.lock").exists()
    planned = metadata(binary, home, ["plan"], options=options)
    metadata(binary, home, ["lock"], options=options)
    metadata(binary, home, ["lock", "--check"], options=options)
    metadata(binary, home, ["doctor"], options=options)
    assert not any(secret.encode() in (home / "mod.lock").read_bytes() for secret in CANARIES)
    actual = core.run_case(Path("/fixture"), evidence / "actual-config", binary, home, True,
        restrictive=True, expected_releases=2, sandboxed=True, long_output=True, cm_options=options,
        extra_env={"CM_CONFIG_OBSERVATION": str(evidence / "actual-config-view.json")})
    rows = core.trace_rows(evidence / "actual-config/core-trace.jsonl")
    limits = [r["detail"] for r in rows if r["event"] == "output-limit-decision"]
    assert len(limits) == 2 and all(r["limit"] == 128 for r in limits)
    assert read(evidence / "actual-config-view.json") == {"owner_view_only": True, "four_layer_result": True}
    assert all("0123456789abcdef" * 256 not in r["output"] for r in actual["provider_requests"][1]["outputs"])
    # Normal startup recomputes current inputs; a stale record is only fatal to explicit checking.
    (home / "mod.lock").write_bytes(b"stale record")
    core.run_case(Path("/fixture"), evidence / "startup-ignores-stale-record", binary, home, True,
        restrictive=True, expected_releases=2, sandboxed=True, cm_options=options)
    metadata(binary, home, ["lock", "--check"], options=options, success=False)
    # ZIP order/method and directory slot names must not enter the content identity or lock.
    identities = []
    for n, (reverse, archive) in enumerate(((False, False), (True, False), (False, True), (True, True))):
        candidate = install(work / ("order-" + str(n)), inputs, reverse=reverse, archive=archive)
        metadata(binary, candidate, ["lock"])
        identities.append({"lock_sha256": sha(candidate / "mod.lock"), "plan": metadata(binary, candidate, ["plan"])["output"]["plan"]})
    assert len({item["lock_sha256"] for item in identities}) == 1
    zip_business = core.run_case(Path("/fixture"), evidence / "actual-zip", binary, candidate, True,
        restrictive=True, expected_releases=2, sandboxed=True)
    host = planned["output"]["plan"]["host"]
    exact = install(work / "exact", inputs)
    mutate(exact, "output-fixture", lambda m: (m.update(kind="exact_host"), m["compat"].update(exact_host={
        "build_id": host["build_id"], "executable_sha256": host["executable_sha256"]})))
    exact_plan = metadata(binary, exact, ["plan"])
    exact_business = core.run_case(Path("/fixture"), evidence / "actual-exact-host", binary, exact, True,
        restrictive=True, expected_releases=2, sandboxed=True)
    mutate(exact, "output-fixture", lambda m: m["compat"]["exact_host"].update(executable_sha256="0" * 64))
    mismatch = metadata(binary, exact, ["plan"], success=False)
    mutate(exact, "output-fixture", lambda m: (m.update(kind="advanced_hook"), m["compat"]["exact_host"].update(patch_map_sha256="0" * 64)))
    declared = metadata(binary, exact, ["list"])
    assert declared["output"]["mods"]["output-fixture"]["qualification"] == {"declared": True, "verified": False, "unsupported": True}
    unsupported = metadata(binary, exact, ["plan"], success=False)
    rejection = rejection_cases(work / "rejections", inputs, binary, evidence / "rejections")
    rejection["zip"] = zip_rejections(work / "zip", inputs, binary)
    integrity = lock_integrity(work / "integrity", inputs, binary)
    config = config_rejections(work / "config", inputs, binary, evidence / "config-rejections")
    mixed = install(work / "mixed", inputs, configured=True)
    shutil.rmtree(mixed / "mods/serial-fixture")
    shutil.copytree(inputs / "mods/a", mixed / "mods/serial-fixture")
    shutil.copytree(inputs / "mods/m01-legacy-v2", mixed / "mods/legacy-v2")
    selection(mixed, ["output-fixture", "serial-fixture", "compose-a"], configured=True)
    mixed_plan = metadata(binary, mixed, ["plan"], options=options)
    mixed_business = core.run_case(Path("/fixture"), evidence / "actual-mixed", binary, mixed, True,
        restrictive=True, expected_releases=3, sandboxed=True, cm_options=options,
        extra_env={"CM_LEGACY_CONFIG_OBSERVATION": str(evidence / "legacy-config-view.json")})
    assert read(evidence / "legacy-config-view.json") == {"selection_projection_only": True}
    assert read(inputs / "producer.json")["regressions"]["p03"]["status"] == "pass"
    remote = remote_rejection(binary, home)
    assert sha(binary) == baseline
    reports = [
        {"sdk_plan": identities[0], "exact_host": exact_plan, "wrong_host": mismatch, "binary_required": True,
            "actual_zip": zip_business, "actual_exact_host": exact_business, "mixed_plan": mixed_plan, "actual_mixed": mixed_business},
        {"permutations": identities, "canonical_identity_equal": True}, rejection, integrity,
        {"actual_config": actual, "plan": planned, "rejected": config, "owner_view_only": True, "array_replacement": True,
            "legacy_config_projection": read(evidence / "legacy-config-view.json"),
            "state_description_only": True, "native_memory_isolation": False},
        {"remote": remote, "advanced_declared": declared, "unsupported_activation": unsupported,
            "commands": ["list", "plan", "doctor", "lock", "lock --check"], "third_party_code_executed": False},
    ]
    for name, data in zip(REPORTS, reports):
        write(Path("/evidence") / name, {"status": "behavior_pass", **data})
    write(evidence / "suite.json", {"status": "pass", "host_sha256": baseline, "report_names": REPORTS,
        "cache_mode": "none", "product_build_calls": 0})


def producer_audit(inputs, package, destination):
    """Source attachments stay in the producer-only audit and never enter the strict consumer."""
    import runtime_composition as composition
    work = Path(os.environ["RUNNER_TEMP"]) / "cm-m01-metadata-audit"
    home = install(work / "profile", inputs, configured=True)
    source = home / "mods/output-fixture"
    sentinel = work / "must-not-execute"
    install_sentinel = work / "post-install-must-not-execute"
    state = home / "state/m01-state-sentinel.json"
    write(state, {"preserved": True})
    (source / "build.rs").write_text('fn main() { panic!("must not compile or execute"); }\n')
    script = source / "post-install.sh"
    script.write_text('#!/bin/sh\nprintf executed > "$CM_POST_INSTALL_SENTINEL"\n')
    script.chmod(0o755)
    options = ["--cm-profile", "review", "--cm-set", "output-fixture.limit=128"]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "CODEX_HOME": str(home), "CM_FIXTURE_EVENTS": str(sentinel),
        "CM_POST_INSTALL_SENTINEL": str(install_sentinel)}
    Path(env["HOME"]).mkdir()
    traces = []
    commands = []
    for kind in ("directory", "zip"):
        if kind == "zip":
            zip_package(source, source.with_suffix(".cmod"))
            shutil.rmtree(source)
        watched = [home / "cm-runtime.toml", state, *(p for p in (home / "mods").rglob("*") if p.is_file())]
        before = {p.relative_to(home).as_posix(): sha(p) for p in watched}
        for index, action in enumerate((["list"], ["plan"], ["doctor"], ["lock"], ["lock", "--check"], ["doctor"])):
            lock_before = sha(home / "mod.lock") if (home / "mod.lock").exists() else None
            prefix = work / ("syscalls." + kind + "." + str(index))
            command = ["strace", "-ff", "-qq", "-yy", "-s", "1024", "-e", "trace=execve,execveat,network,open,openat,mmap,mprotect",
                "-o", str(prefix), "--", str(package / "bin/codex"), *options, "cm", *action]
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
            assert all(secret not in result.stdout + result.stderr for secret in CANARIES)
            assert result.returncode == 0 and not sentinel.exists() and not install_sentinel.exists(), (kind, action, result.returncode)
            assert json.loads(result.stdout)["already_native_executed"] is False
            assert {p.relative_to(home).as_posix(): sha(p) for p in watched} == before
            if action != ["lock"]:
                assert (sha(home / "mod.lock") if (home / "mod.lock").exists() else None) == lock_before
            current = []
            for path in work.glob(prefix.name + ".*"):
                text = path.read_text()
                safe = composition.redact_syscalls(text)
                for secret in CANARIES: safe = safe.replace(secret, "<redacted>")
                target = destination / path.name; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(safe)
                calls = re.findall(r'execve\("([^"\n]+)"', text)
                assert all(Path(p).resolve() == (package / "bin/codex").resolve() for p in calls), calls
                assert "execveat(" not in text
                assert not re.search(r'\b(?:connect|sendto)\(', text), ("Metadata network operation; see sanitized trace", path.name)
                pairs = [path.suffix[1:] + " " + line for line in text.splitlines() if line.startswith("socketpair(")]
                composition.audit_network(pairs, work, ())
                assert not re.search(r'mmap\(.*PROT_EXEC.*(?:/mods/|memfd:cm)', text)
                assert "m01-state-sentinel.json" not in text
                current.append({"file": path.name, "sha256": sha(target), "exec_count": len(calls), "anonymous_unix_socketpairs": len(pairs)})
            assert current and sum(item["exec_count"] for item in current) == 1
            traces.extend(current)
            commands.append({"container": kind, "command": action, "return_code": result.returncode,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()})
    write(destination / "metadata-source-attachments.json", {"status": "pass", "native_sentinel_absent": True,
        "post_install_sentinel_absent": True, "author_source_attachments_inert": True, "state_unopened_and_preserved": True,
        "data_inputs_unchanged": True, "readonly_commands_preserved_lock": True, "build_calls": 0, "commands": commands, "traces": traces})


def prepare_binary_packages(inputs):
    for source, name, configured in (("a", "m01-a", False), ("b/normal", "m01-b", False), ("b/config", "m01-config", True)):
        package = inputs / "mods" / name
        shutil.copytree(inputs / "mods" / source, package)
        fields = convert(package, configured=configured)
        fields["provenance"]["revision"] = os.environ["CM_SOURCE_SHA"]
        manifest(package, fields)
    archive = inputs / "mods/m01-b.cmod"
    zip_package(inputs / "mods/m01-b", archive)
    result = {name: {"manifest_sha256": sha(inputs / "mods" / name / "mod.toml"),
        "payload_sha256": sha(inputs / "mods" / name / "payload.so")} for name in ("m01-a", "m01-b", "m01-config")}
    result["m01-b.cmod"] = {"archive_sha256": sha(archive), "size": archive.stat().st_size}
    return result


def self_check():
    with tempfile.TemporaryDirectory() as directory:
        package = Path(directory) / "package"; package.mkdir()
        value = {"format_version": 3, "config": {"properties": {"name.with.dots": {"type": "string"}}}}
        manifest(package, value)
        assert tomllib.loads((package / "mod.toml").read_text()) == value
        (package / "payload.so").write_bytes(b"fixture-data")
        archive = Path(directory) / "fixture.cmod"
        zip_package(package, archive, reverse=True)
        with zipfile.ZipFile(archive) as zipped:
            assert set(zipped.namelist()) == {"mod.toml", "payload.so"} and zipped.testzip() is None
        assert len(set(REPORTS)) == 6
    print(json.dumps({"m01_fixture_handoff_self_check": "pass"}))


def produce():
    import runtime_consumer
    runtime_consumer.produce()


if __name__ == "__main__":
    {"produce": produce, "matrix": matrix}[sys.argv[1]]()
