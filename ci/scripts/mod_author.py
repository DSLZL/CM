#!/usr/bin/env python3
"""M05 independent author preparation; runtime dispatch imports no build helpers."""
import importlib.util
import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib

import ci_progress
from mod_manifest import read, sha, write

SDK_REVISION = "d3abb2bea2dda5964ba2725b1abd095c3f46678b"
TEMPLATE = "templates/native-mod"
TARGET = "x86_64-unknown-linux-gnu"
REPORTS = ("author-to-user-workflow.json", "source-only-authoring.json", "runtime-author-diagnostics.json",
           "independent-mod-update.json", "metadata-diagnostics-boundary.json", "zero-build-cli-contract.json")
RUNTIME_FILES = ("ci/scripts/mod_author.py", "ci/scripts/mod_manifest.py", "ci/scripts/runtime_sdk.py",
    "ci/scripts/managed_package.py", "ci/scripts/runtime_state.py", "ci/scripts/ci_progress.py",
    "fixtures/mod-author/driver.py", "fixtures/runtime-consumer/driver.py",
    "fixtures/native-loader/core_acceptance.py", "fixtures/native-loader/tool_barrier.py",
    "fixtures/runtime-sdk/driver.py", "fixtures/managed-package/driver.py", "fixtures/state/driver.py")


def driver():
    path = Path(__file__).resolve().parents[2] / "fixtures/mod-author/driver.py"
    spec = importlib.util.spec_from_file_location("cm_m05_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configure():
    from record_run import require_hosted_linux
    require_hosted_linux()
    from linux_ci import append_environment
    cfg = read(Path(os.environ["CM_SOURCE_DIR"]) / ".github/cm-ci.json")
    assert cfg["task_id"] == "CM-M05" and cfg["target"] == TARGET and cfg["rust_toolchain"] == "1.95.0"
    assert os.environ["CM_BUILD_KIND"] == "mod-only"
    append_environment({"RUSTUP_TOOLCHAIN": cfg["rust_toolchain"], "CM_RUST_TOOLCHAIN": cfg["rust_toolchain"],
        "CM_TARGET": TARGET, "RUSTC_WRAPPER": ""})
    self_check()


def compile_diagnostics(text, source):
    """Never export rendered messages, source snippets, arbitrary paths or URLs."""
    diagnostics = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") != "compiler-message":
            continue
        message = row["message"]
        spans = []
        for span in message.get("spans", []):
            path = Path(span["file_name"])
            path = path if path.is_absolute() else source / path
            if path.resolve().is_relative_to(source.resolve()):
                relative = path.resolve().relative_to(source.resolve()).as_posix()
                if re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", relative) and ".." not in Path(relative).parts:
                    spans.append({"file": relative, **{key: span[key] for key in
                        ("line_start", "line_end", "column_start", "column_end")}})
        code = (message.get("code") or {}).get("code")
        diagnostics.append({"level": message.get("level") if message.get("level") in
            ("error", "warning", "note", "help", "failure-note") else "unknown",
            "stage": "author_link" if message.get("message", "").startswith("linking with ") else "author_compile",
            "code": code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_:]{1,100}", code) else None,
            "spans": spans})
    return diagnostics


def author_command(source, logs, label, command, *, success=True):
    stopped = threading.Event()
    started = time.monotonic()

    def heartbeat():
        while not stopped.wait(30):
            ci_progress.emit(label, "running", started)

    worker = threading.Thread(target=heartbeat, daemon=True)
    env = {**os.environ, "CARGO_TARGET_DIR": str(source / "target"), "RUSTC_WRAPPER": "",
        "CARGO_INCREMENTAL": "0", "RUSTFLAGS": "-C target-cpu=x86-64"}
    with ci_progress.stage(label):
        worker.start()
        try:
            result = subprocess.run(command, cwd=source, env=env, capture_output=True, text=True,
                errors="replace", timeout=900)
            report = {"phase": label, "command": command, "return_code": result.returncode,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "diagnostics": compile_diagnostics(result.stdout, source), "raw_output_exported": False,
                "ci_url": "https://github.com/DSLZL/CM-build-linux-x64/actions/runs/" + os.environ["GITHUB_RUN_ID"]}
            write(logs / (label + ".json"), report)
            print(json.dumps(report), flush=True)
            assert (result.returncode == 0) is success, "Author phase failed: " + label
            return result, report
        except (OSError, subprocess.TimeoutExpired):
            write(logs / (label + ".json"), {"phase": label, "command": command,
                "status": "failed", "failure": "execution_error_or_timeout", "raw_output_exported": False,
                "elapsed_seconds": round(time.monotonic() - started, 3)})
            raise RuntimeError("Author phase could not complete: " + label) from None
        finally:
            stopped.set()
            worker.join(timeout=1)


def source_review(root):
    from dispatch_build import self_check as blocked_ci_checks
    settings = read(root / TEMPLATE / ".vscode/settings.json")
    disabled = ("rust-analyzer.checkOnSave", "rust-analyzer.cargo.buildScripts.enable",
        "rust-analyzer.cargo.buildScripts.rebuildOnSave", "rust-analyzer.procMacro.enable",
        "rust-analyzer.cargo.autoreload", "editor.formatOnSave")
    assert all(settings.get(key) is False for key in disabled)
    assert settings["task.allowAutomaticTasks"] == "off"
    assert not (root / TEMPLATE / "build.rs").exists() and not (root / TEMPLATE / ".vscode/tasks.json").exists()
    workflow = (root / TEMPLATE / ".github/workflows/author.yml").read_text()
    assert "dispatch_build.py" in workflow and not re.search(r"\bcargo\s+(build|test|check|clippy)", workflow)
    routing = read(root / ".github/cm-build-routing.json")
    return {"status": "pass", "settings": settings, "automatic_local_commands": [],
        "routing_configured": routing["configured"], "third_party_extensions_verified": False,
        "blocked_ci_checks": blocked_ci_checks(),
        "files": {path: sha(root / path) for path in (TEMPLATE + "/.vscode/settings.json",
            TEMPLATE + "/README.md", TEMPLATE + "/.github/workflows/author.yml",
            "docs/mod-author-guide.md", "docs/mod-user-guide.md")}}


def prepare_source(root, source, variant, *, controlled=False):
    assert not source.exists(), "Author directory and target must start empty"
    shutil.copytree(root / TEMPLATE, source)
    if controlled:
        path = source / "src/lib.rs"
        text = path.read_text()
        if variant == "v1":
            assert '"v2"' in text and 'version = "0.1.1"' in (source / "Cargo.toml").read_text()
            path.write_text(text.replace('"v2"', '"v1"'))
            for name in ("Cargo.toml", "mod.toml"):
                path = source / name
                path.write_text(path.read_text().replace('version = "0.1.1"', 'version = "0.1.0"', 1))
            path = source / "Cargo.lock"
            path.write_text(path.read_text().replace('name = "cm-native-mod"\nversion = "0.1.1"',
                'name = "cm-native-mod"\nversion = "0.1.0"'))
        elif variant == "init-fail":
            path.write_text(text.replace("Ok(Greeting { host: init.host })",
                'let _ = init;\n    Err("CM_M05_DIAGNOSTIC_SECRET controlled init error".into())'))
        elif variant == "compile-fail":
            path.write_text(text + '\nfn controlled_compile_error() { let _: u32 = "CM_M05_DIAGNOSTIC_SECRET"; }\n')
        else:
            raise AssertionError("Unknown controlled author variant")


def build(root, inputs, frozen, logs, variant, *, controlled=False):
    import host
    import mod_manifest
    source = Path(os.environ["RUNNER_TEMP"]) / ("cm-author-" + variant)
    prepare_source(root, source, variant, controlled=controlled)
    cargo = tomllib.loads((source / "Cargo.toml").read_text())
    assert cargo["dependencies"]["cm-sdk"]["rev"] == SDK_REVISION and cargo["workspace"] == {}
    before = sha(source / "Cargo.lock")
    sources = host.manifest(source)
    if variant == "compile-fail":
        result, report = author_command(source, logs, "m05-author-compile-fail",
            ["cargo", "check", "--locked", "--target", TARGET, "--message-format=json"], success=False)
        assert report["diagnostics"] and any(row["spans"] for row in report["diagnostics"])
        assert not (source / "target" / TARGET / "author/libcm_native_mod.so").exists()
        return {**report, "source_manifest": sources, "package_emitted": False,
            "stage": "author_compile", "mod_id": "native-mod", "sdk_revision": SDK_REVISION,
            "source_sha": os.environ["CM_SOURCE_SHA"], "target": TARGET, "abi": "2.2",
            "host_executable_sha256": frozen["executable_sha256"]}
    commands = []
    for phase in ("fmt", "clippy", "test", "build"):
        command = (["cargo", "fmt", "--", "--check"] if phase == "fmt" else
            ["cargo", phase, "--locked", "--target", TARGET, "--profile", "author", "--message-format=json"])
        if phase == "clippy":
            command += ["--all-targets", "--", "-D", "warnings"]
        _, report = author_command(source, logs, "m05-author-" + variant + "-" + phase, command)
        commands.append(report)
    result, _ = author_command(source, logs, "m05-author-" + variant + "-metadata",
        ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", TARGET])
    metadata = json.loads(result.stdout)
    assert sorted(package["name"] for package in metadata["packages"]) == ["cm-abi", "cm-native-mod", "cm-sdk"]
    assert all(package["source"] == "git+https://github.com/DSLZL/CM.git?rev=" + SDK_REVISION + "#" + SDK_REVISION
        for package in metadata["packages"] if package["name"] in ("cm-sdk", "cm-abi"))
    assert sha(source / "Cargo.lock") == before
    destination = inputs / "mods/m05" / variant
    assert not destination.exists()
    destination.mkdir(parents=True)
    payload = source / "target" / TARGET / "author/libcm_native_mod.so"
    shutil.copyfile(payload, destination / "payload.so")
    fields = tomllib.loads((source / "mod.toml").read_text())
    assert fields["version"] == cargo["package"]["version"]
    fields["binary"].update(size=payload.stat().st_size, sha256=sha(payload),
        glibc_min=mod_manifest.native_glibc_min(payload))
    fields["provenance"]["revision"] = os.environ["CM_SOURCE_SHA"]
    mod_manifest.manifest(destination, fields)
    archive = destination.with_suffix(".cmod")
    mod_manifest.zip_package(destination, archive)
    return {"status": "pass", "variant": variant, "controlled_source_mutation": controlled,
        "source_sha": os.environ["CM_SOURCE_SHA"], "source_manifest": sources,
        "lock_sha256": before, "sdk_revision": SDK_REVISION,
        "dependencies": sorted(package["name"] for package in metadata["packages"]),
        "toolchain": "1.95.0", "target": TARGET, "profile": "author", "rustflags": "-C target-cpu=x86-64",
        "commands": commands, "initial_target_empty": True,
        "host_frozen_before_author_build": frozen["executable_sha256"],
        "host_build_id": frozen["host_identity"]["host_build_id"],
        "payload_sha256": sha(payload), "manifest_sha256": sha(destination / "mod.toml"),
        "archive_sha256": sha(archive), "package_version": fields["version"]}


def refresh(root, inputs):
    for relative in RUNTIME_FILES:
        destination = inputs / "fixture" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    shutil.copyfile(root / "ci/scripts/runtime_consumer.py", inputs / "runtime_consumer.py")
    shutil.copyfile(root / "ci/scripts/ci_progress.py", inputs / "ci_progress.py")


def prepare(inputs, package, frozen, logs):
    from runtime_consumer import provenance
    root = Path(os.environ["CM_SOURCE_DIR"])
    assert sha(package / "bin/codex") == frozen["executable_sha256"]
    refresh(root, inputs)
    authors = {variant: build(root, inputs, frozen, logs, variant, controlled=variant != "v2")
        for variant in ("v1", "v2", "init-fail")}
    compile_failure = build(root, inputs, frozen, logs, "compile-fail", controlled=True)
    receipt = {"schema_version": 1, "build_kind": "qualification", "authors": authors,
        "provenance": provenance(), "producer_job": os.environ["GITHUB_JOB"], "host": frozen,
        "compile_failure": compile_failure, "source_review": source_review(root),
        "author_phase_host_build_commands": [], "author_phase_other_mod_build_commands": [],
        "sdk_revision": SDK_REVISION}
    write(inputs / "fixture/m05-producer.json", receipt)
    write(Path(os.environ["CM_CI_ARTIFACT_DIR"]) / "author-receipt.json", receipt)
    assert sha(package / "bin/codex") == frozen["executable_sha256"]
    return receipt


def produce_from_origin():
    import host
    import runtime_consumer as consumer
    root = Path(os.environ["CM_SOURCE_DIR"])
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    origin_root = Path(os.environ["CM_VERIFIED_ORIGIN_DIR"])
    verified = read(origin_root / "verified-origin.json")
    original = origin_root / "runtime-inputs"
    consumer.validate_inputs(original)
    old = read(original / "producer.json")
    frozen = old["host"]
    cfg = read(root / ".github/cm-ci.json")
    assert cfg["task_id"] == "CM-M05" and old["task_id"] == "CM-M05"
    assert old["m05"]["build_kind"] == "qualification" and old["m05"]["sdk_revision"] == SDK_REVISION
    identity = frozen["host_identity"]["inputs"]
    assert identity["cm_inputs"] == host.manifest_digest(host.product_manifest(root)), "Host production inputs changed; new qualification required"
    assert identity["profiles"] == {name: cfg[name] for name in ("build_profile", "test_profile", "clippy_profile")}
    assert identity["units"] == sorted([{**unit, "packages": sorted(unit["packages"]),
        "features": sorted(unit.get("features", []))} for unit in cfg["units"]], key=lambda unit: unit["id"])
    assert cfg["compile_env"] == {key: identity["flags"][key] for key in cfg["compile_env"]}
    assert identity["toolchain"]["declared"] == cfg["rust_toolchain"] == "1.95.0"
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    assert not inputs.exists()
    shutil.copytree(original, inputs, symlinks=True)
    (inputs / "input-manifest.json").unlink()
    old_m05 = read(inputs / "fixture/m05-producer.json")
    baseline = {variant: {**old_m05["authors"][variant], "origin": old["provenance"]}
        for variant in ("v1", "init-fail")}
    destination = inputs / "mods/m05/v2"
    assert destination.is_relative_to(inputs) and destination.is_dir()
    shutil.rmtree(destination)
    destination.with_suffix(".cmod").unlink()
    target = build(root, inputs, frozen, logs, "v2")
    assert target["package_version"] != baseline["v1"]["package_version"], "Mod update must have a new explicit version"
    assert target["payload_sha256"] != baseline["v1"]["payload_sha256"], "Mod update must change actual behavior bytes"
    refresh(root, inputs)
    receipt = {"schema_version": 1, "build_kind": "mod-only", "authors": {**baseline, "v2": target},
        "provenance": consumer.provenance(), "producer_job": os.environ["GITHUB_JOB"], "host": frozen,
        "compile_failure": {**old_m05["compile_failure"], "origin": old["provenance"]},
        "source_review": source_review(root), "host_origin": verified,
        "host_build_commands": [], "helper_build_commands": [], "private_core_build_commands": [],
        "other_mod_build_commands": [], "current_author_variants": ["v2"], "sdk_revision": SDK_REVISION}
    write(inputs / "fixture/m05-producer.json", receipt)
    producer = {**old, "provenance": consumer.provenance(), "producer_job": os.environ["GITHUB_JOB"],
        "host_origin": verified, "baseline_origin": old["provenance"], "m05": receipt}
    write(inputs / "producer.json", producer)
    import runtime_composition
    (inputs / "observer.py").write_text(consumer.runtime_observer_source(runtime_composition))
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    artifact.mkdir(parents=True, exist_ok=True)
    write(artifact / "author-receipt.json", receipt)


def compiler_audit(text, target):
    from runtime_composition import complete_syscalls
    crates, executions = set(), []
    for line in complete_syscalls(text.splitlines()):
        if not re.search(r"\bexecve(?:at)?\(", line) or not line.rstrip().endswith("= 0"):
            continue
        assert "execveat(" not in line, "Unclassified author execution"
        arguments = re.search(r'execve\(("(?:[^"\\]|\\.)*"), \[(.*?)\],', line)
        assert arguments, "Incomplete author execution record"
        tokens = [ast.literal_eval(value) for value in re.findall(r'"(?:[^"\\]|\\.)*"', arguments[2])]
        assert tokens and "..." not in arguments[2], "Truncated author execution record"
        executable = Path(ast.literal_eval(arguments[1])).name
        if executable in ("rustc", "clippy-driver") and "--crate-name" in tokens:
            if any(token == "--print" or token.startswith("--print=") for token in tokens):
                continue
            name = tokens[tokens.index("--crate-name") + 1]
            assert name in ("cm_abi", "cm_sdk", "cm_native_mod"), "Unexpected crate compilation"
            crates.add(name)
            executions.append({"executable": executable, "crate": name})
        elif executable in ("make", "meson", "ninja", "cmake", "sccache"):
            raise AssertionError("Unexpected helper, private Core or cached compiler execution")
        elif re.search(r"(?:^|-)(?:cc|gcc|g\+\+|c\+\+|clang(?:\+\+)?|ld(?:\.bfd|\.gold)?|lld|collect2|as)(?:-[0-9.]+)?$", executable):
            assert "-o" in tokens, "Unclassified native compiler/linker execution"
            output = Path(tokens[tokens.index("-o") + 1]).resolve()
            assert output.is_relative_to(target.resolve()), "Linker output outside the independent Mod target"
            assert not any(Path(token).suffix in (".c", ".cc", ".cpp", ".S") for token in tokens), "Unexpected native source compilation"
            executions.append({"executable": executable, "output": output.relative_to(target.resolve()).as_posix()})
    assert crates == {"cm_abi", "cm_sdk", "cm_native_mod"}, "Independent SDK/Mod compiler evidence missing"
    return {"status": "pass", "rustc_crates": sorted(crates), "compiler_executions": executions,
        "host_helper_private_core_or_other_mod_compilations": 0,
        "scope": "actual current Mod-only producer process and descendants"}


def audit_mod_only():
    import runtime_consumer as consumer
    from worker_policy import archive_members
    assert os.environ["CM_BUILD_KIND"] == "mod-only"
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    trace = logs / "m05-author-exec.log"
    try:
        audit = compiler_audit(trace.read_text(), Path(os.environ["RUNNER_TEMP"]) / "cm-author-v2/target")
        assert os.environ.get("CM_AUTHOR_BUILD_EXIT") == "0", "Current author build failed"
    except (OSError, AssertionError, SyntaxError, ValueError):
        write(logs / "m05-builder-execution-audit.json", {"status": "failed",
            "failure": "author_build_or_compiler_boundary", "raw_trace_exported": False})
        raise RuntimeError("Mod-only author build or compiler boundary failed") from None
    finally:
        trace.unlink(missing_ok=True)
    write(logs / "m05-builder-execution-audit.json", audit)
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    producer = read(inputs / "producer.json")
    producer["m05"]["builder_execution_audit"] = audit
    write(inputs / "producer.json", producer)
    write(inputs / "fixture/m05-producer.json", producer["m05"])
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    write(artifact / "author-receipt.json", producer["m05"])
    entries = consumer.inventory(inputs)
    write(inputs / "input-manifest.json", {"files": entries, "sha256": consumer.digest(entries)})
    transfer = Path(os.environ["CM_CONSUMER_TRANSFER_DIR"])
    transfer.mkdir()
    import tarfile
    with tarfile.open(transfer / "runtime-inputs.tar", "w") as archive:
        archive.add(inputs, arcname="runtime-inputs")
    with tarfile.open(transfer / "runtime-inputs.tar", "r:") as archive:
        archive_members(archive.getmembers(), "runtime-inputs")
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    artifact.mkdir(parents=True, exist_ok=True)
    write(artifact / "producer-inputs.json", {"status": "pass", "task_id": "CM-M05",
        "provenance": consumer.provenance(), "input_manifest_sha256": consumer.digest(entries),
        "host_origin": producer["host_origin"], "consumer_acceptance": "not_run"})


def produce():
    from record_run import require_hosted_linux
    require_hosted_linux()
    assert os.environ["GITHUB_REPOSITORY"] == "DSLZL/CM-build-linux-x64"
    if os.environ.get("CM_BUILD_KIND", "qualification") == "mod-only":
        produce_from_origin()
    else:
        assert os.environ.get("CM_BUILD_KIND", "qualification") == "qualification"
        __import__("runtime_consumer").produce()


def self_check():
    assert len(REPORTS) == len(set(REPORTS)) == 6
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory() as directory:
        for variant, version in (("v1", "0.1.0"), ("v2", "0.1.1")):
            source = Path(directory) / variant
            prepare_source(root, source, variant, controlled=variant == "v1")
            cargo = tomllib.loads((source / "Cargo.toml").read_text())
            lock = tomllib.loads((source / "Cargo.lock").read_text())
            fields = tomllib.loads((source / "mod.toml").read_text())
            assert cargo["package"]["version"] == fields["version"] == version
            assert next(row for row in lock["package"] if row["name"] == "cm-native-mod")["version"] == version
            assert cargo["dependencies"]["cm-sdk"]["rev"] == SDK_REVISION
            assert '"version":"' + variant + '"' in (source / "src/lib.rs").read_text()
            if variant == "v2":
                for name in ("Cargo.toml", "Cargo.lock", "mod.toml", "src/lib.rs"):
                    assert sha(source / name) == sha(root / TEMPLATE / name), "Current v2 author source was mutated"
    source = Path("/author")
    message = {"reason": "compiler-message", "message": {"level": "error", "code": {"code": "E0308"},
        "message": "CM_M05_DIAGNOSTIC_SECRET", "rendered": "CM_M05_DIAGNOSTIC_SECRET",
        "spans": [{"file_name": "src/lib.rs", "line_start": 4, "line_end": 4,
                   "column_start": 1, "column_end": 2, "text": ["CM_M05_DIAGNOSTIC_SECRET"]}]}}
    safe = compile_diagnostics(json.dumps(message), source)
    assert safe[0]["spans"][0]["file"] == "src/lib.rs" and safe[0]["code"] == "E0308"
    assert "CM_M05_DIAGNOSTIC_SECRET" not in json.dumps(safe)
    message["message"]["message"] = 'linking with "CM_M05_DIAGNOSTIC_SECRET" failed'
    linked = compile_diagnostics(json.dumps(message), source)
    assert linked[0]["stage"] == "author_link" and "CM_M05_DIAGNOSTIC_SECRET" not in json.dumps(linked)
    message["message"]["spans"][0]["file_name"] = "../outside.rs"
    assert compile_diagnostics(json.dumps(message), source)[0]["spans"] == []
    trace = '\n'.join('1 execve("/bin/rustc", ["rustc", "--crate-name", "' + name + '"], 0x0 /* 0 vars */) = 0'
        for name in ("cm_abi", "cm_sdk", "cm_native_mod"))
    assert compiler_audit(trace, source / "target")["host_helper_private_core_or_other_mod_compilations"] == 0
    split = trace.replace('"cm_sdk"], 0x0 /* 0 vars */) = 0',
        '"cm_sdk"], 0x0 /* 0 vars */ <unfinished ...>\n1 <... execve resumed>) = 0')
    assert compiler_audit(split, source / "target")["rustc_crates"] == ["cm_abi", "cm_native_mod", "cm_sdk"]
    linker = '1 execve("/bin/cc", ["cc", "-o", "/author/target/debug/deps/mod.so"], 0x0 /* 0 vars */) = 0'
    assert compiler_audit(trace + "\n" + linker, source / "target")["compiler_executions"][-1]["executable"] == "cc"
    for compiler in ("rustc", "clippy-driver"):
        try:
            compiler_audit(trace.replace('/bin/rustc', '/bin/' + compiler)
                .replace('"rustc"', '"innocent-argv-zero"').replace('"cm_sdk"', '"codex_core"'), source / "target")
        except AssertionError:
            pass
        else:
            raise AssertionError("Host compilation passed the Mod-only boundary")
    for linker in ('1 execve("/bin/cc", ["cc", "-o", "/helper/bwrap"], 0x0 /* 0 vars */) = 0',
                   '1 execve("/bin/x86_64-linux-gnu-gcc", ["gcc", "-o", "/helper/bwrap"], 0x0 /* 0 vars */) = 0',
                   '1 execve("/bin/cc", ["cc", "helper.c", "-o", "/author/target/helper"], 0x0 /* 0 vars */) = 0'):
        try:
            compiler_audit(trace + "\n" + linker, source / "target")
        except AssertionError:
            pass
        else:
            raise AssertionError("Helper source or output passed the Mod-only boundary")
    driver().self_check()
    print(json.dumps({"m05_author_handoff_self_check": "pass"}))


if __name__ == "__main__":
    {"configure": configure, "produce": produce, "audit-mod-only": audit_mod_only,
     "matrix": lambda: driver().matrix(), "self-check": self_check}[sys.argv[1]]()
