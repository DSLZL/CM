#!/usr/bin/env python3
"""Reference CI driver. Map real Cargo units before use; never run locally."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import tomllib
from record_run import require_hosted_linux

TARGET = "x86_64-unknown-linux-gnu"
SCCACHE_VERSION = "0.18.0"


def digest(value):
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def source_file(root, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise RuntimeError("Expected a repository-relative file path")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise RuntimeError("Required mapped source file is missing or outside the repository: " + relative)
    return path


def append_environment(values):
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in str(value) or "\r" in str(value):
                raise RuntimeError("Multiline CI environment values are not supported: " + key)
            stream.write(key + "=" + str(value) + "\n")


def load_config(root):
    path = source_file(root, os.environ.get("CM_CI_CONFIG", ".github/cm-ci.json"))
    cfg = json.loads(path.read_text(encoding="utf-8"))
    if cfg.get("schema_version") != 1 or cfg.get("configured") is not True:
        raise RuntimeError("CM-000/P01 must map and review the real CI configuration; this template is blocked until configured=true")
    if cfg.get("target") != TARGET:
        raise RuntimeError("Only the first Linux x64 GNU target is enabled")
    if not re.fullmatch(r"CM-(?:000|[A-Z]\d\d[A-Z]?)", cfg.get("task_id", "")):
        raise RuntimeError("task_id must identify the current mapped CM implementation task")
    checks = cfg.get("required_checks", [])
    if not checks or len(set(checks)) != len(checks) or any(not isinstance(value, str) or not value.startswith(cfg["task_id"] + "-AC") for value in checks):
        raise RuntimeError("required_checks must list the current task's actual required acceptance IDs")
    if not re.fullmatch(r"\d+\.\d+\.\d+", cfg.get("rust_toolchain", "")):
        raise RuntimeError("rust_toolchain must be an exact reviewed stable release, not stable/latest")
    if not cfg.get("units"):
        raise RuntimeError("At least one real framework/CLI Cargo unit is required")
    seen = set()
    for unit in cfg["units"]:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", unit.get("id", "")) or unit["id"] in seen:
            raise RuntimeError("Cargo unit ids must be unique stable names")
        seen.add(unit["id"])
        source_file(root, unit["manifest"])
        source_file(root, unit["lockfile"])
        packages = unit.get("packages", [])
        if not packages or any(not isinstance(name, str) or name.startswith("REPLACE_") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) for name in packages):
            raise RuntimeError("Each Cargo unit needs explicit real package names; no workspace-wide builds")
        if not isinstance(unit.get("features", []), list) or any(not isinstance(x, str) or not x or x.startswith("-") or "," in x for x in unit.get("features", [])):
            raise RuntimeError("features must be an explicit list of Cargo feature names")
    for key in ("build_profile", "test_profile", "clippy_profile"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", cfg.get(key, "")):
            raise RuntimeError("Explicit Cargo profile missing: " + key)
    source_file(root, cfg["acceptance_script"])
    for relative in cfg.get("native_identity_files", []) + cfg.get("cargo_config_files", []):
        source_file(root, relative)
    for key, value in cfg.get("compile_env", {}).items():
        allowed = key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CXX", "AR", "LD", "CFLAGS", "CXXFLAGS", "LDFLAGS"} or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_"))
        if not allowed or key == "CARGO_TARGET_DIR" or not isinstance(value, str):
            raise RuntimeError("Unexpected compile_env entry: " + key)
    return cfg


def execute(root, logs, label, args, env=None):
    if args[0] == "cargo" and "--manifest-path" in args:
        args = list(args)
        index = args.index("--manifest-path") + 1
        manifest = source_file(root, args[index])
        root = manifest.parent
        args[index] = manifest.name
    started = time.monotonic()
    print("CM CI:", " ".join(args), flush=True)
    logfile = logs / (label + ".log")
    with logfile.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(args, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        for line in process.stdout:
            stream.write(line)
            print(line, end="", flush=True)
        code = process.wait()
    event = {"phase": label, "command": args, "cwd": str(root), "return_code": code,
             "elapsed_seconds": round(time.monotonic() - started, 3),
             "ended_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "log": logfile.name}
    with (logs / "phase-results.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event) + "\n")
    if code:
        raise RuntimeError(label + " failed with exit code " + str(code))


def configure(root, cfg):
    epoch = os.environ.get("CM_CACHE_EPOCH", "v1")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", epoch):
        raise RuntimeError("Invalid cache epoch")
    append_environment({"RUSTUP_TOOLCHAIN": cfg["rust_toolchain"], "CM_RUST_TOOLCHAIN": cfg["rust_toolchain"],
                        "CM_TARGET": TARGET, **cfg.get("compile_env", {})})


def identify(root, logs, cfg):
    rustc = subprocess.check_output(["rustc", "-Vv"], text=True).strip()
    cargo = subprocess.check_output(["cargo", "-V"], text=True).strip()
    sccache = subprocess.check_output(["sccache", "--version"], text=True).strip()
    if sccache != "sccache " + SCCACHE_VERSION:
        raise RuntimeError("sccache does not match the pinned CI version")
    native = {}
    for tool in cfg.get("native_tools", ["cc", "c++", "ar", "ld"]):
        path = shutil.which(tool)
        if not path:
            raise RuntimeError("Native compiler identity is unavailable: " + tool)
        real = Path(path).resolve()
        native[tool] = {"path": str(real), "sha256": digest(real.read_bytes()),
                        "version": subprocess.check_output([path, "--version"], text=True).strip()}
    # Compiler entries already hash source bytes; source edits must not discard compatible dependencies.
    files = {p: digest(source_file(root, p).read_bytes()) for p in
             cfg.get("cargo_config_files", []) +
             cfg.get("generated_native_identity_files", [])}
    profiles = {u["manifest"]: tomllib.loads(source_file(root, u["manifest"]).read_text(encoding="utf-8")).get("profile", {}) for u in cfg["units"]}
    flags = {key: value for key, value in os.environ.items() if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CXX", "AR", "LD", "CFLAGS", "CXXFLAGS", "LDFLAGS"} or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_")) and key != "CARGO_TARGET_DIR"}
    compatibility = {"rustc": rustc, "cargo": cargo, "target": TARGET, "sccache": sccache,
        "runner_os": os.environ["RUNNER_OS"], "runner_arch": os.environ["RUNNER_ARCH"],
        "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
        "native": native, "identity_files": files, "cargo_profiles": profiles, "flags": flags,
        "requested_profiles": {k: cfg[k] for k in ("build_profile", "test_profile", "clippy_profile")},
        "units": [{"id": u["id"], "packages": u["packages"], "features": u.get("features", []), "no_default_features": u.get("no_default_features", False)} for u in cfg["units"]]}
    lock_hash = digest({u["lockfile"]: digest(source_file(root, u["lockfile"]).read_bytes()) for u in cfg["units"]})
    compiler_hash = digest({"rustc": rustc, "cargo": cargo})
    fingerprint = digest(compatibility)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    platform = "Linux-X64-" + TARGET
    epoch = os.environ.get("CM_CACHE_EPOCH", "v1")
    cargo_prefix = "cm-cargo-" + epoch + "-" + platform + "-" + compiler_hash + "-"
    sccache_prefix = "cm-sccache-" + epoch + "-" + platform + "-" + SCCACHE_VERSION + "-" + fingerprint + "-"
    values = {"cargo_key": cargo_prefix + lock_hash, "cargo_prefix": cargo_prefix,
              "sccache_key": sccache_prefix + head, "sccache_prefix": sccache_prefix}
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(key + "=" + value + "\n")
    (logs / "build-identity.json").write_text(json.dumps({"compatibility": compatibility, "lock_hash": lock_hash,
        "compiler_fingerprint": compiler_hash, "compatibility_fingerprint": fingerprint,
        "cache_keys": values, "checkout_head": head, "source_repository": os.environ.get("CM_SOURCE_REPOSITORY"),
        "cache_repository": os.environ["GITHUB_REPOSITORY"], "cache_mode": os.environ.get("ACTIONS_CACHE_MODE")}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cargo_args(unit, subcommand, cfg, profile=None):
    args = ["cargo", subcommand, "--locked", "--manifest-path", unit["manifest"], "--target", TARGET]
    if profile:
        args += ["--profile", profile]
    for package in unit["packages"]:
        args += ["--package", package]
    if unit.get("no_default_features", False):
        args.append("--no-default-features")
    if unit.get("features"):
        args += ["--features", ",".join(unit["features"])]
    return args


def build_commands(unit, cfg):
    unit = {**unit, "packages": sorted(unit["packages"]), "features": sorted(unit.get("features", []))}
    fmt = ["cargo", "fmt", "--manifest-path", unit["manifest"]]
    packages = unit["packages"] + (["codex-app-server", "codex-core"] if unit["id"] == "host" else [])
    for package in sorted(set(packages)):
        fmt += ["--package", package]
    clippy = cargo_args(unit, "clippy", cfg, cfg["clippy_profile"])
    if unit["id"] == "host":
        clippy += ["--package", "codex-app-server", "--package", "codex-core"]
    return {
        "fmt": fmt + ["--", "--check"],
        "clippy": clippy + ["--all-targets", "--", "-D", "warnings"],
        "test": cargo_args(unit, "test", cfg, cfg["test_profile"]),
        "build": cargo_args(unit, "build", cfg, cfg["build_profile"]),
    }


def main():
    require_hosted_linux()
    root = Path(os.environ.get("CM_SOURCE_DIR", os.environ["GITHUB_WORKSPACE"])).resolve()
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    logs.mkdir(parents=True, exist_ok=True)
    cfg = load_config(root)
    phase = sys.argv[1]
    if phase == "configure":
        configure(root, cfg)
    elif phase == "identity":
        identify(root, logs, cfg)
    elif phase == "fetch":
        for unit in cfg["units"]:
            execute(root, logs, unit["id"] + "-fetch", ["cargo", "fetch", "--locked", "--manifest-path", unit["manifest"], "--target", TARGET])
    elif phase == "build-test":
        import host
        reused = host.reused_build(root, logs)
        if cfg.get("task_id") == "CM-M02":
            format_errors = []
            for owner in ("lifecycle-audit", "example-tool"):
                try:
                    execute(root, logs, "m02-" + owner + "-fmt", ["cargo", "fmt", "--manifest-path",
                        "fixtures/mods/" + owner + "/Cargo.toml", "--", "--check"])
                except RuntimeError as error:
                    format_errors.append(str(error))
            if format_errors:
                raise RuntimeError("; ".join(format_errors))
        for unit in cfg["units"]:
            env = dict(os.environ)
            env["CARGO_TARGET_DIR"] = str(Path(os.environ["CARGO_TARGET_DIR"]) / unit["id"])
            commands = build_commands(unit, cfg)
            execute(root, logs, unit["id"] + "-fmt", commands["fmt"], env)
            if unit["id"] == "host" and reused is not None:
                print("CM CI: reuse verified Host binaries and original Cargo checks from", json.dumps(reused["origin"]), flush=True)
                continue
            if cfg.get("task_id") == "CM-M02" and unit["id"] == "host":
                boundary = {**unit, "packages": ["cm-abi", "cm-sdk", "cm-runtime"]}
                execute(root, logs, "m02-abi-clippy",
                    cargo_args(boundary, "clippy", cfg, cfg["clippy_profile"]) + ["--all-targets", "--", "-D", "warnings"], env)
            for name in ("clippy", "test", "build"):
                execute(root, logs, unit["id"] + "-" + name, commands[name], env)
    elif phase == "acceptance":
        artifact_dir = Path(os.environ["CM_CI_ARTIFACT_DIR"])
        artifact_dir.mkdir(parents=True, exist_ok=True)
        execute(root, logs, "current-task-acceptance", ["bash", str(source_file(root, cfg["acceptance_script"]))])
        if cfg["task_id"] in ("CM-P04", "CM-M01", "CM-M02"):
            from runtime_consumer import provenance, validate_inputs
            producer = json.loads((artifact_dir / "producer-inputs.json").read_text())
            inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"]).resolve()
            manifest = validate_inputs(inputs)
            if (producer.get("status") != "pass" or producer.get("consumer_acceptance") != "not_run"
                or producer.get("task_id") != cfg["task_id"] or producer.get("provenance") != provenance()
                or producer.get("input_manifest_sha256") != manifest["sha256"]):
                raise RuntimeError("Producer must hand off frozen inputs without claiming consumer acceptance")
            return
        report_path = artifact_dir / "acceptance.json"
        if not report_path.is_file():
            raise RuntimeError("The current task's real acceptance report is required; no green skip")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        if report.get("status") != "pass" or report.get("task_id") != cfg["task_id"] or report.get("target") != TARGET or report.get("implementation_commit") != head:
            raise RuntimeError("Current task acceptance did not pass for this exact Linux x64 checkout")
        results = report.get("checks", [])
        if not results or any(not isinstance(item, dict) or item.get("status") != "pass" or not item.get("command") or not item.get("evidence") for item in results):
            raise RuntimeError("Current task acceptance requires nonempty checks, commands and evidence references")
        ids = [item.get("id") for item in results]
        if len(set(ids)) != len(ids) or not set(cfg["required_checks"]).issubset(ids):
            raise RuntimeError("The current task's required acceptance checks were not all reported")
        for item in results:
            references = item["evidence"]
            if not isinstance(references, list) or not references:
                raise RuntimeError("Each check requires artifact-relative evidence file paths")
            for relative in references:
                source_file(artifact_dir.resolve(), relative)
    else:
        raise RuntimeError("Unknown CI phase: " + phase)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM Linux CI blocked/failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
