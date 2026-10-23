#!/usr/bin/env python3
"""Pinned CM Host producer. Executable phases require the independent Actions runner."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request

from linux_ci import TARGET, append_environment, digest, execute, load_config, source_file
from record_run import require_hosted_linux

ADAPTER = "adapters/codex-e4568a3"
HOST = ADAPTER + "/host"
NATIVE_PACKAGES = (
    "gcc", "g++", "binutils", "libc6-dev", "libc6", "libcap-dev", "libcap2",
    "libasound2-dev", "libasound2t64", "libssl-dev", "libssl3t64", "pkg-config",
)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def manifest(root, paths=None):
    entries = []
    paths = paths if paths is not None else root.rglob("*")
    for path in paths:
        relative = path.relative_to(root)
        if ".git" in relative.parts or (path.is_dir() and not path.is_symlink()):
            continue
        if path.is_symlink():
            entries.append({"path": relative.as_posix(), "mode": "120000", "sha256": digest(os.readlink(path).encode())})
        elif path.is_file():
            mode = "100755" if path.stat().st_mode & stat.S_IXUSR else "100644"
            entries.append({"path": relative.as_posix(), "mode": mode, "sha256": sha(path)})
        else:
            raise RuntimeError("Missing or unsupported source input: " + str(relative))
    return sorted(entries, key=lambda entry: entry["path"])


def manifest_digest(entries):
    names = [entry["path"] for entry in entries]
    if len(names) != len(set(names)) or any(
        Path(name).is_absolute() or ".." in Path(name).parts or "\\" in name for name in names
    ):
        raise RuntimeError("Invalid canonical source paths")
    return digest(sorted(entries, key=lambda entry: entry["path"]))


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def clean(root):
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError("Unregistered dirty CM source")


def cm_manifest(root):
    paths = (root / "ci/source-files.txt").read_text().splitlines()
    tracked = set(git(root, "ls-files").splitlines())
    if len(paths) != len(set(paths)) or set(paths) != tracked:
        raise RuntimeError("Host input list must cover exactly the reviewed tracked CM source")
    return manifest(root, [source_file(root, path) for path in paths])


def prepare(root, logs):
    clean(root)
    pin = read(root / ADAPTER / "source.json")
    pristine = Path(os.environ["RUNNER_TEMP"]) / "cm-upstream-pristine"
    host = root / HOST
    if pristine.exists() or host.exists():
        raise RuntimeError("Refusing pre-existing snapshot or Host directory")
    pristine.mkdir()
    execute(pristine, logs, "upstream-init", ["git", "init", "."])
    execute(pristine, logs, "upstream-origin", ["git", "remote", "add", "origin", pin["repository"]])
    execute(pristine, logs, "upstream-fetch", ["git", "fetch", "--depth=1", "origin", pin["commit"]])
    execute(pristine, logs, "upstream-checkout", ["git", "checkout", "--detach", "FETCH_HEAD"])
    clean(pristine)
    if git(pristine, "rev-parse", "HEAD") != pin["commit"] or git(pristine, "rev-parse", "HEAD^{tree}") != pin["tree"]:
        raise RuntimeError("Upstream commit/tree mismatch")
    if any(line.startswith("160000 ") for line in git(pristine, "ls-tree", "-r", "HEAD").splitlines()):
        raise RuntimeError("Submodule closure needs an explicit pin")
    original = manifest(pristine)
    for name, expected in pin["original_files"].items():
        if sha(source_file(pristine, name)) != expected:
            raise RuntimeError("Original upstream bytes differ: " + name)
    execute(pristine, logs, "host-worktree", ["git", "worktree", "add", "--detach", str(host), pin["commit"]])
    execute(host, logs, "host-overlay", ["git", "apply", str(root / ADAPTER / "cli.patch")])
    for source, destination in pin["overlay"].items():
        shutil.copyfile(source_file(root, source), host / destination)
    # Generated worker inputs never become publication inputs or .gitignore exceptions.
    with (root / ".git/info/exclude").open("a", encoding="utf-8") as stream:
        stream.write("\n/" + HOST + "/\n/" + ADAPTER + "/inputs/\n")
    clean(root)
    final = manifest(host)
    before = {entry["path"]: entry for entry in original}
    after = {entry["path"]: entry for entry in final}
    changes = [{"path": name, "original": before.get(name), "host": after.get(name)}
               for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]
    expected_changes = {"codex-rs/cli/src/main.rs", "codex-rs/app-server/src/message_processor.rs",
                        *pin["overlay"].values()}
    if {change["path"] for change in changes} != expected_changes:
        raise RuntimeError("Unexpected source changes outside the reviewed Host overlay")
    original_lock = pristine / "codex-rs/Cargo.lock"
    final_lock = host / "codex-rs/Cargo.lock"
    shutil.copyfile(original_lock, logs / "original-Cargo.lock")
    shutil.copyfile(final_lock, logs / "host-Cargo.lock")
    provenance = {
        "upstream_repository": pin["repository"], "upstream_commit": pin["commit"], "upstream_tree": pin["tree"],
        "original_manifest_sha256": manifest_digest(original), "host_manifest_sha256": manifest_digest(final),
        "original_lock_sha256": sha(original_lock), "host_lock_sha256": sha(final_lock),
        "cm_patch_sha256": sha(root / ADAPTER / "cli.patch"),
        "overlay": {name: sha(root / name) for name in pin["overlay"]},
        "changes": changes,
        "lock_change": "none; original and final roles remain separate" if sha(original_lock) == sha(final_lock)
                       else "changed by the reviewed CM overlay",
        "source_repository": os.environ["CM_SOURCE_REPOSITORY"], "source_sha": git(root, "rev-parse", "HEAD"),
    }
    write(logs / "original-source-manifest.json", original)
    write(logs / "host-source-manifest.json", final)
    write(logs / "host-source-provenance.json", provenance)
    append_environment({"CM_HOST_PRISTINE": str(pristine), "CODEX_REPO_ROOT": str(host)})


def native(root, logs):
    host = root / HOST
    os.environ["CODEX_REPO_ROOT"] = str(host)
    sys.path.insert(0, str(host / "scripts"))
    from codex_package.targets import TARGET_SPECS
    from codex_package.v8 import resolve_codex_v8_cargo_env

    if any(os.environ.get(key) for key in (
        "V8_FROM_SOURCE", "RUSTY_V8_ARCHIVE", "RUSTY_V8_SRC_BINDING_PATH",
        "CODEX_SKIP_BWRAP_BUILD", "CODEX_BWRAP_SOURCE_DIR", "CODEX_BWRAP_SHA256",
        "PKG_CONFIG_PATH", "PKG_CONFIG_SYSROOT_DIR",
    )):
        raise RuntimeError("Unregistered native input override")
    v8_env = resolve_codex_v8_cargo_env(TARGET_SPECS[TARGET])
    if set(v8_env) != {"RUSTY_V8_ARCHIVE", "RUSTY_V8_SRC_BINDING_PATH"}:
        raise RuntimeError("Verified V8 archive and binding are required")
    versions, package_files = {}, set()
    gcc_major = subprocess.check_output(["gcc", "-dumpversion"], text=True).strip().split(".")[0]
    packages = (*NATIVE_PACKAGES, "gcc-" + gcc_major, "g++-" + gcc_major, "cpp-" + gcc_major,
                "libgcc-" + gcc_major + "-dev", "libstdc++-" + gcc_major + "-dev",
                "binutils-x86-64-linux-gnu", "libc-bin")
    for package in packages:
        versions[package] = subprocess.check_output(["dpkg-query", "-W", package], text=True).strip()
        package_files.update(subprocess.check_output(["dpkg-query", "-L", package], text=True).splitlines())
    native_files = []
    for name in sorted(package_files):
        path = Path(name)
        if path.is_file():
            native_files.append({"path": name, "sha256": sha(path),
                                 "link": os.readlink(path) if path.is_symlink() else None})
    tools = {}
    for tool in ("rustc", "cargo"):
        path = Path(subprocess.check_output(["rustup", "which", tool], text=True).strip())
        tools[tool] = {"sha256": sha(path), "version": subprocess.check_output([str(path), "-Vv"], text=True).strip()}
    inputs = {"v8": {key: {"name": Path(value).name, "sha256": sha(Path(value))}
                     for key, value in v8_env.items()},
              "native_packages": versions, "native_files_sha256": digest(native_files), "rust_tools": tools}
    write(logs / "native-files.json", native_files)
    write(root / ADAPTER / "inputs/native.json", inputs)
    append_environment(v8_env)


def helper(root, logs):
    cfg = load_config(root)
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "helper"
    if target.exists():
        raise RuntimeError("Refusing old helper target artifacts")
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    manifest_path = cfg["units"][0]["manifest"]
    execute(root, logs, "helper-fmt",
            ["cargo", "fmt", "--manifest-path", manifest_path, "-p", "codex-bwrap", "--", "--check"], env)
    for phase in ("clippy", "test", "build"):
        args = ["cargo", phase, "--locked", "--manifest-path", manifest_path, "--target", TARGET,
                "--profile", cfg["build_profile"], "-p", "codex-bwrap"]
        if phase == "clippy":
            args += ["--all-targets", "--", "-D", "warnings"]
        execute(root, logs, "helper-" + phase, args, env)
    binary = target / TARGET / cfg["build_profile"] / "bwrap"
    execute(root, logs, "helper-version", [str(binary), "--version"], env)
    inputs = {"sha256": sha(binary), "target": TARGET, "profile": cfg["build_profile"],
              "package": "codex-bwrap", "integrity_env": "CODEX_BWRAP_SHA256"}
    write(logs / "host-helper.json", inputs)
    append_environment({"CODEX_BWRAP_SHA256": inputs["sha256"]})


def verify_sources(root, logs):
    clean(root)
    provenance = read(logs / "host-source-provenance.json")
    for path, expected in (
        (Path(os.environ["CM_HOST_PRISTINE"]), provenance["original_manifest_sha256"]),
        (root / HOST, provenance["host_manifest_sha256"]),
    ):
        if manifest_digest(manifest(path)) != expected:
            raise RuntimeError("Source snapshot drift: " + path.name)
    if sha(root / HOST / "codex-rs/Cargo.lock") != provenance["host_lock_sha256"]:
        raise RuntimeError("Final Host lock drift")
    native_path = root / ADAPTER / "inputs/native.json"
    if native_path.is_file():
        native_inputs = read(native_path)
        for key, entry in native_inputs["v8"].items():
            if sha(Path(os.environ[key])) != entry["sha256"]:
                raise RuntimeError("Verified V8 artifact drift: " + key)
        for tool, entry in native_inputs["rust_tools"].items():
            path = Path(subprocess.check_output(["rustup", "which", tool], text=True).strip())
            if sha(path) != entry["sha256"]:
                raise RuntimeError("Compiler binary drift: " + tool)
        for entry in read(logs / "native-files.json"):
            path = Path(entry["path"])
            link = os.readlink(path) if path.is_symlink() else None
            if sha(path) != entry["sha256"] or link != entry["link"]:
                raise RuntimeError("Native library/header/tool drift: " + entry["path"])
    helper_path = logs / "host-helper.json"
    if helper_path.is_file():
        helper = read(helper_path)
        binary = Path(os.environ["CARGO_TARGET_DIR"]) / "helper" / TARGET / helper["profile"] / "bwrap"
        if sha(binary) != helper["sha256"] or os.environ.get("CODEX_BWRAP_SHA256") != helper["sha256"]:
            raise RuntimeError("Prebuilt helper or embedded integrity digest drift")
    return provenance


def identity_inputs(root, logs):
    provenance = verify_sources(root, logs)
    cfg = load_config(root)
    for key, expected in cfg["compile_env"].items():
        if os.environ.get(key) != expected:
            raise RuntimeError("Actual compile environment drift: " + key)
    if os.environ.get("CARGO_INCREMENTAL") != "0" or os.environ.get("RUSTC_WRAPPER") != "sccache":
        raise RuntimeError("Required non-incremental pinned compiler wrapper changed")
    compatibility = read(logs / "build-identity.json")["compatibility"]
    units = [{**unit, "packages": sorted(unit["packages"]), "features": sorted(unit.get("features", []))}
             for unit in cfg["units"]]
    native_tools = {name: {key: value for key, value in tool.items() if key != "path"}
                    for name, tool in compatibility["native"].items()}
    return {
        "source": provenance["host_manifest_sha256"], "cm_inputs": manifest_digest(cm_manifest(root)),
        "lock": provenance["host_lock_sha256"], "target": cfg["target"],
        "toolchain": {"declared": cfg["rust_toolchain"], "rustc": compatibility["rustc"], "cargo": compatibility["cargo"]},
        "profiles": {name: cfg[name] for name in ("build_profile", "test_profile", "clippy_profile")},
        "units": sorted(units, key=lambda unit: unit["id"]),
        "flags": {**compatibility["flags"], "CARGO_INCREMENTAL": "0", "RUSTC_WRAPPER": "sccache"},
        "cargo_configuration": compatibility["identity_files"], "native_tools": native_tools,
        "native": read(root / ADAPTER / "inputs/native.json"),
        "helper": read(logs / "host-helper.json"),
    }


def build_identity(pin, inputs, protocol):
    required = {"source", "cm_inputs", "lock", "target", "toolchain", "profiles", "units",
                "flags", "cargo_configuration", "native_tools", "native", "helper"}
    if set(inputs) != required or any(inputs[key] in (None, "", []) for key in required - {"flags"}):
        raise RuntimeError("Incomplete Host build inputs")
    if any(not isinstance(inputs[key], dict) or not inputs[key] for key in (
        "toolchain", "profiles", "cargo_configuration", "native_tools", "native", "helper"
    )):
        raise RuntimeError("Incomplete structured Host input")
    if set(inputs["toolchain"]) != {"declared", "rustc", "cargo"} or not all(inputs["toolchain"].values()):
        raise RuntimeError("Incomplete compiler identity")
    if not inputs["units"] or any(not unit.get("packages") for unit in inputs["units"]):
        raise RuntimeError("Missing actual Cargo build units")
    return {"schema_version": 1, "host_release_id": pin["host_release_id"],
            "host_build_id": "sha256:" + digest(inputs), "host_api_version": pin["host_api_version"],
            "capabilities": pin["capabilities"], "protocol_contract_id": "sha256:" + protocol,
            "stage": pin["stage"], "inputs": inputs}


def seal(root, logs):
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "host"
    if target.exists():
        raise RuntimeError("Refusing old target artifacts before the first build")
    pin = read(root / ADAPTER / "source.json")
    inputs = identity_inputs(root, logs)
    protocol = manifest_digest(manifest(root / HOST / pin["protocol_source"]))
    identity = build_identity(pin, inputs, protocol)
    identity_path = logs / "host-identity.json"
    write(identity_path, identity)
    write(logs / "host-cm-inputs.json", cm_manifest(root))
    write(logs / "host-build-start.json", {"host_build_id": identity["host_build_id"], "target_was_absent": True})
    append_environment({"CM_HOST_IDENTITY_JSON": str(identity_path)})


def require_build_success(events):
    required = {unit + "-" + phase for unit in ("helper", "host") for phase in ("fmt", "clippy", "test", "build")}
    successful = {event["phase"] for event in events if event["return_code"] == 0}
    if not required <= successful or any(
        event["return_code"] != 0 for event in events if event["phase"] in required
    ):
        raise RuntimeError("No complete successful current Host build; stale outputs are forbidden")


def verify_binary(path, expected, env=None):
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError("Missing executable Host")
    actual = json.loads(subprocess.check_output([str(path), "cm-host-identity"], env=env, text=True))
    if actual != expected:
        raise RuntimeError("Executable belongs to a different or incomplete Host identity")
    return sha(path)


def official_fixture(root, fixture):
    pin = read(root / ADAPTER / "source.json")["official_asset"]
    archive = fixture / "official.tar.gz"
    with urllib.request.urlopen(pin["url"], timeout=120) as response, archive.open("wb") as output:
        shutil.copyfileobj(response, output)
    if archive.stat().st_size != pin["size"] or sha(archive) != pin["sha256"]:
        raise RuntimeError("Official release asset does not match its independently pinned digest")
    installation = fixture / "official-install"
    installation.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(installation, filter="data")
    binaries = [path for path in installation.rglob("*") if path.is_file() and
                path.name in {"codex", "codex-x86_64-unknown-linux-musl"}]
    if len(binaries) != 1:
        raise RuntimeError("Official fixture must contain exactly one Codex entrypoint")
    return installation, binaries[0]


def acceptance(root, logs):
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    evidence = artifact / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    if read(logs / "host-input-identity.json").get("status") != "pass":
        raise RuntimeError("Required producer regression checks did not pass")
    provenance = verify_sources(root, logs)
    identity = read(logs / "host-identity.json")
    if identity["inputs"] != identity_inputs(root, logs):
        raise RuntimeError("Sealed inputs changed after compilation")
    events = [json.loads(line) for line in (logs / "phase-results.jsonl").read_text().splitlines()]
    require_build_success(events)
    if read(logs / "host-build-start.json") != {"host_build_id": identity["host_build_id"], "target_was_absent": True}:
        raise RuntimeError("Missing clean build-start seal")
    cfg = load_config(root)
    host = root / HOST
    binaries = Path(os.environ["CARGO_TARGET_DIR"]) / "host" / TARGET / cfg["build_profile"]
    executable = binaries / "codex"
    verify_binary(executable, identity)
    wrong = copy.deepcopy(identity)
    wrong["host_build_id"] = "sha256:" + "0" * 64
    try:
        verify_binary(executable, wrong)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("An actual stale-identity executable was accepted")
    lock = host / "codex-rs/Cargo.lock"
    original = lock.read_bytes()
    try:
        lock.write_bytes(original + b"\n")
        try:
            verify_sources(root, logs)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Final lock drift was accepted")
    finally:
        lock.write_bytes(original)
    pristine_lock = Path(os.environ["CM_HOST_PRISTINE"]) / "codex-rs/Cargo.lock"
    original = pristine_lock.read_bytes()
    try:
        pristine_lock.write_bytes(original + b"\n")
        try:
            verify_sources(root, logs)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Original snapshot drift was accepted")
    finally:
        pristine_lock.write_bytes(original)
    rejections = read(logs / "host-identity-rejection.json")
    rejections["actual_executable_and_final_lock_rejection"] = {
        "status": "pass", "actual_executable_sha256": sha(executable),
        "checks": ["actual executable vs wrong embedded identity", "actual final lock drift", "actual original snapshot drift"],
    }
    write(logs / "host-identity-rejection.json", rejections)
    verify_sources(root, logs)
    package = Path(os.environ["RUNNER_TEMP"]) / "cm-host-package"
    helper = Path(os.environ["CARGO_TARGET_DIR"]) / "helper" / TARGET / cfg["build_profile"] / "bwrap"
    execute(root, logs, "host-package", [
        "python3", "-B", str(host / "scripts/build_codex_package.py"), "--target", TARGET,
        "--package-dir", str(package), "--package-version", "0.1.0-p01", "--strip", "none",
        "--entrypoint-bin", str(executable), "--code-mode-host-bin", str(binaries / "codex-code-mode-host"),
        "--bwrap-bin", str(helper),
    ])
    write(package / "cm-host.json", identity)
    licenses = package / "licenses"
    licenses.mkdir()
    for name in ("LICENSE", "NOTICE"):
        source = host / name
        if source.is_file():
            shutil.copyfile(source, licenses / ("codex-" + name))
    if not list(licenses.iterdir()):
        raise RuntimeError("Missing upstream license")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", TARGET],
        cwd=host / "codex-rs", text=True, env={**os.environ, "CARGO_TARGET_DIR": str(binaries.parents[1])}))
    sbom = {"format": "cm-resolved-cargo-inventory-v1", "target": TARGET,
            "lock_sha256": provenance["host_lock_sha256"],
            "packages": sorted([{"id": value["id"], "name": value["name"], "version": value["version"],
                                  "source": value["source"], "license": value["license"],
                                  "license_file_declared": bool(value.get("license_file"))}
                                 for value in metadata["packages"]], key=lambda value: value["id"]),
            "native": read(root / ADAPTER / "inputs/native.json"),
            "note": "Resolved dependency and license declarations; not a license-compliance certification."}
    write(package / "dependency-inventory.json", sbom)
    package_before = manifest_digest(manifest(package))
    with tempfile.TemporaryDirectory(prefix="cm-no-mod-", dir=os.environ["RUNNER_TEMP"]) as tmp:
        fixture = Path(tmp)
        profile = fixture / "official-profile"
        profile.mkdir()
        (profile / "config.toml").write_text('model = "official-profile-sentinel"\n')
        (profile / "auth.json").write_text('{"fixture":true}\n')
        installation, official = official_fixture(root, fixture)
        before = {"installation": manifest_digest(manifest(installation)), "profile": manifest_digest(manifest(profile))}
        cm_home = fixture / "cm-home"
        cm_home.mkdir()
        env = {**os.environ, "CODEX_HOME": str(cm_home), "HOME": str(fixture / "home")}
        Path(env["HOME"]).mkdir()
        verify_binary(package / "bin/codex", identity, env)
        if sha(package / "codex-resources/bwrap") != identity["inputs"]["helper"]["sha256"]:
            raise RuntimeError("Packaged helper differs from the compiled-in integrity digest")
        for label, executable, args, expected in (
            ("bwrap", package / "codex-resources/bwrap", ["--version"], "bubblewrap"),
            ("code-mode-host", package / "bin/codex-code-mode-host", ["--help"], "Usage:"),
            ("ripgrep", package / "codex-path/rg", ["--version"], "ripgrep"),
        ):
            execute(root, logs, "host-packaged-" + label, [str(executable), *args], env)
            if expected not in (logs / ("host-packaged-" + label + ".log")).read_text():
                raise RuntimeError("Packaged helper did not produce its expected output: " + label)
        behavior = {}
        version = tomllib.loads((host / "codex-rs/Cargo.toml").read_text())["workspace"]["package"]["version"]
        for args, expected in (
            (["--version"], "codex-cli " + version), (["--help"], "cm-host-identity"),
            (["exec", "--help"], "Usage:"), (["features", "list"], "code_mode"),
        ):
            label = "host-baseline-" + "-".join(arg.lstrip("-") for arg in args)
            execute(root, logs, label, [str(package / "bin/codex"), *args], env)
            if expected not in (logs / (label + ".log")).read_text():
                raise RuntimeError("Packaged CLI baseline output mismatch: " + label)
            behavior[" ".join(args)] = sha(logs / (label + ".log"))
        official_version = subprocess.check_output(
            [str(official), "--version"], env={**env, "CODEX_HOME": str(profile)}, text=True).strip()
        if "0.163.0" not in official_version:
            raise RuntimeError("Official reference version differs from its pinned release")
        core_args = ["cargo", "test", "--locked", "--manifest-path", cfg["units"][0]["manifest"],
                     "--target", TARGET, "--profile", cfg["test_profile"], "-p", "codex-core", "--lib",
                     "command_canonicalization::tests::", "--", "--nocapture"]
        execute(root, logs, "host-core-baseline", core_args,
                {**os.environ, "CARGO_TARGET_DIR": str(binaries.parents[1]), "CODEX_HOME": str(cm_home)})
        if "4 passed; 0 failed" not in (logs / "host-core-baseline.log").read_text():
            raise RuntimeError("Representative unchanged Core behavior tests did not actually run")
        after = {"installation": manifest_digest(manifest(installation)), "profile": manifest_digest(manifest(profile))}
        if before != after:
            raise RuntimeError("Official installation/profile was modified")
        if manifest_digest(manifest(package)) != package_before:
            raise RuntimeError("The same packaged CM Host was modified during its no-Mod baseline")
        baseline = {"host_build_id": identity["host_build_id"], "mod_set": [], "behavior_logs_sha256": behavior,
                    "core_tests": "command_canonicalization::tests: 4 actual upstream behavior tests",
                    "official_fixture": {"release": "rust-v0.163.0", "version_output": official_version, **before},
                    "after": after, "cm_package_unchanged_sha256": package_before,
                    "upstream_difference": "Pinned S0 plus CLI identity command, embedded inputs and a behavior-preserving "
                                           "time-provider let-and-return cleanup for strict Clippy; no loader/capabilities yet. "
                                           "The official release uses a distinct commit; no binary equivalence is claimed."}
    verify_sources(root, logs)
    package_manifest = manifest(package)
    archive = artifact / ("cm-host-" + identity["host_build_id"].removeprefix("sha256:")[:16] + "-linux-x64.tar.gz")
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(package, arcname="cm-host")
    receipt = {"schema_version": 1, "host_identity": identity, "artifact_sha256": sha(archive),
               "archive": archive.name, "package_manifest_sha256": manifest_digest(package_manifest),
               "executable_sha256": verify_binary(package / "bin/codex", identity),
               "source_repository": os.environ["CM_SOURCE_REPOSITORY"], "source_sha": git(root, "rev-parse", "HEAD"),
               "workflow_repository": os.environ["GITHUB_REPOSITORY"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
               "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "job": os.environ["GITHUB_JOB"], "target": TARGET,
               "cache_repository": os.environ["GITHUB_REPOSITORY"], "cache_mode": os.environ["ACTIONS_CACHE_MODE"],
               "cache_evidence": "Worker cache observations and always-run sccache statistics accompany this artifact"}
    write(evidence / "host-package-manifest.json", package_manifest)
    write(evidence / "host-baseline-build.json", receipt)
    write(evidence / "host-empty-baseline.json", baseline)
    for name in ("host-source-provenance.json", "host-identity.json", "host-cm-inputs.json",
                 "host-source-manifest.json", "original-source-manifest.json", "original-Cargo.lock", "host-Cargo.lock",
                 "host-input-identity.json", "host-identity-rejection.json", "host-helper.json"):
        shutil.copyfile(logs / name, evidence / name)
    checks = [
        ("CM-P01-AC01", "host-input-identity.json"), ("CM-P01-AC02", "host-source-provenance.json"),
        ("CM-P01-AC03", "host-identity-rejection.json"), ("CM-P01-AC04", "host-baseline-build.json"),
        ("CM-P01-AC05", "host-empty-baseline.json"),
    ]
    write(artifact / "acceptance.json", {
        "schema_version": 1, "task_id": "CM-P01", "status": "pass", "target": TARGET,
        "implementation_commit": git(root, "rev-parse", "HEAD"),
        "checks": [{"id": check, "status": "pass", "command": "python3 -B ci/scripts/host.py acceptance",
                    "evidence": ["evidence/" + name]} for check, name in checks],
    })


def main():
    require_hosted_linux()
    if os.environ.get("GITHUB_REPOSITORY") != "DSLZL/CM-build-linux-x64":
        raise RuntimeError("Host execution requires the fixed independent builder repository")
    root = Path(os.environ["CM_SOURCE_DIR"]).resolve()
    logs = Path(os.environ["CM_CI_LOG_DIR"]).resolve()
    logs.mkdir(parents=True, exist_ok=True)
    {"prepare": prepare, "native": native, "helper": helper, "seal": seal, "acceptance": acceptance}[sys.argv[1]](root, logs)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM Host failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
