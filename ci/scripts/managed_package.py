#!/usr/bin/env python3
"""M03 author preparation and compiler-free public CLI acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPORTS = ("prebuilt-host-package.json", "drop-in-install.json", "independent-prebuilt-launcher.json",
           "atomic-mod-installation.json", "prebuilt-backend-selection.json", "native-runtime-dependencies.json")


def driver():
    path = Path(__file__).resolve().parents[2] / "fixtures/managed-package/driver.py"
    spec = importlib.util.spec_from_file_location("cm_m03_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(inputs, package, frozen, logs):
    import host
    import mod_manifest
    from linux_ci import execute
    root = Path(os.environ["CM_SOURCE_DIR"])
    for source in ("ci/scripts/managed_package.py", "fixtures/managed-package/driver.py"):
        destination = inputs / "fixture" / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source, destination)
    for owner in ("lifecycle-audit", "example-tool"):
        mod_manifest.zip_package(inputs / "mods/m02" / owner / "normal", inputs / "mods" / (owner + ".cmod"))
    sentinel = inputs / "mods/constructor-sentinel"
    sentinel.mkdir()
    execute(root, logs, "m03-constructor-author-build", ["cc", "-shared", "-fPIC", "-march=x86-64",
        str(root / "fixtures/native-loader/replacement.c"), "-o", str(sentinel / "payload.so")])
    import tomllib
    fields = tomllib.loads((inputs / "mods/m01-b/mod.toml").read_text())
    fields["id"] = "constructor-sentinel"
    fields["state"]["owner"] = fields["id"]
    fields["binary"].update(size=(sentinel / "payload.so").stat().st_size,
        sha256=mod_manifest.sha(sentinel / "payload.so"),
        glibc_min=mod_manifest.native_glibc_min(sentinel / "payload.so"))
    mod_manifest.manifest(sentinel, fields)
    (sentinel / "postinstall.py").write_text("raise RuntimeError('installation must never run attachments')\n")
    checks = ("nonempty_unmarked_home_and_concurrent_writer_are_rejected",
              "descriptor_is_unchanged_before_commit_and_truthful_after_rename",
              "swapped_profile_inputs_never_commit",
              "cas_publication_never_replaces_existing_content",
              "actual_cpu_requirements_and_glibc_versions_are_bounded")
    log = host.build_log(logs, "host-test")
    text = log.read_text()
    assert all(name + " ... ok" in text for name in checks), "M03 precise transaction/native parser tests did not run"
    assert mod_manifest.sha(package / "bin/codex") == frozen["executable_sha256"]
    mod_manifest.write(inputs / "fixture/m03-producer.json", {"status": "pass",
        "precise_unit_checks": list(checks), "host_test_log_sha256": mod_manifest.sha(log),
        "unit_binary_is_published_host": False, "host_executable_sha256": frozen["executable_sha256"],
        "baseline": "actual GitHub-hosted ubuntu-24.04 X64 GNU runtime; no glibc 2.17 Host claim"})


def self_check():
    assert len(REPORTS) == len(set(REPORTS)) == 6
    driver().self_check()
    print(json.dumps({"m03_handoff_self_check": "pass"}))


if __name__ == "__main__":
    {"produce": lambda: __import__("runtime_consumer").produce(),
     "matrix": lambda: driver().matrix(), "self-check": self_check}[sys.argv[1]]()
