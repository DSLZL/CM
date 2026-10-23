#!/usr/bin/env python3
"""Producer regression checks; run only in the independent Linux worker."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ci/scripts"))
import host
from linux_ci import execute


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = host.read(ROOT / host.ADAPTER / "source.json")
        cls.sealed = host.read(Path(os.environ["CM_CI_LOG_DIR"]) / "host-identity.json")

    def test_path_order_and_mtime_do_not_change_inputs(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            roots = [Path(first), Path(second)]
            for root in roots:
                (root / "nested").mkdir()
                (root / "nested/input").write_bytes(b"same immutable bytes\n")
                (root / "link").symlink_to("nested/input")
            os.utime(roots[1] / "nested/input", (1, 1))
            forward = host.manifest(roots[0])
            reverse = host.manifest(roots[1], reversed(list(roots[1].rglob("*"))))
            self.assertEqual(host.manifest_digest(forward), host.manifest_digest(reverse))
            self.assertEqual(host.manifest_digest(forward), host.manifest_digest(list(reversed(reverse))))
            inputs = copy.deepcopy(self.sealed["inputs"])
            inputs["source"] = host.manifest_digest(forward)
            first_id = host.build_identity(self.pin, inputs, "0" * 64)["host_build_id"]
            inputs["source"] = host.manifest_digest(reverse)
            self.assertEqual(first_id, host.build_identity(self.pin, inputs, "0" * 64)["host_build_id"])
            (roots[1] / "nested/input").write_bytes(b"different bytes\n")
            self.assertNotEqual(host.manifest_digest(forward), host.manifest_digest(host.manifest(roots[1])))
            (roots[1] / "nested/input").write_bytes(b"same immutable bytes\n")
            (roots[1] / "nested/input").chmod(0o755)
            self.assertNotEqual(host.manifest_digest(forward), host.manifest_digest(host.manifest(roots[1])))

    def test_every_input_class_changes_identity(self):
        inputs = self.sealed["inputs"]
        protocol = self.sealed["protocol_contract_id"].removeprefix("sha256:")
        baseline = host.build_identity(self.pin, inputs, protocol)["host_build_id"]
        changes = {
            "source": "0" * 64, "cm_inputs": "1" * 64, "lock": "2" * 64,
            "target": "aarch64-unknown-linux-gnu",
            "toolchain": {**inputs["toolchain"], "rustc": "different compiler"},
            "profiles": {**inputs["profiles"], "build_profile": "release"},
            "flags": {**inputs["flags"], "RUSTFLAGS": "-C target-cpu=native"},
            "units": [{**inputs["units"][0], "features": ["different-feature"]}],
            "cargo_configuration": {**inputs["cargo_configuration"], "extra": "3" * 64},
            "native_tools": {**inputs["native_tools"], "changed-tool": {"sha256": "4" * 64}},
            "native": {**inputs["native"], "v8": {"archive": "different verified artifact"}},
            "helper": {**inputs["helper"], "sha256": "5" * 64},
        }
        for key, value in changes.items():
            with self.subTest(input=key):
                candidate = copy.deepcopy(inputs)
                candidate[key] = value
                self.assertNotEqual(baseline, host.build_identity(self.pin, candidate, protocol)["host_build_id"])
        self.assertNotEqual(baseline, self.pin["commit"])
        self.assertNotEqual(baseline, self.pin["host_release_id"])
        self.assertNotIn("artifact_sha256", self.sealed)
        self.assertNotIn("mod_set", inputs)

    def test_missing_inputs_and_invalid_paths_are_rejected(self):
        for key in self.sealed["inputs"]:
            candidate = copy.deepcopy(self.sealed["inputs"])
            del candidate[key]
            with self.subTest(missing=key), self.assertRaises(RuntimeError):
                host.build_identity(self.pin, candidate, "0" * 64)
        with self.assertRaises(RuntimeError):
            host.manifest_digest([{"path": "../outside"}])
        with self.assertRaises(RuntimeError):
            host.manifest_digest([{"path": "same"}, {"path": "same"}])
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(RuntimeError):
            host.verify_binary(Path(tmp) / "missing-codex", self.sealed)

    def test_dirty_source_and_old_target_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            (root / "unregistered.rs").write_text("unexpected source")
            with self.assertRaises(RuntimeError):
                host.clean(root)
            (root / "host").mkdir()
            with patch.dict(os.environ, {"CARGO_TARGET_DIR": str(root)}), self.assertRaises(RuntimeError):
                host.seal(ROOT, root)

    def test_failed_or_incomplete_build_cannot_select_stale_outputs(self):
        events = [{"phase": unit + "-" + phase, "return_code": 0}
                  for unit in ("helper", "host") for phase in ("fmt", "clippy", "test", "build")]
        events.append({"phase": "helper-sandbox", "return_code": 0})
        host.require_build_success(events)
        for index, event in enumerate(events):
            with self.assertRaises(RuntimeError):
                host.require_build_success(events[:index] + events[index + 1:])
            with self.assertRaises(RuntimeError):
                host.require_build_success(events[:index] + [{**event, "return_code": 1}] + events[index + 1:])

    def test_shared_cargo_entry_uses_manifest_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text("[workspace]\n")
            tools = root / "tools"
            tools.mkdir()
            cargo = tools / "cargo"
            cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$PWD" "$@"\n')
            cargo.chmod(0o755)
            logs = root / "logs"
            logs.mkdir()
            with patch.dict(os.environ, {"PATH": str(tools) + os.pathsep + os.environ["PATH"]}):
                execute(root, logs, "cwd", ["cargo", "fetch", "--manifest-path", "workspace/Cargo.toml"])
                with self.assertRaises(RuntimeError):
                    execute(root, logs, "outside", ["cargo", "fetch", "--manifest-path", "../Cargo.toml"])
            output = (logs / "cwd.log").read_text().splitlines()
            self.assertEqual(output[0], str(workspace))
            self.assertEqual(output[-1], "Cargo.toml")
            event = json.loads((logs / "phase-results.jsonl").read_text().splitlines()[0])
            self.assertEqual(event["cwd"], str(workspace))


if __name__ == "__main__":
    host.require_hosted_linux()
    if os.environ["GITHUB_REPOSITORY"] != "DSLZL/CM-build-linux-x64":
        raise SystemExit("Independent builder required")
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IdentityTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    host.write(logs / "host-input-identity.json", {
        "status": "pass", "test": "test_path_order_and_mtime_do_not_change_inputs",
        "actual_host_build_id": IdentityTests.sealed["host_build_id"],
        "variants": ["different temporary roots", "reverse traversal", "reverse manifest", "mtime"],
        "binary_reproducibility": "not claimed",
    })
    host.write(logs / "host-identity-rejection.json", {
        "status": "pass", "unit_tests_run": result.testsRun,
        "input_classes": list(IdentityTests.sealed["inputs"]),
        "rejections": ["missing input", "path traversal", "duplicate path", "missing binary", "dirty CM checkout",
                       "old target directory", "failed build", "incomplete build"],
        "actual_executable_and_final_lock_rejection": "The acceptance caller must separately complete these real checks",
    })
