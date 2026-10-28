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
import linux_ci
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

    def test_fixture_changes_do_not_change_product_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pin = {"patches": ["cli.patch"], "overlay": {"crates/cm/src/host_identity.rs": "cli/identity.rs"}}
            names = [host.ADAPTER + "/source.json", host.ADAPTER + "/cli.patch",
                     "crates/cm/src/host_identity.rs", "fixtures/runtime-consumer/driver.py"]
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(pin) if name.endswith("source.json") else "original input")
            with patch.object(host, "cm_manifest", side_effect=lambda _: host.manifest(root, [root / name for name in names])):
                baseline = host.manifest_digest(host.product_manifest(root))
                (root / names[-1]).write_text("changed fixture only")
                self.assertEqual(baseline, host.manifest_digest(host.product_manifest(root)))
                (root / "crates/cm/src/host_identity.rs").write_text("changed compiled product")
                self.assertNotEqual(baseline, host.manifest_digest(host.product_manifest(root)))
            with patch.object(host, "cm_manifest", return_value=[]), self.assertRaises(RuntimeError):
                host.product_manifest(root)

    def test_cache_requires_exact_bytes_identity_origin_and_successful_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            cache.mkdir()
            for name in host.HOST_CACHE_FILES:
                (cache / name).write_text("frozen " + name)
                if not name.endswith(".log"):
                    (cache / name).chmod(0o755)
            receipt = {"schema_version": 1, "identity": self.sealed, "files": host.manifest(cache),
                "origin": {"source_repository": os.environ["CM_SOURCE_REPOSITORY"],
                    "workflow_repository": os.environ["GITHUB_REPOSITORY"], "source_sha": "1" * 40,
                    "workflow_sha": "2" * 40, "run_id": "1", "run_attempt": "1", "job": "linux-x64"},
                "quality": [{"phase": phase, "return_code": 0, "command": command}
                            for phase, command in host.host_check_commands(self.sealed).items()]}
            host.write(cache / "build.json", receipt)
            self.assertEqual(receipt, host.verify_build_cache(cache, self.sealed))
            metadata = cache / "build.json"
            backing = Path(tmp) / "original-build.json"
            backing.write_bytes(metadata.read_bytes())
            metadata.unlink()
            metadata.symlink_to(backing)
            with self.assertRaises(RuntimeError):
                host.verify_build_cache(cache, self.sealed)
            metadata.unlink()
            metadata.write_bytes(backing.read_bytes())
            changed_identity = {**self.sealed, "host_build_id": "sha256:" + "0" * 64}
            with self.assertRaises(RuntimeError):
                host.verify_build_cache(cache, changed_identity)
            original = (cache / "codex").read_bytes()
            (cache / "codex").write_bytes(b"damaged binary")
            with self.assertRaises(RuntimeError):
                host.verify_build_cache(cache, self.sealed)
            (cache / "codex").write_bytes(original)
            (cache / "unexpected").write_text("extra cache input")
            with self.assertRaises(RuntimeError):
                host.verify_build_cache(cache, self.sealed)
            (cache / "unexpected").unlink()
            for change in ("origin", "failed-check", "missing-check", "wrong-command", "malformed-phase"):
                candidate = copy.deepcopy(receipt)
                if change == "origin":
                    candidate["origin"]["source_repository"] = "untrusted/source"
                elif change == "failed-check":
                    candidate["quality"][0]["return_code"] = 1
                elif change == "wrong-command":
                    candidate["quality"][0]["command"].append("--unchecked-option")
                elif change == "malformed-phase":
                    candidate["quality"][0]["phase"] = []
                else:
                    candidate["quality"].pop()
                host.write(cache / "build.json", candidate)
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    host.verify_build_cache(cache, self.sealed)
            host.write(cache / "build.json", receipt)
            self.assertEqual(receipt, host.verify_build_cache(cache, self.sealed))
            current = [{"phase": "helper-" + phase, "return_code": 0} for phase in ("fmt", "clippy", "test", "build", "sandbox")]
            with self.assertRaises(RuntimeError):
                host.require_build_success(current, receipt)
            current.append({"phase": "host-fmt", "return_code": 0})
            host.require_build_success(current, receipt)
            with self.assertRaises(RuntimeError):
                host.require_build_success([*current, {"phase": "host-test", "return_code": 1}], receipt)

    def test_verified_cache_hit_skips_host_compile_but_reruns_formatting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = {"units": [{"id": "host", "manifest": "Cargo.toml", "packages": ["codex-cli"]}],
                   "build_profile": "dev-small", "clippy_profile": "dev-small", "test_profile": "dev-small"}
            with patch.dict(os.environ, {"CM_SOURCE_DIR": str(root), "GITHUB_WORKSPACE": str(root), "CM_CI_LOG_DIR": str(root)}), \
                    patch.object(linux_ci, "require_hosted_linux"), patch.object(linux_ci, "load_config", return_value=cfg), \
                    patch.object(host, "reused_build") as reused, patch.object(linux_ci, "execute") as run, \
                    patch.object(sys, "argv", ["linux_ci.py", "build-test"]):
                reused.return_value = {"origin": {"run_id": "original"}}
                linux_ci.main()
                self.assertEqual([call.args[2] for call in run.call_args_list], ["host-fmt"])
                reused.return_value = None
                run.reset_mock()
                linux_ci.main()
                self.assertEqual([call.args[2] for call in run.call_args_list], ["host-fmt", "host-clippy", "host-test", "host-build"])

    def test_m02_fixture_formatting_blocks_host_compile_even_on_cache_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = {"task_id": "CM-M02",
                   "units": [{"id": "host", "manifest": "Cargo.toml", "packages": ["codex-cli"]}],
                   "build_profile": "dev-small", "clippy_profile": "dev-small", "test_profile": "dev-small"}
            with patch.dict(os.environ, {"CM_SOURCE_DIR": str(root), "GITHUB_WORKSPACE": str(root), "CM_CI_LOG_DIR": str(root)}), \
                    patch.object(linux_ci, "require_hosted_linux"), patch.object(linux_ci, "load_config", return_value=cfg), \
                    patch.object(host, "reused_build", return_value={"origin": {"run_id": "original"}}) as reused, \
                    patch.object(linux_ci, "execute") as run, patch.object(sys, "argv", ["linux_ci.py", "build-test"]):
                expected = ["m02-lifecycle-audit-fmt", "m02-example-tool-fmt"]
                run.side_effect = [RuntimeError(label) for label in expected]
                with self.assertRaises(RuntimeError) as failure:
                    linux_ci.main()
                self.assertEqual([call.args[2] for call in run.call_args_list], expected)
                for label in expected:
                    self.assertIn(label, str(failure.exception))
                run.side_effect = None
                run.reset_mock()
                linux_ci.main()
                self.assertEqual([call.args[2] for call in run.call_args_list], [*expected, "host-fmt"])
                reused.return_value = None
                run.reset_mock()
                linux_ci.main()
                self.assertEqual([call.args[2] for call in run.call_args_list],
                    [*expected, "host-fmt", "m02-abi-clippy", "host-clippy", "host-test", "host-build"])

    def test_host_cache_round_trip_retains_original_quality_and_detects_restored_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            cache = root / "cache"
            binaries = root / "target/host" / host.TARGET / "dev-small"
            binaries.mkdir(parents=True)
            for name in ("codex", "codex-code-mode-host"):
                (binaries / name).write_bytes(("original " + name).encode())
                (binaries / name).chmod(0o755)
            host.write(logs / "host-identity.json", self.sealed)
            events = [{"phase": "helper-" + phase, "return_code": 0, "command": ["cargo", phase]}
                      for phase in ("fmt", "clippy", "test", "build")]
            events += [{"phase": phase, "return_code": 0, "command": command}
                       for phase, command in host.host_check_commands(self.sealed).items()]
            events += [{"phase": "helper-sandbox", "return_code": 0}, {"phase": "current-task-acceptance", "return_code": 0}]
            (logs / "phase-results.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            for phase in host.HOST_BUILD_PHASES:
                (logs / (phase + ".log")).write_text("original successful " + phase)
            with patch.dict(os.environ, {"CM_HOST_BUILD_CACHE_DIR": str(cache), "CARGO_TARGET_DIR": str(root / "target"),
                    "ACTIONS_CACHE_MODE": "write"}), patch.object(host, "load_config", return_value={"build_profile": "dev-small"}), \
                    patch.object(host, "verify_binary") as verify:
                host.restore_build(ROOT, logs)
                self.assertEqual(host.read(logs / "host-build-cache.json")["status"], "miss")
                host.save_build(ROOT, logs)
                original = host.read(cache / "build.json")
                for name in ("codex", "codex-code-mode-host"):
                    (binaries / name).unlink()
                binaries.rmdir()
                host.restore_build(ROOT, logs)
                verify.assert_called_once_with(cache / "codex", self.sealed)
                self.assertEqual(host.reused_build(ROOT, logs), original)
                self.assertEqual(host.build_log(logs, "host-test").read_text(), "original successful host-test")
                self.assertEqual(host.read(logs / "host-build-cache.json")["origin"], original["origin"])
                (binaries / "codex").write_bytes(b"changed after restore")
                with self.assertRaises(RuntimeError):
                    host.reused_build(ROOT, logs)

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

    def test_compiler_cache_survives_image_release_but_rejects_tool_or_flag_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            (root / "Cargo.toml").write_text("[profile.dev-small]\ndebug = 0\n")
            (root / "Cargo.lock").write_text("locked dependencies")
            compiler = root / "cc"
            compiler.write_bytes(b"compiler-v1")
            output = root / "github-output"
            cfg = {"native_tools": ["cc"], "cargo_config_files": ["Cargo.toml"],
                   "units": [{"id": "host", "manifest": "Cargo.toml", "lockfile": "Cargo.lock",
                              "packages": ["codex-cli"]}],
                   "build_profile": "dev-small", "test_profile": "dev-small", "clippy_profile": "dev-small"}

            def checked(command, **_):
                if command[0] == "sccache":
                    return "sccache " + linux_ci.SCCACHE_VERSION
                if command[0] == "git":
                    return "1" * 40
                return "pinned " + " ".join(command)

            def identify():
                output.write_text("")
                linux_ci.identify(root, logs, cfg)
                value = host.read(logs / "build-identity.json")
                self.assertEqual(dict(line.split("=", 1) for line in output.read_text().splitlines()), value["cache_keys"])
                return value

            env = {"GITHUB_OUTPUT": str(output), "GITHUB_REPOSITORY": "DSLZL/CM-build-linux-x64",
                   "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24",
                   "ImageVersion": "before", "RUSTFLAGS": "-C target-cpu=x86-64"}
            with patch.dict(os.environ, env, clear=True), patch.object(linux_ci.shutil, "which", return_value=str(compiler)), \
                    patch.object(linux_ci.subprocess, "check_output", side_effect=checked):
                before = identify()
                os.environ["ImageVersion"] = "after"
                after = identify()
                self.assertEqual(before["compatibility_fingerprint"], after["compatibility_fingerprint"])
                self.assertEqual(before["cache_keys"]["sccache_prefix"], after["cache_keys"]["sccache_prefix"])
                self.assertNotEqual(before["cache_keys"]["sccache_legacy_prefix"], after["cache_keys"]["sccache_legacy_prefix"])
                self.assertEqual(after["compatibility"]["image_version"], "after")
                for key, value in (("RUSTFLAGS", "-C target-cpu=x86-64-v3"), ("RUNNER_ARCH", "ARM64"), ("ImageOS", "ubuntu26")):
                    with self.subTest(changed=key), patch.dict(os.environ, {key: value}):
                        self.assertNotEqual(after["compatibility_fingerprint"], identify()["compatibility_fingerprint"])
                compiler.write_bytes(b"compiler-v2")
                self.assertNotEqual(after["compatibility_fingerprint"], identify()["compatibility_fingerprint"])

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
                       "old target directory", "failed build", "incomplete build", "cache identity/bytes/origin drift",
                       "failed or incomplete cached checks", "changed check commands", "malformed cached phases",
                       "missing current formatting", "restored binary drift"],
        "host_reuse": "Product/fixture separation, immutable cache round trip and hit/miss compilation gates tested",
        "actual_executable_and_final_lock_rejection": "The acceptance caller must separately complete these real checks",
    })
