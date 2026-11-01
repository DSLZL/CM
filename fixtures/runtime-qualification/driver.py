"""Independent G04 failure/recovery transactions in the existing strict consumer."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci/scripts"))
import managed_package
import mod_manifest
import runtime_cases
from runtime_qualification import REPORTS

INPUTS = Path("/inputs")
WORK = Path("/work/g04")
PROFILE = Path("/profile/g04")
EVIDENCE = Path("/evidence/g04")
OFFICIAL_PROFILE = WORK / "official-profile"
COPY = WORK / "package"


def reject(command, env):
    directory = EVIDENCE / "rejection"
    directory.mkdir(exist_ok=True)
    result = subprocess.run(command, env=env, cwd=WORK, capture_output=True, text=True, timeout=60)
    row = {"command": command, "return_code": result.returncode, "stderr": result.stderr}
    mod_manifest.write(directory / "result.json", row)
    assert result.returncode != 0 and result.stderr, row
    if result.stderr.startswith("{"):
        row["diagnostic"] = json.loads(result.stderr.splitlines()[0])
        assert row["diagnostic"]["already_native_executed"] is False, row
    for name in ("constructor-sentinel", "native.jsonl", "events.jsonl"):
        assert not (directory / name).exists(), "Rejection executed native code: " + name
    return row


def package_failure(relative, *, damage=False):
    shutil.copytree(INPUTS / "host", COPY, symlinks=True)
    path = COPY / relative
    before = mod_manifest.sha(path)
    if damage:
        path.write_bytes(path.read_bytes() + b"\nG04 damaged inventory input\n")
    else:
        path.unlink()
    result = reject(m.launch_command(COPY / "bin/codex", PROFILE / "active", ["exec", "unused"]),
                    m.environment(EVIDENCE / "rejection"))
    assert result["diagnostic"]["stage"] == result["diagnostic"]["code"] == "package", result
    result.update(stage="package_preflight", component=relative, original_sha256=before)
    return result


def case_missing_bwrap():
    return package_failure("codex-resources/bwrap")


def case_missing_rg():
    return package_failure("codex-path/rg")


def case_missing_code_mode():
    return package_failure("bin/codex-code-mode-host")


def case_missing_inventory():
    return package_failure("cm-runtime-files.json")


def case_damaged_package():
    return package_failure("cm-host.json", damage=True)


def case_abi():
    package = WORK / "wrong-abi"
    shutil.copytree(INPUTS / "mods/constructor-sentinel", package)
    fields = tomllib.loads((package / "mod.toml").read_text())
    fields["compat"]["abi_major"] = 65535
    mod_manifest.manifest(package, fields)
    # Keep the real constructor-bearing ELF and its valid hash, isolating the ABI guard.
    assert mod_manifest.sha(package / fields["binary"]["path"]) == fields["binary"]["sha256"]
    result = m.reject_install(PROFILE / "active", package, "wrong-abi")
    assert "abi" in result["diagnostic"].lower(), result
    return {"stage": "mod_preflight", **result}


def case_loader_environment():
    env = m.environment(EVIDENCE / "rejection")
    env["LD_LIBRARY_PATH"] = str(WORK / "untrusted-libraries")
    result = reject(m.launch_command(m.BINARY, PROFILE / "active", ["exec", "unused"]), env)
    assert result["diagnostic"]["stage"] == "preflight" and result["diagnostic"]["code"] == "managed_profile", result
    return {"stage": "managed_environment_preflight", **result}


def case_missing_library():
    mutation = mod_manifest.read(Path("/fixture/missing-library.json"))
    removed = Path(mutation["removed_library"])
    assert removed.is_absolute() and not removed.exists()
    assert str(removed) in mod_manifest.read(INPUTS / "host/cm-runtime-files.json")["system_files"]
    result = reject(m.launch_command(m.BINARY, PROFILE / "active", ["exec", "unused"]),
                    m.environment(EVIDENCE / "rejection"))
    if "error while loading shared libraries" in result["stderr"]:
        assert removed.name in result["stderr"]
        stage = "os_dynamic_loader"
    else:
        assert result["diagnostic"]["stage"] == result["diagnostic"]["code"] == "package", result
        stage = "package_preflight"
    return {**result, "stage": stage, "mutation": mutation}


def matrix(case, stage=None):
    global m, sdk
    runtime_cases.enter(globals(), "g04", case)
    m = managed_package.driver()
    m.WORK, m.PROFILE, m.EVIDENCE, m.OFFICIAL_PROFILE, m.COPY = WORK, PROFILE, EVIDENCE, OFFICIAL_PROFILE, COPY
    home = PROFILE / "active"
    user = home / "g04-user-data"
    if stage in (None, "prepare"):
        sdk, producer, authored, frozen, official, writable, global_path, path_before = m.case_setup()
        m.populated(home)
        m.business("baseline", home, sdk)
        user.write_text("preserve this user's bytes\n")
        active = m.state(home)
        protected = {"host": m.protected_inventory(INPUTS / "host"),
                     "mods": m.protected_inventory(INPUTS / "mods"), "user": mod_manifest.sha(user)}
        saved = {"active": [active[0].decode(), active[1]], "protected": protected, "official": official,
                 "writable": writable, "global_path": str(global_path), "path_before": path_before, "frozen": frozen,
                 "runtime_environment": {"glibc": os.confstr("CS_GNU_LIBC_VERSION"),
                     "machine": os.uname().machine, "kernel": os.uname().release,
                     "cpuinfo": Path("/proc/cpuinfo").read_text()}}
        mod_manifest.write(EVIDENCE / "baseline.json", saved)
        if stage == "prepare":
            return
    else:
        assert case == "missing-library" and stage in ("reject", "recover")
        sdk = m.sdk_module()
        saved = mod_manifest.read(EVIDENCE / "baseline.json")
        active = (saved["active"][0].encode(), saved["active"][1])
        protected, official, writable = saved["protected"], saved["official"], saved["writable"]
        global_path, path_before, frozen = Path(saved["global_path"]), saved["path_before"], saved["frozen"]
    if stage != "recover":
        rejected = globals()[runtime_cases.function(case)]()
        mod_manifest.write(EVIDENCE / "rejected.json", rejected)
    else:
        rejected = mod_manifest.read(EVIDENCE / "rejected.json")
    assert m.state(home) == active, "Failed operation changed the successful generation"
    assert mod_manifest.sha(user) == protected["user"]
    assert m.protected_inventory(INPUTS / "host") == protected["host"]
    assert m.protected_inventory(INPUTS / "mods") == protected["mods"]
    assert m.protected_inventory(INPUTS / "official") == official
    assert m.protected_inventory(OFFICIAL_PROFILE) == writable
    if stage == "reject":
        return
    recovered = m.business("recovery", home, sdk)
    after = {"host": m.protected_inventory(INPUTS / "host"), "mods": m.protected_inventory(INPUTS / "mods"),
             "user": mod_manifest.sha(user)}
    assert m.state(home) == active and after == protected
    assert m.protected_inventory(INPUTS / "official") == official
    assert m.protected_inventory(OFFICIAL_PROFILE) == writable
    assert shutil.which("codex", path=str(global_path)) == str(global_path / "codex")
    assert os.environ["PATH"] == path_before and mod_manifest.sha(m.BINARY) == frozen
    mod_manifest.write(EVIDENCE / "protection.json", {"before": protected, "after": after,
        "active_descriptor": active[0].decode(), "generation": active[1],
        "official_before": official, "official_after": m.protected_inventory(INPUTS / "official"),
        "official_profile_before": writable, "official_profile_after": m.protected_inventory(OFFICIAL_PROFILE)})
    row = {"case": case, "rejection": rejected, "recovery": recovered,
           "active_generation_unchanged": True, "user_data_unchanged": True,
           "frozen_inputs_unchanged": True, "official_install_and_profile_unchanged": True}
    runtime_cases.finish("g04", case, ({}, {}, {}, {}, {"transactions": [row]}), REPORTS)


if __name__ == "__main__":
    assert sys.argv[1] == "matrix"
    matrix(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
