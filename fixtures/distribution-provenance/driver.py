#!/usr/bin/env python3
"""S01 atomic cases in the disconnected, compiler-free consumer."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import zipfile

sys.path.insert(0, "/fixture/ci/scripts")
import ci_progress
import distribution_provenance as distribution
import mod_manifest
import runtime_cases

INPUTS = Path("/inputs")
WORK = Path("/work")
PROFILE = Path("/profile")
EVIDENCE = Path("/evidence")
BINARY = INPUTS / "host/bin/codex"
PROOFS = Path("/fixture/s01-proofs")
MATERIALS = INPUTS / "distribution"
POLICY = Path("/fixture") / distribution.POLICY_PATH
BOOTSTRAP = Path("/fixture/s01-bootstrap")
_counter = 0


def report(index, key, value):
    rows = [{} for _ in distribution.REPORTS]
    rows[index] = {key: value}
    return rows


def state(home):
    marker = home / "cm-profile.json"
    if not marker.is_file():
        return None
    raw = marker.read_bytes()
    generation = home / "store/generations" / json.loads(raw)["generation"]
    return raw, distribution.read(generation)


def command(home, *arguments, good=True, metadata=True, binary=BINARY, extra=None):
    global _counter
    _counter += 1
    directory = EVIDENCE / ("command-" + str(_counter))
    directory.mkdir(parents=True)
    argv = [str(binary), "cm", "--home", str(home), *map(str, arguments)]
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(WORK), "CODEX_HOME": str(home),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GH_NO_UPDATE_NOTIFIER": "1",
        "CM_SEAMS_EVENTS": str(directory / "events.jsonl"), "CM_NATIVE_TRACE": str(directory / "native.jsonl"),
        "CM_REPLACEMENT_SENTINEL": str(directory / "constructor"), **(extra or {})}
    result = subprocess.run(argv, env=environment, cwd=WORK, capture_output=True, text=True, timeout=120)
    value = {"command": argv, "return_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
        "payload_sha256": distribution.sha(binary)}
    distribution.write(directory / "result.json", value)
    assert (result.returncode == 0) == good, value
    if metadata:
        assert not any((directory / name).exists() for name in ("events.jsonl", "constructor")), "Installer executed native code"
        assert not (WORK / "install-script-executed").exists(), "Installer executed an attached script"
    return json.loads(result.stdout) if good else value


def install(home, owner="a", *, package=None, receipt=None, bundle=None, good=True):
    return command(home, "install", package or INPUTS / "mods/s01" / owner,
        "--receipt", receipt or PROOFS / "subjects" / ("sdk-" + owner + ".json"),
        "--bundle", bundle or PROOFS / "bundle.jsonl", good=good)


def changed_receipt(name, update):
    value = distribution.read(PROOFS / "subjects/sdk-a.json")
    update(value)
    path = WORK / (name + ".json")
    distribution.write(path, value)
    return path


def verified_subject(name, *, helper=None, roots=None, good=True):
    helper = helper or BOOTSTRAP / "gh"
    roots = roots or BOOTSTRAP / "distribution-root.jsonl"
    receipt = PROOFS / "subjects" / (name + ".json")
    value = distribution.read(receipt)
    policy = distribution.read(POLICY)
    args = [str(helper), "attestation", "verify", str(receipt), "--bundle", str(PROOFS / "bundle.jsonl"),
        "--custom-trusted-root", str(roots), "--repo", policy["builder_repository"],
        "--signer-workflow", policy["builder_repository"] + "/" + policy["workflow"],
        "--cert-identity", "https://github.com/" + policy["builder_repository"] + "/" + policy["workflow"] + "@" + policy["ref"],
        "--cert-oidc-issuer", policy["issuer"], "--source-ref", policy["ref"],
        "--source-digest", value["signer"]["workflow_sha"], "--signer-digest", value["signer"]["workflow_sha"],
        "--deny-self-hosted-runners", "--format", "json"]
    result = subprocess.run(args, env={"PATH": "/nonexistent", "HOME": "/nonexistent", "GH_CONFIG_DIR": "/nonexistent",
        "GH_NO_UPDATE_NOTIFIER": "1", "GH_PROMPT_DISABLED": "1"}, capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == good, (args, result.stderr)
    if not good:
        return {"return_code": result.returncode}
    rows = json.loads(result.stdout)
    assert 0 < len(rows) <= 8
    for row in rows:
        verified = row["verificationResult"]
        assert verified["signature"]["certificate"]["sourceRepositoryIdentifier"] == str(policy["builder_repository_id"])
        assert verified["verifiedTimestamps"]
        statement = verified["statement"]
        assert statement["predicateType"] == policy["predicate_type"]
        assert any(item["digest"].get("sha256") == distribution.sha(receipt) for item in statement["subject"])
        assert statement["predicate"]["runDetails"]["metadata"]["invocationId"] == (
            "https://github.com/" + policy["builder_repository"] + "/actions/runs/" +
            str(value["signer"]["run_id"]) + "/attempts/" + str(value["signer"]["attempt"]))
    return {"receipt_sha256": distribution.sha(receipt), "verified": rows}


def current_verification():
    """Always real, even when compatible behavior checkpoints are restored."""
    policy = distribution.read(POLICY)
    bootstrap = distribution.read(BOOTSTRAP / "identity.json")
    assert bootstrap["archive_sha256"] == policy["verifier"]["archive_sha256"]
    assert distribution.sha(BOOTSTRAP / "gh") == bootstrap["binary_sha256"]
    assert distribution.sha(BOOTSTRAP / "distribution-root.jsonl") == distribution.sha(Path("/fixture") / distribution.ROOT_PATH)
    producer = distribution.validate_materials(MATERIALS, policy)
    values = {}
    # This is deliberately before the first candidate Host execution.
    for name in producer["artifacts"]:
        values[name] = verified_subject(name)
        receipt = distribution.read(PROOFS / "subjects" / (name + ".json"))
        draft = distribution.read(MATERIALS / name / "draft.json")
        assert {key: receipt[key] for key in draft if key != "production_origin"} == {
            key: value for key, value in draft.items() if key != "production_origin"}
        for key, value in draft["production_origin"].items():
            assert receipt["production_origin"][key] == value
        directory = INPUTS / producer["artifacts"][name]["directory"]
        for row in distribution.read(MATERIALS / name / "assets.json"):
            path = directory / row["path"]
            actual = hashlib.sha256(os.readlink(path).encode()).hexdigest() if path.is_symlink() else distribution.sha(path)
            assert actual == row["sha256"], "Signed asset differs from consumer bytes"
    distribution.write(Path("/evidence/s01-current-verification.json"), values)
    return values


def case_identity():
    values = {name: verified_subject(name) for name in ("cm-host", "sdk-a", "sdk-b")}
    schema = distribution.read(Path("/fixture/schemas/release-receipt.schema.json"))
    assert schema["additionalProperties"] is False
    assert set(distribution.read(PROOFS / "subjects/sdk-a.json")) == set(schema["required"])
    before = state(PROFILE)
    results = []
    for key, bad in (("repository_id", 1), ("repository", "DSLZL/renamed")):
        path = changed_receipt("source-" + key, lambda value: value["source"].update({key: bad}))
        results.append(install(PROFILE, receipt=path, good=False))
    for key, bad in (("repository_id", 1), ("workflow", ".github/workflows/other.yml"), ("workflow_sha", "0" * 40)):
        path = changed_receipt("signer-" + key, lambda value: value["signer"].update({key: bad}))
        results.append(install(PROFILE, receipt=path, good=False))
    assert state(PROFILE) == before
    return report(0, "fixed_first_party_identity", {"verified": values, "rejections": results})


def case_independent():
    frozen = distribution.sha(BINARY)
    install(PROFILE)
    install(PROFILE, "b")
    old = state(PROFILE)[1]
    assert set(old["provenance"]) == {"sdk-a", "sdk-b"}
    command(PROFILE, "enable", "sdk-a")
    command(PROFILE, "enable", "sdk-b")
    combined = command(PROFILE, "doctor")
    command(PROFILE, "disable", "sdk-a")
    command(PROFILE, "remove", "sdk-a")
    current = state(PROFILE)[1]
    assert set(current["provenance"]) == {"sdk-b"}
    assert current["installed"]["sdk-b"] == old["installed"]["sdk-b"] and distribution.sha(BINARY) == frozen
    return report(0, "independent_objects_and_combination_lock", {"before": old, "after": current, "doctor": combined})


def case_inventory():
    value = distribution.validate_materials(MATERIALS, distribution.read(POLICY))
    notice = distribution.read(MATERIALS / "cm-host/NOTICE.json")
    assert any(row["name"] == "gh" for row in notice["components"])
    assert any("verifier-static-component" in row["roles"] for row in notice["components"])
    assert notice["native_licenses"] and notice["system_runtime_libraries"]
    for row in notice["components"]:
        for license in row["licenses"]:
            path = INPUTS / "host/licenses/components" / license["path"]
            assert distribution.sha(path) == license["sha256"]
    return report(1, "actual_assets_and_license_texts", value)


def case_materials():
    failures = []
    for name in ("sbom.spdx.json", "NOTICE.json", "source.json", "assets.json"):
        directory = WORK / name
        shutil.copytree(MATERIALS, directory)
        (directory / "sdk-a" / name).unlink()
        try:
            distribution.validate_materials(directory, distribution.read(POLICY))
        except (AssertionError, OSError):
            failures.append(name)
        else:
            raise AssertionError("Missing material accepted: " + name)
    for kind in ("unknown-license", "missing-text", "unknown-source", "unknown-component"):
        directory = WORK / kind
        shutil.copytree(MATERIALS, directory)
        material = directory / "sdk-a"
        notice = distribution.read(material / "NOTICE.json")
        if kind == "unknown-license":
            notice["components"][0]["declared_license"] = "UNKNOWN"
        elif kind == "missing-text":
            notice["license_texts"].clear()
        elif kind == "unknown-source":
            notice["components"][0]["source"] = ""
        else:
            notice["assets"][0]["components"] = ["SPDXRef-Package-unknown"]
            distribution.write(material / "assets.json", notice["assets"])
        distribution.write(material / "NOTICE.json", notice)
        draft = distribution.read(material / "draft.json")
        draft["materials"]["notice"] = distribution.sha(material / "NOTICE.json")
        distribution.write(material / "draft.json", draft)
        producer = distribution.read(directory / "producer.json")
        producer["artifacts"]["sdk-a"]["draft_sha256"] = distribution.sha(material / "draft.json")
        distribution.write(directory / "producer.json", producer)
        try:
            distribution.validate_materials(directory, distribution.read(POLICY))
        except (AssertionError, KeyError):
            failures.append(kind)
        else:
            raise AssertionError("Incomplete rehashed materials accepted: " + kind)
    return report(1, "missing_materials_cannot_be_signed", failures)


def case_source():
    closure = distribution.read(MATERIALS / "cm-host/source.json")
    source = closure["source"]
    assert source["upstream_commit"] and source["upstream_tree"] and source["overlay"] and source["cm_patch_sha256"]
    assert source["original_lock_sha256"] and source["host_lock_sha256"]
    assert closure["upstream_original_manifest"] and closure["upstream_final_manifest"]
    for name in ("sdk-a", "sdk-b"):
        value = distribution.read(MATERIALS / name / "source.json")
        assert value["author"]["origin"] and value["author"]["inputs"] and value["author"]["host_linked"] is False
    return report(2, "exact_source_and_build_material_roles", {"source": source, "native": closure["native"],
        "verifier_pin": closure["verifier"]["pin"]})


def case_install_boundary():
    install(PROFILE)
    command(PROFILE, "list")
    command(PROFILE, "doctor")
    source = INPUTS / "mods/s01/a"
    assert all((source / name).is_file() for name in ("build.rs", "proc-macro.rs", "post-install.sh"))
    assert not (WORK / "install-script-executed").exists()
    assert not (WORK / "proc-macro-executed").exists()
    return report(2, "source_attachments_are_inert_data", {"object": state(PROFILE)[1]["installed"], "installer_builds": 0})


def case_proof():
    bad = WORK / "bad-bundle.jsonl"
    results = []
    for data in (b"", b"{}", (PROOFS / "bundle.jsonl").read_bytes()[:-8], b"x" * (2 * 1024 * 1024 + 1)):
        bad.write_bytes(data)
        results.append(install(PROFILE, bundle=bad, good=False))
        assert state(PROFILE) is None
    path = changed_receipt("unknown-schema", lambda row: row.update(schema_version=2))
    results.append(install(PROFILE, receipt=path, good=False))
    return report(3, "invalid_or_missing_signature_never_falls_back", results)


def case_stale():
    source = WORK / "changed"
    shutil.copytree(INPUTS / "mods/s01/a", source)
    with (source / "payload.so").open("ab") as stream:
        stream.write(b"changed")
    fields = tomllib.loads((source / "mod.toml").read_text())
    fields["binary"].update(size=(source / "payload.so").stat().st_size, sha256=distribution.sha(source / "payload.so"))
    mod_manifest.manifest(source, fields)
    rejected = install(PROFILE, package=source, good=False)
    wrong = install(PROFILE, receipt=PROOFS / "subjects/sdk-b.json", good=False)
    install(PROFILE)
    accepted = command(PROFILE, "list")
    return report(3, "old_proof_new_bytes_and_wrong_object", {"changed": rejected, "other": wrong, "original": accepted})


def case_digests():
    values = {}
    for owner in ("a", "b"):
        name = "sdk-" + owner
        receipt = distribution.read(PROOFS / "subjects" / (name + ".json"))
        archive = INPUTS / "mods/s01" / (owner + ".cmod")
        assert distribution.sha(archive) == receipt["artifact"]["archive_sha256"]
        assert archive.stat().st_size == receipt["artifact"]["archive_size"]
        assert distribution.object_identity(INPUTS / "mods/s01" / owner) == receipt["artifact"]["object_sha256"]
        install(PROFILE / owner, owner, package=archive)
        values[name] = receipt["artifact"]
    repacked = WORK / "repacked.cmod"
    shutil.copyfile(INPUTS / "mods/s01/a.cmod", repacked)
    with zipfile.ZipFile(repacked, "a") as archive:
        archive.comment = b"same objects, different raw archive"
    assert distribution.sha(repacked) != values["sdk-a"]["archive_sha256"]
    rejected = install(PROFILE / "repacked", package=repacked, good=False)
    values["repacked_archive_rejected"] = rejected
    return report(3, "raw_archive_object_manifest_payload_are_distinct", values)


def case_compatibility():
    verified = verified_subject("sdk-a")
    old = INPUTS / "upgrade-baseline/host/bin/codex"
    assert old.is_file() and distribution.sha(old) != distribution.sha(BINARY)
    incompatible = command(PROFILE / "old-host", "install", INPUTS / "mods/s01/a", binary=old, good=False)
    assert any(word in incompatible["stderr"].lower() for word in ("compat", "abi", "capability", "host api")), incompatible
    install(PROFILE)
    before = state(PROFILE)
    source = WORK / "bad-abi"
    shutil.copytree(INPUTS / "mods/s01/b", source)
    fields = tomllib.loads((source / "mod.toml").read_text())
    fields["compat"]["abi_major"] = 99
    mod_manifest.manifest(source, fields)
    rejected = install(PROFILE, "b", package=source, good=False)
    assert state(PROFILE) == before
    return report(3, "integrity_provenance_abi_are_separate_gates", {
        "real_signature": verified, "old_host_incompatible": incompatible, "invalid_abi": rejected})


def case_no_op():
    install(PROFILE)
    before = state(PROFILE)
    path = changed_receipt("no-op", lambda value: value.update(policy_sha256="0" * 64))
    rejected = install(PROFILE, receipt=path, good=False)
    assert state(PROFILE) == before
    install(PROFILE)
    paired = command(PROFILE, "install", INPUTS / "mods/s01/a", "--receipt", path, good=False)
    assert state(PROFILE) == before
    return report(3, "no_op_and_cas_do_not_bypass_proof", {"bad": rejected, "paired": paired})


def case_transaction():
    install(PROFILE)
    before = state(PROFILE)
    failures = []
    for relative in ("store/objects", "store/generations"):
        directory = PROFILE / relative
        mode = directory.stat().st_mode & 0o777
        directory.chmod(0o500)
        try:
            result = install(PROFILE, "b", good=False)
            assert state(PROFILE) == before
            failures.append(result)
        finally:
            directory.chmod(mode)
    command(PROFILE, "doctor")
    return report(3, "proof_association_is_transactional", failures)


def case_legacy():
    command(PROFILE, "install", INPUTS / "mods/s01/a")
    value = command(PROFILE, "list")
    assert value["mods"]["sdk-a"]["distribution"]["status"] == "unverified_provenance"
    install(PROFILE)
    assert command(PROFILE, "list")["mods"]["sdk-a"]["distribution"]["status"] == "verified_provenance"
    command(PROFILE, "scan")
    assert state(PROFILE)[1]["provenance"]["sdk-a"]
    accepted = state(PROFILE)
    previous_generation = json.loads(accepted[0])["generation"]
    replacement = WORK / "development-replacement"
    shutil.copytree(INPUTS / "mods/s01/a", replacement)
    (replacement / "development-data.txt").write_text("different object, same native payload")
    command(PROFILE, "replace", "sdk-a", replacement, "--from", accepted[1]["installed"]["sdk-a"])
    assert "sdk-a" not in state(PROFILE)[1].get("provenance", {})
    assert command(PROFILE, "list")["mods"]["sdk-a"]["distribution"]["status"] == "unverified_provenance"
    command(PROFILE, "rollback", previous_generation)
    restored = command(PROFILE, "list")
    assert restored["mods"]["sdk-a"]["distribution"]["status"] == "verified_provenance"
    return report(3, "development_packages_and_explicit_promotion", {"legacy": value, "rollback": restored})


def case_bootstrap():
    value = verified_subject("cm-host")
    bad_root = WORK / "roots.jsonl"
    bad_root.write_text("{}")
    rejected = verified_subject("cm-host", roots=bad_root, good=False)
    assert distribution.sha(BINARY) == distribution.read(PROOFS / "subjects/cm-host.json")["artifact"]["payload_sha256"]
    return report(4, "independent_bootstrap_before_candidate_execution", {"verified": value, "bad_root": rejected})


def case_offline():
    install(PROFILE)
    command(PROFILE, "enable", "sdk-a")
    value = command(PROFILE, "run", "sdk-a__hello", metadata=False)
    assert "author-v1" in value["text"]
    events = [json.loads(line) for path in EVIDENCE.glob("command-*/events.jsonl") for line in path.read_text().splitlines()]
    assert sum(row["event"] == "constructor" for row in events) == 1
    assert any(row["event"] == "init" for row in events)
    rows = [distribution.read(path) for path in EVIDENCE.glob("command-*/result.json")]
    assert all(row["payload_sha256"] == distribution.sha(BINARY) for row in rows)
    document = Path("/fixture/docs/distribution.md").read_text()
    assert all(word in document for word in ("native", "M04", "bootstrap", "offline", "CM"))
    return report(4, "offline_prebuilt_install_and_explicit_native_load", {"run": value, "events": events, "compiler_calls": 0})


def case_failure_boundary():
    authority = distribution.read(PROOFS / "authority.json")
    assert authority["candidate_only"] is True and authority["consumer_acceptance"] == "not_run"
    install(PROFILE)
    before = state(PROFILE)
    bad = WORK / "wrong.json"
    bad.write_text("{}")
    rejected = install(PROFILE, receipt=bad, good=False)
    assert state(PROFILE) == before
    return report(4, "candidate_signature_cannot_accept_failed_consumer", {"authority": authority, "rejection": rejected})


@ci_progress.case()
def matrix(case):
    runtime_cases.enter(globals(), "s01", case)
    WORK.mkdir(parents=True)
    EVIDENCE.mkdir(parents=True)
    value = globals()[runtime_cases.function(case, "s01")]()
    runtime_cases.finish("s01", case, value, distribution.REPORTS)


if __name__ == "__main__":
    if sys.argv[1:] == ["verify-current"]:
        current_verification()
    else:
        assert len(sys.argv) == 3 and sys.argv[1] == "matrix"
        matrix(sys.argv[2])
