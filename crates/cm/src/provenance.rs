//! Offline provenance is independent of package integrity, ABI and state compatibility.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::LoadError;
use crate::loader::{self, InputPin, InstallationSnapshot};

const LIMIT: u64 = 2 * 1024 * 1024;
const POLICY: &str = include_str!("distribution-policy.json");
const ROOT: &[u8] = include_bytes!("distribution-root.jsonl");

fn failure(message: &str) -> LoadError {
    LoadError::input("distribution_provenance", "", message)
}

fn sha(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    repository: String,
    repository_id: u64,
    sha: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signer {
    repository: String,
    repository_id: u64,
    workflow: String,
    workflow_sha: String,
    run_id: u64,
    attempt: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    archive_sha256: String,
    archive_size: u64,
    object_sha256: String,
    manifest_sha256: String,
    payload_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    domain: String,
    role: String,
    name: String,
    version: String,
    target: String,
    source: Source,
    signer: Signer,
    production_origin: Value,
    artifact: Artifact,
    contracts: Value,
    materials: BTreeMap<String, String>,
    policy_sha256: String,
}

/// The evidence bytes are stored in the immutable generation, never a trusted boolean.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proof {
    pub object_sha256: String,
    receipt: String,
    bundle: String,
}

fn receipt(bytes: &[u8]) -> Result<Receipt, LoadError> {
    if bytes.len() > 256 * 1024 {
        return Err(failure("receipt exceeds bound"));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| failure("invalid receipt JSON"))?;
    if crate::config::json_bytes(&value) != bytes {
        return Err(failure(
            "receipt is not canonical JSON or has duplicate keys",
        ));
    }
    let parsed: Receipt = serde_json::from_value(value)
        .map_err(|_| failure("unknown receipt fields or invalid types"))?;
    let policy: Value = serde_json::from_str(POLICY).expect("embedded distribution policy");
    if parsed.schema_version != 1
        || parsed.domain != "cm.release-receipt.v1"
        || !["host", "mod"].contains(&parsed.role.as_str())
        || parsed.name.is_empty()
        || parsed.name.len() > 128
        || parsed.version.is_empty()
        || parsed.version.len() > 128
        || parsed.target != loader::TARGET
        || Some(parsed.source.repository.as_str()) != policy["source_repository"].as_str()
        || Some(parsed.source.repository_id) != policy["source_repository_id"].as_u64()
        || !sha(&parsed.source.sha, 40)
        || Some(parsed.signer.repository.as_str()) != policy["builder_repository"].as_str()
        || Some(parsed.signer.repository_id) != policy["builder_repository_id"].as_u64()
        || Some(parsed.signer.workflow.as_str()) != policy["workflow"].as_str()
        || !sha(&parsed.signer.workflow_sha, 40)
        || parsed.signer.run_id == 0
        || parsed.signer.attempt == 0
        || parsed.policy_sha256 != loader::hash(POLICY.as_bytes())
        || parsed.artifact.archive_size == 0
        || !loader::digest(&parsed.artifact.archive_sha256)
        || !loader::digest(&parsed.artifact.object_sha256)
        || !loader::digest(&parsed.artifact.manifest_sha256)
        || !loader::digest(&parsed.artifact.payload_sha256)
        || parsed
            .production_origin
            .as_object()
            .is_none_or(|v| v.is_empty())
        || !parsed.contracts.is_object()
        || parsed.materials.len() != 3
        || ["sbom", "notice", "source"].iter().any(|name| {
            parsed
                .materials
                .get(*name)
                .is_none_or(|v| !loader::digest(v))
        })
    {
        return Err(failure("receipt violates the fixed distribution policy"));
    }
    Ok(parsed)
}

fn parent_path(file: &File) -> PathBuf {
    format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd()).into()
}

fn output(mut stream: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut stream).take(LIMIT + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn collect_verifier(mut child: Child, timeout: Duration) -> Result<Vec<u8>, LoadError> {
    let process_group = child.id() as libc::pid_t;
    let stdout = child.stdout.take().expect("piped verifier stdout");
    let stderr = child.stderr.take().expect("piped verifier stderr");
    let out = std::thread::spawn(move || output(stdout));
    let err = std::thread::spawn(move || output(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                // Descendants must not retain the pipes beyond the verifier deadline.
                unsafe { libc::kill(-process_group, libc::SIGKILL) };
                let _ = child.wait();
                break None;
            }
        }
    };
    unsafe { libc::kill(-process_group, libc::SIGKILL) };
    let stdout = out
        .join()
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| failure("verifier output failed"))?;
    let stderr = err
        .join()
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| failure("verifier diagnostics failed"))?;
    if status.is_none_or(|s| !s.success())
        || stdout.len() as u64 > LIMIT
        || stderr.len() as u64 > LIMIT
    {
        return Err(failure(
            "offline signature verification failed or timed out",
        ));
    }
    Ok(stdout)
}

fn verify_signature(bytes: &[u8], bundle: &[u8], signer: &Signer) -> Result<InputPin, LoadError> {
    if bundle.is_empty() || bundle.len() as u64 > LIMIT {
        return Err(failure("missing or oversized proof bundle"));
    }
    let executable =
        std::fs::canonicalize("/proc/self/exe").map_err(|_| failure("missing Host identity"))?;
    let root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| failure("missing Host package"))?;
    let (helper, pin) = loader::read_input(&root.join("codex-resources/gh"), 128 * 1024 * 1024)
        .map_err(|_| failure("missing trusted verifier"))?;
    if option_env!("CM_DISTRIBUTION_GH_SHA256") != Some(pin.sha256.as_str()) {
        return Err(failure("verifier differs from the compiled Host pin"));
    }
    // Reuse sealed snapshots so exec and verifier inputs cannot reopen replaced candidate bytes.
    let helper = loader::sealed_named_snapshot(&helper, c"cm-distribution-verifier")
        .map_err(|_| failure("cannot pin verifier"))?;
    let subject = loader::sealed_snapshot(bytes).map_err(|_| failure("cannot pin receipt"))?;
    let bundle = loader::sealed_snapshot(bundle).map_err(|_| failure("cannot pin bundle"))?;
    let roots = loader::sealed_snapshot(ROOT).map_err(|_| failure("cannot pin roots"))?;
    let child = Command::new(parent_path(&helper))
        .args(["attestation", "verify"])
        .arg(parent_path(&subject))
        .arg("--bundle")
        .arg(parent_path(&bundle))
        .arg("--custom-trusted-root")
        .arg(parent_path(&roots))
        .args([
            "--repo",
            "DSLZL/CM-build-linux-x64",
            "--cert-identity",
            "https://github.com/DSLZL/CM-build-linux-x64/.github/workflows/build.yml@refs/heads/main",
            "--cert-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--source-ref",
            "refs/heads/main",
            "--source-digest",
            &signer.workflow_sha,
            "--signer-digest",
            &signer.workflow_sha,
            "--deny-self-hosted-runners",
            "--format",
            "json",
        ])
        .env_clear()
        .env("PATH", "/nonexistent")
        .env("HOME", "/nonexistent")
        .env("GH_CONFIG_DIR", "/nonexistent")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_PROMPT_DISABLED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| failure("cannot start trusted verifier"))?;
    let stdout = collect_verifier(child, Duration::from_secs(20))?;
    verify_output(&stdout, bytes, signer)?;
    pin.revalidate()
        .map_err(|_| failure("trusted verifier input changed"))?;
    Ok(pin)
}

fn verify_output(stdout: &[u8], bytes: &[u8], signer: &Signer) -> Result<(), LoadError> {
    let results: Vec<Value> =
        serde_json::from_slice(stdout).map_err(|_| failure("invalid verifier output"))?;
    if results.is_empty() || results.len() > 8 {
        return Err(failure("unexpected verifier result count"));
    }
    let invocation = format!(
        "https://github.com/DSLZL/CM-build-linux-x64/actions/runs/{}/attempts/{}",
        signer.run_id, signer.attempt
    );
    let subject = loader::hash(bytes);
    for row in results {
        let result = &row["verificationResult"];
        if result["signature"]["certificate"]["sourceRepositoryIdentifier"] != "1430833977"
            || result["verifiedTimestamps"]
                .as_array()
                .is_none_or(|v| v.is_empty())
            || result["statement"]["predicateType"] != "https://slsa.dev/provenance/v1"
            || result["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"]
                != invocation
            || result["statement"]["subject"]
                .as_array()
                .is_none_or(|subjects| {
                    subjects.len() > 256
                        || !subjects.iter().any(|s| s["digest"]["sha256"] == subject)
                })
        {
            return Err(failure(
                "verified certificate, timestamp or subject violates policy",
            ));
        }
    }
    Ok(())
}

impl Proof {
    pub(crate) fn capture(
        snapshot: &InstallationSnapshot,
        receipt_path: &Path,
        bundle_path: &Path,
    ) -> Result<(Self, Vec<InputPin>), LoadError> {
        let receipt_path =
            std::path::absolute(receipt_path).map_err(|_| failure("invalid receipt path"))?;
        let bundle_path =
            std::path::absolute(bundle_path).map_err(|_| failure("invalid bundle path"))?;
        let (receipt, receipt_pin) = loader::read_input(&receipt_path, 256 * 1024)
            .map_err(|_| failure("cannot read receipt"))?;
        let (bundle, bundle_pin) =
            loader::read_input(&bundle_path, LIMIT).map_err(|_| failure("cannot read bundle"))?;
        let proof = Self {
            object_sha256: snapshot.sha256.clone(),
            receipt: String::from_utf8(receipt).map_err(|_| failure("receipt must be UTF8"))?,
            bundle: String::from_utf8(bundle).map_err(|_| failure("bundle must be UTF8"))?,
        };
        let verifier_pin = proof.verify(snapshot)?;
        let mut pins = snapshot.pins.clone();
        pins.extend([receipt_pin, bundle_pin, verifier_pin]);
        Ok((proof, pins))
    }

    fn verify(&self, snapshot: &InstallationSnapshot) -> Result<InputPin, LoadError> {
        let parsed = receipt(self.receipt.as_bytes())?;
        let manifest = crate::manifest::parse(&snapshot.files["mod.toml"])?;
        if parsed.role != "mod"
            || parsed.name != snapshot.id
            || parsed.version != manifest.version
            || self.object_sha256 != snapshot.sha256
            || parsed.artifact.object_sha256 != snapshot.sha256
            || parsed.artifact.manifest_sha256 != loader::hash(&snapshot.files["mod.toml"])
            || parsed.artifact.payload_sha256 != loader::hash(&snapshot.files[&manifest.payload])
            || snapshot.archive.as_ref().is_some_and(|(size, hash)| {
                parsed.artifact.archive_size != *size || parsed.artifact.archive_sha256 != *hash
            })
        {
            return Err(failure("receipt does not describe these exact Mod bytes"));
        }
        verify_signature(
            self.receipt.as_bytes(),
            self.bundle.as_bytes(),
            &parsed.signer,
        )
    }

    pub(crate) fn summary(&self) -> Value {
        json!({"status":"verified_provenance", "object_sha256":self.object_sha256,
            "receipt_sha256":loader::hash(self.receipt.as_bytes()),
            "bundle_sha256":loader::hash(self.bundle.as_bytes()), "native_sandbox":false})
    }
}

pub(crate) fn verify_generation(
    home: &Path,
    generation: &crate::profile::Generation,
) -> Result<Vec<InputPin>, LoadError> {
    let mut pins = Vec::new();
    for (id, proof) in &generation.provenance {
        if generation.installed.get(id) != Some(&proof.object_sha256) {
            return Err(failure("provenance association is stale"));
        }
        let snapshot =
            loader::installation_snapshot(&home.join("store/objects").join(&proof.object_sha256))?;
        pins.push(proof.verify(&snapshot)?);
        pins.extend(snapshot.pins);
    }
    Ok(pins)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer {
            repository: "DSLZL/CM-build-linux-x64".into(),
            repository_id: 1430833977,
            workflow: ".github/workflows/build.yml".into(),
            workflow_sha: "a".repeat(40),
            run_id: 1,
            attempt: 2,
        }
    }

    #[test]
    fn verifier_output_requires_all_verified_identity_fields() {
        let bytes = b"subject bytes";
        let row = json!({"verificationResult": {
            "signature": {"certificate": {"sourceRepositoryIdentifier": "1430833977"}},
            "verifiedTimestamps": [{"type": "unit-parser-fixture"}],
            "statement": {"predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"runDetails": {"metadata": {"invocationId":
                    "https://github.com/DSLZL/CM-build-linux-x64/actions/runs/1/attempts/2"}}},
                "subject": [{"digest": {"sha256": loader::hash(bytes)}}]}}});
        assert!(
            verify_output(
                &serde_json::to_vec(&vec![row.clone()]).unwrap(),
                bytes,
                &signer()
            )
            .is_ok()
        );
        for pointer in [
            "/verificationResult/signature/certificate/sourceRepositoryIdentifier",
            "/verificationResult/verifiedTimestamps",
            "/verificationResult/statement/predicateType",
            "/verificationResult/statement/predicate/runDetails/metadata/invocationId",
            "/verificationResult/statement/subject",
        ] {
            let mut invalid = row.clone();
            *invalid.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                verify_output(
                    &serde_json::to_vec(&vec![invalid]).unwrap(),
                    bytes,
                    &signer()
                )
                .is_err()
            );
        }
        for invalid in [
            b"{}".as_slice(),
            b"[]".as_slice(),
            b"[null]".as_slice(),
            b"truncated".as_slice(),
        ] {
            assert!(verify_output(invalid, bytes, &signer()).is_err());
        }
        assert!(
            verify_output(
                &serde_json::to_vec(&vec![row; 9]).unwrap(),
                bytes,
                &signer()
            )
            .is_err()
        );
        assert!(verify_signature(bytes, b"", &signer()).is_err());
        assert!(verify_signature(bytes, &vec![0; LIMIT as usize + 1], &signer()).is_err());
    }

    #[test]
    fn verifier_failure_timeout_and_output_limits_fail_closed() {
        for script in [
            "printf rejected >&2; exit 3",
            "exec sleep 60",
            "sleep 60 & wait",
            "head -c 2097153 /dev/zero",
        ] {
            let child = Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap();
            assert!(collect_verifier(child, Duration::from_millis(100)).is_err());
        }
    }

    #[test]
    fn noncanonical_duplicate_and_unknown_receipts_are_not_trusted() {
        for bytes in [
            br#"{"schema_version":1,"schema_version":1}"#.as_slice(),
            br#"{"schema_version":1,"unrecognized":true}"#.as_slice(),
            b"{}".as_slice(),
        ] {
            assert!(receipt(bytes).is_err());
        }
    }

    #[test]
    fn empty_legacy_generation_keeps_its_original_bytes() {
        let value = crate::profile::canonical(&crate::profile::Generation::default());
        assert!(!String::from_utf8(value).unwrap().contains("provenance"));
    }
}
