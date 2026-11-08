//! Signed first-party binary discovery. Metadata and CAS writes never activate a generation.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::profile::{Directory, Transaction};
use crate::{
    LoadError, config, loader, mod_install, mod_lock, package, profile, provenance, runtime_plan,
};

const INDEX_LIMIT: u64 = 4 * 1024 * 1024;
const PROOF_LIMIT: u64 = 2 * 1024 * 1024;
const PLAN_LIMIT: u64 = 256 * 1024;
const TRANSFER_LIMIT: u64 = 512 * 1024 * 1024;
const NAMESPACE: &str = "github:1430833890";

pub enum Resource<'a> {
    Index,
    IndexBundle,
    Artifact(&'a str),
}

/// The CLI owns HTTP/file transport; the runtime owns signatures, identities and installation.
pub trait Transport {
    fn fetch(
        &mut self,
        resource: Resource<'_>,
        limit: u64,
    ) -> impl Future<Output = Result<Vec<u8>, LoadError>>;
}

pub fn read_transport_file(path: &Path, limit: u64) -> Result<Vec<u8>, LoadError> {
    let (bytes, pin) = loader::read_input(path, limit)
        .map_err(|_| failure("index_source", "unsafe or missing file transport input"))?;
    pin.revalidate()
        .map_err(|_| failure("input_drift", "file transport input changed"))?;
    Ok(bytes)
}

pub enum Command<'a> {
    List,
    Plan {
        selections: &'a [String],
        output: &'a Path,
    },
    Install {
        plan: &'a Path,
    },
}

fn failure(code: &str, text: &str) -> LoadError {
    LoadError::input(code, "", text)
}

fn reject(record: &Record, code: &str, text: &str) -> LoadError {
    let mut error = LoadError::input(code, &record.id, text);
    error.field = Some(format!("records.{}", record.record_id));
    error
}

fn record_error(record: &Record, mut error: LoadError) -> LoadError {
    if error.mod_id.is_none() {
        error.mod_id = Some(record.id.clone());
    }
    let field = error.field.get_or_insert_with(|| "input".into());
    if ![
        "records.",
        "compat.",
        "binary.",
        "dependencies",
        "state",
        "provenance",
    ]
    .iter()
    .any(|prefix| field.starts_with(prefix))
    {
        *field = format!("records.{}.{field}", record.record_id);
    }
    error
}

fn parse<T: DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T, LoadError> {
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(failure("index_envelope", "JSON byte limit"));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| failure("index_envelope", "invalid JSON"))?;
    // This also rejects duplicate keys, whitespace and alternate number spellings.
    if config::json_bytes(&value) != bytes {
        return Err(failure("index_envelope", "canonical JSON required"));
    }
    serde_json::from_value(value).map_err(|_| failure("index_envelope", "invalid closed schema"))
}

fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn ci_request_id(value: &str) -> bool {
    text(value, 128)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || [4, 7].iter().any(|&at| bytes[at] != b'-')
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(at, byte)| ![4, 7, 10, 13, 16, 19].contains(&at) && !byte.is_ascii_digit())
    {
        return false;
    }
    let number = |start: usize, end: usize| value[start..end].parse::<u32>().unwrap_or(0);
    let year = number(0, 4);
    let month = number(5, 7);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year >= 1970
        && number(8, 10) > 0
        && number(8, 10) <= days
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
}

fn relative(value: &str) -> bool {
    value.is_ascii()
        && value.len() <= 512
        && !value.is_empty()
        && value.split('/').count() <= 16
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: String,
    size: u64,
    sha256: String,
}

impl Reference {
    fn valid(&self, limit: u64) -> bool {
        relative(&self.path) && self.size > 0 && self.size <= limit && loader::digest(&self.sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    statement: Reference,
    bundle: Reference,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    kind: crate::manifest::ModKind,
    binary: crate::manifest::Binary,
    compat: crate::manifest::Compatibility,
    dependencies: Vec<loader::Dependency>,
    conflicts: Vec<String>,
    state: Option<crate::manifest::State>,
}

impl Declaration {
    fn valid(&self) -> bool {
        let binary = &self.binary;
        let compat = &self.compat;
        relative(&binary.path)
            && binary.size > 0
            && binary.size <= loader::MAX_PAYLOAD
            && loader::digest(&binary.sha256)
            && loader::identifier(&binary.entry)
            && binary.entry.len() <= 128
            && binary.cpu == "x86-64"
            && text(&binary.glibc_min, 16)
            && binary
                .glibc_min
                .split_once('.')
                .is_some_and(|(a, b)| a.parse::<u32>().is_ok() && b.parse::<u32>().is_ok())
            && compat.abi_major > 0
            && compat.abi_minor_min <= compat.abi_minor_max
            && text(&compat.host_api_min, 128)
            && semver::Version::parse(&compat.host_api_min).is_ok()
            && !compat.required_capabilities.is_empty()
            && compat.required_capabilities.len() <= 8
            && compat
                .required_capabilities
                .iter()
                .all(|v| loader::identifier(v) && v.len() <= 128)
            && compat
                .required_capabilities
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == compat.required_capabilities.len()
            && compat.exact_host.as_ref().is_none_or(|v| {
                v.build_id
                    .strip_prefix("sha256:")
                    .is_some_and(loader::digest)
                    && loader::digest(&v.executable_sha256)
                    && v.patch_map_sha256
                        .as_ref()
                        .is_none_or(|v| loader::digest(v))
            })
            && self.dependencies.len() <= 32
            && self.dependencies.iter().all(|v| {
                loader::identifier(&v.id)
                    && v.id.len() <= 128
                    && text(&v.version, 128)
                    && semver::VersionReq::parse(&v.version).is_ok()
            })
            && self.conflicts.len() <= 32
            && self
                .conflicts
                .iter()
                .all(|v| loader::identifier(v) && v.len() <= 128)
            && self.state.as_ref().is_none_or(|v| {
                loader::identifier(&v.owner)
                    && v.owner.len() <= 128
                    && loader::identifier(&v.schema)
                    && v.schema.len() <= 128
                    && v.version > 0
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    record_id: String,
    namespace: String,
    publisher: String,
    id: String,
    version: String,
    display_name: String,
    cargo_package: String,
    target: String,
    status: String,
    archive: Reference,
    object_sha256: String,
    manifest_sha256: String,
    payload_sha256: String,
    receipt: Reference,
    bundle: Reference,
    declarations: Declaration,
    native_dependencies: Vec<String>,
    qualification: Option<Evidence>,
}

impl Record {
    fn identity(&self) -> Value {
        json!({"namespace":self.namespace,"id":self.id,"version":self.version,
            "target":self.target,"archive_sha256":self.archive.sha256,"archive_size":self.archive.size,
            "object_sha256":self.object_sha256,"manifest_sha256":self.manifest_sha256,
            "payload_sha256":self.payload_sha256})
    }

    fn subject(&self) -> String {
        let mut value = serde_json::to_value(self).expect("record serializes");
        value
            .as_object_mut()
            .expect("record object")
            .remove("qualification");
        loader::hash(&config::json_bytes(&value))
    }

    fn validate(&self) -> Result<(), LoadError> {
        if !loader::identifier(&self.record_id)
            || self.record_id.len() > 128
            || !loader::identifier(&self.id)
            || self.id.len() > 128
            || !text(&self.version, 128)
            || semver::Version::parse(&self.version).is_err()
            || !text(&self.display_name, 256)
            || !loader::identifier(&self.cargo_package)
            || self.cargo_package.len() > 128
            || !loader::identifier(&self.target)
            || self.target.len() > 128
            || !matches!(self.status.as_str(), "available" | "revoked")
            || !self.archive.valid(loader::MAX_PACKAGE)
            || !self.receipt.valid(256 * 1024)
            || !self.bundle.valid(PROOF_LIMIT)
            || [
                &self.object_sha256,
                &self.manifest_sha256,
                &self.payload_sha256,
            ]
            .iter()
            .any(|v| !loader::digest(v))
            || self.native_dependencies.len() > 32
            || self
                .native_dependencies
                .iter()
                .any(|v| !loader::identifier(v) || v.len() > 128)
            || self
                .native_dependencies
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.native_dependencies.len()
            || profile::canonical(&self.declarations).len() > 64 * 1024
            || !self.declarations.valid()
            || self.declarations.dependencies.len() > 32
            || self.declarations.conflicts.len() > 32
            || self.declarations.compat.required_capabilities.len() > 8
            || self.declarations.binary.target != self.target
            || self.declarations.binary.sha256 != self.payload_sha256
            || self
                .qualification
                .as_ref()
                .is_some_and(|v| !v.statement.valid(512 * 1024) || !v.bundle.valid(PROOF_LIMIT))
        {
            return Err(reject(self, "index_record", "invalid bounded record"));
        }
        if self.namespace != NAMESPACE || self.publisher != "DSLZL/CM" {
            return Err(reject(
                self,
                "index_namespace",
                "publisher differs from the fixed authority",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema_version: u32,
    domain: String,
    generated_at: String,
    source: provenance::Source,
    signer: provenance::Signer,
    policy_sha256: String,
    records: Vec<Record>,
}

impl Index {
    fn verify(bytes: &[u8], bundle: &[u8]) -> Result<(Self, loader::InputPin), LoadError> {
        let value: Self = parse(bytes, INDEX_LIMIT)?;
        if value.schema_version != 1
            || value.domain != "cm.mod-index.v1"
            || !timestamp(&value.generated_at)
            || value.records.len() > 1024
        {
            return Err(failure("index_envelope", "invalid index envelope"));
        }
        let pin = provenance::verify_index_statement(
            bytes,
            bundle,
            &value.domain,
            &value.source,
            &value.signer,
            &value.policy_sha256,
        )?;
        let mut identities = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for record in &value.records {
            record.validate()?;
            if !ids.insert(&record.record_id)
                || !identities.insert((
                    &record.namespace,
                    &record.id,
                    &record.version,
                    &record.target,
                ))
            {
                return Err(reject(
                    record,
                    "index_identity_conflict",
                    "duplicate record or release identity",
                ));
            }
        }
        Ok((value, pin))
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    index_sha256: String,
    bundle_sha256: String,
}

struct Cache {
    root: Directory,
    blobs: Directory,
    identities: Directory,
    source: Directory,
    transferred: u64,
    started: Instant,
    pins: Vec<loader::InputPin>,
}

fn present(path: &Path) -> Result<bool, LoadError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(failure("index_cache", "cannot inspect cache")),
    }
}

fn publish(
    directory: &Directory,
    name: &str,
    bytes: &[u8],
    replace: bool,
) -> Result<(), LoadError> {
    let temporary = profile::temporary("index");
    directory
        .create_file(&temporary, bytes)
        .map_err(|_| failure("index_cache", "cannot stage cache file"))?;
    let result = (|| {
        directory
            .check()
            .map_err(|_| failure("input_drift", "cache directory changed"))?;
        if replace {
            let from = CString::new(temporary.as_str()).expect("temporary name");
            let to =
                CString::new(name).map_err(|_| failure("index_cache", "invalid cache name"))?;
            if unsafe {
                libc::renameat(
                    directory.file.as_raw_fd(),
                    from.as_ptr(),
                    directory.file.as_raw_fd(),
                    to.as_ptr(),
                )
            } != 0
            {
                return Err(failure("index_cache", "cannot publish cache pointer"));
            }
            directory
                .file
                .sync_all()
                .map_err(|_| failure("index_cache", "cache sync failed"))?;
        } else if !directory
            .publish(&temporary, name)
            .map_err(|_| failure("index_cache", "cannot publish cache file"))?
        {
            let (existing, _) = loader::read_input(&directory.path.join(name), bytes.len() as u64)
                .map_err(|_| failure("index_cache", "cannot verify existing cache file"))?;
            if existing != bytes {
                return Err(failure(
                    "index_identity_conflict",
                    "cache content/address mismatch",
                ));
            }
        }
        Ok(())
    })();
    let temporary = CString::new(temporary).expect("temporary name");
    unsafe { libc::unlinkat(directory.file.as_raw_fd(), temporary.as_ptr(), 0) };
    result
}

impl Cache {
    fn open(transaction: &Transaction, source: &str) -> Result<Self, LoadError> {
        if !text(source, 2048) {
            return Err(failure("index_source", "invalid source"));
        }
        let child = |parent: &Directory, name: &str| {
            parent
                .child(name)
                .map_err(|_| failure("index_cache", "cannot open private index cache"))
        };
        let root = child(&transaction.root, "index")?;
        let blobs = child(&root, "blobs")?;
        let identities = child(&root, "identities")?;
        let sources = child(&root, "sources")?;
        let source = child(&sources, &loader::hash(source.as_bytes()))?;
        Ok(Self {
            root,
            blobs,
            identities,
            source,
            transferred: 0,
            started: Instant::now(),
            pins: Vec::new(),
        })
    }

    fn put(&self, bytes: &[u8], suffix: &str) -> Result<PathBuf, LoadError> {
        let name = format!("{}.{}", loader::hash(bytes), suffix);
        publish(&self.blobs, &name, bytes, false)?;
        Ok(self.blobs.path.join(name))
    }

    fn read(&mut self, hash: &str, suffix: &str, limit: u64) -> Result<Vec<u8>, LoadError> {
        if !loader::digest(hash) {
            return Err(failure("index_cache", "invalid content address"));
        }
        let (bytes, pin) =
            loader::read_input(&self.blobs.path.join(format!("{hash}.{suffix}")), limit).map_err(
                |_| {
                    failure(
                        "index_offline_missing",
                        "required cached bytes are missing or unsafe",
                    )
                },
            )?;
        if loader::hash(&bytes) != hash {
            return Err(failure(
                "index_checksum",
                "cached content differs from its address",
            ));
        }
        self.pins.push(pin);
        Ok(bytes)
    }

    async fn download(
        &mut self,
        transport: &mut impl Transport,
        resource: Resource<'_>,
        limit: u64,
    ) -> Result<Vec<u8>, LoadError> {
        if self.started.elapsed() > Duration::from_secs(120) {
            return Err(failure(
                "index_timeout",
                "operation download deadline exceeded",
            ));
        }
        let remaining = TRANSFER_LIMIT.saturating_sub(self.transferred);
        if remaining == 0 {
            return Err(failure("index_size", "operation download budget exceeded"));
        }
        let bytes = transport.fetch(resource, limit.min(remaining)).await?;
        self.transferred += bytes.len() as u64;
        if bytes.is_empty()
            || bytes.len() as u64 > limit
            || self.transferred > TRANSFER_LIMIT
            || self.started.elapsed() > Duration::from_secs(120)
        {
            return Err(failure("index_size", "download byte/time budget exceeded"));
        }
        Ok(bytes)
    }

    async fn artifact(
        &mut self,
        transport: &mut impl Transport,
        reference: &Reference,
        suffix: &str,
        limit: u64,
        offline: bool,
    ) -> Result<PathBuf, LoadError> {
        let path = self
            .blobs
            .path
            .join(format!("{}.{}", reference.sha256, suffix));
        if !present(&path)? {
            if offline {
                return Err(failure(
                    "index_offline_missing",
                    "required artifact is not cached",
                ));
            }
            let bytes = self
                .download(transport, Resource::Artifact(&reference.path), limit)
                .await?;
            if bytes.len() as u64 != reference.size || loader::hash(&bytes) != reference.sha256 {
                return Err(failure("index_checksum", "download size/digest differs"));
            }
            self.put(&bytes, suffix)?;
        }
        let bytes = self.read(&reference.sha256, suffix, limit)?;
        if bytes.len() as u64 != reference.size {
            return Err(failure("index_checksum", "cached size differs"));
        }
        Ok(path)
    }

    fn revalidate(&self) -> Result<(), LoadError> {
        for directory in [&self.root, &self.blobs, &self.identities, &self.source] {
            directory
                .check()
                .map_err(|_| failure("input_drift", "index directory changed"))?;
        }
        for pin in &self.pins {
            pin.revalidate()
                .map_err(|_| failure("input_drift", "index input changed"))?;
        }
        Ok(())
    }

    fn remember(&mut self, index: &Index) -> Result<(), LoadError> {
        let mut values = Vec::new();
        for record in &index.records {
            let key = loader::hash(&config::json_bytes(&json!([
                record.namespace,
                record.id,
                record.version,
                record.target
            ])));
            let bytes = config::json_bytes(&record.identity());
            let name = format!("{key}.json");
            if present(&self.identities.path.join(&name))? {
                let (old, pin) = loader::read_input(&self.identities.path.join(&name), 4096)
                    .map_err(|_| {
                        reject(
                            record,
                            "index_identity_conflict",
                            "unsafe accepted identity",
                        )
                    })?;
                if old != bytes {
                    return Err(reject(
                        record,
                        "index_identity_conflict",
                        "accepted version cannot change bytes",
                    ));
                }
                self.pins.push(pin);
            }
            values.push((name, bytes));
        }
        for (name, bytes) in values {
            publish(&self.identities, &name, &bytes, false)?;
        }
        Ok(())
    }

    async fn index(
        &mut self,
        transport: &mut impl Transport,
        offline: bool,
    ) -> Result<(Index, Snapshot), LoadError> {
        let snapshot = if offline {
            let (bytes, pin) = loader::read_input(&self.source.path.join("current.json"), 4096)
                .map_err(|_| failure("index_offline_missing", "no cached source snapshot"))?;
            self.pins.push(pin);
            parse(&bytes, 4096)?
        } else {
            let bytes = self
                .download(transport, Resource::Index, INDEX_LIMIT)
                .await?;
            let bundle = self
                .download(transport, Resource::IndexBundle, PROOF_LIMIT)
                .await?;
            let (index, pin) = Index::verify(&bytes, &bundle)?;
            self.pins.push(pin);
            if present(&self.source.path.join("current.json"))? {
                let (previous, _) =
                    loader::read_input(&self.source.path.join("current.json"), 4096)
                        .map_err(|_| failure("index_cache", "cannot inspect accepted snapshot"))?;
                let previous: Snapshot = parse(&previous, 4096)?;
                let previous_bytes = self.read(&previous.index_sha256, "json", INDEX_LIMIT)?;
                let previous_bundle = self.read(&previous.bundle_sha256, "jsonl", PROOF_LIMIT)?;
                let (previous, pin) = Index::verify(&previous_bytes, &previous_bundle)?;
                self.pins.push(pin);
                if index.generated_at < previous.generated_at {
                    return Err(failure(
                        "index_rollback",
                        "source snapshot predates its accepted snapshot",
                    ));
                }
            }
            self.remember(&index)?;
            self.put(&bytes, "json")?;
            self.put(&bundle, "jsonl")?;
            let snapshot = Snapshot {
                index_sha256: loader::hash(&bytes),
                bundle_sha256: loader::hash(&bundle),
            };
            publish(
                &self.source,
                "current.json",
                &profile::canonical(&snapshot),
                true,
            )?;
            snapshot
        };
        let bytes = self.read(&snapshot.index_sha256, "json", INDEX_LIMIT)?;
        let bundle = self.read(&snapshot.bundle_sha256, "jsonl", PROOF_LIMIT)?;
        let (index, pin) = Index::verify(&bytes, &bundle)?;
        self.pins.push(pin);
        self.remember(&index)?;
        // Pin the final pointer too: a concurrent refresh cannot silently change the plan.
        let (pointer, pin) = loader::read_input(&self.source.path.join("current.json"), 4096)
            .map_err(|_| failure("input_drift", "source snapshot disappeared"))?;
        if parse::<Snapshot>(&pointer, 4096)? != snapshot {
            return Err(failure("input_drift", "source snapshot changed"));
        }
        self.pins.push(pin);
        Ok((index, snapshot))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    domain: String,
    source: String,
    snapshot: Snapshot,
    home_identity: String,
    generation_sha256: String,
    selections: Vec<String>,
    profile: Option<String>,
    overrides: Vec<String>,
    host: Value,
    plan_sha256: String,
    lock_sha256: String,
}

fn read_plan(path: &Path) -> Result<(Plan, loader::InputPin), LoadError> {
    if !path.is_absolute() {
        return Err(failure("index_plan", "absolute plan path required"));
    }
    let (bytes, pin) = loader::read_input(path, PLAN_LIMIT)
        .map_err(|_| failure("index_plan", "cannot read plan"))?;
    let plan: Plan = parse(&bytes, PLAN_LIMIT)?;
    if plan.schema_version != 1
        || plan.domain != "cm.index-install-plan.v1"
        || !text(&plan.source, 2048)
        || plan.selections.is_empty()
        || plan.selections.len() > 32
        || plan
            .profile
            .as_ref()
            .is_some_and(|v| !loader::identifier(v))
        || plan.overrides.len() > 128
        || plan.overrides.iter().map(String::len).sum::<usize>() > 64 * 1024
        || [
            &plan.snapshot.index_sha256,
            &plan.snapshot.bundle_sha256,
            &plan.home_identity,
            &plan.generation_sha256,
            &plan.plan_sha256,
            &plan.lock_sha256,
        ]
        .iter()
        .any(|v| !loader::digest(v))
    {
        return Err(failure("index_plan", "invalid plan fields"));
    }
    Ok((plan, pin))
}

/// Read only a bounded, canonical plan to choose the transport; no fetch or activation.
pub fn plan_source(path: &Path) -> Result<String, LoadError> {
    read_plan(path).map(|(plan, _)| plan.source)
}

fn home_identity(transaction: &Transaction) -> Result<String, LoadError> {
    let metadata = transaction
        .root
        .file
        .metadata()
        .map_err(|_| failure("index_plan", "cannot identify home"))?;
    Ok(loader::hash(&profile::canonical(
        &json!({"path":transaction.root.path,
        "device":metadata.dev(),"inode":metadata.ino()}),
    )))
}

fn select<'a>(index: &'a Index, selections: &[String]) -> Result<Vec<&'a Record>, LoadError> {
    if selections.is_empty() || selections.len() > 32 {
        return Err(failure("index_selection", "select 1..32 exact versions"));
    }
    let mut selected = BTreeMap::new();
    for selection in selections {
        let (id, version) = selection
            .split_once('@')
            .ok_or_else(|| failure("index_selection", "expected ID@VERSION"))?;
        if !loader::identifier(id)
            || semver::Version::parse(version).is_err()
            || selected.contains_key(id)
        {
            return Err(failure(
                "index_selection",
                "invalid or duplicate exact selection",
            ));
        }
        let record = index
            .records
            .iter()
            .find(|r| r.id == id && r.version == version && r.target == loader::TARGET)
            .ok_or_else(|| {
                LoadError::input(
                    "index_missing_target",
                    id,
                    "no precompiled artifact for this target",
                )
            })?;
        if record.status != "available" {
            return Err(reject(record, "index_revoked", "record is revoked"));
        }
        selected.insert(id, record);
    }
    Ok(selected.into_values().collect())
}

async fn stage(
    transaction: &mut Transaction,
    cache: &mut Cache,
    transport: &mut impl Transport,
    records: &[&Record],
    offline: bool,
) -> Result<(), LoadError> {
    for record in records {
        let result = async {
            let archive_path = cache
                .artifact(
                    transport,
                    &record.archive,
                    "cmod",
                    loader::MAX_PACKAGE,
                    offline,
                )
                .await?;
            let receipt_path = cache
                .artifact(transport, &record.receipt, "json", 256 * 1024, offline)
                .await?;
            let bundle_path = cache
                .artifact(transport, &record.bundle, "jsonl", PROOF_LIMIT, offline)
                .await?;
            let archive = cache.read(&record.archive.sha256, "cmod", loader::MAX_PACKAGE)?;
            let receipt = cache.read(&record.receipt.sha256, "json", 256 * 1024)?;
            let bundle = cache.read(&record.bundle.sha256, "jsonl", PROOF_LIMIT)?;
            cache.pins.push(provenance::Proof::verify_archive(
                &archive, &receipt, &bundle,
            )?);
            // The trusted archive digest and signature precede ZIP parsing and any object write.
            let snapshot = loader::installation_snapshot(&archive_path)?;
            if loader::index_native_dependencies(&snapshot)? != record.native_dependencies {
                return Err(reject(
                    record,
                    "index_native",
                    "native dependency declaration differs from ELF",
                ));
            }
            let manifest = crate::manifest::parse(&snapshot.files["mod.toml"])?;
            let binary = manifest
                .binary_manifest
                .as_ref()
                .ok_or_else(|| reject(record, "index_record", "format 3 required"))?;
            let summary = binary.summary();
            let expected = profile::canonical(&record.declarations);
            let actual =
                config::json_bytes(&json!({"kind":summary["kind"],"binary":summary["binary"],
            "compat":summary["compat"],"dependencies":summary["dependencies"],
            "conflicts":summary["conflicts"],"state":summary["state"]}));
            if snapshot.id != record.id
                || manifest.version != record.version
                || snapshot.sha256 != record.object_sha256
                || loader::hash(&snapshot.files["mod.toml"]) != record.manifest_sha256
                || manifest.payload_sha256 != record.payload_sha256
                || expected != actual
                || snapshot.files.keys().any(|path| !relative(path))
            {
                return Err(reject(
                    record,
                    "index_manifest",
                    "index declarations differ from the verified package",
                ));
            }
            let old = transaction.next.installed.get(&record.id).cloned();
            if let Some(old) = &old
                && old != &record.object_sha256
            {
                let previous = loader::read_manifest(&transaction.objects.path.join(old))
                    .map_err(|_| reject(record, "input_drift", "old object changed"))?
                    .0;
                if previous.version == record.version {
                    return Err(reject(
                        record,
                        "index_identity_conflict",
                        "same installed version has different bytes",
                    ));
                }
            }
            let replacement = old
                .as_deref()
                .filter(|old| *old != record.object_sha256)
                .map(|old| (record.id.as_str(), old));
            mod_install::ingest_for_preview(
                transaction,
                &archive_path,
                replacement,
                (&receipt_path, &bundle_path),
            )?;
            Ok::<(), LoadError>(())
        }
        .await;
        result.map_err(|error| record_error(record, error))?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consumer {
    run_id: u64,
    attempt: u64,
    job_id: u64,
    source_sha: String,
    worker_sha: String,
    image_os: String,
    image_version: String,
    report: Reference,
    audit: Reference,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Conditions {
    backend: String,
    target: String,
    cpu: String,
    glibc_version: String,
    mods: BTreeMap<String, String>,
    config_sha256: Option<String>,
    state_contracts_sha256: String,
    exclusions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactOrigin {
    id: u64,
    name: String,
    digest: String,
    size_in_bytes: u64,
}

impl ArtifactOrigin {
    fn valid(&self) -> bool {
        self.id > 0
            && text(&self.name, 256)
            && self.size_in_bytes > 0
            && self
                .digest
                .strip_prefix("sha256:")
                .is_some_and(loader::digest)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionOrigin {
    source_sha: String,
    workflow_sha: String,
    run_id: u64,
    run_attempt: u64,
    request_id: String,
    job: String,
    job_id: u64,
    product_artifact: ArtifactOrigin,
    input_artifact: ArtifactOrigin,
}

impl ProductionOrigin {
    fn valid(&self) -> bool {
        [&self.source_sha, &self.workflow_sha].iter().all(|v| {
            v.len() == 40
                && v.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }) && self.run_id > 0
            && self.run_attempt > 0
            && self.job_id > 0
            && ci_request_id(&self.request_id)
            && matches!(
                self.job.as_str(),
                "build-read / linux-x64" | "build-write / linux-x64"
            )
            && self.product_artifact.valid()
            && self.input_artifact.valid()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    schema_version: u32,
    domain: String,
    source: provenance::Source,
    signer: provenance::Signer,
    policy_sha256: String,
    record_sha256: String,
    host: runtime_plan::HostIdentity,
    abi_major: u16,
    abi_minor_min: u16,
    capabilities: Vec<String>,
    support_level: String,
    maturity: String,
    consumer: Consumer,
    production_origin: ProductionOrigin,
    conditions: Conditions,
}

fn qualification_host(host: &runtime_plan::HostIdentity) -> bool {
    host.build_id
        .strip_prefix("sha256:")
        .is_some_and(loader::digest)
        && loader::digest(&host.executable_sha256)
        && host.target == loader::TARGET
        && text(&host.api_version, 128)
        && semver::Version::parse(&host.api_version).is_ok()
        && host.capabilities.len() <= 128
        && host
            .capabilities
            .iter()
            .all(|v| loader::identifier(v) && v.len() <= 128)
        && host.capabilities.iter().collect::<BTreeSet<_>>().len() == host.capabilities.len()
        && host.abis.len() <= 8
        && host.abis.iter().all(|v| {
            text(v, 16)
                && v.split_once('.').is_some_and(|(major, minor)| {
                    major.parse::<u16>().is_ok() && minor.parse::<u16>().is_ok()
                })
        })
        && host.abis.iter().collect::<BTreeSet<_>>().len() == host.abis.len()
        && host
            .patch_map_sha256
            .as_ref()
            .is_none_or(|v| loader::digest(v))
        && host.prepared_slots.len() <= 32
        && host
            .prepared_slots
            .iter()
            .all(|v| loader::identifier(v) && v.len() <= 128)
        && host.prepared_slots.iter().collect::<BTreeSet<_>>().len() == host.prepared_slots.len()
}

async fn support(
    cache: &mut Cache,
    transport: &mut impl Transport,
    record: &Record,
    prepared: &runtime_plan::PreparedPlan,
    offline: bool,
) -> Result<Value, LoadError> {
    let Some(evidence) = &record.qualification else {
        return Ok(
            json!({"origin_verified":true,"declared_compatible":true,"platform_verified":false,
            "reason":"qualification_missing"}),
        );
    };
    cache
        .artifact(transport, &evidence.statement, "json", 512 * 1024, offline)
        .await?;
    cache
        .artifact(transport, &evidence.bundle, "jsonl", PROOF_LIMIT, offline)
        .await?;
    let bytes = cache.read(&evidence.statement.sha256, "json", 512 * 1024)?;
    let bundle = cache.read(&evidence.bundle.sha256, "jsonl", PROOF_LIMIT)?;
    let qualification: Qualification = parse(&bytes, 512 * 1024)?;
    cache.pins.push(provenance::verify_index_statement(
        &bytes,
        &bundle,
        &qualification.domain,
        &qualification.source,
        &qualification.signer,
        &qualification.policy_sha256,
    )?);
    let consumer = &qualification.consumer;
    if qualification.schema_version != 1
        || qualification.domain != "cm.index-qualification.v1"
        || !qualification_host(&qualification.host)
        || qualification.record_sha256 != record.subject()
        || qualification.abi_major != record.declarations.compat.abi_major
        || qualification.abi_minor_min != record.declarations.compat.abi_minor_min
        || qualification.capabilities != record.declarations.compat.required_capabilities
        || !matches!(
            qualification.support_level.as_str(),
            "sdk" | "exact_host" | "prepared_slot"
        )
        || !matches!(qualification.maturity.as_str(), "stable" | "experimental")
        || (qualification.abi_major == 2
            && qualification.abi_minor_min == 3
            && qualification.maturity != "experimental")
        || consumer.run_id == 0
        || consumer.attempt == 0
        || consumer.job_id == 0
        || consumer.run_id != qualification.signer.run_id
        || consumer.attempt != qualification.signer.attempt
        || consumer.source_sha != qualification.source.sha
        || consumer.worker_sha != qualification.signer.workflow_sha
        || consumer.image_os != "ubuntu24"
        || !text(&consumer.image_version, 64)
        || !consumer.report.valid(16 * 1024 * 1024)
        || !consumer.audit.valid(16 * 1024 * 1024)
        || !qualification.production_origin.valid()
        || qualification.support_level
            != match &record.declarations.kind {
                crate::manifest::ModKind::Sdk => "sdk",
                crate::manifest::ModKind::ExactHost => "exact_host",
                crate::manifest::ModKind::AdvancedHook => "prepared_slot",
            }
        || qualification.conditions.backend != "Embedded"
        || qualification.conditions.target != loader::TARGET
        || qualification.conditions.cpu != "x86-64"
        || !text(&qualification.conditions.glibc_version, 32)
        || qualification.conditions.mods.len() > 32
        || qualification
            .conditions
            .mods
            .iter()
            .any(|(id, sha)| !loader::identifier(id) || !loader::digest(sha))
        || qualification
            .conditions
            .config_sha256
            .as_ref()
            .is_some_and(|sha| !loader::digest(sha))
        || !loader::digest(&qualification.conditions.state_contracts_sha256)
        || qualification.conditions.exclusions.len() > 32
        || qualification
            .conditions
            .exclusions
            .iter()
            .any(|v| !loader::identifier(v) || v.len() > 128)
    {
        return Err(reject(
            record,
            "index_qualification",
            "invalid mandatory qualification evidence",
        ));
    }
    let plan = prepared.plan();
    let state = loader::hash(&profile::canonical(prepared.state_contracts()));
    let glibc = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) }
        .to_str()
        .map_err(|_| failure("index_qualification", "cannot identify glibc"))?;
    let exact = qualification.host == plan.host
        && qualification.conditions.glibc_version == glibc
        && qualification.conditions.mods == plan.candidate_contents
        && qualification.conditions.config_sha256 == plan.config.sha256
        && qualification.conditions.state_contracts_sha256 == state;
    Ok(
        json!({"origin_verified":true,"declared_compatible":true,"platform_verified":exact,
        "reason":if exact {"exact_qualification"} else {"qualification_conditions_differ"},
        "qualification_sha256":evidence.statement.sha256,"support_level":qualification.support_level,
        "maturity":qualification.maturity,"exclusions":qualification.conditions.exclusions,
        "consumer":{"run_id":consumer.run_id,"attempt":consumer.attempt,"job_id":consumer.job_id,
            "report_sha256":consumer.report.sha256,"audit_sha256":consumer.audit.sha256,
            "image_os":consumer.image_os,"image_version":consumer.image_version}}),
    )
}

pub async fn run(
    home: &Path,
    source: &str,
    command: Command<'_>,
    offline: bool,
    transport: &mut impl Transport,
    options: &config::Options,
) -> Result<Value, LoadError> {
    profile::validate_environment(home)?;
    let host = package::managed_identity()?;
    let host_pin = package::PackagePin::capture(&host)?;
    let mut transaction = Transaction::begin(home, host)?;
    let baseline = loader::hash(&profile::canonical(&transaction.next));
    let home_id = home_identity(&transaction)?;
    let mut cache = Cache::open(&transaction, source)?;
    let (index, snapshot) = cache.index(transport, offline).await?;
    if matches!(command, Command::List) {
        cache.revalidate()?;
        host_pin.revalidate()?;
        transaction.revalidate()?;
        return Ok(
            json!({"schema_version":2,"operation":"index_list","index_sha256":snapshot.index_sha256,
            "generated_at":index.generated_at,"offline":offline,"source_refreshed":!offline,"revocation_fresh":false,
            "committed":false,"already_native_executed":false,"records":index.records.iter().map(|r| json!({
                "record_id":r.record_id,"namespace":r.namespace,"publisher":r.publisher,"id":r.id,
                "version":r.version,"target":r.target,"status":r.status,"object_sha256":r.object_sha256,
                "display_name_sha256":loader::hash(r.display_name.as_bytes()),"origin_verified":true,
                "declared_compatible":null,"platform_verified":false,"reason":"plan_required"})).collect::<Vec<_>>()}),
        );
    }
    let (saved, plan_pin) = if let Command::Install { plan } = &command {
        let (saved, pin) = read_plan(plan)?;
        if saved.source != source
            || saved.snapshot != snapshot
            || saved.home_identity != home_id
            || saved.generation_sha256 != baseline
        {
            return Err(failure(
                "input_drift",
                "source, home or active generation differs; preview again",
            ));
        }
        (Some(saved), Some(pin))
    } else {
        (None, None)
    };
    let selections = match (&command, &saved) {
        (Command::Plan { selections, .. }, _) => *selections,
        (Command::Install { .. }, Some(plan)) => &plan.selections,
        _ => unreachable!("list returned above"),
    };
    let records = select(&index, selections)?;
    // Preview stages immutable verified objects, never replacement state or an active descriptor.
    // Keep state lease acquisition for the final existing commit path.
    stage(&mut transaction, &mut cache, transport, &records, offline).await?;
    let chosen_options = saved.as_ref().map(|p| config::Options {
        profile: p.profile.clone(),
        overrides: p.overrides.clone(),
    });
    let options = chosen_options.as_ref().unwrap_or(options);
    let prepared = transaction.preview(options)?;
    let actual_host = serde_json::to_value(&prepared.plan().host).expect("Host serializes");
    if prepared.plan().host != host_pin.identity {
        return Err(failure(
            "host_identity",
            "executing Host differs from package",
        ));
    }
    let plan_sha256 = prepared.plan().sha256();
    let lock_sha256 = loader::hash(&mod_lock::canonical(prepared.plan()));
    let mut labels = BTreeMap::new();
    for record in &records {
        labels.insert(
            record.id.clone(),
            support(&mut cache, transport, record, &prepared, offline)
                .await
                .map_err(|error| record_error(record, error))?,
        );
    }
    cache.revalidate()?;
    host_pin.revalidate()?;
    prepared.revalidate()?;
    transaction.revalidate()?;
    if let Some(pin) = &plan_pin {
        pin.revalidate()
            .map_err(|_| failure("input_drift", "plan changed"))?;
    }
    let result = match command {
        Command::Plan { output, .. } => {
            let host_root = transaction
                .host
                .executable
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| failure("index_plan", "missing Host root"))?;
            let official = std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|p| p.join(".codex"));
            if !output.is_absolute()
                || output.starts_with(home.join("store"))
                || output.starts_with(home.join("state"))
                || output.starts_with(home.join("index"))
                || output == home.join("cm-profile.json")
                || output == home.join("cm-runtime.toml")
                || output.starts_with(host_root)
                || official.as_ref().is_some_and(|p| output.starts_with(p))
            {
                return Err(failure(
                    "index_plan",
                    "plan must be a new independent absolute file",
                ));
            }
            let plan = Plan {
                schema_version: 1,
                domain: "cm.index-install-plan.v1".into(),
                source: source.into(),
                snapshot,
                home_identity: home_id,
                generation_sha256: baseline,
                selections: records
                    .iter()
                    .map(|r| format!("{}@{}", r.id, r.version))
                    .collect(),
                profile: options.profile.clone(),
                overrides: options.overrides.clone(),
                host: actual_host,
                plan_sha256: plan_sha256.clone(),
                lock_sha256: lock_sha256.clone(),
            };
            let directory = Directory::open(
                output
                    .parent()
                    .ok_or_else(|| failure("index_plan", "missing plan parent"))?,
            )
            .map_err(|_| failure("index_plan", "plan parent must be owned and private"))?;
            let bytes = profile::canonical(&plan);
            if bytes.len() as u64 > PLAN_LIMIT {
                return Err(failure("index_plan", "plan byte limit"));
            }
            let name = output
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| failure("index_plan", "invalid plan name"))?;
            directory
                .create_file(name, &bytes)
                .map_err(|_| failure("index_plan", "plan already exists or cannot be written"))?;
            json!({"operation":"index_plan","committed":false,"plan_file_sha256":loader::hash(&bytes),
                "plan":prepared.plan(),"plan_sha256":plan_sha256,"lock_sha256":lock_sha256})
        }
        Command::Install { .. } => {
            let saved = saved.expect("install plan loaded");
            if saved.host != actual_host
                || saved.plan_sha256 != plan_sha256
                || saved.lock_sha256 != lock_sha256
            {
                return Err(failure(
                    "input_drift",
                    "Host, configuration or resolved plan differs",
                ));
            }
            transaction.commit_checked(options, |current| {
                cache.revalidate()?;
                host_pin.revalidate()?;
                if let Some(pin) = &plan_pin {
                    pin.revalidate()
                        .map_err(|_| failure("input_drift", "plan changed"))?;
                }
                if current.plan().sha256() != saved.plan_sha256
                    || loader::hash(&mod_lock::canonical(current.plan())) != saved.lock_sha256
                {
                    return Err(failure(
                        "input_drift",
                        "commit no longer matches reviewed plan",
                    ));
                }
                Ok(())
            })?
        }
        Command::List => unreachable!("list returned above"),
    };
    let mut result = result;
    result["state_contracts_sha256"] = json!(loader::hash(&profile::canonical(
        prepared.state_contracts()
    )));
    result["support"] = json!(labels);
    result["offline"] = json!(offline);
    result["source_refreshed"] = json!(!offline);
    result["revocation_fresh"] = json!(false);
    result["already_native_executed"] = json!(false);
    Ok(crate::diagnostics::metadata(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_request_ids_match_worker_ascii_contract() {
        for value in [
            "cm-mp01-lx01-20261108T170615Z-1739473d",
            "A_1.z-2",
            "._-",
        ] {
            assert!(ci_request_id(value), "{value:?}");
        }
        assert!(ci_request_id(&"x".repeat(128)));
        for value in [
            "",
            "a/b",
            "a\\b",
            "a:b",
            "a+b",
            "white space",
            "é",
            "line\nbreak",
        ] {
            assert!(!ci_request_id(value), "{value:?}");
        }
        assert!(!ci_request_id(&"x".repeat(129)));
        assert!(!loader::identifier("A_1.z-2"));
    }

    #[test]
    fn qualification_host_claims_reject_unbounded_or_repeated_identities() {
        let mut host = runtime_plan::HostIdentity {
            build_id: format!("sha256:{}", "a".repeat(64)),
            executable_sha256: "b".repeat(64),
            target: loader::TARGET.into(),
            api_version: "0.8.0".into(),
            capabilities: vec!["state.files.v1".into()],
            abis: vec!["2.2".into()],
            patch_map_sha256: None,
            prepared_slots: vec![],
        };
        assert!(qualification_host(&host));
        host.capabilities.push("state.files.v1".into());
        assert!(!qualification_host(&host));
        host.capabilities.pop();
        host.abis = vec!["2.2".into(); 9];
        assert!(!qualification_host(&host));
        host.abis = vec!["2.2.extra".into()];
        assert!(!qualification_host(&host));
    }

    #[test]
    fn untrusted_json_and_transport_paths_are_closed() {
        for path in [
            "../a",
            "/a",
            "a//b",
            "a/./b",
            "a\\b",
            "https://host/a",
            "a?x=y",
            "a/%2e%2e/b",
            "a/\u{00df}",
        ] {
            assert!(!relative(path), "{path}");
        }
        assert!(relative("packages/v1/example-tool.cmod"));
        for value in [
            "2026-00-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-11-06T24:00:00Z",
            "2026-11-06T00:60:00Z",
        ] {
            assert!(!timestamp(value));
        }
        assert!(timestamp("2024-02-29T23:59:59Z"));
        assert!(
            parse::<Snapshot>(
                br#"{"index_sha256":"a","bundle_sha256":"b","index_sha256":"c"}"#,
                4096
            )
            .is_err()
        );
        assert!(
            parse::<Snapshot>(
                br#"{"bundle_sha256":"b","index_sha256":"a","run":"shell"}"#,
                4096
            )
            .is_err()
        );
    }
}
