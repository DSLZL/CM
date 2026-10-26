use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use cm_abi::ABI_MAJOR;
use cm_abi::ABI_MINOR;
use cm_abi::CAPABILITY;
use cm_abi::CONTRIBUTION;
use cm_abi::v2;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

mod elf;
pub(crate) mod native;
pub(crate) mod registration;

pub(crate) const MAX_MANIFEST: u64 = 64 * 1024;
pub(crate) const MAX_PAYLOAD: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_RESOURCE: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_CONTRIBUTIONS: usize = 128;
pub const TARGET: &str = "x86_64-unknown-linux-gnu";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Before,
    Around,
    Replacement,
    After,
    LegacyFilter,
    OutputLimit,
}

impl Kind {
    pub(crate) fn abi(&self) -> u32 {
        match self {
            Self::Before => v2::BEFORE,
            Self::Around => v2::AROUND,
            Self::Replacement => v2::REPLACEMENT,
            Self::After => v2::AFTER,
            Self::LegacyFilter => 0,
            Self::OutputLimit => 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependency {
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contribution {
    pub id: String,
    pub capability: String,
    pub resource: String,
    pub kind: Kind,
    #[serde(default)]
    pub order_before: Vec<String>,
    #[serde(default)]
    pub order_after: Vec<String>,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Resource {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub format_version: u32,
    pub id: String,
    pub version: String,
    pub payload: String,
    pub payload_size: u64,
    pub payload_sha256: String,
    pub target: String,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub required_capabilities: Vec<String>,
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub contribution: String,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub contributions: Vec<Contribution>,
    #[serde(default)]
    pub resources: Vec<Resource>,
    #[serde(skip)]
    pub binary_manifest: Option<crate::manifest::BinaryManifest>,
}

impl Manifest {
    pub(crate) fn hooks(&self) -> Vec<Contribution> {
        if self.abi_major == 1 {
            vec![Contribution {
                id: self.contribution.clone(),
                capability: CAPABILITY.into(),
                resource: CAPABILITY.into(),
                kind: Kind::LegacyFilter,
                order_before: Vec::new(),
                order_after: Vec::new(),
                priority: 0,
            }]
        } else {
            self.contributions.clone()
        }
    }
}

pub(crate) struct ResourceSnapshot {
    pub path: String,
    pub bytes: Vec<u8>,
}

pub(crate) struct Preflighted {
    pub manifest: Manifest,
    pub snapshot: File,
    pub needed: Vec<String>,
    pub resources: Vec<ResourceSnapshot>,
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn executable_hash(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("Host executable must be a regular file".into());
    }
    let mut buffer = [0_u8; 64 * 1024];
    let mut previous = None;
    for _ in 0..2 {
        let mut digest = Sha256::new();
        loop {
            let length = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if length == 0 {
                break;
            }
            digest.update(&buffer[..length]);
        }
        let current = file.metadata().map_err(|e| e.to_string())?;
        if metadata.dev() != current.dev()
            || metadata.ino() != current.ino()
            || metadata.len() != current.len()
            || metadata.mtime() != current.mtime()
            || metadata.mtime_nsec() != current.mtime_nsec()
        {
            return Err("Host executable changed while hashing".into());
        }
        let digest = format!("{:x}", digest.finalize());
        if file_stamp(&metadata) == file_stamp(&current) || previous.as_ref() == Some(&digest) {
            return Ok(digest);
        }
        // Linking a shared executable changes ctime; confirm its bytes with a second full read.
        previous = Some(digest);
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    }
    Err("Host executable changed while hashing".into())
}

pub(crate) fn open_at(
    parent: &File,
    name: &std::ffi::OsStr,
    directory: bool,
) -> Result<File, String> {
    let name = CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn open_directory(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("managed path must be absolute".into());
    }
    let mut directory = File::open("/").map_err(|e| e.to_string())?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => directory = open_at(&directory, name, true)?,
            _ => return Err("managed path must have only normal components".into()),
        }
    }
    Ok(directory)
}

fn file_stamp(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[derive(Clone)]
pub(crate) struct InputPin {
    path: PathBuf,
    pub sha256: String,
    pub size: u64,
    limit: u64,
    device: u64,
    inode: u64,
}

impl InputPin {
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        let (_, current) = read_input(&self.path, self.limit).map_err(|error| {
            format!(
                "locked input {} expected size={} sha256={}: {error}",
                self.path.display(),
                self.size,
                self.sha256
            )
        })?;
        if self.sha256 != current.sha256
            || self.size != current.size
            || self.device != current.device
            || self.inode != current.inode
        {
            return Err(format!(
                "locked input changed: {} expected size={} sha256={} actual size={} sha256={}",
                self.path.display(),
                self.size,
                self.sha256,
                current.size,
                current.sha256
            ));
        }
        Ok(())
    }
}

pub(crate) fn read_input(path: &Path, limit: u64) -> Result<(Vec<u8>, InputPin), String> {
    let parent = open_directory(path.parent().ok_or("missing input parent")?)?;
    let mut file = open_at(
        &parent,
        path.file_name().ok_or("missing input name")?,
        false,
    )?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err("expected a bounded regular file with one link".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit
        || bytes.len() as u64 != before.len()
        || file_stamp(&before) != file_stamp(&file.metadata().map_err(|e| e.to_string())?)
    {
        return Err("input changed while reading or exceeded its bound".into());
    }
    let pin = InputPin {
        path: path.into(),
        sha256: hash(&bytes),
        size: bytes.len() as u64,
        limit,
        device: before.dev(),
        inode: before.ino(),
    };
    Ok((bytes, pin))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Inventory {
    pub packages: BTreeMap<String, (u64, u64)>,
    root: Option<(u64, u64)>,
}

pub(crate) fn inventory(home: &Path) -> Result<Inventory, String> {
    if !home.is_absolute() {
        return Err("CM profile must be absolute".into());
    }
    let root = home.join("mods");
    match fs::symlink_metadata(&root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Inventory {
                packages: BTreeMap::new(),
                root: None,
            });
        }
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let directory = open_directory(&root)?;
    let metadata = directory.metadata().map_err(|e| e.to_string())?;
    let mut packages = BTreeMap::new();
    for entry in fs::read_dir(snapshot_path(&directory)).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "package path is not UTF-8")?;
        if packages.len() >= 32 {
            return Err("runtime set exceeds 32 packages".into());
        }
        let package = open_at(
            &directory,
            std::ffi::OsStr::new(&name),
            !name.ends_with(".cmod"),
        )?;
        let metadata = package.metadata().map_err(|e| e.to_string())?;
        if name.ends_with(".cmod") && (!metadata.is_file() || metadata.nlink() != 1) {
            return Err(".cmod must be a regular file with one link".into());
        }
        packages.insert(name, (metadata.dev(), metadata.ino()));
    }
    Ok(Inventory {
        packages,
        root: Some((metadata.dev(), metadata.ino())),
    })
}

pub(crate) fn payload_path(package: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if relative.is_empty()
        || relative.len() > 512
        || relative.contains(['\\', ':'])
        || relative.chars().any(char::is_control)
        || path.components().count() > 16
        || path.is_absolute()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("input must be a bounded package-relative normal path".into());
    }
    let normalized: PathBuf = path.components().map(|part| part.as_os_str()).collect();
    if normalized.as_os_str() != relative {
        return Err("input path must use its canonical relative spelling".into());
    }
    Ok(package.join(path))
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

pub(crate) fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn check_manifest(manifest: &Manifest) -> Result<(), String> {
    if !identifier(&manifest.id)
        || !version(&manifest.version)
        || manifest.target != TARGET
        || manifest.payload_size == 0
        || manifest.payload_size > MAX_PAYLOAD
        || !digest(&manifest.payload_sha256)
    {
        return Err("unsupported manifest id/version/target/digest/size".into());
    }
    match manifest.format_version {
        3 if manifest.binary_manifest.is_some() => {}
        1 if manifest.abi_major == ABI_MAJOR
            && manifest.abi_minor == ABI_MINOR
            && manifest.contribution == CONTRIBUTION
            && manifest.required_capabilities == [CAPABILITY]
            && manifest.dependencies.is_empty()
            && manifest.conflicts.is_empty()
            && manifest.contributions.is_empty()
            && manifest.resources.is_empty() => {}
        2 if manifest.abi_major == v2::ABI_MAJOR
            && manifest.abi_minor == v2::ABI_MINOR
            && manifest.contribution.is_empty()
            && manifest.required_capabilities == [v2::CAPABILITY]
            && !manifest.contributions.is_empty()
            && manifest.contributions.len() <= MAX_CONTRIBUTIONS => {}
        2 if manifest.abi_major == 2
            && manifest.abi_minor == 1
            && manifest.contribution.is_empty()
            && !manifest.required_capabilities.is_empty()
            && manifest.required_capabilities.len() <= 2
            && manifest
                .required_capabilities
                .iter()
                .all(|cap| [v2::CAPABILITY, cm_abi::v21::CAPABILITY].contains(&cap.as_str()))
            && manifest
                .required_capabilities
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == manifest.required_capabilities.len()
            && !manifest.contributions.is_empty()
            && manifest.contributions.len() <= MAX_CONTRIBUTIONS => {}
        _ => return Err("unsupported manifest format/ABI/capability/contribution".into()),
    }
    Ok(())
}

pub(crate) fn read_manifest(package: &Path) -> Result<(Manifest, InputPin), crate::LoadError> {
    let (bytes, pin) = read_input(&package.join("mod.toml"), MAX_MANIFEST)
        .map_err(|e| crate::LoadError::input("manifest_parse", "", &e))?;
    let manifest = crate::manifest::parse(&bytes)?;
    Ok((manifest, pin))
}

pub(crate) fn prepare_package(
    package: &Path,
    manifest: Manifest,
) -> Result<(Preflighted, Vec<InputPin>), String> {
    let mut pins = Vec::new();
    let prepared = prepare_bytes(manifest, |relative, limit| {
        let (bytes, pin) = read_input(&payload_path(package, relative)?, limit)?;
        pins.push(pin);
        Ok(bytes)
    })?;
    Ok((prepared, pins))
}

fn prepare_bytes(
    manifest: Manifest,
    mut read: impl FnMut(&str, u64) -> Result<Vec<u8>, String>,
) -> Result<Preflighted, String> {
    let bytes = read(&manifest.payload, MAX_PAYLOAD)?;
    if bytes.len() as u64 != manifest.payload_size || hash(&bytes) != manifest.payload_sha256 {
        return Err("payload size or SHA-256 mismatch".into());
    }
    let needed = elf::check(&bytes)?;
    let snapshot = sealed_snapshot(&bytes)?;
    let mut resources = Vec::new();
    for resource in &manifest.resources {
        if resource.size > MAX_RESOURCE || !digest(&resource.sha256) {
            return Err("invalid resource size or digest".into());
        }
        let bytes = read(&resource.path, MAX_RESOURCE)?;
        if bytes.len() as u64 != resource.size || hash(&bytes) != resource.sha256 {
            return Err(format!(
                "resource size or SHA-256 mismatch: {}",
                resource.path
            ));
        }
        resources.push(ResourceSnapshot {
            path: resource.path.clone(),
            bytes,
        });
    }
    resources.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Preflighted {
        manifest,
        snapshot,
        needed,
        resources,
    })
}

const MAX_PACKAGE: u64 = 128 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;

pub(crate) struct Candidate {
    pub manifest: Manifest,
    pub manifest_sha256: String,
    pub content_sha256: String,
    pub pins: Vec<InputPin>,
    pub tree: Option<BTreeSet<String>>,
    pub package: PathBuf,
    files: Option<BTreeMap<String, Vec<u8>>>,
}

impl Candidate {
    pub(crate) fn snapshot_size(&self) -> usize {
        self.files
            .as_ref()
            .map_or(0, |files| files.values().map(Vec::len).sum())
    }

    pub(crate) fn prepare(mut self) -> Result<(Preflighted, Vec<InputPin>), String> {
        if let Some(mut files) = self.files.take() {
            let prepared = prepare_bytes(self.manifest, |path, limit| {
                let bytes = files
                    .remove(path)
                    .ok_or("package: declared file is missing")?;
                if bytes.len() as u64 > limit {
                    return Err("package: file exceeds its bound".into());
                }
                Ok(bytes)
            })?;
            Ok((prepared, self.pins))
        } else {
            let (prepared, mut pins) = prepare_package(&self.package, self.manifest)?;
            pins.extend(self.pins);
            Ok((prepared, pins))
        }
    }
}

fn walk(
    directory: &File,
    prefix: &str,
    depth: usize,
    entries: &mut BTreeSet<String>,
) -> Result<(), String> {
    if depth > 16 {
        return Err("package: directory depth limit".into());
    }
    for item in fs::read_dir(snapshot_path(directory)).map_err(|e| e.to_string())? {
        let item = item.map_err(|e| e.to_string())?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| "package: non-UTF8 path")?;
        let path = format!("{prefix}{name}");
        payload_path(Path::new("/package"), &path)?;
        let meta = item.file_type().map_err(|e| e.to_string())?;
        let dir = meta.is_dir();
        if !dir && !meta.is_file() {
            return Err("package: links and special files are forbidden".into());
        }
        if !entries.insert(if dir {
            format!("{path}/")
        } else {
            path.clone()
        }) || entries.len() > MAX_ENTRIES
        {
            return Err("package: duplicate path or entry limit".into());
        }
        if dir {
            walk(
                &open_at(directory, &item.file_name(), true)?,
                &format!("{path}/"),
                depth + 1,
                entries,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn directory_entries(package: &Path) -> Result<BTreeSet<String>, String> {
    let mut entries = BTreeSet::new();
    walk(&open_directory(package)?, "", 0, &mut entries)?;
    Ok(entries)
}

pub(crate) fn candidate(package: &Path) -> Result<Candidate, crate::LoadError> {
    let invalid = |message: String| crate::LoadError::input("manifest_parse", "", &message);
    let archive = package.extension().is_some_and(|s| s == "cmod");
    let (manifest, manifest_sha256, mut pins, mut files, tree) = if archive {
        let (bytes, pin) = read_input(package, MAX_PACKAGE).map_err(invalid)?;
        let files = zip_files(&bytes).map_err(invalid)?;
        let raw = files
            .get("mod.toml")
            .ok_or_else(|| invalid("package: mod.toml is missing".into()))?;
        if raw.len() as u64 > MAX_MANIFEST {
            return Err(invalid("manifest: byte limit".into()));
        }
        (
            crate::manifest::parse(raw)?,
            hash(raw),
            vec![pin],
            Some(files),
            None,
        )
    } else {
        let (manifest, pin) = read_manifest(package)?;
        if manifest.format_version == 3 {
            let tree = directory_entries(package).map_err(invalid)?;
            let mut files = BTreeMap::new();
            let mut pins = vec![pin.clone()];
            let mut total = 0_u64;
            for path in tree.iter().filter(|s| !s.ends_with('/')) {
                let limit = if path == &manifest.payload {
                    MAX_PAYLOAD
                } else if path == "mod.toml" {
                    MAX_MANIFEST
                } else {
                    MAX_RESOURCE
                };
                let (bytes, input) =
                    read_input(&payload_path(package, path).map_err(invalid)?, limit)
                        .map_err(invalid)?;
                total += bytes.len() as u64;
                if total > MAX_PACKAGE {
                    return Err(invalid("package: total byte limit".into()));
                }
                pins.push(input);
                files.insert(path.clone(), bytes);
            }
            if files
                .get("mod.toml")
                .is_none_or(|raw| hash(raw) != pin.sha256)
            {
                return Err(invalid("manifest: changed during package snapshot".into()));
            }
            (manifest, pin.sha256, pins, Some(files), Some(tree))
        } else {
            (manifest, pin.sha256.clone(), vec![pin], None, None)
        }
    };
    if archive && manifest.format_version != 3 {
        return Err(invalid("package: .cmod requires format 3".into()));
    }
    if manifest.format_version == 3 {
        check_manifest(&manifest).map_err(invalid)?;
    }
    if let Some(files) = &files {
        for (path, bytes) in files {
            let limit = if path == &manifest.payload {
                MAX_PAYLOAD
            } else if path == "mod.toml" {
                MAX_MANIFEST
            } else {
                MAX_RESOURCE
            };
            if bytes.len() as u64 > limit {
                return Err(invalid("package: attachment byte limit".into()));
            }
        }
    }
    let content_sha256 = if let Some(files) = files.as_mut() {
        let identities: BTreeMap<_, _> = files
            .iter()
            .map(|(path, bytes)| (path, (bytes.len(), hash(bytes))))
            .collect();
        hash(&serde_json::to_vec(&identities).expect("content identities serialize"))
    } else {
        manifest_sha256.clone()
    };
    Ok(Candidate {
        manifest,
        manifest_sha256,
        content_sha256,
        pins: std::mem::take(&mut pins),
        tree,
        package: package.into(),
        files,
    })
}

// zip's index replaces duplicate names; check the bounded ZIP envelope before it allocates an index.
fn zip_directory(bytes: &[u8]) -> Result<usize, String> {
    let bad = || "package: unsupported or malformed ZIP envelope".to_string();
    let u16_at = |at: usize| -> Result<usize, String> {
        Ok(u16::from_le_bytes(bytes.get(at..at + 2).ok_or_else(bad)?.try_into().unwrap()) as usize)
    };
    let u32_at = |at: usize| -> Result<usize, String> {
        Ok(u32::from_le_bytes(bytes.get(at..at + 4).ok_or_else(bad)?.try_into().unwrap()) as usize)
    };
    let end = (bytes.len().saturating_sub(65557)..bytes.len().saturating_sub(21))
        .rev()
        .find(|&i| {
            bytes.get(i..i + 4) == Some(b"PK\x05\x06")
                && u16_at(i + 20).is_ok_and(|len| i + 22 + len == bytes.len())
        })
        .ok_or_else(bad)?;
    let count = u16_at(end + 10)?;
    let start = u32_at(end + 16)?;
    if count == 0
        || count > MAX_ENTRIES
        || u16_at(end + 4)? != 0
        || u16_at(end + 6)? != 0
        || u16_at(end + 8)? != count
        || start.checked_add(u32_at(end + 12)?) != Some(end)
        || end.saturating_sub(start) > 1024 * 1024
    {
        return Err(bad());
    }
    let mut position = start;
    let mut names = BTreeSet::new();
    let mut ranges = Vec::new();
    for _ in 0..count {
        if bytes.get(position..position + 4) != Some(b"PK\x01\x02") {
            return Err(bad());
        }
        let flags = u16_at(position + 8)?;
        let method = u16_at(position + 10)?;
        let name_len = u16_at(position + 28)?;
        let extra = u16_at(position + 30)?;
        let comment = u16_at(position + 32)?;
        let local = u32_at(position + 42)?;
        let name = bytes
            .get(position + 46..position + 46 + name_len)
            .ok_or_else(bad)?;
        let data_end = local
            .checked_add(30 + name_len + u16_at(local + 28)?)
            .and_then(|n| n.checked_add(u32_at(position + 20).ok()?))
            .ok_or_else(bad)?;
        if flags & (1 | 64 | 8192) != 0
            || ![0, 8].contains(&method)
            || u16_at(position + 34)? != 0
            || !names.insert(name)
            || local >= start
            || bytes.get(local..local + 4) != Some(b"PK\x03\x04")
            || u16_at(local + 6)? != flags
            || u16_at(local + 8)? != method
            || u16_at(local + 26)? != name_len
            || bytes.get(local + 30..local + 30 + name_len) != Some(name)
            || data_end > start
            || ranges.iter().any(|&(a, b)| local < b && a < data_end)
            || (flags & 8 == 0
                && (u32_at(local + 14)? != u32_at(position + 16)?
                    || u32_at(local + 18)? != u32_at(position + 20)?
                    || u32_at(local + 22)? != u32_at(position + 24)?))
        {
            return Err(bad());
        }
        ranges.push((local, data_end));
        position = position
            .checked_add(46 + name_len + extra + comment)
            .ok_or_else(bad)?;
        if position > end {
            return Err(bad());
        }
    }
    if position != end || ranges.iter().map(|&(start, _)| start).min() != Some(0) {
        return Err(bad());
    }
    Ok(count)
}

fn zip_files(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let count = zip_directory(bytes)?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|_| "package: invalid ZIP directory")?;
    if zip.len() != count || zip.offset() != 0 {
        return Err("package: duplicate ZIP entry or prefixed archive".into());
    }
    let mut files = BTreeMap::new();
    let mut entries = BTreeSet::new();
    let mut total = 0_u64;
    for index in 0..zip.len() {
        let mut file = zip
            .by_index(index)
            .map_err(|_| "package: unreadable/encrypted ZIP entry")?;
        let raw = std::str::from_utf8(file.name_raw())
            .map_err(|_| "package: non-UTF8 ZIP path")?
            .to_string();
        let path = raw.strip_suffix('/').unwrap_or(&raw);
        payload_path(Path::new("/package"), path)?;
        if !entries.insert(path.to_owned())
            || file.encrypted()
            || ![
                zip::CompressionMethod::Stored,
                zip::CompressionMethod::Deflated,
            ]
            .contains(&file.compression())
            || file.unix_mode().is_some_and(|mode| {
                ![0, libc::S_IFREG, libc::S_IFDIR].contains(&(mode & libc::S_IFMT))
            })
            || file.unix_mode().is_some_and(|mode| {
                (mode & libc::S_IFMT == libc::S_IFDIR) != file.is_dir() && mode & libc::S_IFMT != 0
            })
            || (file.is_dir() && file.size() != 0)
        {
            return Err("package: invalid ZIP entry type/path/method".into());
        }
        if file.is_dir() {
            continue;
        }
        if !file.is_file() || file.size() > MAX_PAYLOAD {
            return Err("package: ZIP entry limit".into());
        }
        total = total
            .checked_add(file.size())
            .ok_or("package: ZIP byte overflow")?;
        if total > MAX_PACKAGE {
            return Err("package: ZIP total byte limit".into());
        }
        let expected = file.size();
        let mut data = Vec::new();
        (&mut file)
            .take(expected + 1)
            .read_to_end(&mut data)
            .map_err(|_| "package: ZIP data/CRC failure")?;
        if data.len() as u64 != expected {
            return Err("package: ZIP actual size mismatch".into());
        }
        files.insert(raw, data);
    }
    for path in entries.clone() {
        let mut parent = Path::new(&path).parent();
        while let Some(p) = parent {
            if !p.as_os_str().is_empty() {
                let p = p.to_string_lossy().to_string();
                if files.contains_key(&p) {
                    return Err("package: ZIP file/directory collision".into());
                }
                entries.insert(p);
                if entries.len() > MAX_ENTRIES {
                    return Err("package: ZIP logical entry limit".into());
                }
            }
            parent = p.parent();
        }
    }
    Ok(files)
}

pub(crate) fn sealed_snapshot(bytes: &[u8]) -> Result<File, String> {
    // Seal the verified buffer, never reopen the package path for dlopen.
    let fd = unsafe {
        libc::memfd_create(
            c"cm-mod-v1".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
    }
    let mut writer = unsafe { File::from_raw_fd(fd) };
    writer.write_all(bytes).map_err(|e| e.to_string())?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0
        || unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & seals != seals
    {
        return Err(format!(
            "required memfd seals unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut snapshot = File::open(format!("/proc/self/fd/{fd}")).map_err(|e| e.to_string())?;
    let mut sealed = Vec::new();
    snapshot
        .read_to_end(&mut sealed)
        .map_err(|e| e.to_string())?;
    if hash(&sealed) != hash(bytes) {
        return Err("sealed payload identity drift".into());
    }
    snapshot
        .seek(SeekFrom::Start(0))
        .map_err(|e| e.to_string())?;
    drop(writer);
    Ok(snapshot)
}

pub(crate) fn snapshot_path(snapshot: &File) -> PathBuf {
    format!("/proc/self/fd/{}", snapshot.as_raw_fd()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_known_metadata_reject_before_native() {
        let base = Path::new("/managed/package");
        for value in [
            "",
            "/tmp/x.so",
            "../x.so",
            "bin/../../x.so",
            "a\\b.so",
            "a:b.so",
            "a\0b.so",
            "a//b.so",
            "a/./b.so",
        ] {
            assert!(payload_path(base, value).is_err());
        }
        assert!(!identifier(""));
        assert!(!identifier("../escape"));
        assert!(!identifier("MixedCase"));
        assert!(identifier("test.mod-1"));
        assert!(!version("^1.0"));
    }

    #[test]
    fn seals_pin_bytes_and_disallow_writes() {
        let snapshot = sealed_snapshot(b"verified bytes").unwrap();
        let path = snapshot_path(&snapshot);
        assert_eq!(fs::read(&path).unwrap(), b"verified bytes");
        let mut writer = fs::OpenOptions::new().write(true).open(path).unwrap();
        assert!(writer.write_all(b"changed bytes!").is_err());
    }

    #[test]
    fn executable_hash_tracks_bytes_across_link_changes() {
        let base = std::env::temp_dir().join(format!("cm-executable-hash-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let path = base.join("host");
        let link = base.join("installation");
        fs::write(&path, b"original executable").unwrap();
        let expected = hash(b"original executable");
        assert_eq!(executable_hash(&path).unwrap(), expected);
        fs::hard_link(&path, &link).unwrap();
        assert_eq!(executable_hash(&path).unwrap(), expected);
        fs::remove_file(&link).unwrap();
        assert_eq!(executable_hash(&path).unwrap(), expected);
        fs::write(&path, b"modified executable").unwrap();
        assert_ne!(executable_hash(&path).unwrap(), expected);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&base).unwrap();
    }

    #[test]
    fn descriptor_reads_reject_symlinks_and_identity_drift() {
        let base = std::env::temp_dir().join(format!("cm-pin-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let path = base.join("input");
        fs::write(&path, b"old").unwrap();
        let (_, pin) = read_input(&path, 3).unwrap();
        assert!(pin.revalidate().is_ok());
        fs::rename(&path, base.join("old")).unwrap();
        fs::write(&path, b"old").unwrap();
        assert!(pin.revalidate().is_err());
        std::os::unix::fs::symlink(&path, base.join("link")).unwrap();
        assert!(read_input(&base.join("link"), 3).is_err());
        std::os::unix::fs::symlink(&base, base.join("directory-link")).unwrap();
        assert!(read_input(&base.join("directory-link/input"), 3).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    #[ignore = "requires the separately built author Mod after Host freeze"]
    fn replacement_and_in_place_edits_cannot_change_preflight_snapshot() {
        let original = fs::read(std::env::var_os("CM_P02_FIXTURE_LIBRARY").unwrap()).unwrap();
        let replacement =
            fs::read(std::env::var_os("CM_P02_REPLACEMENT_LIBRARY").unwrap()).unwrap();
        for replace in [true, false] {
            let home =
                std::env::temp_dir().join(format!("cm-snapshot-{}-{replace}", std::process::id()));
            let package = home.join("mods/fixture");
            fs::create_dir_all(&package).unwrap();
            let path = package.join("payload.so");
            fs::write(&path, &original).unwrap();
            fs::write(package.join("mod.toml"), format!(
                "format_version=1\nid='serial-fixture'\nversion='0.1.0'\npayload='payload.so'\npayload_size={}\npayload_sha256='{}'\ntarget='{}'\nabi_major=1\nabi_minor=0\nrequired_capabilities=['{}']\ndependencies=[]\ncontribution='{}'\n",
                original.len(), hash(&original), TARGET, CAPABILITY, CONTRIBUTION,
            )).unwrap();
            let (manifest, _) = read_manifest(&package).unwrap();
            check_manifest(&manifest).unwrap();
            let (candidate, _) = prepare_package(&package, manifest).unwrap();
            if replace {
                fs::rename(&path, path.with_extension("old")).unwrap();
            }
            fs::write(&path, &replacement).unwrap();
            assert_eq!(
                hash(&fs::read(snapshot_path(&candidate.snapshot)).unwrap()),
                hash(&original)
            );
            let mut loaded = native::NativeMod::load(candidate).unwrap();
            let input = cm_abi::PolicyInput {
                header: cm_abi::Header::of::<cm_abi::PolicyInput>(),
                namespace: cm_abi::Bytes::from_static("functions"),
                tool: cm_abi::Bytes::from_static("exec_command"),
                call_id: cm_abi::Bytes::from_static("snapshot-call"),
                thread_id: cm_abi::Bytes::from_static("snapshot-thread"),
                turn_id: cm_abi::Bytes::from_static("snapshot-turn"),
                original_parallel: 1,
                reserved: 0,
            };
            assert_eq!(loaded.policy(&input).unwrap(), cm_abi::FORCE_SERIAL);
            loaded.release().unwrap();
        }
        assert!(!Path::new(&std::env::var_os("CM_REPLACEMENT_SENTINEL").unwrap()).exists());
    }
}
