use std::collections::BTreeMap;
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
}

impl Kind {
    pub(crate) fn abi(&self) -> u32 {
        match self {
            Self::Before => v2::BEFORE,
            Self::Around => v2::AROUND,
            Self::Replacement => v2::REPLACEMENT,
            Self::After => v2::AFTER,
            Self::LegacyFilter => 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependency {
    pub id: String,
    pub version: String,
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
}

impl Manifest {
    pub(crate) fn hooks(&self) -> Vec<Contribution> {
        if self.format_version == 1 {
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
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    if file_stamp(&metadata) != file_stamp(&file.metadata().map_err(|e| e.to_string())?) {
        return Err("Host executable changed while hashing".into());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn open_at(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File, String> {
    let name = CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory(path: &Path) -> Result<File, String> {
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
        metadata.dev(), metadata.ino(), metadata.len(), metadata.mtime(),
        metadata.mtime_nsec(), metadata.ctime(), metadata.ctime_nsec(),
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
        let (_, current) = read_input(&self.path, self.limit).map_err(|error| format!(
            "locked input {} expected size={} sha256={}: {error}", self.path.display(), self.size, self.sha256))?;
        if self.sha256 != current.sha256 || self.size != current.size
            || self.device != current.device || self.inode != current.inode
        {
            return Err(format!("locked input changed: {} expected size={} sha256={} actual size={} sha256={}", self.path.display(), self.size, self.sha256, current.size, current.sha256));
        }
        Ok(())
    }
}

pub(crate) fn read_input(path: &Path, limit: u64) -> Result<(Vec<u8>, InputPin), String> {
    let parent = open_directory(path.parent().ok_or("missing input parent")?)?;
    let mut file = open_at(&parent, path.file_name().ok_or("missing input name")?, false)?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err("expected a bounded regular file with one link".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit
        || bytes.len() as u64 != before.len()
        || file_stamp(&before) != file_stamp(&file.metadata().map_err(|e| e.to_string())?)
    {
        return Err("input changed while reading or exceeded its bound".into());
    }
    let pin = InputPin {
        path: path.into(), sha256: hash(&bytes), size: bytes.len() as u64, limit,
        device: before.dev(), inode: before.ino(),
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
            return Ok(Inventory { packages: BTreeMap::new(), root: None });
        }
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let directory = open_directory(&root)?;
    let metadata = directory.metadata().map_err(|e| e.to_string())?;
    let mut packages = BTreeMap::new();
    for entry in fs::read_dir(snapshot_path(&directory)).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().into_string().map_err(|_| "package path is not UTF-8")?;
        if packages.len() >= 32 {
            return Err("runtime set exceeds 32 packages".into());
        }
        let package = open_at(&directory, std::ffi::OsStr::new(&name), true)?;
        let metadata = package.metadata().map_err(|e| e.to_string())?;
        packages.insert(name, (metadata.dev(), metadata.ino()));
    }
    Ok(Inventory { packages, root: Some((metadata.dev(), metadata.ino())) })
}

pub(crate) fn payload_path(package: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if relative.is_empty() || relative.len() > 512 || path.is_absolute()
        || !path.components().all(|part| matches!(part, Component::Normal(_)))
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
    !value.is_empty() && value.len() <= 128 && value.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

pub(crate) fn version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn check_manifest(manifest: &Manifest) -> Result<(), String> {
    if !identifier(&manifest.id) || !version(&manifest.version)
        || manifest.target != TARGET || manifest.payload_size == 0
        || manifest.payload_size > MAX_PAYLOAD || !digest(&manifest.payload_sha256)
    {
        return Err("unsupported manifest id/version/target/digest/size".into());
    }
    match manifest.format_version {
        1 if manifest.abi_major == ABI_MAJOR && manifest.abi_minor == ABI_MINOR
            && manifest.contribution == CONTRIBUTION
            && manifest.required_capabilities == [CAPABILITY]
            && manifest.dependencies.is_empty() && manifest.conflicts.is_empty()
            && manifest.contributions.is_empty() && manifest.resources.is_empty() => {}
        2 if manifest.abi_major == v2::ABI_MAJOR && manifest.abi_minor == v2::ABI_MINOR
            && manifest.contribution.is_empty()
            && manifest.required_capabilities == [v2::CAPABILITY]
            && !manifest.contributions.is_empty()
            && manifest.contributions.len() <= MAX_CONTRIBUTIONS => {}
        _ => return Err("unsupported manifest format/ABI/capability/contribution".into()),
    }
    Ok(())
}

pub(crate) fn read_manifest(package: &Path) -> Result<(Manifest, InputPin), String> {
    let (bytes, pin) = read_input(&package.join("mod.toml"), MAX_MANIFEST)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let manifest = toml::from_str(text).map_err(|e| format!("manifest: {e}"))?;
    Ok((manifest, pin))
}

pub(crate) fn prepare_package(
    package: &Path,
    manifest: Manifest,
) -> Result<(Preflighted, Vec<InputPin>), String> {
    let (bytes, pin) = read_input(&payload_path(package, &manifest.payload)?, MAX_PAYLOAD)?;
    if pin.size != manifest.payload_size || pin.sha256 != manifest.payload_sha256 {
        return Err("payload size or SHA-256 mismatch".into());
    }
    let needed = elf::check(&bytes)?;
    let snapshot = sealed_snapshot(&bytes)?;
    let mut pins = vec![pin];
    let mut resources = Vec::new();
    for resource in &manifest.resources {
        if resource.size > MAX_RESOURCE || !digest(&resource.sha256) {
            return Err("invalid resource size or digest".into());
        }
        let (bytes, pin) = read_input(&payload_path(package, &resource.path)?, MAX_RESOURCE)?;
        if pin.size != resource.size || pin.sha256 != resource.sha256 {
            return Err(format!("resource size or SHA-256 mismatch: {}", resource.path));
        }
        resources.push(ResourceSnapshot { path: resource.path.clone(), bytes });
        pins.push(pin);
    }
    resources.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((Preflighted { manifest, snapshot, needed, resources }, pins))
}

pub(crate) fn sealed_snapshot(bytes: &[u8]) -> Result<File, String> {
    // Seal the verified buffer, never reopen the package path for dlopen.
    let fd = unsafe {
        libc::memfd_create(c"cm-mod-v1".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
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
        return Err(format!("required memfd seals unavailable: {}", std::io::Error::last_os_error()));
    }
    let mut snapshot = File::open(format!("/proc/self/fd/{fd}")).map_err(|e| e.to_string())?;
    let mut sealed = Vec::new();
    snapshot.read_to_end(&mut sealed).map_err(|e| e.to_string())?;
    if hash(&sealed) != hash(bytes) {
        return Err("sealed payload identity drift".into());
    }
    snapshot.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
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
        for value in ["", "/tmp/x.so", "../x.so", "bin/../../x.so"] {
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
        let replacement = fs::read(std::env::var_os("CM_P02_REPLACEMENT_LIBRARY").unwrap()).unwrap();
        for replace in [true, false] {
            let home = std::env::temp_dir().join(format!("cm-snapshot-{}-{replace}", std::process::id()));
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
            assert_eq!(hash(&fs::read(snapshot_path(&candidate.snapshot)).unwrap()), hash(&original));
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
