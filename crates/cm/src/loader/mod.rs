use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Component;
use std::path::Path;

use cm_abi::ABI_MAJOR;
use cm_abi::ABI_MINOR;
use cm_abi::CAPABILITY;
use cm_abi::CONTRIBUTION;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;

mod elf;
pub(crate) mod native;

const MAX_MANIFEST: u64 = 64 * 1024;
pub(crate) const MAX_PAYLOAD: u64 = 64 * 1024 * 1024;
pub const TARGET: &str = "x86_64-unknown-linux-gnu";

#[derive(Debug, Deserialize)]
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
    pub dependencies: Vec<String>,
    pub contribution: String,
}

pub(crate) struct Preflighted {
    pub manifest: Manifest,
    pub snapshot: File,
    pub needed: Vec<String>,
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn plain_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        return Err("expected a bounded regular file with one link".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("file grew beyond its limit".into());
    }
    Ok(bytes)
}

fn plain_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "expected a non-symlink directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn payload_path(package: &Path, relative: &str) -> Result<std::path::PathBuf, String> {
    let path = Path::new(relative);
    if relative.is_empty()
        || relative.len() > 512
        || path.is_absolute()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("payload must be a bounded package-relative normal path".into());
    }
    let full = package.join(path);
    let mut parent = package.to_path_buf();
    for part in path.parent().into_iter().flat_map(Path::components) {
        parent.push(part.as_os_str());
        plain_directory(&parent)?;
    }
    Ok(full)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn check_manifest(manifest: &Manifest) -> Result<(), String> {
    if manifest.format_version != 1
        || !identifier(&manifest.id)
        || manifest.version.is_empty()
        || manifest.version.len() > 128
        || !manifest
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        || manifest.target != TARGET
        || manifest.abi_major != ABI_MAJOR
        || manifest.abi_minor != ABI_MINOR
        || manifest.contribution != CONTRIBUTION
        || manifest.required_capabilities != [CAPABILITY]
        || !manifest.dependencies.is_empty()
        || manifest.payload_size == 0
        || manifest.payload_size > MAX_PAYLOAD
        || manifest.payload_sha256.len() != 64
        || !manifest
            .payload_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("unsupported manifest format/id/version/target/ABI/capability/dependency/contribution/digest/size".into());
    }
    Ok(())
}

fn sealed_snapshot(bytes: &[u8]) -> Result<File, String> {
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

pub(crate) fn prepare(home: &Path) -> Result<Option<Preflighted>, String> {
    if !home.is_absolute() {
        return Err("CM profile must be absolute".into());
    }
    let root = home.join("mods");
    match fs::symlink_metadata(&root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
        Ok(_) => plain_directory(&root)?,
    }
    let entries = fs::read_dir(&root)
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if entries.len() > 1 {
        return Err(
            "P02 accepts at most one contribution owner; no candidate is silently skipped".into(),
        );
    }
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    let package = entry.path();
    plain_directory(&package)?;
    let text = String::from_utf8(plain_file(&package.join("mod.toml"), MAX_MANIFEST)?)
        .map_err(|e| e.to_string())?;
    let manifest: Manifest = toml::from_str(&text).map_err(|e| format!("manifest: {e}"))?;
    check_manifest(&manifest)?;
    let bytes = plain_file(&payload_path(&package, &manifest.payload)?, MAX_PAYLOAD)?;
    if bytes.len() as u64 != manifest.payload_size || hash(&bytes) != manifest.payload_sha256 {
        return Err("payload size or SHA-256 mismatch".into());
    }
    let needed = elf::check(&bytes)?;
    let snapshot = sealed_snapshot(&bytes)?;
    Ok(Some(Preflighted {
        manifest,
        snapshot,
        needed,
    }))
}

pub(crate) fn snapshot_path(snapshot: &File) -> std::path::PathBuf {
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
    }

    #[test]
    fn seals_pin_bytes_and_disallow_writes() {
        let snapshot = sealed_snapshot(b"verified bytes").unwrap();
        let path = snapshot_path(&snapshot);
        assert_eq!(fs::read(&path).unwrap(), b"verified bytes");
        let mut writer = OpenOptions::new().write(true).open(path).unwrap();
        assert!(writer.write_all(b"changed bytes!").is_err());
    }

    #[test]
    #[ignore = "requires the separately built author Mod after Host freeze"]
    fn replacement_and_in_place_edits_cannot_change_preflight_snapshot() {
        let library = std::env::var_os("CM_P02_FIXTURE_LIBRARY").unwrap();
        let original = fs::read(library).unwrap();
        let replacement =
            fs::read(std::env::var_os("CM_P02_REPLACEMENT_LIBRARY").unwrap()).unwrap();
        for replace in [true, false] {
            let home =
                std::env::temp_dir().join(format!("cm-snapshot-{}-{replace}", std::process::id()));
            let package = home.join("mods/fixture");
            fs::create_dir_all(&package).unwrap();
            let path = package.join("payload.so");
            fs::write(&path, &original).unwrap();
            fs::write(
                package.join("mod.toml"),
                format!(
                    "format_version=1\nid='serial-fixture'\nversion='0.1.0'\npayload='payload.so'\npayload_size={}\npayload_sha256='{}'\ntarget='{}'\nabi_major=1\nabi_minor=0\nrequired_capabilities=['{}']\ndependencies=[]\ncontribution='{}'\n",
                    original.len(),
                    hash(&original),
                    TARGET,
                    CAPABILITY,
                    CONTRIBUTION,
                ),
            )
            .unwrap();
            let candidate = prepare(&home).unwrap().unwrap();
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
            fs::remove_dir_all(home).unwrap();
        }
        let sentinel = std::env::var_os("CM_REPLACEMENT_SENTINEL").unwrap();
        assert!(!Path::new(&sentinel).exists());
    }
}
