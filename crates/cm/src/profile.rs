//! Immutable package generations; only cm-profile.json changes at activation.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::LoadError;
use crate::loader::{self, InputPin};
use crate::package::ManagedHost;

const LIMIT: u64 = 4 * 1024 * 1024;
const OWNER: &[u8] = b"{\"schema_version\":1,\"domain\":\"cm.home.v1\"}\n";
static TEMP: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! { static FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }

fn fault(point: u8) -> Result<(), LoadError> {
    #[cfg(test)]
    if FAULT.get() == point {
        return Err(failure(if point == 4 {
            "committed: injected post-rename sync failure"
        } else {
            "injected pre-commit failure"
        }));
    }
    let _ = point;
    Ok(())
}

pub(crate) fn failure(message: &str) -> LoadError {
    LoadError::input(
        if message.starts_with("committed:") {
            "committed_durability"
        } else {
            "managed_profile"
        },
        "",
        message,
    )
}

pub(crate) fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    crate::config::json_bytes(&serde_json::to_value(value).expect("profile DTO serializes"))
}

pub(crate) fn validate_environment(home: &Path) -> Result<(), LoadError> {
    for name in ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"] {
        if std::env::var_os(name).is_some() {
            return Err(failure(
                "managed execution rejects loader and remote executor environment overrides",
            ));
        }
    }
    if std::env::vars_os()
        .any(|(name, _)| name.as_encoded_bytes().starts_with(b"CODEX_EXEC_SERVER_"))
        || present(&home.join("environments.toml"))?
    {
        return Err(failure(
            "managed execution does not support executor environment overrides or environments.toml",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Generation {
    pub schema_version: u32,
    pub domain: String,
    pub installed: BTreeMap<String, String>,
    pub enabled: BTreeSet<String>,
    pub consumed: BTreeSet<String>,
    pub config_sha256: Option<String>,
    pub lock_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<crate::state::View>,
}

impl Default for Generation {
    fn default() -> Self {
        Self {
            schema_version: 1,
            domain: "cm.generation.v1".into(),
            installed: BTreeMap::new(),
            enabled: BTreeSet::new(),
            consumed: BTreeSet::new(),
            config_sha256: None,
            lock_sha256: String::new(),
            state: None,
        }
    }
}

impl Generation {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let format = match (self.schema_version, self.domain.as_str(), &self.state) {
            (1, "cm.generation.v1", None) => true,
            (2, "cm.generation.v2", Some(state)) => state.validate().is_ok(),
            _ => false,
        };
        if !format
            || self.installed.len() > 32
            || self.consumed.len() > 4096
            || self
                .installed
                .iter()
                .any(|(id, sha)| !loader::identifier(id) || !loader::digest(sha))
            || self
                .enabled
                .iter()
                .any(|id| !self.installed.contains_key(id))
            || self.consumed.iter().any(|sha| !loader::digest(sha))
            || self
                .config_sha256
                .as_deref()
                .is_some_and(|s| !loader::digest(s))
            || (!self.lock_sha256.is_empty() && !loader::digest(&self.lock_sha256))
        {
            return Err("invalid managed generation".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Active {
    pub schema_version: u32,
    pub domain: String,
    pub host: ManagedHost,
    pub generation: String,
}

pub(crate) struct Snapshot {
    pub generation: Generation,
    pub host: ManagedHost,
    pub generation_id: String,
    home: PathBuf,
    root_identity: (u64, u64),
    pins: Vec<InputPin>,
}

impl Snapshot {
    pub(crate) fn packages(&self) -> Vec<(String, PathBuf, String)> {
        self.generation
            .installed
            .iter()
            .map(|(id, sha)| {
                (
                    id.clone(),
                    self.home.join("store/objects").join(sha),
                    sha.clone(),
                )
            })
            .collect()
    }

    pub(crate) fn revalidate(&self) -> Result<(), LoadError> {
        let directory = Directory::open(&self.home).map_err(|e| failure(&e))?;
        if identity(&directory.file)? != self.root_identity {
            return Err(failure("managed home identity changed"));
        }
        for pin in &self.pins {
            pin.revalidate().map_err(|e| failure(&e))?;
        }
        Ok(())
    }

    pub(crate) fn candidate(
        home: &Path,
        host: ManagedHost,
        generation: Generation,
    ) -> Result<Self, LoadError> {
        generation.validate().map_err(|e| failure(&e))?;
        let directory = Directory::open(home).map_err(|e| failure(&e))?;
        let (marker, pin) =
            loader::read_input(&home.join(".cm-owner"), 128).map_err(|e| failure(&e))?;
        if marker != OWNER {
            return Err(failure("invalid CM ownership marker"));
        }
        Ok(Self {
            generation_id: loader::hash(&canonical(&generation)),
            generation,
            host,
            home: home.into(),
            root_identity: identity(&directory.file)?,
            pins: vec![pin],
        })
    }
}

fn identity(file: &File) -> Result<(u64, u64), LoadError> {
    file.metadata()
        .map(|m| (m.dev(), m.ino()))
        .map_err(|e| failure(&e.to_string()))
}

fn present(path: &Path) -> Result<bool, LoadError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(failure(&e.to_string())),
    }
}

pub(crate) fn managed(home: &Path) -> Result<bool, LoadError> {
    if !present(&home.join(".cm-owner"))? {
        if present(&home.join("cm-profile.json"))? {
            return Err(failure(
                "unmarked managed descriptor; refusing profile takeover",
            ));
        }
        return Ok(false);
    }
    Directory::open(home).map_err(|e| failure(&e))?;
    let (bytes, _) = loader::read_input(&home.join(".cm-owner"), 128).map_err(|e| failure(&e))?;
    if bytes != OWNER {
        return Err(failure("invalid CM ownership marker"));
    }
    Ok(true)
}

pub(crate) fn snapshot(home: &Path) -> Result<Option<Snapshot>, LoadError> {
    snapshot_for(home, true)
}

pub(crate) fn snapshot_for(home: &Path, honor_launch: bool) -> Result<Option<Snapshot>, LoadError> {
    if !managed(home)? {
        return Ok(None);
    }
    let (bytes, active_pin) =
        loader::read_input(&home.join("cm-profile.json"), LIMIT).map_err(|e| failure(&e))?;
    let active: Active =
        serde_json::from_slice(&bytes).map_err(|_| failure("invalid active descriptor"))?;
    if active.schema_version != 1
        || active.domain != "cm.profile.v1"
        || !loader::digest(&active.generation)
        || canonical(&active) != bytes
        || active.host != crate::package::managed_identity()?
    {
        return Err(failure("active descriptor/Host identity mismatch"));
    }
    let generation_id = match std::env::var_os("CM_MANAGED_GENERATION").filter(|_| honor_launch) {
        Some(value) => {
            if std::env::var_os("CM_MANAGED_HOME").as_deref() != Some(home.as_os_str()) {
                return Err(failure("managed launch home mismatch"));
            }
            let value = value
                .into_string()
                .map_err(|_| failure("non-UTF8 generation identity"))?;
            if !loader::digest(&value) {
                return Err(failure("invalid launch generation"));
            }
            value
        }
        None => active.generation,
    };
    let (bytes, generation_pin) =
        loader::read_input(&home.join("store/generations").join(&generation_id), LIMIT)
            .map_err(|e| failure(&e))?;
    if loader::hash(&bytes) != generation_id {
        return Err(failure("generation digest mismatch"));
    }
    let generation: Generation =
        serde_json::from_slice(&bytes).map_err(|_| failure("invalid generation"))?;
    generation.validate().map_err(|e| failure(&e))?;
    if generation.lock_sha256.is_empty() {
        return Err(failure("generation has no validated lock identity"));
    }
    if canonical(&generation) != bytes {
        return Err(failure("noncanonical generation"));
    }
    let mut result = Snapshot::candidate(home, active.host, generation)?;
    result.generation_id = generation_id;
    result.pins.extend([active_pin, generation_pin]);
    Ok(Some(result))
}

pub(crate) struct Directory {
    pub file: File,
    pub path: PathBuf,
}

impl Directory {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let file = loader::open_directory(path)?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("managed directory must be owned by this user and private (0700)".into());
        }
        Ok(Self {
            file,
            path: path.into(),
        })
    }

    pub(crate) fn child(&self, name: &str) -> Result<Self, String> {
        let name_c = CString::new(name).map_err(|e| e.to_string())?;
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let file = loader::open_at(&self.file, OsStr::new(name), true)?;
        let result = Self {
            file,
            path: self.path.join(name),
        };
        result.check()?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        Ok(result)
    }

    pub(crate) fn check(&self) -> Result<(), String> {
        let current = loader::open_directory(&self.path)?;
        let old = self.file.metadata().map_err(|e| e.to_string())?;
        let now = current.metadata().map_err(|e| e.to_string())?;
        if (old.dev(), old.ino()) != (now.dev(), now.ino())
            || now.uid() != unsafe { libc::geteuid() }
            || now.mode() & 0o077 != 0
        {
            return Err("managed directory identity/ownership changed".into());
        }
        Ok(())
    }

    pub(crate) fn create_file(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let name = CString::new(name).map_err(|e| e.to_string())?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            unsafe {
                libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0);
            }
            return Err(error.to_string());
        }
        Ok(())
    }

    pub(crate) fn publish(&self, temporary: &str, target: &str) -> Result<bool, String> {
        self.check()?;
        let source = CString::new(temporary).map_err(|e| e.to_string())?;
        let target = CString::new(target).map_err(|e| e.to_string())?;
        if unsafe {
            libc::renameat2(
                self.file.as_raw_fd(),
                source.as_ptr(),
                self.file.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0
        {
            self.file.sync_all().map_err(|e| e.to_string())?;
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(error.to_string())
        }
    }
}

pub(crate) fn temporary(kind: &str) -> String {
    format!(
        ".{kind}.{}.{}.tmp",
        std::process::id(),
        TEMP.fetch_add(1, Ordering::Relaxed)
    )
}

/// Removes only this operation's private, never-published staging tree.
pub(crate) fn discard(parent: &Directory, name: &str) -> Result<(), String> {
    let c_name = CString::new(name).map_err(|e| e.to_string())?;
    let file = loader::open_at(&parent.file, OsStr::new(name), true)?;
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|e| e.to_string())?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let entry_name = entry.file_name();
        let directory = loader::open_at(&file, &entry_name, true);
        let leaf = CString::new(entry_name.as_bytes()).map_err(|e| e.to_string())?;
        if directory.is_ok() {
            let child = Directory {
                file: file.try_clone().map_err(|e| e.to_string())?,
                path: parent.path.join(name),
            };
            discard(&child, entry_name.to_str().ok_or("non-UTF8 staging name")?)?;
        } else if unsafe { libc::unlinkat(file.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    if unsafe { libc::unlinkat(parent.file.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR) } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(crate) struct Transaction {
    pub root: Directory,
    pub objects: Directory,
    pub generations: Directory,
    pub next: Generation,
    pub host: ManagedHost,
    lock: File,
    old: Option<InputPin>,
    pinned_inputs: Vec<InputPin>,
    pinned_directories: Vec<Directory>,
    pub(crate) state_guard: Option<crate::state::Guard>,
}

impl Transaction {
    pub(crate) fn revalidate(&self) -> Result<(), LoadError> {
        for directory in [&self.root, &self.objects, &self.generations]
            .into_iter()
            .chain(self.pinned_directories.iter())
        {
            directory.check().map_err(|e| failure(&e))?;
        }
        let current_lock = loader::open_at(&self.root.file, OsStr::new(".cm-write.lock"), false)
            .map_err(|e| failure(&e))?;
        if identity(&self.lock)? != identity(&current_lock)? {
            return Err(failure("write lock identity changed"));
        }
        for pin in &self.pinned_inputs {
            pin.revalidate().map_err(|e| failure(&e))?;
        }
        if let Some(old) = &self.old {
            old.revalidate().map_err(|e| failure(&e))?;
        } else if present(&self.root.path.join("cm-profile.json"))? {
            return Err(failure("concurrent active descriptor appeared"));
        }
        Ok(())
    }

    pub(crate) fn begin(home: &Path, host: ManagedHost) -> Result<Self, LoadError> {
        let result = (|| -> Result<Self, String> {
            if !home.is_absolute() || home == Path::new("/") {
                return Err("CM home must be an absolute independent directory".into());
            }
            let package = host
                .executable
                .parent()
                .and_then(Path::parent)
                .ok_or("missing Host root")?;
            let official = std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|p| p.join(".codex"));
            if home.starts_with(package)
                || package.starts_with(home)
                || official
                    .as_ref()
                    .is_some_and(|p| home.starts_with(p) || p.starts_with(home))
            {
                return Err("CM home overlaps Host package or official profile".into());
            }
            if !home.exists() {
                let parent = loader::open_directory(home.parent().ok_or("missing home parent")?)?;
                let name = CString::new(home.file_name().ok_or("missing home name")?.as_bytes())
                    .map_err(|e| e.to_string())?;
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                parent.sync_all().map_err(|e| e.to_string())?;
            }
            let raw = loader::open_directory(home)?;
            if !managed(home).map_err(|e| e.to_string())? {
                if std::fs::read_dir(format!("/proc/self/fd/{}", raw.as_raw_fd()))
                    .map_err(|e| e.to_string())?
                    .next()
                    .is_some()
                {
                    return Err("refusing to adopt a nonempty, unmarked profile".into());
                }
                if raw.metadata().map_err(|e| e.to_string())?.uid() != unsafe { libc::geteuid() }
                    || unsafe { libc::fchmod(raw.as_raw_fd(), 0o700) } != 0
                {
                    return Err("cannot own private CM home".into());
                }
                let root = Directory {
                    file: raw,
                    path: home.into(),
                };
                root.create_file(".cm-owner", OWNER)?;
                root.file.sync_all().map_err(|e| e.to_string())?;
            }
            let root = Directory::open(home)?;
            let lock_name = c".cm-write.lock";
            let fd = unsafe {
                libc::openat(
                    root.file.as_raw_fd(),
                    lock_name.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let lock = unsafe { File::from_raw_fd(fd) };
            let metadata = lock.metadata().map_err(|e| e.to_string())?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            {
                return Err("profile write lock is busy or unsafe".into());
            }
            let store = root.child("store")?;
            let objects = store.child("objects")?;
            let generations = store.child("generations")?;
            let inbox = root.child("mods")?;
            let (marker, owner_pin) = loader::read_input(&home.join(".cm-owner"), 128)?;
            if marker != OWNER {
                return Err("invalid CM ownership marker".into());
            }
            let old = if present(&home.join("cm-profile.json")).map_err(|e| e.to_string())? {
                Some(loader::read_input(&home.join("cm-profile.json"), LIMIT)?.1)
            } else {
                None
            };
            let active = if old.is_some() {
                snapshot_for(home, false).map_err(|e| e.to_string())?
            } else {
                None
            };
            if let Some(old) = &old {
                old.revalidate()?;
            }
            let mut pinned_inputs = vec![owner_pin];
            let next = if let Some(active) = active {
                pinned_inputs.extend(active.pins);
                active.generation
            } else {
                Generation::default()
            };
            Ok(Self {
                root,
                objects,
                generations,
                host,
                lock,
                old,
                next,
                pinned_inputs,
                pinned_directories: vec![store, inbox],
                state_guard: None,
            })
        })();
        result.map_err(|e| failure(&e))
    }

    pub(crate) fn commit(
        mut self,
        options: &crate::config::Options,
    ) -> Result<serde_json::Value, LoadError> {
        let config = self.root.path.join("cm-runtime.toml");
        self.next.validate().map_err(|e| failure(&e))?;
        self.next.config_sha256 = if present(&config)? {
            Some(
                loader::read_input(&config, loader::MAX_MANIFEST)
                    .map_err(|e| failure(&e))?
                    .1
                    .sha256,
            )
        } else {
            None
        };
        let snapshot = Snapshot::candidate(&self.root.path, self.host.clone(), self.next.clone())?;
        let prepared = crate::runtime_plan::prepare_managed(&self.root.path, options, snapshot)?;
        prepared.revalidate()?;
        crate::state::reconcile(&mut self, prepared.state_contracts())?;
        let mut next = self.next.clone();
        next.lock_sha256 = loader::hash(&crate::mod_lock::canonical(prepared.plan()));
        let bytes = canonical(&next);
        if bytes.len() as u64 > LIMIT {
            return Err(failure("generation exceeds byte limit"));
        }
        let generation = loader::hash(&bytes);
        let name = temporary("generation");
        self.generations
            .create_file(&name, &bytes)
            .map_err(|e| failure(&e))?;
        let publication = self.generations.publish(&name, &generation);
        if publication.is_err() {
            let temporary = CString::new(name.as_str()).expect("temporary name");
            unsafe {
                libc::unlinkat(self.generations.file.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        let published = publication.map_err(|e| failure(&e))?;
        if !published {
            let c_name = CString::new(name).expect("temporary name");
            unsafe {
                libc::unlinkat(self.generations.file.as_raw_fd(), c_name.as_ptr(), 0);
            }
            let (existing, _) = loader::read_input(&self.generations.path.join(&generation), LIMIT)
                .map_err(|e| failure(&e))?;
            if existing != bytes {
                return Err(failure("existing generation differs from its address"));
            }
        }
        fault(2)?;
        let active = Active {
            schema_version: 1,
            domain: "cm.profile.v1".into(),
            host: self.host.clone(),
            generation,
        };
        let name = temporary("profile");
        let result = (|| -> Result<(), LoadError> {
            self.root
                .create_file(&name, &canonical(&active))
                .map_err(|e| failure(&e))?;
            prepared.revalidate()?;
            self.revalidate()?;
            fault(3)?;
            if let Some(guard) = &self.state_guard {
                guard.revalidate()?;
            }
            let source = CString::new(name.as_str()).expect("temporary name");
            if unsafe {
                libc::renameat(
                    self.root.file.as_raw_fd(),
                    source.as_ptr(),
                    self.root.file.as_raw_fd(),
                    c"cm-profile.json".as_ptr(),
                )
            } != 0
            {
                return Err(failure("active descriptor rename failed"));
            }
            fault(4)?;
            self.root.file.sync_all().map_err(|_| {
                failure("committed: active descriptor renamed; directory durability is uncertain")
            })?;
            Ok(())
        })();
        if result.is_err() {
            let source = CString::new(name).expect("temporary name");
            unsafe {
                libc::unlinkat(self.root.file.as_raw_fd(), source.as_ptr(), 0);
            }
        }
        result?;
        Ok(
            serde_json::json!({"schema_version":1, "committed":true, "generation":active.generation,
            "installed":next.installed, "enabled":next.enabled, "restart_required":true,
            "data_preserved":true, "already_native_executed":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    fn root() -> PathBuf {
        let path = std::env::temp_dir().join(temporary("cm-profile-test"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        path
    }

    fn host() -> ManagedHost {
        ManagedHost {
            executable: PathBuf::from("/cm-test-host/bin/codex"),
            executable_sha256: "a".repeat(64),
            inventory_sha256: "b".repeat(64),
            target: loader::TARGET.into(),
        }
    }

    #[test]
    fn nonempty_unmarked_home_and_concurrent_writer_are_rejected() {
        let home = root();
        std::fs::write(home.join("official-state"), b"preserve").unwrap();
        assert!(Transaction::begin(&home, host()).is_err());
        assert_eq!(
            std::fs::read(home.join("official-state")).unwrap(),
            b"preserve"
        );
        std::fs::remove_file(home.join("official-state")).unwrap();
        let first = Transaction::begin(&home, host()).unwrap();
        assert!(Transaction::begin(&home, host()).is_err());
        drop(first);
        assert!(Transaction::begin(&home, host()).is_ok());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn descriptor_is_unchanged_before_commit_and_truthful_after_rename() {
        for point in [2, 3, 4] {
            let home = root();
            let mut transaction = Transaction::begin(&home, host()).unwrap();
            let old = b"old descriptor bytes";
            std::fs::write(home.join("cm-profile.json"), old).unwrap();
            transaction.old = Some(
                loader::read_input(&home.join("cm-profile.json"), LIMIT)
                    .unwrap()
                    .1,
            );
            FAULT.set(point);
            let error = transaction
                .commit(&crate::config::Options::default())
                .unwrap_err();
            FAULT.set(0);
            let bytes = std::fs::read(home.join("cm-profile.json")).unwrap();
            if point < 4 {
                assert_eq!(bytes, old);
                assert_ne!(error.code, "committed_durability");
            } else {
                assert_eq!(error.code, "committed_durability");
                let active: Active = serde_json::from_slice(&bytes).unwrap();
                let generation =
                    std::fs::read(home.join("store/generations").join(&active.generation)).unwrap();
                assert_eq!(loader::hash(&generation), active.generation);
                let generation: Generation = serde_json::from_slice(&generation).unwrap();
                assert!(!generation.lock_sha256.is_empty());
            }
            assert!(
                std::fs::read_dir(&home).unwrap().all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
            );
            std::fs::remove_dir_all(home).unwrap();
        }
    }

    #[test]
    fn swapped_profile_inputs_never_commit() {
        for name in ["cm-profile.json", ".cm-owner", ".cm-write.lock"] {
            let home = root();
            let mut transaction = Transaction::begin(&home, host()).unwrap();
            let old = b"old descriptor bytes";
            std::fs::write(home.join("cm-profile.json"), old).unwrap();
            transaction.old = Some(
                loader::read_input(&home.join("cm-profile.json"), LIMIT)
                    .unwrap()
                    .1,
            );
            let path = home.join(name);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::rename(&path, home.join("swapped-input")).unwrap();
            std::fs::write(&path, bytes).unwrap();
            assert!(
                transaction
                    .commit(&crate::config::Options::default())
                    .is_err()
            );
            assert_eq!(std::fs::read(home.join("cm-profile.json")).unwrap(), old);
            std::fs::remove_dir_all(home).unwrap();
        }
    }

    #[test]
    fn cas_publication_never_replaces_existing_content() {
        let home = root();
        let directory = Directory::open(&home).unwrap();
        directory.create_file("old", b"old").unwrap();
        directory.create_file("new", b"new").unwrap();
        assert!(!directory.publish("new", "old").unwrap());
        assert_eq!(std::fs::read(home.join("old")).unwrap(), b"old");
        assert_eq!(std::fs::read(home.join("new")).unwrap(), b"new");
        std::fs::remove_dir_all(home).unwrap();
    }
}
