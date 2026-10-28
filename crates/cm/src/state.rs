//! Owned file state is separate from the ABI's process-local scope values.
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::LoadError;
use crate::config::Options;
use crate::loader::{self, Manifest};
use crate::package::ManagedHost;
use crate::profile::{self, Directory, Generation, Snapshot, Transaction};

pub(crate) const CAPABILITY: &str = "state.files.v1";
const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_CHECKPOINT: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ENTRIES: usize = MAX_ENTRIES * 32;

type Result<T> = std::result::Result<T, LoadError>;

fn failure(code: &str, message: &str) -> LoadError {
    LoadError::input(code, "", message)
}

fn io(error: std::io::Error) -> LoadError {
    failure(
        "state_ownership",
        &format!("managed state filesystem operation failed: {:?}", error.kind()),
    )
}

pub(crate) fn component(value: &str) -> bool {
    loader::identifier(value) && value != "." && value != ".."
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Owner {
    pub schema: String,
    pub version: u32,
    pub object_sha256: String,
}

impl Owner {
    fn validate(&self) -> bool {
        component(&self.schema) && self.version > 0 && loader::digest(&self.object_sha256)
    }

    fn compatible(&self, other: &Self) -> bool {
        self.schema == other.schema && self.version == other.version
    }

    fn relative(&self, id: &str) -> String {
        format!("{id}/{}/{}", self.schema, self.version)
    }
}

pub(crate) fn declaration(manifest: &Manifest, object: &str) -> Result<Option<Owner>> {
    if !manifest.required_capabilities.iter().any(|cap| cap == CAPABILITY) {
        return Ok(None);
    }
    let state = manifest.binary_manifest.as_ref().and_then(|m| m.state.as_ref());
    let Some(state) = state else {
        return Err(failure("state_compatibility", "file state requires a format 3 declaration"));
    };
    let owner = Owner {
        schema: state.schema.clone(),
        version: state.version,
        object_sha256: object.into(),
    };
    if state.owner != manifest.id || !component(&state.owner) || !owner.validate() {
        return Err(failure("state_ownership", "invalid file state owner/schema/version"));
    }
    Ok(Some(owner))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    tree: String,
    owner: String,
    schema: String,
    version: u32,
    operation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct View {
    schema_version: u32,
    domain: String,
    home_id: String,
    tree: String,
    owners: BTreeMap<String, Owner>,
    cleanups: BTreeMap<String, Cleanup>,
}

impl View {
    pub(crate) fn contains_owner(&self, id: &str) -> bool {
        self.owners.contains_key(id)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.domain != "cm.file-state.v1"
            || !loader::digest(&self.home_id)
            || !loader::digest(&self.tree)
            || self.owners.len() > 4096
            || self.cleanups.len() > 4096
            || self.owners.iter().any(|(id, owner)| !component(id) || !owner.validate())
            || self.cleanups.iter().any(|(id, operation)| {
                !component(id)
                    || id != &operation.owner
                    || !component(&operation.schema)
                    || operation.version == 0
                    || !loader::digest(&operation.tree)
                    || !loader::digest(&operation.operation)
            })
        {
            return Err(failure("state_ownership", "invalid versioned state view"));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    schema_version: u32,
    domain: String,
    home_id: String,
    home_device: u64,
    home_inode: u64,
    state_device: u64,
    state_inode: u64,
    lease_device: u64,
    lease_inode: u64,
}

impl Identity {
    fn validate(&self, bytes: &[u8], home: &Directory, root: &Directory, lease: &File) -> Result<()> {
        let home = home.file.metadata().map_err(io)?;
        let root = root.file.metadata().map_err(io)?;
        let lease = lease.metadata().map_err(io)?;
        if self.schema_version != 1 || self.domain != "cm.state-home.v1"
            || !loader::digest(&self.home_id) || profile::canonical(self) != bytes
            || (self.home_device, self.home_inode) != (home.dev(), home.ino())
            || (self.state_device, self.state_inode) != (root.dev(), root.ino())
            || (self.lease_device, self.lease_inode) != (lease.dev(), lease.ino())
        {
            return Err(failure("state_ownership", "invalid state home identity"));
        }
        Ok(())
    }
}

fn random_id() -> Result<String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut bytes)).map_err(io)?;
    Ok(loader::hash(&bytes))
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io(error)),
    }
}

fn names(directory: &Directory) -> Result<BTreeSet<String>> {
    directory.check().map_err(|_| failure("input_drift", "state directory changed"))?;
    let mut result = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.file.as_raw_fd())).map_err(io)? {
        let name = entry.map_err(io)?.file_name();
        let name = name.to_str().ok_or_else(|| failure("state_ownership", "non-UTF8 state path"))?;
        if name.is_empty() || name == "." || name == ".." || name.len() > 512 {
            return Err(failure("state_ownership", "invalid state path component"));
        }
        if result.len() >= MAX_TOTAL_ENTRIES {
            return Err(failure("state_budget", "state entry budget exceeded"));
        }
        result.insert(name.to_owned());
    }
    Ok(result)
}

fn open_child(parent: &Directory, name: &str) -> Result<Directory> {
    let file = loader::open_at(&parent.file, OsStr::new(name), true)
        .map_err(|_| failure("state_ownership", "expected owned state directory"))?;
    let child = Directory { file, path: parent.path.join(name) };
    child.check().map_err(|_| failure("state_ownership", "unsafe state directory"))?;
    Ok(child)
}

fn regular(parent: &Directory, name: &str) -> Result<File> {
    let name = CString::new(name).map_err(|_| failure("state_ownership", "invalid file name"))?;
    let fd = unsafe {
        libc::openat(
            parent.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(failure("state_ownership", "state file is absent or is a link"));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7077 != 0
    {
        return Err(failure("state_ownership", "state must be a private regular file with one link"));
    }
    Ok(file)
}

struct Store {
    home: Directory,
    root: Directory,
    trees: Directory,
    checkpoints: Directory,
    lease: File,
    identity: Pin,
    home_id: String,
}

impl Store {
    fn open(home: &Path, exclusive: bool) -> Result<Self> {
        let home = Directory::open(home).map_err(|_| failure("state_ownership", "unsafe CM home"))?;
        let state = home.child("state").map_err(|_| failure("state_ownership", "unsafe state parent"))?;
        let root = state.child("cm-files-v1").map_err(|_| failure("state_ownership", "unsafe state namespace"))?;
        let identity_path = root.path.join("identity.json");
        if !present(&identity_path)?
            && names(&root)?.iter().any(|name| {
                name != ".lease" && !(name.starts_with(".identity.") && name.ends_with(".tmp"))
            })
        {
            return Err(failure("state_ownership", "refusing to adopt an unmarked state namespace"));
        }
        let fd = unsafe {
            libc::openat(
                root.file.as_raw_fd(),
                c".lease".as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(failure("state_ownership", "unsafe state lease"));
        }
        let lease = unsafe { File::from_raw_fd(fd) };
        let metadata = lease.metadata().map_err(io)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7077 != 0
        {
            return Err(failure("state_ownership", "unsafe state lease"));
        }
        let kind = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
        if unsafe { libc::flock(lease.as_raw_fd(), kind | libc::LOCK_NB) } != 0 {
            return Err(failure("state_busy", "state is in use; exit CM runtimes before this operation"));
        }
        if !present(&identity_path)? {
            let home_metadata = home.file.metadata().map_err(io)?;
            let state_metadata = root.file.metadata().map_err(io)?;
            let identity = Identity {
                schema_version: 1,
                domain: "cm.state-home.v1".into(),
                home_id: random_id()?,
                home_device: home_metadata.dev(),
                home_inode: home_metadata.ino(),
                state_device: state_metadata.dev(),
                state_inode: state_metadata.ino(),
                lease_device: metadata.dev(),
                lease_inode: metadata.ino(),
            };
            let temporary = profile::temporary("identity");
            root.create_file(&temporary, &profile::canonical(&identity))
                .map_err(|_| failure("state_ownership", "cannot prepare state home identity"))?;
            let published = root.publish(&temporary, "identity.json")
                .map_err(|_| failure("state_ownership", "cannot publish state home identity"))?;
            if !published {
                unlink(&root, &temporary, false)?;
            }
        }
        let (bytes, pin) = read_marker(&root, "identity.json", 4096)
            .map_err(|_| failure("state_ownership", "invalid state home identity"))?;
        let identity: Identity = serde_json::from_slice(&bytes)
            .map_err(|_| failure("state_ownership", "invalid state home identity"))?;
        identity.validate(&bytes, &home, &root, &lease)?;
        let trees = root.child("trees").map_err(|_| failure("state_ownership", "unsafe working trees"))?;
        let checkpoints = root.child("checkpoints").map_err(|_| failure("state_ownership", "unsafe checkpoints"))?;
        let result = Self { home, root, trees, checkpoints, lease, identity: pin, home_id: identity.home_id };
        result.revalidate()?;
        Ok(result)
    }

    fn revalidate(&self) -> Result<()> {
        for directory in [&self.home, &self.root, &self.trees, &self.checkpoints] {
            directory.check().map_err(|_| failure("input_drift", "state directory identity changed"))?;
        }
        self.identity.revalidate().map_err(|_| failure("input_drift", "state home identity changed"))?;
        let current = regular(&self.root, ".lease")?;
        let old = self.lease.metadata().map_err(io)?;
        let now = current.metadata().map_err(io)?;
        if (old.dev(), old.ino()) != (now.dev(), now.ino()) {
            return Err(failure("input_drift", "state lease inode changed"));
        }
        Ok(())
    }

    fn tree(&self, view: &View) -> Result<Directory> {
        view.validate()?;
        if view.home_id != self.home_id {
            return Err(failure("state_ownership", "state view belongs to a different home"));
        }
        open_child(&self.trees, &view.tree)
    }
}

#[derive(PartialEq, Eq)]
struct Stamp(u64, u64, u64, u32, u32, u64, i64, i64, i64, i64);

fn stamp(metadata: &Metadata) -> Stamp {
    Stamp(metadata.dev(), metadata.ino(), metadata.len(), metadata.mode(), metadata.uid(),
        metadata.nlink(), metadata.mtime(), metadata.mtime_nsec(), metadata.ctime(), metadata.ctime_nsec())
}

struct Pin {
    path: PathBuf,
    stamp: Stamp,
    directory: bool,
}

impl Pin {
    fn new(path: PathBuf, file: &File, directory: bool) -> Result<Self> {
        Ok(Self { path, stamp: stamp(&file.metadata().map_err(io)?), directory })
    }

    fn revalidate(&self) -> Result<()> {
        let file = if self.directory {
            loader::open_directory(&self.path).map_err(|_| failure("input_drift", "state directory replaced"))?
        } else {
            let parent = Directory::open(self.path.parent().ok_or_else(|| failure("state_ownership", "missing parent"))?)
                .map_err(|_| failure("input_drift", "state parent replaced"))?;
            regular(&parent, self.path.file_name().and_then(OsStr::to_str)
                .ok_or_else(|| failure("state_ownership", "invalid state file path"))?)?
        };
        if stamp(&file.metadata().map_err(io)?) != self.stamp {
            return Err(failure("input_drift", "state input changed during operation"));
        }
        Ok(())
    }
}

fn read_marker(parent: &Directory, name: &str, limit: u64) -> Result<(Vec<u8>, Pin)> {
    let mut file = regular(parent, name)?;
    let before = file.metadata().map_err(io)?;
    if before.len() > limit {
        return Err(failure("state_budget", "state marker exceeds byte limit"));
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() as u64 != before.len() || stamp(&before) != stamp(&file.metadata().map_err(io)?) {
        return Err(failure("input_drift", "state marker changed while reading"));
    }
    let pin = Pin { path: parent.path.join(name), stamp: stamp(&before), directory: false };
    Ok((bytes, pin))
}

pub(crate) struct Guard {
    store: Store,
    pins: Vec<Pin>,
}

impl Guard {
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.store.revalidate()?;
        for pin in &self.pins { pin.revalidate()?; }
        Ok(())
    }
}

fn unlink(parent: &Directory, name: &str, directory: bool) -> Result<()> {
    parent.check().map_err(|_| failure("input_drift", "unlink parent changed"))?;
    let name = CString::new(name).map_err(|_| failure("state_ownership", "invalid unlink name"))?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    if unsafe { libc::unlinkat(parent.file.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(io(std::io::Error::last_os_error()));
    }
    parent.file.sync_all().map_err(io)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    directory: bool,
    mode: u32,
    size: u64,
    sha256: Option<String>,
}

#[derive(Default)]
struct Capture {
    entries: BTreeMap<String, Record>,
    pins: Vec<Pin>,
}

#[derive(Default)]
struct Budget {
    entries: usize,
    bytes: u64,
}

fn record(capture: &mut Capture, budget: &mut Budget, relative: &str, value: Record) -> Result<()> {
    if relative.len() > 512
        || relative.split('/').count() > 16
        || budget.entries >= MAX_ENTRIES
        || capture.entries.len() >= MAX_TOTAL_ENTRIES
    {
        return Err(failure("state_budget", "state path/depth/entry budget exceeded"));
    }
    budget.entries += 1;
    if capture.entries.insert(relative.into(), value).is_some() {
        return Err(failure("state_ownership", "duplicate state entry"));
    }
    Ok(())
}

fn copy_file(
    source: &Directory,
    destination: Option<&Directory>,
    name: &str,
    relative: &str,
    budget: &mut Budget,
    capture: &mut Capture,
) -> Result<()> {
    let mut input = regular(source, name)?;
    let before = input.metadata().map_err(io)?;
    if before.len() > MAX_BYTES.saturating_sub(budget.bytes) {
        return Err(failure("state_budget", "state owner exceeds 1 GiB"));
    }
    let mut output = if let Some(destination) = destination {
        let name = CString::new(name).map_err(|_| failure("state_ownership", "invalid copy name"))?;
        let fd = unsafe {
            libc::openat(
                destination.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 { return Err(io(std::io::Error::last_os_error())); }
        Some(unsafe { File::from_raw_fd(fd) })
    } else {
        None
    };
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = input.read(&mut buffer).map_err(io)?;
        if length == 0 { break; }
        bytes += length as u64;
        if bytes > before.len() || bytes > MAX_BYTES.saturating_sub(budget.bytes) {
            return Err(failure("state_budget", "state file grew beyond its bound"));
        }
        digest.update(&buffer[..length]);
        if let Some(output) = &mut output {
            fault(3)?;
            output.write_all(&buffer[..length]).map_err(io)?;
        }
    }
    if bytes != before.len() || stamp(&before) != stamp(&input.metadata().map_err(io)?) {
        return Err(failure("input_drift", "state file changed while copying"));
    }
    if let Some(output) = &output {
        if unsafe { libc::fchmod(output.as_raw_fd(), before.mode() & 0o777) } != 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        output.sync_all().map_err(io)?;
    }
    budget.bytes += bytes;
    record(capture, budget, relative, Record {
        directory: false,
        mode: before.mode() & 0o777,
        size: bytes,
        sha256: Some(format!("{:x}", digest.finalize())),
    })?;
    capture.pins.push(Pin { path: source.path.join(name), stamp: stamp(&before), directory: false });
    Ok(())
}

fn walk(
    source: &Directory,
    destination: Option<&Directory>,
    relative: &str,
    budget: &mut Budget,
    capture: &mut Capture,
) -> Result<()> {
    let before = source.file.metadata().map_err(io)?;
    record(capture, budget, relative, Record {
        directory: true,
        mode: before.mode() & 0o777,
        size: 0,
        sha256: None,
    })?;
    let entries = names(source)?;
    for name in &entries {
        let path = format!("{relative}/{name}");
        if path.len() > 512 || path.split('/').count() > 16 {
            return Err(failure("state_budget", "state path/depth budget exceeded"));
        }
        if let Ok(child) = open_child(source, name) {
            let target = destination.map(|parent| parent.child(name))
                .transpose().map_err(|_| failure("state_ownership", "cannot create state directory"))?;
            walk(&child, target.as_ref(), &path, budget, capture)?;
        } else {
            copy_file(source, destination, name, &path, budget, capture)?;
        }
    }
    if entries != names(source)? || stamp(&before) != stamp(&source.file.metadata().map_err(io)?) {
        return Err(failure("input_drift", "state directory changed while copying"));
    }
    if let Some(destination) = destination {
        if unsafe { libc::fchmod(destination.file.as_raw_fd(), before.mode() & 0o777) } != 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        destination.file.sync_all().map_err(io)?;
    }
    capture.pins.push(Pin { path: source.path.clone(), stamp: stamp(&before), directory: true });
    Ok(())
}

fn owner_directory(root: &Directory, id: &str, owner: &Owner) -> Result<Directory> {
    let id_root = open_child(root, id)?;
    let schema = open_child(&id_root, &owner.schema)?;
    let version = owner.version.to_string();
    if names(&id_root)? != BTreeSet::from([owner.schema.clone()])
        || names(&schema)? != BTreeSet::from([version.clone()])
    {
        return Err(failure("state_ownership", "unexpected owner/schema state directories"));
    }
    open_child(&schema, &version)
}

fn empty_owner(root: &Directory, id: &str, owner: &Owner) -> Result<bool> {
    Ok(names(&owner_directory(root, id, owner)?)?.is_empty())
}

fn create_owner(root: &Directory, id: &str, owner: &Owner) -> Result<Directory> {
    root.child(id).and_then(|id| id.child(&owner.schema))
        .and_then(|schema| schema.child(&owner.version.to_string()))
        .map_err(|_| failure("state_ownership", "cannot create owned state path"))
}

fn capture_owner(
    root: &Directory,
    destination: Option<&Directory>,
    id: &str,
    owner: &Owner,
    capture: &mut Capture,
) -> Result<()> {
    let source = owner_directory(root, id, owner)?;
    let target = destination.map(|root| create_owner(root, id, owner)).transpose()?;
    let mut budget = Budget::default();
    // Header directories are also bounded and recorded, without traversing another owner.
    for relative in [id.to_owned(), format!("{id}/{}", owner.schema)] {
        let directory = Directory::open(&root.path.join(&relative))
            .map_err(|_| failure("state_ownership", "unsafe state header directory"))?;
        let metadata = directory.file.metadata().map_err(io)?;
        record(capture, &mut budget, &relative, Record {
            directory: true, mode: metadata.mode() & 0o777, size: 0, sha256: None,
        })?;
        capture.pins.push(Pin { path: directory.path, stamp: stamp(&metadata), directory: true });
    }
    walk(&source, target.as_ref(), &owner.relative(id), &mut budget, capture)?;
    if let Some(destination) = destination {
        for relative in [format!("{id}/{}", owner.schema), id.to_owned()] {
            let old = Directory::open(&root.path.join(&relative))
                .map_err(|_| failure("state_ownership", "unsafe state header"))?;
            let new = Directory::open(&destination.path.join(relative))
                .map_err(|_| failure("state_ownership", "unsafe copied header"))?;
            let mode = old.file.metadata().map_err(io)?.mode() & 0o777;
            if unsafe { libc::fchmod(new.file.as_raw_fd(), mode) } != 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            new.file.sync_all().map_err(io)?;
        }
    }
    Ok(())
}

fn capture_tree(root: &Directory, owners: &BTreeMap<String, Owner>) -> Result<Capture> {
    if names(root)? != owners.keys().cloned().collect() {
        return Err(failure("state_ownership", "working tree contains unowned entries"));
    }
    let mut capture = Capture::default();
    for (id, owner) in owners { capture_owner(root, None, id, owner, &mut capture)?; }
    capture.pins.push(Pin::new(root.path.clone(), &root.file, true)?);
    for pin in &capture.pins { pin.revalidate()?; }
    Ok(capture)
}

fn set_view(transaction: &mut Transaction, view: View) {
    transaction.next.schema_version = 2;
    transaction.next.domain = "cm.generation.v2".into();
    transaction.next.state = Some(view);
}

fn new_view(store: &Store) -> Result<View> {
    Ok(View {
        schema_version: 1,
        domain: "cm.file-state.v1".into(),
        home_id: store.home_id.clone(),
        tree: random_id()?,
        owners: BTreeMap::new(),
        cleanups: BTreeMap::new(),
    })
}

fn guard(home: &Path, exclusive: bool) -> Result<Guard> {
    Ok(Guard { store: Store::open(home, exclusive)?, pins: Vec::new() })
}

pub(crate) fn exclusive(transaction: &mut Transaction) -> Result<()> {
    if transaction.state_guard.is_none() {
        transaction.state_guard = Some(guard(&transaction.root.path, true)?);
    }
    Ok(())
}

pub(crate) fn reconcile(
    transaction: &mut Transaction,
    contracts: &BTreeMap<String, Owner>,
) -> Result<()> {
    let old_view = transaction.next.state.clone();
    if old_view.is_none() && contracts.keys().all(|id| !transaction.next.enabled.contains(id)) {
        return Ok(());
    }
    let changed = contracts.iter().any(|(id, owner)| match old_view.as_ref().and_then(|v| v.owners.get(id)) {
        Some(old) => old != owner,
        None => transaction.next.enabled.contains(id),
    });
    if transaction.state_guard.is_none() {
        transaction.state_guard = Some(guard(&transaction.root.path, changed)?);
    }
    let held = transaction.state_guard.as_ref().expect("state guard");
    let mut view = match &old_view {
        Some(view) => view.clone(),
        None => new_view(&held.store)?,
    };
    let old_tree = old_view.as_ref().map(|old| held.store.tree(old)).transpose()?;
    let mut rebuild = old_view.is_none();
    let mut retained = view.owners.clone();
    for (id, owner) in contracts {
        match retained.get(id) {
            Some(old) if old.compatible(owner) => {
                view.owners.insert(id.clone(), owner.clone());
            }
            Some(old) => {
                if !empty_owner(old_tree.as_ref().expect("old tree"), id, old)? {
                    return Err(failure("state_compatibility", "state schema/version differs; restore a matching checkpoint or explicitly clean offline").owner(id, None));
                }
                retained.remove(id);
                view.owners.remove(id);
                if transaction.next.enabled.contains(id) { view.owners.insert(id.clone(), owner.clone()); }
                rebuild = true;
            }
            None if transaction.next.enabled.contains(id) => {
                if let Some(operation) = view.cleanups.get(id) {
                    let tree = open_child(&held.store.trees, &operation.tree)?;
                    if present(&tree.path.join(id))? {
                        return Err(failure("state_ownership", "finish the previous cleanup before creating new state"));
                    }
                }
                view.owners.insert(id.clone(), owner.clone());
                rebuild = true;
            }
            None => {}
        }
    }
    if rebuild {
        let temporary = profile::temporary("state");
        let stage = held.store.trees.child(&temporary)
            .map_err(|_| failure("state_ownership", "cannot prepare state tree"))?;
        let result = (|| {
            let mut source_pins = Vec::new();
            if let Some(old_tree) = &old_tree {
                // Validate the entire source before copying any owner.
                source_pins.extend(capture_tree(old_tree, &old_view.as_ref().expect("old view").owners)?.pins);
            }
            for (id, owner) in &view.owners {
                if let (Some(root), Some(old)) = (&old_tree, retained.get(id)) {
                    if old.compatible(owner) {
                        let mut captured = Capture::default();
                        capture_owner(root, Some(&stage), id, old, &mut captured)?;
                        source_pins.extend(captured.pins);
                        continue;
                    }
                }
                create_owner(&stage, id, owner)?;
            }
            for pin in &source_pins { pin.revalidate()?; }
            held.revalidate()?;
            let id = random_id()?;
            if !held.store.trees.publish(&temporary, &id)
                .map_err(|_| failure("state_ownership", "cannot publish working tree"))?
            {
                return Err(failure("state_ownership", "working tree identity collision"));
            }
            Ok((id, source_pins))
        })();
        if result.is_err() { let _ = profile::discard(&held.store.trees, &temporary); }
        let (id, pins) = result?;
        view.tree = id;
        let capture = capture_tree(&held.store.tree(&view)?, &view.owners)?;
        let held = transaction.state_guard.as_mut().expect("state guard");
        held.pins.extend(pins);
        held.pins.extend(capture.pins);
    }
    view.validate()?;
    set_view(transaction, view);
    Ok(())
}

pub(crate) fn acquire_runtime(
    home: &Path,
    snapshot: Option<&Snapshot>,
    contracts: &BTreeMap<String, Owner>,
    selected: &[String],
) -> Result<Option<Guard>> {
    let Some(snapshot) = snapshot else {
        if std::env::var_os("CM_MOD_STATE_ROOT").is_some() {
            return Err(failure("state_ownership", "unmanaged runtime has a forged state root"));
        }
        if selected.iter().any(|id| contracts.contains_key(id)) {
            return Err(failure("state_ownership", "file state requires an independent managed CM home"));
        }
        return Ok(None);
    };
    let mut held = guard(home, false)?;
    let current = profile::snapshot_for(home, false)?
        .ok_or_else(|| failure("state_ownership", "managed profile disappeared"))?;
    let selected_state = selected.iter().filter(|id| contracts.contains_key(*id)).collect::<Vec<_>>();
    if let Some(view) = &snapshot.generation.state {
        let tree = held.store.tree(view)?;
        let current_view = current.generation.state.as_ref()
            .ok_or_else(|| failure("state_compatibility", "current generation has no file state"))?;
        if view.home_id != current_view.home_id || view.tree != current_view.tree {
            return Err(failure("state_compatibility", "delayed generation refers to an obsolete state tree"));
        }
        for id in selected_state {
            let expected = &contracts[id];
            let owner = view.owners.get(id)
                .ok_or_else(|| failure("state_compatibility", "state owner is not allocated"))?;
            if owner != expected || current_view.owners.get(id) != Some(owner) {
                return Err(failure("state_compatibility", "state declaration/binding differs"));
            }
            let owned = owner_directory(&tree, id, owner)?;
            // Mutable payloads are deliberately not pinned across a business session.
            held.pins.push(Pin::new(owned.path, &owned.file, true)?);
        }
        held.store.revalidate()?;
        if std::env::var_os("CM_MOD_STATE_ROOT").as_deref() != Some(tree.path.as_os_str()) {
            return Err(failure("state_ownership", "state environment differs from the verified working tree"));
        }
    } else if !selected_state.is_empty() {
        return Err(failure("state_compatibility", "legacy generation cannot satisfy file state"));
    } else if std::env::var_os("CM_MOD_STATE_ROOT").is_some() {
        return Err(failure("state_ownership", "legacy runtime has a forged state root"));
    }
    snapshot.revalidate()?;
    held.store.revalidate()?;
    crate::event("state-lease", json!({"shared":true, "process_lifetime":true, "persistent":snapshot.generation.state.is_some()}));
    Ok(Some(held))
}

/// Called by the CLI's single-threaded main, before constructing any async runtime.
pub fn prepare_environment(home: &Path) -> Result<()> {
    let snapshot = profile::snapshot(home)?;
    let expected = snapshot.as_ref().and_then(|snapshot| snapshot.generation.state.as_ref())
        .map(|view| home.join("state/cm-files-v1/trees").join(&view.tree));
    if let Some(supplied) = std::env::var_os("CM_MOD_STATE_ROOT")
        && expected.as_deref().map(Path::as_os_str) != Some(supplied.as_os_str())
    {
        return Err(failure("state_ownership", "caller supplied an invalid state root"));
    }
    if let Some(path) = expected {
        Directory::open(&path).map_err(|_| failure("state_ownership", "unsafe state root"))?;
        // SAFETY: this entry point runs in CLI main before Tokio/helper threads exist.
        unsafe { std::env::set_var("CM_MOD_STATE_ROOT", path); }
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema_version: u32,
    domain: String,
    home_id: String,
    host: ManagedHost,
    generation: String,
    config_sha256: Option<String>,
    owners: BTreeMap<String, Owner>,
    entries: BTreeMap<String, Record>,
}

pub enum Command<'a> {
    Path(&'a str),
    Checkpoint,
    Rollback { generation: &'a str, restore: Option<&'a str> },
    Clean { id: &'a str, confirm: &'a str },
}

fn read_generation(transaction: &Transaction, id: &str) -> Result<(Generation, Pin)> {
    if !loader::digest(id) { return Err(failure("state_checkpoint", "invalid generation identity")); }
    let (bytes, pin) = read_marker(&transaction.generations, id, 4 * 1024 * 1024)
        .map_err(|_| failure("state_checkpoint", "generation is absent or unsafe"))?;
    let generation: Generation = serde_json::from_slice(&bytes)
        .map_err(|_| failure("state_checkpoint", "invalid generation"))?;
    generation.validate().map_err(|_| failure("state_checkpoint", "invalid generation format"))?;
    if loader::hash(&bytes) != id || profile::canonical(&generation) != bytes || generation.lock_sha256.is_empty() {
        return Err(failure("state_checkpoint", "generation identity differs"));
    }
    Ok((generation, pin))
}

fn checkpoint(mut transaction: Transaction, options: &Options) -> Result<Value> {
    exclusive(&mut transaction)?;
    let current = profile::snapshot_for(&transaction.root.path, false)?
        .ok_or_else(|| failure("state_checkpoint", "no committed managed profile"))?;
    let view = current.generation.state.as_ref()
        .ok_or_else(|| failure("state_checkpoint", "no managed file state to checkpoint"))?;
    let prepared = crate::runtime_plan::prepare_managed(
        &transaction.root.path, options,
        Snapshot::candidate(&transaction.root.path, transaction.host.clone(), transaction.next.clone())?,
    )?;
    prepared.revalidate()?;
    let held = transaction.state_guard.as_mut().expect("checkpoint guard");
    let source = held.store.tree(view)?;
    let expected = capture_tree(&source, &view.owners)?;
    let temporary = profile::temporary("checkpoint");
    let stage = held.store.checkpoints.child(&temporary)
        .map_err(|_| failure("state_checkpoint", "cannot prepare checkpoint"))?;
    let result = (|| {
        let data = stage.child("data").map_err(|_| failure("state_checkpoint", "cannot prepare checkpoint data"))?;
        let mut copied = Capture::default();
        for (id, owner) in &view.owners { capture_owner(&source, Some(&data), id, owner, &mut copied)?; }
        if copied.entries != expected.entries || capture_tree(&data, &view.owners)?.entries != expected.entries {
            return Err(failure("state_checkpoint", "checkpoint copy differs from source"));
        }
        let checkpoint = Checkpoint {
            schema_version: 1, domain: "cm.state-checkpoint.v1".into(),
            home_id: held.store.home_id.clone(), host: transaction.host.clone(),
            generation: current.generation_id.clone(),
            config_sha256: current.generation.config_sha256.clone(),
            owners: view.owners.clone(), entries: copied.entries,
        };
        let bytes = profile::canonical(&checkpoint);
        if bytes.len() as u64 > MAX_CHECKPOINT {
            return Err(failure("state_budget", "checkpoint manifest exceeds 16 MiB"));
        }
        stage.create_file("checkpoint.json", &bytes)
            .map_err(|_| failure("state_checkpoint", "cannot write checkpoint manifest"))?;
        stage.file.sync_all().map_err(io)?;
        for pin in expected.pins.iter().chain(copied.pins.iter()) { pin.revalidate()?; }
        current.revalidate()?;
        prepared.revalidate()?;
        held.revalidate()?;
        let id = loader::hash(&bytes);
        if !held.store.checkpoints.publish(&temporary, &id)
            .map_err(|_| failure("state_checkpoint", "cannot publish checkpoint"))?
        {
            let existing = open_child(&held.store.checkpoints, &id)?;
            let (old, _) = read_marker(&existing, "checkpoint.json", MAX_CHECKPOINT)
                .map_err(|_| failure("state_checkpoint", "unsafe existing checkpoint"))?;
            if names(&existing)? != BTreeSet::from(["checkpoint.json".into(), "data".into()])
                || old != bytes || capture_tree(&open_child(&existing, "data")?, &view.owners)?.entries != checkpoint.entries {
                return Err(failure("state_checkpoint", "existing checkpoint content differs"));
            }
            profile::discard(&held.store.checkpoints, &temporary)
                .map_err(|_| failure("state_checkpoint", "cannot discard duplicate checkpoint"))?;
        }
        Ok(json!({"schema_version":1, "checkpoint":id, "generation":current.generation_id,
            "complete":true, "owners":view.owners.keys().collect::<Vec<_>>(),
            "active_changed":false, "already_native_executed":false}))
    })();
    if result.is_err() { let _ = profile::discard(&held.store.checkpoints, &temporary); }
    transaction.revalidate()?;
    result
}

fn restore(
    transaction: &mut Transaction,
    target: &Generation,
    generation: &str,
    id: &str,
) -> Result<()> {
    if !loader::digest(id) { return Err(failure("state_checkpoint", "invalid checkpoint identity")); }
    exclusive(transaction)?;
    let held = transaction.state_guard.as_ref().expect("restore guard");
    let checkpoint_dir = open_child(&held.store.checkpoints, id)?;
    if names(&checkpoint_dir)? != BTreeSet::from(["checkpoint.json".into(), "data".into()]) {
        return Err(failure("state_checkpoint", "unexpected checkpoint entries"));
    }
    let (bytes, checkpoint_pin) = read_marker(&checkpoint_dir, "checkpoint.json", MAX_CHECKPOINT)
        .map_err(|_| failure("state_checkpoint", "checkpoint manifest is absent or unsafe"))?;
    let checkpoint: Checkpoint = serde_json::from_slice(&bytes)
        .map_err(|_| failure("state_checkpoint", "invalid checkpoint manifest"))?;
    let target_view = target.state.as_ref()
        .ok_or_else(|| failure("state_checkpoint", "target generation has no file state contract"))?;
    if checkpoint.schema_version != 1 || checkpoint.domain != "cm.state-checkpoint.v1"
        || loader::hash(&bytes) != id || profile::canonical(&checkpoint) != bytes
        || checkpoint.home_id != held.store.home_id || checkpoint.home_id != target_view.home_id
        || checkpoint.host != transaction.host || checkpoint.generation != generation
        || checkpoint.config_sha256 != target.config_sha256 || checkpoint.owners != target_view.owners
        || checkpoint.entries.len() > MAX_TOTAL_ENTRIES
    {
        return Err(failure("state_checkpoint", "checkpoint home/Host/generation/config/owners binding differs"));
    }
    let data = open_child(&checkpoint_dir, "data")?;
    let captured = capture_tree(&data, &checkpoint.owners)?;
    if captured.entries != checkpoint.entries {
        return Err(failure("state_checkpoint", "checkpoint data differs from its manifest"));
    }
    let old_view = transaction.next.state.clone();
    let old_tree = old_view.as_ref().map(|view| held.store.tree(view)).transpose()?;
    let mut view = match &old_view { Some(view) => view.clone(), None => new_view(&held.store)? };
    for id in checkpoint.owners.keys() {
        if let Some(operation) = view.cleanups.get(id) {
            let tree = open_child(&held.store.trees, &operation.tree)?;
            if present(&tree.path.join(id))? {
                return Err(failure("state_ownership", "finish the previous cleanup before restoring this owner"));
            }
        }
    }
    view.owners.extend(checkpoint.owners.clone());
    let temporary = profile::temporary("restore");
    let stage = held.store.trees.child(&temporary)
        .map_err(|_| failure("state_checkpoint", "cannot stage restored state"))?;
    let result = (|| {
        let mut pins = captured.pins;
        if let (Some(root), Some(old)) = (&old_tree, &old_view) {
            pins.extend(capture_tree(root, &old.owners)?.pins);
        }
        for (id, owner) in &view.owners {
            let source = if checkpoint.owners.contains_key(id) {
                &data
            } else {
                old_tree.as_ref().ok_or_else(|| failure("state_checkpoint", "missing retained owner tree"))?
            };
            let mut copied = Capture::default();
            capture_owner(source, Some(&stage), id, owner, &mut copied)?;
            pins.extend(copied.pins);
        }
        let destination = capture_tree(&stage, &view.owners)?;
        // Restored owners must match the authenticated checkpoint byte for byte.
        for (path, record) in &checkpoint.entries {
            if destination.entries.get(path) != Some(record) {
                return Err(failure("state_checkpoint", "restored state differs from checkpoint"));
            }
        }
        for pin in &pins { pin.revalidate()?; }
        held.revalidate()?;
        checkpoint_pin.revalidate().map_err(|_| failure("input_drift", "checkpoint manifest replaced"))?;
        fault(1)?;
        let tree = random_id()?;
        if !held.store.trees.publish(&temporary, &tree)
            .map_err(|_| failure("state_checkpoint", "cannot publish restored state"))?
        {
            return Err(failure("state_checkpoint", "restored tree identity collision"));
        }
        Ok((tree, pins))
    })();
    if result.is_err() { let _ = profile::discard(&held.store.trees, &temporary); }
    let (tree, pins) = result?;
    view.tree = tree;
    let published = capture_tree(&held.store.tree(&view)?, &view.owners)?;
    let held = transaction.state_guard.as_mut().expect("restore guard");
    held.pins.extend(pins);
    held.pins.extend(published.pins);
    held.pins.push(checkpoint_pin);
    set_view(transaction, view);
    Ok(())
}

fn rollback(mut transaction: Transaction, generation: &str, checkpoint: Option<&str>, options: &Options) -> Result<Value> {
    let (target, pin) = read_generation(&transaction, generation)?;
    exclusive(&mut transaction)?;
    if let Some(checkpoint) = checkpoint { restore(&mut transaction, &target, generation, checkpoint)?; }
    transaction.next.installed = target.installed;
    transaction.next.enabled = target.enabled;
    transaction.next.consumed.extend(target.consumed);
    transaction.state_guard.as_mut().expect("rollback guard").pins.push(pin);
    let mut receipt = transaction.commit(options)?;
    receipt["rollback_target"] = json!(generation);
    receipt["restored_checkpoint"] = json!(checkpoint);
    Ok(receipt)
}

fn remove_tree(parent: &Directory, name: &str) -> Result<()> {
    let directory = open_child(parent, name)?;
    for entry in names(&directory)? {
        if open_child(&directory, &entry).is_ok() {
            remove_tree(&directory, &entry)?;
        } else {
            regular(&directory, &entry)?;
            unlink(&directory, &entry, false)?;
        }
    }
    directory.check().map_err(|_| failure("input_drift", "cleanup directory replaced"))?;
    unlink(parent, name, true)
}

fn cleanup(tree: &Directory, id: &str, owner: &Owner) -> Result<()> {
    if !present(&tree.path.join(id))? { return Ok(()); }
    let root = open_child(tree, id)?;
    if !names(&root)?.is_subset(&BTreeSet::from([owner.schema.clone()])) {
        return Err(failure("state_ownership", "cleanup contains a different schema"));
    }
    if present(&root.path.join(&owner.schema))? {
        let schema = open_child(&root, &owner.schema)?;
        if !names(&schema)?.is_subset(&BTreeSet::from([owner.version.to_string()])) {
            return Err(failure("state_ownership", "cleanup contains a different version"));
        }
        if present(&schema.path.join(owner.version.to_string()))? {
            open_child(&schema, &owner.version.to_string())?;
        }
    }
    // A previous unlink may have removed either header; validate the remaining owned subtree.
    let mut captured = Capture::default();
    walk(&root, None, id, &mut Budget::default(), &mut captured)?;
    for pin in &captured.pins { pin.revalidate()?; }
    fault(2)?;
    remove_tree(tree, id)
}

fn clean(mut transaction: Transaction, id: &str, confirm: &str, options: &Options) -> Result<Value> {
    if !component(id) || confirm != id {
        return Err(failure("state_ownership", "cleanup requires a valid owner ID and matching --confirm"));
    }
    if transaction.next.enabled.contains(id) {
        return Err(failure("state_busy", "disable or remove the owner before explicit cleanup"));
    }
    exclusive(&mut transaction)?;
    let mut view = transaction.next.state.clone()
        .ok_or_else(|| failure("state_ownership", "no allocated file state"))?;
    let held = transaction.state_guard.as_ref().expect("cleanup guard");
    let source = held.store.tree(&view)?;
    let Some(owner) = view.owners.get(id).cloned() else {
        let operation = view.cleanups.get(id)
            .ok_or_else(|| failure("state_ownership", "owner has no current state or cleanup operation"))?;
        let tree = open_child(&held.store.trees, &operation.tree)?;
        transaction.revalidate()?;
        let owner = Owner { schema: operation.schema.clone(), version: operation.version, object_sha256: "0".repeat(64) };
        let result = cleanup(&tree, id, &owner);
        return Ok(json!({"schema_version":1,"committed":true, "cleanup_operation":operation.operation,
            "cleanup_pending":result.is_err(), "current_working_state_removed":result.is_ok(),
            "checkpoints_preserved":true, "historical_working_trees_preserved":true,
            "retry":true, "restart_required":true, "already_native_executed":false}));
    };
    let captured = capture_tree(&source, &view.owners)?;
    let operation = Cleanup {
        tree: view.tree.clone(), owner: id.into(), schema: owner.schema.clone(), version: owner.version,
        operation: loader::hash(&profile::canonical(&(held.store.home_id.clone(), view.tree.clone(), id, &owner))),
    };
    let temporary = profile::temporary("clean");
    let stage = held.store.trees.child(&temporary)
        .map_err(|_| failure("state_ownership", "cannot prepare cleaned state view"))?;
    view.owners.remove(id);
    view.cleanups.insert(id.into(), operation.clone());
    let result = (|| {
        let mut pins = captured.pins;
        for (other_id, other_owner) in &view.owners {
            let mut copied = Capture::default();
            capture_owner(&source, Some(&stage), other_id, other_owner, &mut copied)?;
            pins.extend(copied.pins);
        }
        for pin in &pins { pin.revalidate()?; }
        held.revalidate()?;
        let tree = random_id()?;
        if !held.store.trees.publish(&temporary, &tree)
            .map_err(|_| failure("state_ownership", "cannot publish cleaned state view"))?
        {
            return Err(failure("state_ownership", "cleaned tree identity collision"));
        }
        Ok((tree, pins))
    })();
    if result.is_err() { let _ = profile::discard(&held.store.trees, &temporary); }
    let (tree, pins) = result?;
    view.tree = tree;
    let destination = capture_tree(&held.store.tree(&view)?, &view.owners)?;
    // dup keeps the same flock alive across the profile commit and physical deletion.
    let _lease = held.store.lease.try_clone().map_err(io)?;
    let held = transaction.state_guard.as_mut().expect("cleanup guard");
    held.pins.extend(pins);
    held.pins.extend(destination.pins);
    set_view(&mut transaction, view);
    let mut receipt = transaction.commit(options)?;
    let result = cleanup(&source, id, &owner);
    receipt["data_preserved"] = json!(false);
    receipt["cleanup_operation"] = json!(operation.operation);
    receipt["cleanup_pending"] = json!(result.is_err());
    receipt["current_working_state_removed"] = json!(result.is_ok());
    receipt["checkpoints_preserved"] = json!(true);
    receipt["historical_working_trees_preserved"] = json!(true);
    Ok(receipt)
}

pub fn run(home: &Path, command: Command<'_>, options: &Options) -> Result<Value> {
    if let Command::Path(id) = command {
        if !component(id) { return Err(failure("state_ownership", "invalid state owner ID")); }
        let current = profile::snapshot_for(home, false)?
            .ok_or_else(|| failure("state_ownership", "no managed profile"))?;
        let view = current.generation.state.as_ref()
            .ok_or_else(|| failure("state_ownership", "no managed file state"))?;
        let owner = view.owners.get(id).ok_or_else(|| failure("state_ownership", "owner has no current working state"))?;
        // Read-only query: never creates a namespace, state tree, or lease.
        let home_directory = Directory::open(home).map_err(|_| failure("state_ownership", "unsafe CM home"))?;
        let namespace = Directory::open(&home.join("state/cm-files-v1"))
            .map_err(|_| failure("state_ownership", "unsafe state namespace"))?;
        let (bytes, pin) = read_marker(&namespace, "identity.json", 4096)
            .map_err(|_| failure("state_ownership", "invalid state home identity"))?;
        let identity: Identity = serde_json::from_slice(&bytes)
            .map_err(|_| failure("state_ownership", "invalid state home identity"))?;
        identity.validate(&bytes, &home_directory, &namespace, &regular(&namespace, ".lease")?)?;
        if identity.home_id != view.home_id { return Err(failure("state_ownership", "state view belongs to another home")); }
        let root = namespace.path.join("trees").join(&view.tree);
        let directory = Directory::open(&root).map_err(|_| failure("state_ownership", "unsafe working tree"))?;
        owner_directory(&directory, id, owner)?;
        pin.revalidate().map_err(|_| failure("input_drift", "state home identity changed"))?;
        current.revalidate()?;
        return Ok(json!({"owner":id,"schema":owner.schema,"version":owner.version,
            "root":root,"path":root.join(owner.relative(id)), "generation":current.generation_id,
            "enabled":current.generation.enabled.contains(id),"already_native_executed":false}));
    }
    let transaction = Transaction::begin(home, crate::package::managed_identity()?)?;
    match command {
        Command::Checkpoint => checkpoint(transaction, options),
        Command::Rollback { generation, restore } => rollback(transaction, generation, restore, options),
        Command::Clean { id, confirm } => clean(transaction, id, confirm, options),
        Command::Path(_) => unreachable!(),
    }
}

#[cfg(test)]
thread_local! { static FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }

fn fault(point: u8) -> Result<()> {
    #[cfg(test)]
    if FAULT.get() == point {
        return Err(if point == 3 {
            io(std::io::Error::from_raw_os_error(libc::ENOSPC))
        } else {
            failure("state_checkpoint", "injected state operation failure")
        });
    }
    let _ = point;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, symlink};
    use std::process::{Command as Process, Stdio};

    struct Home(PathBuf);

    impl Home {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("cm-state-test-{}", random_id().unwrap()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn owner(version: u32) -> Owner {
        Owner { schema: "notes".into(), version, object_sha256: "a".repeat(64) }
    }

    fn fixture(store: &Store) -> View {
        let mut view = new_view(store).unwrap();
        view.owners.insert("example-tool".into(), owner(1));
        view.owners.insert("other".into(), owner(1));
        let root = store.trees.child(&view.tree).unwrap();
        for (id, owner) in &view.owners {
            let path = create_owner(&root, id, owner).unwrap();
            path.create_file("value", id.as_bytes()).unwrap();
        }
        view
    }

    #[test]
    fn versioned_generation_does_not_reinterpret_legacy_state() {
        let legacy = Generation::default();
        let bytes = profile::canonical(&legacy);
        assert!(!String::from_utf8(bytes.clone()).unwrap().contains("\"state\""));
        let mut decoded: Generation = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.validate().is_ok());
        decoded.schema_version = 2;
        decoded.domain = "cm.generation.v2".into();
        assert!(decoded.validate().is_err());
        let home = Home::new();
        let held = guard(&home.0, true).unwrap();
        decoded.state = Some(fixture(&held.store));
        assert!(decoded.validate().is_ok());
        decoded.schema_version = 1;
        assert!(decoded.validate().is_err());
        assert!(!component("."));
        assert!(!component(".."));
        assert!(!component("../other"));
        assert!(owner(1).compatible(&Owner { object_sha256: "b".repeat(64), ..owner(1) }));
        assert!(!owner(1).compatible(&owner(2)));
    }

    #[test]
    fn bounded_snapshot_preserves_bytes_modes_and_unrelated_owner() {
        let home = Home::new();
        let held = guard(&home.0, true).unwrap();
        let view = fixture(&held.store);
        let source = held.store.tree(&view).unwrap();
        let old = capture_tree(&source, &view.owners).unwrap();
        let destination = held.store.trees.child(&random_id().unwrap()).unwrap();
        let mut copied = Capture::default();
        for (id, owner) in &view.owners {
            capture_owner(&source, Some(&destination), id, owner, &mut copied).unwrap();
        }
        assert_eq!(copied.entries, old.entries);
        assert_eq!(capture_tree(&destination, &view.owners).unwrap().entries, old.entries);
        for pin in old.pins.iter().chain(copied.pins.iter()) { pin.revalidate().unwrap(); }
        cleanup(&source, "example-tool", &owner(1)).unwrap();
        assert!(!source.path.join("example-tool").exists());
        assert_eq!(fs::read(source.path.join(owner(1).relative("other")).join("value")).unwrap(), b"other");
        assert_eq!(fs::read(destination.path.join(owner(1).relative("example-tool")).join("value")).unwrap(), b"example-tool");
    }

    #[test]
    fn links_special_files_and_unowned_paths_are_rejected_before_cleanup() {
        for kind in ["symlink", "hardlink", "fifo", "unowned"] {
            let home = Home::new();
            let held = guard(&home.0, true).unwrap();
            let view = fixture(&held.store);
            let root = held.store.tree(&view).unwrap();
            let own = owner_directory(&root, "example-tool", &owner(1)).unwrap();
            let external = home.0.join("external");
            fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&external)
                .unwrap().write_all(b"preserve").unwrap();
            match kind {
                "symlink" => symlink(&external, own.path.join("bad")).unwrap(),
                "hardlink" => fs::hard_link(&external, own.path.join("bad")).unwrap(),
                "fifo" => {
                    let path = CString::new(own.path.join("bad").as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                "unowned" => { root.child("foreign").unwrap(); }
                _ => unreachable!(),
            }
            assert!(capture_tree(&root, &view.owners).is_err());
            if kind != "unowned" {
                assert!(cleanup(&root, "example-tool", &owner(1)).is_err());
                assert!(read_marker(&own, "bad", 128).is_err());
            }
            assert_eq!(fs::read(&external).unwrap(), b"preserve");
            assert!(own.path.join("value").is_file());
        }
    }

    #[test]
    fn copy_budget_and_replaced_inputs_fail_without_touching_source() {
        let home = Home::new();
        let held = guard(&home.0, true).unwrap();
        let view = fixture(&held.store);
        let tree = held.store.tree(&view).unwrap();
        let own = owner_directory(&tree, "example-tool", &owner(1)).unwrap();
        let large = own.path.join("large");
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&large)
            .unwrap().set_len(MAX_BYTES + 1).unwrap();
        assert!(capture_tree(&tree, &view.owners).is_err());
        fs::remove_file(large).unwrap();
        let capture = capture_tree(&tree, &view.owners).unwrap();
        let path = own.path.join("value");
        fs::rename(&path, home.0.join("old-value")).unwrap();
        own.create_file("value", b"example-tool").unwrap();
        assert!(capture.pins.iter().any(|pin| pin.revalidate().is_err()));
        assert_eq!(fs::read(home.0.join("old-value")).unwrap(), b"example-tool");
        let mut captured = Capture::default();
        let mut budget = Budget { entries: MAX_ENTRIES, bytes: 0 };
        assert!(record(&mut captured, &mut budget, "safe", Record {
            directory: true, mode: 0o700, size: 0, sha256: None,
        }).is_err());
        assert!(captured.entries.is_empty());
    }

    #[test]
    fn replaced_lock_inode_cannot_bypass_a_live_lease() {
        let home = Home::new();
        let held = guard(&home.0, false).unwrap();
        let path = held.store.root.path.join(".lease");
        fs::rename(&path, held.store.root.path.join("old-lease")).unwrap();
        held.store.root.create_file(".lease", b"").unwrap();
        assert!(held.revalidate().is_err());
        assert!(guard(&home.0, true).is_err());
    }

    #[test]
    fn cleanup_failure_keeps_precise_retry_scope_and_snapshot_copy() {
        let home = Home::new();
        let held = guard(&home.0, true).unwrap();
        let view = fixture(&held.store);
        let root = held.store.tree(&view).unwrap();
        FAULT.set(2);
        assert!(cleanup(&root, "example-tool", &owner(1)).is_err());
        FAULT.set(0);
        assert!(root.path.join("example-tool/notes/1/value").is_file());
        cleanup(&root, "example-tool", &owner(1)).unwrap();
        cleanup(&root, "example-tool", &owner(1)).unwrap();
        assert_eq!(fs::read(root.path.join("other/notes/1/value")).unwrap(), b"other");
    }

    #[test]
    fn cleanup_retry_accepts_only_remaining_owned_headers() {
        let home = Home::new();
        let held = guard(&home.0, true).unwrap();
        let view = fixture(&held.store);
        let root = held.store.tree(&view).unwrap();
        fs::remove_dir_all(root.path.join("example-tool/notes")).unwrap();
        root.child("example-tool").unwrap().child("foreign-schema").unwrap();
        assert!(cleanup(&root, "example-tool", &owner(1)).is_err());
        fs::remove_dir(root.path.join("example-tool/foreign-schema")).unwrap();
        cleanup(&root, "example-tool", &owner(1)).unwrap();
        assert!(!root.path.join("example-tool").exists());
        assert_eq!(fs::read(root.path.join("other/notes/1/value")).unwrap(), b"other");
    }

    fn restore_fixture(home: &Home) -> (Transaction, Generation, String, String) {
        let host = ManagedHost {
            executable: PathBuf::from("/cm-test-host/bin/codex"),
            executable_sha256: "a".repeat(64),
            inventory_sha256: "b".repeat(64),
            target: loader::TARGET.into(),
        };
        let mut transaction = Transaction::begin(&home.0, host).unwrap();
        exclusive(&mut transaction).unwrap();
        let store = &transaction.state_guard.as_ref().unwrap().store;
        let view = fixture(store);
        let tree = store.tree(&view).unwrap();
        let generation = Generation {
            schema_version: 2,
            domain: "cm.generation.v2".into(),
            state: Some(view.clone()),
            lock_sha256: "c".repeat(64),
            ..Generation::default()
        };
        let generation_id = loader::hash(&profile::canonical(&generation));
        let checkpoint = Checkpoint {
            schema_version: 1,
            domain: "cm.state-checkpoint.v1".into(),
            home_id: store.home_id.clone(),
            host: transaction.host.clone(),
            generation: generation_id.clone(),
            config_sha256: None,
            owners: view.owners.clone(),
            entries: capture_tree(&tree, &view.owners).unwrap().entries,
        };
        let bytes = profile::canonical(&checkpoint);
        let id = loader::hash(&bytes);
        let directory = store.checkpoints.child(&id).unwrap();
        directory.create_file("checkpoint.json", &bytes).unwrap();
        let data = directory.child("data").unwrap();
        for (id, owner) in &view.owners {
            capture_owner(&tree, Some(&data), id, owner, &mut Capture::default()).unwrap();
        }
        set_view(&mut transaction, view);
        (transaction, generation, generation_id, id)
    }

    #[test]
    fn restore_interruption_preserves_active_view_and_checkpoint_before_retry() {
        let home = Home::new();
        let (mut transaction, target, generation, checkpoint) = restore_fixture(&home);
        let before = profile::canonical(&transaction.next);
        FAULT.set(1);
        assert!(restore(&mut transaction, &target, &generation, &checkpoint).is_err());
        FAULT.set(0);
        assert_eq!(profile::canonical(&transaction.next), before);
        assert!(!home.0.join("cm-profile.json").exists());
        let store = &transaction.state_guard.as_ref().unwrap().store;
        assert!(names(&store.trees).unwrap().iter().all(|name| !name.ends_with(".tmp")));
        restore(&mut transaction, &target, &generation, &checkpoint).unwrap();
        let after = transaction.next.state.as_ref().unwrap();
        assert_ne!(after.tree, target.state.as_ref().unwrap().tree);
        let store = &transaction.state_guard.as_ref().unwrap().store;
        assert_eq!(fs::read(store.tree(after).unwrap().path.join("example-tool/notes/1/value")).unwrap(), b"example-tool");
        assert!(store.checkpoints.path.join(&checkpoint).join("data/example-tool/notes/1/value").is_file());
        transaction.state_guard.as_ref().unwrap().revalidate().unwrap();
    }

    #[test]
    fn checkpoint_binding_and_data_corruption_are_rejected_before_publication() {
        for field in ["home", "host", "generation", "config", "owner", "data"] {
            let home = Home::new();
            let (mut transaction, target, generation, id) = restore_fixture(&home);
            let before = profile::canonical(&transaction.next);
            let store = &transaction.state_guard.as_ref().unwrap().store;
            let directory = store.checkpoints.path.join(&id);
            let manifest = directory.join("checkpoint.json");
            let mut checkpoint: Checkpoint = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
            match field {
                "home" => checkpoint.home_id = "d".repeat(64),
                "host" => checkpoint.host.executable_sha256 = "d".repeat(64),
                "generation" => checkpoint.generation = "d".repeat(64),
                "config" => checkpoint.config_sha256 = Some("d".repeat(64)),
                "owner" => checkpoint.owners.get_mut("example-tool").unwrap().version = 2,
                "data" => fs::write(directory.join("data/example-tool/notes/1/value"), b"corrupted").unwrap(),
                _ => unreachable!(),
            }
            let bytes = profile::canonical(&checkpoint);
            fs::write(&manifest, &bytes).unwrap();
            let new_id = loader::hash(&bytes);
            if id != new_id { fs::rename(&directory, store.checkpoints.path.join(&new_id)).unwrap(); }
            assert!(restore(&mut transaction, &target, &generation, &new_id).is_err(), "{field}");
            assert_eq!(profile::canonical(&transaction.next), before);
            assert!(!home.0.join("cm-profile.json").exists());
        }
    }

    #[test]
    fn enospc_during_restore_preserves_source_and_active_view() {
        let home = Home::new();
        let (mut transaction, target, generation, checkpoint) = restore_fixture(&home);
        let before = profile::canonical(&transaction.next);
        FAULT.set(3);
        assert!(restore(&mut transaction, &target, &generation, &checkpoint).is_err());
        FAULT.set(0);
        assert_eq!(profile::canonical(&transaction.next), before);
        assert!(!home.0.join("cm-profile.json").exists());
        let store = &transaction.state_guard.as_ref().unwrap().store;
        assert_eq!(fs::read(store.tree(target.state.as_ref().unwrap()).unwrap().path.join("example-tool/notes/1/value")).unwrap(), b"example-tool");
        assert!(names(&store.trees).unwrap().iter().all(|name| !name.ends_with(".tmp")));
    }

    #[test]
    #[ignore = "spawned only by state_live_process_lease_is_released_by_sigkill"]
    fn state_lease_child() {
        let home = std::env::var_os("CM_TEST_STATE_HOME").expect("child profile");
        let _held = guard(Path::new(&home), false).unwrap();
        println!("state-lease-ready");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
    }

    #[test]
    #[ignore = "spawned only by helper_exec_does_not_inherit_the_state_lease"]
    fn state_unrelated_child() {
        println!("state-helper-ready");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
    }

    #[test]
    fn helper_exec_does_not_inherit_the_state_lease() {
        let home = Home::new();
        let held = guard(&home.0, false).unwrap();
        let mut child = Process::new(std::env::current_exe().unwrap())
            .args(["--exact", "state::tests::state_unrelated_child", "--ignored", "--nocapture"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0, "helper exited before barrier");
            if line.trim() == "state-helper-ready" { break; }
        }
        drop(held);
        let exclusive = guard(&home.0, true).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        exclusive.revalidate().unwrap();
    }

    #[test]
    fn state_live_process_lease_is_released_by_sigkill() {
        let home = Home::new();
        let mut child = Process::new(std::env::current_exe().unwrap())
            .args(["--exact", "state::tests::state_lease_child", "--ignored", "--nocapture"])
            .env("CM_TEST_STATE_HOME", &home.0)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0, "lease child exited before barrier");
            if line.trim() == "state-lease-ready" { break; }
        }
        assert_eq!(guard(&home.0, true).err().unwrap().code, "state_busy");
        let other_reader = guard(&home.0, false).unwrap();
        drop(other_reader);
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(guard(&home.0, true).is_ok());
    }
}
