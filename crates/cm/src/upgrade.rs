//! Explicit, offline preparation of an independent profile for this Host.
use std::collections::BTreeMap;
use crate::loader::Handle as File;
#[cfg(not(windows))]
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};

use crate::config::Options;
use crate::profile::{Directory, Transaction, UpgradeSource};
use crate::{LoadError, loader, mod_install, mod_lock, package, runtime_plan, state};

fn failure(code: &str, message: &str) -> LoadError {
    LoadError::input(code, "", message)
}

fn inode(file: &File) -> Result<loader::Identity, LoadError> {
    loader::identity(file).map_err(|e| failure("input_drift", &e))
}

#[cfg(not(windows))]
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(windows)]
fn overlaps(left: &Path, right: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        #[link_name = "CompareStringOrdinal"]
        fn compare_ordinal(left: *const u16, left_length: i32, right: *const u16, right_length: i32, ignore_case: i32) -> i32;
    }
    let starts = |left: &Path, right: &Path| {
        let mut left = left.components();
        for right in right.components() {
            let Some(left) = left.next() else { return false; };
            let left: Vec<_> = left.as_os_str().encode_wide().collect();
            let right: Vec<_> = right.as_os_str().encode_wide().collect();
            if left.len() > i32::MAX as usize || right.len() > i32::MAX as usize {
                return true;
            }
            let comparison = unsafe { compare_ordinal(left.as_ptr(), left.len() as i32, right.as_ptr(), right.len() as i32, 1) };
            // A failed comparison must not permit an unverified destination.
            match comparison {
                0 => return true,
                2 => {},
                _ => return false,
            }
        }
        true
    };
    starts(left, right) || starts(right, left)
}

struct Destination {
    path: PathBuf,
    parent: File,
    existing: Option<Directory>,
}

impl Destination {
    fn capture(path: &Path, source: &Path, hosts: &[&Path]) -> Result<Self, LoadError> {
        if !path.is_absolute()
            || path.parent().is_none()
            || path
                .components()
                .any(|part| match part {
                    Component::RootDir | Component::Normal(_) => false,
                    #[cfg(windows)]
                    Component::Prefix(prefix) => !matches!(prefix.kind(), std::path::Prefix::Disk(_)),
                    _ => true,
                })
            || overlaps(path, source)
            || hosts.iter().any(|host| overlaps(path, host))
            || ["HOME", if cfg!(windows) { "USERPROFILE" } else { "HOME" }].iter().any(|name| std::env::var_os(name)
                .is_some_and(|home| overlaps(path, &PathBuf::from(home).join(".codex"))))
        {
            return Err(failure(
                "upgrade_destination",
                "candidate must be an independent absolute directory",
            ));
        }
        let parent = loader::open_directory(
            path.parent()
                .ok_or_else(|| failure("upgrade_destination", "missing parent"))?,
        )
        .map_err(|e| failure("upgrade_destination", &e))?;
        let existing = match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(failure("upgrade_destination", &error.to_string())),
            Ok(_) => {
                let directory =
                    Directory::open(path).map_err(|e| failure("upgrade_destination", &e))?;
                #[cfg(not(windows))]
                let enumeration = PathBuf::from(format!("/proc/self/fd/{}", directory.file.as_raw_fd()));
                #[cfg(windows)]
                let enumeration = directory.file.path();
                if std::fs::read_dir(enumeration)
                    .map_err(|e| failure("upgrade_destination", &e.to_string()))?
                    .next()
                    .is_some()
                {
                    return Err(failure(
                        "upgrade_destination",
                        "candidate directory must be empty",
                    ));
                }
                Some(directory)
            }
        };
        Ok(Self {
            path: path.into(),
            parent,
            existing,
        })
    }

    fn revalidate(&self, created: Option<&Directory>) -> Result<(), LoadError> {
        let current = loader::open_directory(self.path.parent().expect("captured parent"))
            .map_err(|e| failure("input_drift", &e))?;
        if inode(&self.parent)? != inode(&current)? {
            return Err(failure("input_drift", "candidate parent changed"));
        }
        if let Some(directory) = created.or(self.existing.as_ref()) {
            directory.check().map_err(|e| failure("input_drift", &e))?;
            if let Some(before) = &self.existing
                && inode(&before.file)? != inode(&directory.file)?
            {
                return Err(failure("input_drift", "candidate directory changed"));
            }
        } else {
            match std::fs::symlink_metadata(&self.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(failure(
                        "input_drift",
                        "candidate appeared or became unsafe",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn lock(plan: &runtime_plan::PreparedPlan) -> String {
    loader::hash(&mod_lock::canonical(plan.plan()))
}

fn revalidate_objects(
    objects: &[(PathBuf, loader::InstallationSnapshot)],
) -> Result<(), LoadError> {
    for (path, snapshot) in objects {
        for pin in &snapshot.pins {
            pin.revalidate().map_err(|e| failure("input_drift", &e))?;
        }
        if let Some(tree) = &snapshot.tree
            && loader::directory_entries(path).as_ref() != Ok(tree)
        {
            return Err(failure("input_drift", "retained object inventory changed"));
        }
    }
    Ok(())
}

/// Static diagnostics and a single atomic candidate commit; never runs native Mod code.
pub fn run(
    home: &Path,
    candidate: &Path,
    check: bool,
    variants: &[PathBuf],
    options: &Options,
) -> Result<Value, LoadError> {
    crate::profile::validate_environment(home)?;
    if variants.len() > 32 {
        return Err(failure(
            "upgrade_variant",
            "variant count exceeds installed package limit",
        ));
    }
    let target_host = package::managed_identity()?;
    let target_package = package::PackagePin::capture(&target_host)?;
    let executable = loader::current_executable().map_err(|e| failure("host_identity", &e.to_string()))?;
    let current = runtime_plan::HostIdentity::read(&executable)?;
    if target_package.identity != current {
        return Err(failure(
            "host_identity",
            "package and executing Host identities differ",
        ));
    }
    let source = UpgradeSource::open(home)?;
    let source_root = source
        .snapshot
        .host
        .executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| failure("host_identity", "missing source Host root"))?;
    let target_root = target_host
        .executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| failure("host_identity", "missing target Host root"))?;
    let destination = Destination::capture(candidate, home, &[source_root, target_root])?;
    let mut source_state =
        state::UpgradeState::capture(home, source.snapshot.generation.state.as_ref())?;
    let original = runtime_plan::prepare_upgrade(
        home,
        options,
        &source.snapshot,
        &BTreeMap::new(),
        Some(source.package.identity.clone()),
    )?;
    // Generations store the canonical lock digest, not a separate lock file.
    if lock(&original) != source.snapshot.generation.lock_sha256 {
        return Err(failure(
            "upgrade_source_lock",
            "source lock cannot be reproduced with these configuration options",
        ));
    }
    let mut replacements = BTreeMap::new();
    for input in variants {
        let input =
            std::path::absolute(input).map_err(|e| failure("upgrade_variant", &e.to_string()))?;
        if overlaps(&input, home)
            || overlaps(&input, candidate)
            || overlaps(&input, source_root)
            || overlaps(&input, target_root)
        {
            return Err(failure(
                "upgrade_variant",
                "variant overlaps protected inputs",
            ));
        }
        let snapshot = loader::installation_snapshot(&input)?;
        let Some(old) = source.snapshot.generation.installed.get(&snapshot.id) else {
            return Err(LoadError::input(
                "upgrade_variant",
                &snapshot.id,
                "variant ID is not installed",
            ));
        };
        let previous = loader::read_manifest(&home.join("store/objects").join(old))?.0;
        let next = crate::manifest::parse(&snapshot.files["mod.toml"])?;
        if previous.version != next.version || replacements.contains_key(&snapshot.id) {
            return Err(LoadError::input(
                "upgrade_variant",
                &snapshot.id,
                "variant must have the same version and a unique installed ID",
            ));
        }
        replacements.insert(snapshot.id, (input, snapshot.sha256));
    }
    let target =
        runtime_plan::prepare_upgrade(home, options, &source.snapshot, &replacements, None)?;
    if let Some(state) = &source_state {
        state.check_contracts(target.state_contracts())?;
    }
    let expected = lock(&target);
    let mut retained = Vec::new();
    let mut retained_bytes = 0_usize;
    if let Some(state) = &source_state {
        for (id, digest) in state.objects() {
            if source.snapshot.generation.installed.get(&id) == Some(&digest) {
                continue;
            }
            let path = home.join("store/objects").join(&digest);
            let snapshot = loader::installation_snapshot(&path)?;
            if snapshot.id != id || snapshot.sha256 != digest {
                return Err(LoadError::input(
                    "input_drift",
                    &id,
                    "retained state object differs from its address",
                ));
            }
            retained_bytes += snapshot.files.values().map(Vec::len).sum::<usize>();
            if retained_bytes > 256 * 1024 * 1024 {
                return Err(failure("budget", "retained package snapshot byte limit"));
            }
            retained.push((path, snapshot));
        }
    }
    let revalidate = || -> Result<(), LoadError> {
        source.revalidate()?;
        target_package.revalidate()?;
        original.revalidate_inputs()?;
        target.revalidate()?;
        revalidate_objects(&retained)
    };
    revalidate()?;
    destination.revalidate(None)?;
    let mut report = json!({
        "schema_version":2, "operation":"upgrade", "declared_compatible":true,
        "verified":false, "already_native_executed":false, "committed":false,
        "source_home":home, "candidate_home":candidate,
        "source_generation":source.snapshot.generation_id,
        "source_lock_sha256":source.snapshot.generation.lock_sha256,
        "target_lock_sha256":expected,
        "source_host":{"release_id":source.package.release_id,"identity":source.package.identity},
        "target_host":{"release_id":target_package.release_id,"identity":current},
        "variants":replacements.iter().map(|(id, (_, digest))| (id, digest)).collect::<BTreeMap<_, _>>(),
        "candidate_manifests":target.plan().candidate_manifests,
        "candidate_contents":target.plan().candidate_contents,
        "installed":source.snapshot.generation.installed,
        "enabled":source.snapshot.generation.enabled,
        "config":target.plan().config, "state_contracts":target.state_contracts(),
        "restart_required":true, "data_preserved":true
    });
    if check {
        if let Some(state) = &source_state {
            state.revalidate()?;
        }
        return Ok(report);
    }
    let mut transaction = Transaction::begin_candidate(candidate, target_host)?;
    let created = Directory::open(candidate).map_err(|e| failure("input_drift", &e))?;
    destination.revalidate(Some(&created))?;
    // Retained state may refer to an older object with the same installed ID.
    for (path, snapshot) in &retained {
        transaction.next.installed.clear();
        transaction.next.enabled.clear();
        mod_install::ingest(&mut transaction, path, None)?;
        if transaction.next.installed.get(&snapshot.id) != Some(&snapshot.sha256) {
            return Err(failure(
                "input_drift",
                "retained object changed during copy",
            ));
        }
    }
    transaction.next.installed.clear();
    transaction.next.enabled.clear();
    for (_, path, _) in source.snapshot.packages() {
        mod_install::ingest(&mut transaction, &path, None)?;
    }
    for (id, (path, _)) in &replacements {
        let old = &source.snapshot.generation.installed[id];
        mod_install::ingest(&mut transaction, path, Some((id, old)))?;
    }
    transaction.next.enabled = source.snapshot.generation.enabled.clone();
    transaction.next.consumed = source.snapshot.generation.consumed.clone();
    transaction
        .next
        .consumed
        .extend(replacements.values().map(|(_, digest)| digest.clone()));
    if source.snapshot.generation.config_sha256.is_some() {
        let (bytes, _) = loader::read_input(&home.join("cm-runtime.toml"), loader::MAX_MANIFEST)
            .map_err(|e| failure("input_drift", &e))?;
        transaction
            .root
            .create_file("cm-runtime.toml", &bytes)
            .map_err(|e| failure("upgrade_copy", &e))?;
    }
    if let Some(state) = &mut source_state {
        state.copy_into(&mut transaction)?;
    }
    let result = transaction.commit_checked(options, |prepared| {
        revalidate()?;
        if let Some(state) = &source_state {
            state.revalidate()?;
        }
        destination.revalidate(Some(&created))?;
        if lock(prepared) != expected {
            return Err(failure(
                "input_drift",
                "candidate lock differs from the checked plan",
            ));
        }
        Ok(())
    })?;
    report["committed"] = json!(true);
    report["generation"] = result["generation"].clone();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_must_not_alias_inputs_or_official_home() {
        for path in [
            "relative",
            "/",
            "/tmp/source",
            "/tmp/source/child",
            "/tmp/../candidate",
        ] {
            assert!(Destination::capture(Path::new(path), Path::new("/tmp/source"), &[]).is_err());
        }
        assert!(
            Destination::capture(
                Path::new("/tmp/host/profile"),
                Path::new("/tmp/source"),
                &[Path::new("/tmp/host")],
            )
            .is_err()
        );
        #[cfg(windows)]
        {
            for path in [r"C:\", r"c:\CM\source", r"C:\CM\source\child", r"C:\CM\source\..\candidate", r"\\?\C:\CM\candidate"] {
                assert!(Destination::capture(Path::new(path), Path::new(r"C:\CM\SOURCE"), &[]).is_err(), "{path}");
            }
            assert!(overlaps(Path::new(r"C:\CM\HOST\profile"), Path::new(r"c:\cm\host")));
            assert!(!overlaps(Path::new(r"C:\CM\candidate"), Path::new(r"c:\cm\source")));
        }
    }
}
