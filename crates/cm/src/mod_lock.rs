//! A reproducibility record, never executable input or a substitute for prepare/commit.
#[cfg(windows)]
use std::ffi::OsStr;
use std::io::Write;
#[cfg(not(windows))]
use std::os::fd::AsRawFd;
#[cfg(not(windows))]
use std::os::fd::FromRawFd;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
#[cfg(not(windows))]
use std::{ffi::CString, fs::File};

use serde::Serialize;

use crate::LoadError;
use crate::loader;
use crate::runtime_plan::{PreparedPlan, RuntimePlan};

const LIMIT: u64 = 4 * 1024 * 1024;
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct RuntimeLock<'a> {
    schema_version: u32,
    domain: &'static str,
    plan: &'a RuntimePlan,
}

pub fn canonical(plan: &RuntimePlan) -> Vec<u8> {
    let value = serde_json::to_value(RuntimeLock {
        schema_version: 1,
        domain: "cm.mod-lock.v1",
        plan,
    })
    .expect("lock serializes");
    crate::config::json_bytes(&value)
}

fn failure(message: &str) -> LoadError {
    LoadError::input("mod_lock", "", message)
}

pub fn check(home: &Path, plan: &RuntimePlan) -> Result<(), LoadError> {
    let (bytes, _) = loader::read_input(&home.join("mod.lock"), LIMIT)
        .map_err(|_| failure("mod.lock: missing or unsafe file"))?;
    // Only canonical records match: duplicate/unknown fields, schemas and stale inputs all fail.
    if bytes != canonical(plan) {
        return Err(failure(
            "mod.lock: stale or noncanonical; regenerate explicitly with cm lock",
        ));
    }
    Ok(())
}

pub(crate) fn present(home: &Path) -> Result<bool, LoadError> {
    match std::fs::symlink_metadata(home.join("mod.lock")) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(failure("mod.lock: cannot inspect file")),
    }
}

pub fn write(home: &Path, prepared: &PreparedPlan) -> Result<(), LoadError> {
    let directory =
        loader::open_directory(home).map_err(|_| failure("mod.lock: unsafe profile directory"))?;
    #[cfg(windows)]
    directory
        .check_private()
        .map_err(|_| failure("mod.lock: unsafe profile directory"))?;
    let before =
        loader::identity(&directory).map_err(|_| failure("mod.lock: cannot inspect profile"))?;
    let old = if present(home)? {
        Some(
            loader::read_input(&home.join("mod.lock"), LIMIT)
                .map_err(|_| failure("mod.lock: existing file is unsafe"))?
                .1,
        )
    } else {
        None
    };
    let bytes = canonical(prepared.plan());
    if bytes.len() as u64 > LIMIT {
        return Err(failure("mod.lock: byte limit"));
    }
    let name = format!(
        ".mod.lock.{}.{}.tmp",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    );
    #[cfg(not(windows))]
    let native_name = CString::new(name.as_str()).expect("constant path parts");
    #[cfg(not(windows))]
    let mut temp = {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                native_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(failure("mod.lock: cannot create exclusive temporary file"));
        }
        unsafe { File::from_raw_fd(fd) }
    };
    #[cfg(windows)]
    let mut temp = directory
        .create_output(OsStr::new(&name))
        .map_err(|_| failure("mod.lock: cannot create exclusive temporary file"))?;
    #[cfg(windows)]
    let temporary_identity =
        loader::identity(&temp).map_err(|_| failure("mod.lock: cannot identify temporary file"))?;
    let result = (|| {
        temp.write_all(&bytes)
            .and_then(|()| temp.flush())
            .and_then(|()| temp.sync_all())
            .map_err(|_| failure("mod.lock: temporary write failed"))?;
        prepared.revalidate()?;
        let current = loader::open_directory(home)
            .and_then(|f| loader::identity(&f))
            .map_err(|_| failure("mod.lock: profile changed"))?;
        if before != current {
            return Err(failure("mod.lock: profile changed"));
        }
        if let Some(old) = &old {
            old.revalidate()
                .map_err(|_| failure("mod.lock: existing lock changed"))?;
        } else if present(home)? {
            return Err(failure("mod.lock: concurrent lock appeared"));
        }
        #[cfg(not(windows))]
        {
            if unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    native_name.as_ptr(),
                    directory.as_raw_fd(),
                    c"mod.lock".as_ptr(),
                )
            } != 0
            {
                return Err(failure("mod.lock: atomic rename failed"));
            }
            directory
                .sync_all()
                .map_err(|_| failure("mod.lock: directory sync failed after rename"))?;
        }
        #[cfg(windows)]
        {
            drop(temp);
            if let Some(old) = &old {
                directory
                    .replace(OsStr::new(&name), OsStr::new("mod.lock"), old.identity())
                    .map_err(|e| failure(&e))?;
            } else if !directory
                .publish(OsStr::new(&name), OsStr::new("mod.lock"))
                .map_err(|e| failure(&e))?
            {
                return Err(failure("mod.lock: concurrent lock appeared"));
            }
            directory
                .sync_private_directory()
                .map_err(|e| failure(&format!("committed: {e}")))?;
        }
        Ok(())
    })();
    if result.is_err() {
        #[cfg(not(windows))]
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), native_name.as_ptr(), 0);
        }
        #[cfg(windows)]
        let _ = directory.remove(OsStr::new(&name), temporary_identity, false);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_drift_preserves_old_lock_and_removes_temporary_file() {
        let home = std::env::temp_dir().join(format!("cm-lock-drift-{}", std::process::id()));
        #[cfg(not(windows))]
        std::fs::create_dir(&home).unwrap();
        #[cfg(windows)]
        crate::profile::Directory::create_home(&home).unwrap();
        let selected = home.join("cm-runtime.toml");
        std::fs::write(&selected, "format_version = 1\nenabled = []\n").unwrap();
        let prepared = crate::runtime_plan::prepare(&home).unwrap();
        write(&home, &prepared).unwrap();
        let original = std::fs::read(home.join("mod.lock")).unwrap();
        check(&home, prepared.plan()).unwrap();
        std::fs::write(&selected, "format_version = 1\nenabled = []\n# drift\n").unwrap();
        assert!(write(&home, &prepared).is_err());
        assert_eq!(std::fs::read(home.join("mod.lock")).unwrap(), original);
        assert!(std::fs::read_dir(&home).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        std::fs::remove_file(home.join("mod.lock")).unwrap();
        std::fs::remove_file(selected).unwrap();
        std::fs::remove_dir(home).unwrap();
    }
}
