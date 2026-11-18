#[cfg(not(windows))]
use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use sha2::Digest;
use sha2::Sha256;

#[cfg(not(windows))]
pub(crate) use std::fs::File as Handle;
#[cfg(not(windows))]
pub(crate) type Identity = (u64, u64);
#[cfg(windows)]
pub(crate) type Identity = (u64, [u8; 16]);
#[cfg(windows)]
#[path = "input/windows.rs"]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{Handle, open_at, open_directory, open_lock};

pub(crate) fn try_lock(file: &Handle, exclusive: bool) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        use std::os::fd::AsRawFd;

        let kind = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        if unsafe { libc::flock(file.as_raw_fd(), kind | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        file.check_private().map_err(std::io::Error::other)?;
        if exclusive {
            file.try_lock()
        } else {
            file.try_lock_shared()
        }
        .map_err(Into::into)
    }
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(not(windows))]
pub(crate) fn open_at(parent: &Handle, name: &OsStr, directory: bool) -> Result<Handle, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let name = std::ffi::CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { Handle::from_raw_fd(fd) })
}

#[cfg(not(windows))]
pub(crate) fn open_directory(path: &Path) -> Result<Handle, String> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err("managed path must be absolute".into());
    }
    let mut directory = Handle::open("/").map_err(|e| e.to_string())?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => directory = open_at(&directory, name, true)?,
            _ => return Err("managed path must have only normal components".into()),
        }
    }
    Ok(directory)
}

#[derive(PartialEq, Eq)]
pub(super) struct Information {
    identity: Identity,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    pub(super) regular: bool,
    pub(super) links: u64,
}

#[cfg(not(windows))]
pub(super) fn information(file: &Handle) -> Result<Information, String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|e| e.to_string())?;
    Ok(Information {
        identity: (metadata.dev(), metadata.ino()),
        size: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
        regular: metadata.is_file(),
        links: metadata.nlink(),
    })
}

#[cfg(windows)]
pub(super) use windows::information;

pub(crate) fn identity(file: &Handle) -> Result<Identity, String> {
    Ok(information(file)?.identity)
}

#[derive(Clone)]
pub(crate) struct InputPin {
    path: PathBuf,
    pub sha256: String,
    pub size: u64,
    limit: u64,
    identity: Identity,
}

impl InputPin {
    #[cfg(windows)]
    pub(crate) fn identity(&self) -> Identity {
        self.identity
    }

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
            || self.identity != current.identity
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
    let bound = limit.checked_add(1).ok_or("invalid input bound")?;
    let parent = open_directory(path.parent().ok_or("missing input parent")?)?;
    let mut file = open_at(
        &parent,
        path.file_name().ok_or("missing input name")?,
        false,
    )?;
    let before = information(&file)?;
    if !before.regular || before.links != 1 || before.size > limit {
        return Err("expected a bounded regular file with one link".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(bound)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit
        || bytes.len() as u64 != before.size
        || before != information(&file)?
    {
        return Err("input changed while reading or exceeded its bound".into());
    }
    let pin = InputPin {
        path: path.into(),
        sha256: hash(&bytes),
        size: bytes.len() as u64,
        limit,
        identity: before.identity,
    };
    Ok((bytes, pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revalidation_compares_the_complete_file_identity() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cm-input-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let path = std::fs::canonicalize(path).unwrap();
        #[cfg(windows)]
        let path = PathBuf::from(path.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
        let file = path.join("value");
        std::fs::write(&file, b"same bytes").unwrap();
        let (_, pin) = read_input(&file, 10).unwrap();
        pin.revalidate().unwrap();
        let mut changed = pin.clone();
        changed.identity.0 ^= 1;
        assert!(changed.revalidate().is_err());
        #[cfg(not(windows))]
        {
            let mut changed = pin.clone();
            changed.identity.1 ^= 1;
            assert!(changed.revalidate().is_err());
        }
        #[cfg(windows)]
        for byte in 0..16 {
            let mut changed = pin.clone();
            changed.identity.1[byte] ^= 1;
            assert!(changed.revalidate().is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
