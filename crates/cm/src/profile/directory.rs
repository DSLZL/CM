#[cfg(not(windows))]
use std::ffi::CString;
use std::ffi::OsStr;
#[cfg(not(windows))]
use std::fs::File;
#[cfg(not(windows))]
use std::io::Write;
#[cfg(not(windows))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(not(windows))]
use std::os::unix::ffi::OsStrExt;
#[cfg(not(windows))]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::loader;

pub(crate) struct Directory {
    pub file: loader::Handle,
    pub path: PathBuf,
}

impl Directory {
    pub(crate) fn sync(&self) -> Result<(), String> {
        #[cfg(not(windows))]
        return self.file.sync_all().map_err(|error| error.to_string());
        #[cfg(windows)]
        self.file.sync_private_directory()
    }

    #[cfg(windows)]
    pub(crate) fn create_home(path: &Path) -> Result<Self, String> {
        let parent = loader::open_directory(path.parent().ok_or("missing home parent")?)?;
        let file = parent.create_home(path.file_name().ok_or("missing home name")?)?;
        let result = Self { file, path: path.into() };
        result
            .check()
            .map_err(|error| format!("committed: private home created; {error}"))?;
        Ok(result)
    }

    #[cfg(windows)]
    pub(crate) fn replace_file(
        &self,
        temporary: &str,
        target: &str,
        expected: Option<loader::Identity>,
    ) -> Result<(), String> {
        self.check()?;
        if let Some(expected) = expected {
            self.file.replace(OsStr::new(temporary), OsStr::new(target), expected)?;
            self.file
                .sync_private_directory()
                .and_then(|()| self.check())
                .map_err(|error| format!("committed: namespace replacement completed; {error}"))
        } else if self.publish(temporary, target)? {
            Ok(())
        } else {
            Err("active descriptor appeared before publication".into())
        }
    }

    #[cfg(not(windows))]
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

    #[cfg(windows)]
    pub(crate) fn publish(&self, temporary: &str, target: &str) -> Result<bool, String> {
        self.check()?;
        let published = self
            .file
            .publish(OsStr::new(temporary), OsStr::new(target))?;
        if published {
            self.file
                .sync_private_directory()
                .and_then(|()| self.check())
                .map_err(|error| format!("committed: namespace publication completed; {error}"))?;
        } else {
            self.check()?;
        }
        Ok(published)
    }

    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let file = loader::open_directory(path)?;
        #[cfg(not(windows))]
        {
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(
                    "managed directory must be owned by this user and private (0700)".into(),
                );
            }
        }
        #[cfg(windows)]
        file.check_private()?;
        Ok(Self {
            file,
            path: path.into(),
        })
    }

    pub(crate) fn check(&self) -> Result<(), String> {
        let current = loader::open_directory(&self.path)?;
        #[cfg(not(windows))]
        {
            let old = self.file.metadata().map_err(|e| e.to_string())?;
            let now = current.metadata().map_err(|e| e.to_string())?;
            if (old.dev(), old.ino()) != (now.dev(), now.ino())
                || now.uid() != unsafe { libc::geteuid() }
                || now.mode() & 0o077 != 0
            {
                return Err("managed directory identity/ownership changed".into());
            }
        }
        #[cfg(windows)]
        {
            if self.file.identity()? != current.identity()? {
                return Err("managed directory identity/ownership changed".into());
            }
            self.file.check_private()?;
            current.check_private()?;
        }
        Ok(())
    }

    pub(crate) fn child(&self, name: &str) -> Result<Self, String> {
        self.child_mode(name, false)
    }

    pub(crate) fn staging(&self, name: &str) -> Result<Self, String> {
        self.child_mode(name, true)
    }

    #[cfg(not(windows))]
    fn child_mode(&self, name: &str, create_only: bool) -> Result<Self, String> {
        let name_c = CString::new(name).map_err(|e| e.to_string())?;
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0
            && (create_only
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists)
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

    #[cfg(windows)]
    fn child_mode(&self, name: &str, create_only: bool) -> Result<Self, String> {
        self.check()?;
        let result = Self {
            file: self.file.create_directory(OsStr::new(name), create_only)?,
            path: self.path.join(name),
        };
        result.check()?;
        self.file.sync_private_directory()?;
        self.check()?;
        Ok(result)
    }

    #[cfg(not(windows))]
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

    #[cfg(windows)]
    // The caller must flush, revalidate, and discard its staging tree on failure.
    pub(crate) fn create_output(&self, name: &str) -> Result<loader::Handle, String> {
        self.check()?;
        self.file.create_output(OsStr::new(name))
    }

    #[cfg(windows)]
    pub(crate) fn create_file(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.check()?;
        self.file.create_file(OsStr::new(name), bytes)
    }

    #[cfg(not(windows))]
    pub(crate) fn writer_file(&self, create: bool) -> Result<loader::Handle, String> {
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c".cm-write.lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_NONBLOCK
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | if create { libc::O_CREAT } else { 0 },
                0o600,
            )
        };
        if fd < 0 {
            return Err("profile write lock is absent or unsafe".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("profile write lock is busy or unsafe".into());
        }
        Ok(file)
    }

    #[cfg(windows)]
    pub(crate) fn writer_file(&self, create: bool) -> Result<loader::Handle, String> {
        self.check()?;
        loader::open_lock(&self.file, OsStr::new(".cm-write.lock"), create)
    }

    #[cfg(windows)]
    pub(crate) fn remove(
        &self,
        name: &OsStr,
        expected: loader::Identity,
        directory: bool,
    ) -> Result<(), String> {
        self.check()?;
        self.file.remove(name, expected, directory)?;
        self.file
            .sync_private_directory()
            .and_then(|()| self.check())
            .map_err(|error| format!("committed: private removal completed; {error}"))
    }
}

/// Removes only this operation's private, never-published staging tree.
#[cfg(not(windows))]
pub(crate) fn discard(
    parent: &Directory,
    name: &str,
    expected: loader::Identity,
) -> Result<(), String> {
    let c_name = CString::new(name).map_err(|e| e.to_string())?;
    let file = loader::open_at(&parent.file, OsStr::new(name), true)?;
    if loader::identity(&file)? != expected {
        return Err("staging directory identity changed".into());
    }
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|e| e.to_string())?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let entry_name = entry.file_name();
        let directory = loader::open_at(&file, &entry_name, true);
        let leaf = CString::new(entry_name.as_bytes()).map_err(|e| e.to_string())?;
        if let Ok(directory) = directory {
            let expected = loader::identity(&directory)?;
            let child = Directory {
                file: file.try_clone().map_err(|e| e.to_string())?,
                path: parent.path.join(name),
            };
            discard(
                &child,
                entry_name.to_str().ok_or("non-UTF8 staging name")?,
                expected,
            )?;
        } else if unsafe { libc::unlinkat(file.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    if loader::identity(&loader::open_at(&parent.file, OsStr::new(name), true)?)? != expected {
        return Err("staging directory identity changed".into());
    }
    if unsafe { libc::unlinkat(parent.file.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR) } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn discard(
    parent: &Directory,
    name: &str,
    expected: loader::Identity,
) -> Result<(), String> {
    parent.check()?;
    let file = loader::open_at(&parent.file, OsStr::new(name), true)?;
    if loader::identity(&file)? != expected {
        return Err("staging directory identity changed".into());
    }
    let stage = Directory {
        file,
        path: parent.path.join(name),
    };
    stage.check()?;
    let names = std::fs::read_dir(&stage.path)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    for name in names {
        if let Ok(file) = loader::open_at(&stage.file, &name, true) {
            file.check_private()?;
            let expected = loader::identity(&file)?;
            drop(file);
            discard(
                &stage,
                name.to_str().ok_or("non-UTF8 staging name")?,
                expected,
            )?;
        } else {
            let file = loader::open_at(&stage.file, &name, false)?;
            file.check_private()?;
            let expected = loader::identity(&file)?;
            drop(file);
            stage.remove(&name, expected, false)?;
        }
    }
    stage.check()?;
    drop(stage);
    parent.remove(OsStr::new(name), expected, true)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn staging_cleanup_preserves_a_replacement_directory() {
        let path = std::env::temp_dir().join(super::super::temporary("directory-test"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let root = Directory::open(&path).unwrap();
        let stage = root.staging("stage").unwrap();
        stage
            .child("nested")
            .unwrap()
            .create_file("value", b"owned")
            .unwrap();
        let original = loader::identity(&stage.file).unwrap();
        assert!(root.staging("stage").is_err());
        drop(stage);
        std::fs::rename(path.join("stage"), path.join("saved")).unwrap();
        let replacement = root.staging("stage").unwrap();
        replacement.create_file("value", b"keep").unwrap();
        let replaced = loader::identity(&replacement.file).unwrap();
        drop(replacement);
        assert_ne!(original, replaced);
        assert!(discard(&root, "stage", original).is_err());
        assert_eq!(std::fs::read(path.join("stage/value")).unwrap(), b"keep");
        assert_eq!(
            std::fs::read(path.join("saved/nested/value")).unwrap(),
            b"owned"
        );
        discard(&root, "stage", replaced).unwrap();
        discard(&root, "saved", original).unwrap();
        assert!(std::fs::read_dir(&path).unwrap().next().is_none());
        drop(root);
        std::fs::remove_dir(path).unwrap();
    }
}
