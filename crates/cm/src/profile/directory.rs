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
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::loader;

pub(crate) struct Directory {
    pub file: loader::Handle,
    pub path: PathBuf,
}

impl Directory {
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
        let published = self.file.publish(OsStr::new(temporary), OsStr::new(target))?;
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

    #[cfg(not(windows))]
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

    #[cfg(windows)]
    pub(crate) fn child(&self, name: &str) -> Result<Self, String> {
        self.check()?;
        let result = Self {
            file: self.file.create_directory(OsStr::new(name))?,
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
}
