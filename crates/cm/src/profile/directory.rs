#[cfg(not(windows))]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::loader;

pub(crate) struct Directory {
    pub file: loader::Handle,
    pub path: PathBuf,
}

impl Directory {
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
}
