use std::ffi::CStr;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::NonNull;

use libloading::os::windows::Library;

unsafe extern "C" {
    fn cm_windows_pin_copy(bytes: *const u8, length: usize, kind: u32) -> *mut c_void;
    fn cm_windows_pin_free(pin: *mut c_void);
    fn cm_windows_pin_path(pin: *const c_void) -> *const u16;
    fn cm_windows_pin_load(pin: *const c_void, dependencies: *const u16) -> *mut c_void;
}

fn wide(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut result: Vec<_> = value.encode_wide().collect();
    if result.contains(&0) || result.len() >= 4096 {
        return Err("Windows path/dependency list exceeds bounds or contains NUL".into());
    }
    result.push(0);
    Ok(result)
}

pub(crate) struct Snapshot {
    pin: NonNull<c_void>,
    path: PathBuf,
}

// The snapshot owns ordinary file handles with no thread affinity.
unsafe impl Send for Snapshot {}

impl Snapshot {
    fn take(pin: *mut c_void) -> Result<Self, String> {
        let pin = NonNull::new(pin).ok_or_else(|| std::io::Error::last_os_error().to_string())?;
        let path = unsafe { cm_windows_pin_path(pin.as_ptr()) };
        let length = (0..4096).find(|&at| unsafe { *path.add(at) == 0 }).unwrap();
        let path =
            std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(path, length) });
        Ok(Self {
            pin,
            path: path.into(),
        })
    }

    pub(crate) fn create(bytes: &[u8], name: &CStr) -> Result<Self, String> {
        let kind = match name.to_bytes() {
            b"cm-mod-v1" => 0,
            b"cm-distribution-verifier" => 1,
            b"cm-distribution-bundle" => 2,
            _ => 3,
        };
        Self::take(unsafe { cm_windows_pin_copy(bytes.as_ptr(), bytes.len(), kind) })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn load(self, needed: &[String]) -> Result<&'static Library, String> {
        let dependencies = wide(OsStr::new(&needed.join(",")))?;
        // Constructors can publish pointers even if loading or negotiation fails.
        // The Windows entry supervisor discards its owned stage after the child exits.
        let pinned = Box::leak(Box::new(self));
        let module = unsafe { cm_windows_pin_load(pinned.pin.as_ptr(), dependencies.as_ptr()) };
        if module.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let library = unsafe { Library::from_raw(module as _) };
        Ok(Box::leak(Box::new(library)))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe { cm_windows_pin_free(self.pin.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_budgets_distinguish_verifiers_modules_and_bundles() {
        for (kind, limit) in [(0, 64), (1, 128), (2, 2), (3, 32)] {
            assert!(
                unsafe { cm_windows_pin_copy(b"x".as_ptr(), limit * 1024 * 1024 + 1, kind) }
                    .is_null()
            );
        }
        assert!(unsafe { cm_windows_pin_copy(b"x".as_ptr(), 1, 4) }.is_null());
        let bytes = vec![b'x'; 33 * 1024 * 1024];
        let snapshot = Snapshot::create(&bytes, c"cm-distribution-verifier").unwrap();
        let path = snapshot.path().to_owned();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes.len() as u64);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        drop(snapshot);
        assert!(!path.exists());
    }
}
