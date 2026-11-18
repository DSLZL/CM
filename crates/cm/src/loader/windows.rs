use std::ffi::CStr;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::NonNull;

use libloading::os::windows::Library;

unsafe extern "C" {
    fn cm_windows_pin_open(path: *const u16, expected: *const u16) -> *mut c_void;
    fn cm_windows_pin_copy(bytes: *const u8, length: usize, kind: u32) -> *mut c_void;
    fn cm_windows_pin_free(pin: *mut c_void);
    fn cm_windows_pin_duplicate(pin: *const c_void) -> *mut c_void;
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
    file: Option<File>,
    pin: NonNull<c_void>,
    path: PathBuf,
}

// The snapshot owns ordinary file handles with no thread affinity.
unsafe impl Send for Snapshot {}

impl Snapshot {
    fn take(pin: *mut c_void) -> Result<Self, String> {
        let pin = NonNull::new(pin).ok_or_else(|| std::io::Error::last_os_error().to_string())?;
        let file = unsafe { cm_windows_pin_duplicate(pin.as_ptr()) };
        if file.is_null() {
            let error = std::io::Error::last_os_error().to_string();
            unsafe { cm_windows_pin_free(pin.as_ptr()) };
            return Err(error);
        }
        let path = unsafe { cm_windows_pin_path(pin.as_ptr()) };
        let length = (0..4096).find(|&at| unsafe { *path.add(at) == 0 }).unwrap();
        let path =
            std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(path, length) });
        Ok(Self {
            file: Some(unsafe { File::from_raw_handle(file) }),
            pin,
            path: path.into(),
        })
    }

    pub(crate) fn open(path: &Path, expected: &str) -> Result<Self, String> {
        let path = wide(path.as_os_str())?;
        let expected = wide(OsStr::new(expected))?;
        Self::take(unsafe { cm_windows_pin_open(path.as_ptr(), expected.as_ptr()) })
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

    pub(crate) fn read(&self) -> Result<Vec<u8>, String> {
        let mut file = self
            .file
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.is_empty() || bytes.len() > 32 * 1024 * 1024 {
            return Err("Windows snapshot size exceeds bounds".into());
        }
        Ok(bytes)
    }

    pub(crate) fn load(self, needed: &[String]) -> Result<&'static Library, String> {
        let dependencies = wide(OsStr::new(&needed.join(",")))?;
        // Constructors can publish pointers even if loading or negotiation fails.
        // shortcut: loaded temp snapshots need launcher cleanup after exit before Windows is enabled.
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
        drop(self.file.take());
        unsafe { cm_windows_pin_free(self.pin.as_ptr()) };
    }
}
