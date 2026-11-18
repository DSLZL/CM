use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::ops::Deref;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::Arc;

use super::Information;

#[repr(C)]
struct NativeInformation {
    volume: u64,
    id: [u8; 16],
    size: i64,
    modified: i64,
    changed: i64,
    links: u32,
    attributes: u32,
}

unsafe extern "C" {
    fn cm_windows_directory_open(path: *const u16) -> *mut std::ffi::c_void;
    fn cm_windows_child_open(
        parent: *const std::ffi::c_void,
        name: *const u16,
        directory: i32,
    ) -> *mut std::ffi::c_void;
    fn cm_windows_file_information(
        pin: *const std::ffi::c_void,
        info: *mut NativeInformation,
    ) -> i32;
    fn cm_windows_pin_duplicate(pin: *const std::ffi::c_void) -> *mut std::ffi::c_void;
    fn cm_windows_pin_path(pin: *const std::ffi::c_void) -> *const u16;
    fn cm_windows_pin_free(pin: *mut std::ffi::c_void);
}

struct Pin(NonNull<std::ffi::c_void>);

// The immutable pin contains only Windows handles; Arc closes them after the final reader.
unsafe impl Send for Pin {}
unsafe impl Sync for Pin {}

impl Drop for Pin {
    fn drop(&mut self) {
        unsafe { cm_windows_pin_free(self.0.as_ptr()) };
    }
}

pub(crate) struct Handle {
    file: File,
    pin: Arc<Pin>,
    path: PathBuf,
}

impl Handle {
    fn take(raw: *mut std::ffi::c_void) -> Result<Self, String> {
        let pin = Arc::new(Pin(NonNull::new(raw).ok_or_else(|| {
            io::Error::last_os_error().to_string()
        })?));
        let raw = unsafe { cm_windows_pin_duplicate(pin.0.as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error().to_string());
        }
        let file = unsafe { File::from_raw_handle(raw) };
        let path = unsafe { cm_windows_pin_path(pin.0.as_ptr()) };
        let mut length = 0;
        while length < 4096 && unsafe { *path.add(length) } != 0 {
            length += 1;
        }
        if length == 4096 {
            return Err("pinned input path exceeds its bound".into());
        }
        let path = OsString::from_wide(unsafe { std::slice::from_raw_parts(path, length) });
        Ok(Self { file, pin, path: path.into() })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            pin: Arc::clone(&self.pin),
            path: self.path.clone(),
        })
    }
}

impl Deref for Handle {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
}

impl Read for Handle {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for Handle {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

fn wide(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.is_empty() || value.len() >= 4096 || value.contains(&0) {
        return Err("invalid Windows input path".into());
    }
    value.push(0);
    Ok(value)
}

pub(crate) fn open_directory(path: &Path) -> Result<Handle, String> {
    let path = wide(path.as_os_str())?;
    Handle::take(unsafe { cm_windows_directory_open(path.as_ptr()) })
}

pub(crate) fn open_at(parent: &Handle, name: &OsStr, directory: bool) -> Result<Handle, String> {
    let name = wide(name)?;
    Handle::take(unsafe {
        cm_windows_child_open(parent.pin.0.as_ptr(), name.as_ptr(), i32::from(directory))
    })
}

pub(in super::super) fn information(file: &Handle) -> Result<Information, String> {
    let mut info = std::mem::MaybeUninit::uninit();
    if unsafe { cm_windows_file_information(file.pin.0.as_ptr(), info.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let info: NativeInformation = unsafe { info.assume_init() };
    Ok(Information {
        identity: (info.volume, info.id),
        size: u64::try_from(info.size).map_err(|_| "negative input length")?,
        modified: (info.modified, 0),
        changed: (info.changed, 0),
        regular: info.attributes & 0x10 == 0,
        links: u64::from(info.links),
    })
}
