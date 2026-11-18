use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
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
    fn cm_windows_private_check(pin: *const std::ffi::c_void) -> i32;
    fn cm_windows_private_metadata(
        pin: *const std::ffi::c_void,
        attributes: *mut u32,
        text: *mut u16,
        capacity: usize,
    ) -> i32;
    fn cm_windows_private_copy_metadata(
        target: *const std::ffi::c_void,
        source: *const std::ffi::c_void,
    ) -> i32;
    fn cm_windows_private_create(
        parent: *const std::ffi::c_void,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn cm_windows_private_write(
        parent: *const std::ffi::c_void,
        name: *const u16,
        bytes: *const u8,
        length: usize,
    ) -> i32;
    fn cm_windows_private_directory(
        parent: *const std::ffi::c_void,
        name: *const u16,
        create_only: i32,
    ) -> *mut std::ffi::c_void;
    fn cm_windows_private_sync(directory: *const std::ffi::c_void) -> i32;
    fn cm_windows_home_create(
        parent: *const std::ffi::c_void,
        name: *const u16,
        created: *mut i32,
    ) -> *mut std::ffi::c_void;
    fn cm_windows_private_publish(
        parent: *const std::ffi::c_void,
        source: *const u16,
        target: *const u16,
    ) -> i32;
    fn cm_windows_private_replace(
        parent: *const std::ffi::c_void,
        source: *const u16,
        target: *const u16,
        volume: u64,
        id: *const u8,
    ) -> i32;
    fn cm_windows_private_remove(
        parent: *const std::ffi::c_void,
        name: *const u16,
        volume: u64,
        id: *const u8,
        directory: i32,
    ) -> i32;
    fn cm_windows_lock_open(
        parent: *const std::ffi::c_void,
        name: *const u16,
        create: i32,
    ) -> *mut std::ffi::c_void;
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
    pub(crate) fn private_metadata(&self) -> Result<(u32, String), String> {
        let mut text = vec![0; 4096];
        let mut attributes = 0;
        if unsafe {
            cm_windows_private_metadata(
                self.pin.0.as_ptr(),
                &mut attributes,
                text.as_mut_ptr(),
                text.len(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        let length = text
            .iter()
            .position(|value| *value == 0)
            .ok_or("unterminated private metadata")?;
        Ok((
            attributes,
            String::from_utf16(&text[..length]).map_err(|e| e.to_string())?,
        ))
    }

    // Only use on unpublished output; failure can leave partially copied metadata.
    pub(crate) fn copy_metadata(&self, source: &Self) -> Result<(), String> {
        let target = self.pin.0.as_ptr();
        let source = source.pin.0.as_ptr();
        let result = unsafe { cm_windows_private_copy_metadata(target, source) };
        if result != 1 {
            let error = io::Error::last_os_error();
            return Err(format!("private metadata copy failed ({result}): {error}"));
        }
        Ok(())
    }

    pub(crate) fn check_private(&self) -> Result<(), String> {
        if unsafe { cm_windows_private_check(self.pin.0.as_ptr()) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> Result<super::Identity, String> {
        Ok(information(self)?.identity)
    }

    pub(crate) fn create_file(&self, name: &OsStr, bytes: &[u8]) -> Result<(), String> {
        let name = wide(name)?;
        if unsafe {
            cm_windows_private_write(
                self.pin.0.as_ptr(),
                name.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    pub(crate) fn create_output(&self, name: &OsStr) -> Result<Self, String> {
        let name = wide(name)?;
        Self::take(unsafe { cm_windows_private_create(self.pin.0.as_ptr(), name.as_ptr()) })
    }

    pub(crate) fn create_directory(&self, name: &OsStr, create_only: bool) -> Result<Self, String> {
        let name = wide(name)?;
        Self::take(unsafe {
            cm_windows_private_directory(self.pin.0.as_ptr(), name.as_ptr(), i32::from(create_only))
        })
    }

    pub(crate) fn create_home(&self, name: &OsStr) -> Result<Self, String> {
        let name = wide(name)?;
        let mut created = 0;
        let raw =
            unsafe { cm_windows_home_create(self.pin.0.as_ptr(), name.as_ptr(), &mut created) };
        Self::take(raw).map_err(|error| {
            if created != 0 {
                format!("committed: private home created; {error}")
            } else {
                error
            }
        })
    }

    pub(crate) fn sync_private_directory(&self) -> Result<(), String> {
        if unsafe { cm_windows_private_sync(self.pin.0.as_ptr()) } == 0 {
            let error = io::Error::last_os_error();
            return Err(format!("private directory flush failed: {error}"));
        }
        Ok(())
    }

    pub(crate) fn publish(&self, source: &OsStr, target: &OsStr) -> Result<bool, String> {
        self.rename(source, target, None)
    }

    pub(crate) fn replace(
        &self,
        source: &OsStr,
        target: &OsStr,
        expected: super::Identity,
    ) -> Result<(), String> {
        if self.rename(source, target, Some(expected))? {
            Ok(())
        } else {
            Err("expected private replacement did not commit".into())
        }
    }

    fn rename(
        &self,
        source: &OsStr,
        target: &OsStr,
        expected: Option<super::Identity>,
    ) -> Result<bool, String> {
        let source = wide(source)?;
        let target = wide(target)?;
        match unsafe {
            if let Some((volume, id)) = expected {
                cm_windows_private_replace(
                    self.pin.0.as_ptr(),
                    source.as_ptr(),
                    target.as_ptr(),
                    volume,
                    id.as_ptr(),
                )
            } else {
                cm_windows_private_publish(self.pin.0.as_ptr(), source.as_ptr(), target.as_ptr())
            }
        } {
            1 => Ok(true),
            0 => Ok(false),
            -2 => Err(format!(
                "committed: namespace publication completed; {}",
                io::Error::last_os_error()
            )),
            code => {
                let error = io::Error::last_os_error();
                let operation = match code {
                    -3 => "source open",
                    -4 => "permission validation",
                    -5 => "target preparation",
                    -6 => "rename",
                    _ => "parent validation",
                };
                Err(format!("namespace publication {operation} failed: {error}"))
            }
        }
    }

    pub(crate) fn remove(
        &self,
        name: &OsStr,
        expected: super::Identity,
        directory: bool,
    ) -> Result<(), String> {
        let name = wide(name)?;
        match unsafe {
            cm_windows_private_remove(
                self.pin.0.as_ptr(),
                name.as_ptr(),
                expected.0,
                expected.1.as_ptr(),
                i32::from(directory),
            )
        } {
            1 => Ok(()),
            -2 => Err(format!(
                "committed: private removal completed; {}",
                io::Error::last_os_error()
            )),
            code => {
                let error = io::Error::last_os_error();
                let operation = match code {
                    -3 => "source open",
                    -4 => "permission validation",
                    -5 => "identity validation",
                    -6 => "disposition",
                    _ => "parent validation",
                };
                Err(format!("private removal {operation} failed: {error}"))
            }
        }
    }

    fn take(raw: *mut std::ffi::c_void) -> Result<Self, String> {
        let pin = Arc::new(Pin(
            NonNull::new(raw).ok_or_else(|| io::Error::last_os_error().to_string())?
        ));
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
        Ok(Self {
            file,
            pin,
            path: path.into(),
        })
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

impl Write for Handle {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
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

pub(crate) fn open_lock(parent: &Handle, name: &OsStr, create: bool) -> io::Result<Handle> {
    let name = wide(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let raw = unsafe {
        cm_windows_lock_open(parent.pin.0.as_ptr(), name.as_ptr(), i32::from(create))
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    Handle::take(raw).map_err(io::Error::other)
}

pub(crate) fn information(file: &Handle) -> Result<Information, String> {
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
        attributes: info.attributes,
    })
}
