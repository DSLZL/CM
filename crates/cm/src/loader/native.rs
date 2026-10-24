use std::ffi::c_void;
use std::mem::align_of;
use std::mem::size_of;
use std::ptr;

use cm_abi::*;
use libloading::os::unix::Library;
use libloading::os::unix::RTLD_LOCAL;
use libloading::os::unix::RTLD_NOW;

use super::Preflighted;
use super::snapshot_path;
use crate::LoadError;
use crate::event;

#[repr(C)]
struct ErrorStorage {
    before: [u8; 16],
    data: [u8; ERROR_CAPACITY],
    after: [u8; 16],
}

pub(crate) fn invoke(
    stage: &str,
    call: impl FnOnce(*mut ErrorBuffer) -> u32,
) -> Result<(), LoadError> {
    let mut storage = ErrorStorage {
        before: [0x5a; 16],
        data: [0; ERROR_CAPACITY],
        after: [0xa5; 16],
    };
    let data = storage.data.as_mut_ptr();
    let mut error = ErrorBuffer {
        data,
        capacity: ERROR_CAPACITY as u64,
        len: 0,
    };
    let status = call(&mut error);
    if storage.before != [0x5a; 16]
        || storage.after != [0xa5; 16]
        || error.data != data
        || error.capacity != ERROR_CAPACITY as u64
        || error.len > ERROR_CAPACITY as u64
    {
        return Err(LoadError::native(
            stage,
            "invalid error buffer/length/canary",
        ));
    }
    let message = std::str::from_utf8(&storage.data[..error.len as usize])
        .map_err(|_| LoadError::native(stage, "error buffer is not UTF-8"))?;
    match status {
        OK => Ok(()),
        FAILED | PANICKED => Err(LoadError::native(
            stage,
            &format!("status={status}: {message}"),
        )),
        _ => Err(LoadError::native(stage, "unknown ABI status")),
    }
}

fn header(header: Header, minimum: usize) -> Result<(), LoadError> {
    if header.struct_size < minimum as u32
        || header.struct_size > 4096
        || header.major != ABI_MAJOR
        || header.minor != ABI_MINOR
    {
        return Err(LoadError::native(
            "negotiate",
            "unsupported ABI table size/version",
        ));
    }
    Ok(())
}

pub(crate) unsafe fn text(view: Bytes, limit: usize) -> Result<String, LoadError> {
    if view.len > limit as u64 || (view.len != 0 && view.data.is_null()) {
        return Err(LoadError::native(
            "negotiate",
            "invalid byte view length/null",
        ));
    }
    let bytes = if view.len == 0 {
        &[]
    } else {
        // The ABI requires a valid readable allocation; native pointers are not sandboxed.
        unsafe { std::slice::from_raw_parts(view.data, view.len as usize) }
    };
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| LoadError::native("negotiate", "byte view is not UTF-8"))
}

#[repr(C)]
struct OutputStorage {
    before: [u8; 16],
    output: PolicyOutput,
    after: [u8; 16],
}

pub(crate) struct NativeMod {
    api: ModApi,
    userdata: *mut c_void,
}

// All access, including release, is serialized by the owning Runtime's mutex.
unsafe impl Send for NativeMod {}

pub(crate) fn open(
    manifest: &super::Manifest,
    snapshot: std::fs::File,
    needed: &[String],
) -> Result<&'static Library, LoadError> {
    let path = snapshot_path(&snapshot);
    event(
        "preflighted",
        serde_json::json!({
            "id": manifest.id, "version": manifest.version,
            "payload_sha256": manifest.payload_sha256,
            "needed": needed, "load_path": path, "sealed": true,
        }),
    );
    // Constructors can publish pointers even when negotiation subsequently fails.
    let _snapshot = Box::leak(Box::new(snapshot));
    event(
        "dlopen-start",
        serde_json::json!({"id": manifest.id, "already_native_executed": true}),
    );
    let library = unsafe { Library::open(Some(&path), RTLD_NOW | RTLD_LOCAL) }
        .map_err(|e| LoadError::native("dlopen", &e.to_string()))?;
    Ok(Box::leak(Box::new(library)))
}

impl NativeMod {
    pub(crate) fn load(preflighted: Preflighted) -> Result<Self, LoadError> {
        let Preflighted {
            manifest,
            snapshot,
            needed,
            ..
        } = preflighted;
        let library = open(&manifest, snapshot, &needed)?;
        let entry = unsafe { library.get::<Entry>(b"cm_mod_entry_v1\0") }
            .map_err(|e| LoadError::native("entry", &e.to_string()))?;
        let host = HostApi {
            header: Header::of::<HostApi>(),
            capability: Bytes::from_static(CAPABILITY),
            reserved: 0,
        };
        let mut table: *const Header = ptr::null();
        invoke("entry", |error| unsafe { entry(&host, &mut table, error) })?;
        if table.is_null() || !(table as usize).is_multiple_of(align_of::<u32>()) {
            return Err(LoadError::native(
                "negotiate",
                "null/misaligned size prefix",
            ));
        }
        let declared_size = unsafe { table.cast::<u32>().read() };
        if declared_size < size_of::<Header>() as u32 {
            return Err(LoadError::native("negotiate", "short ABI header prefix"));
        }
        // Read only the declared prefix before any full-table field.
        header(unsafe { table.read() }, size_of::<ModApi>())?;
        if !(table as usize).is_multiple_of(align_of::<ModApi>()) {
            return Err(LoadError::native("negotiate", "misaligned v1 table"));
        }
        let api = unsafe { table.cast::<ModApi>().read() };
        if api.reserved != 0
            || api.init.is_none()
            || api.policy.is_none()
            || unsafe { text(api.mod_id, 128)? } != manifest.id
            || unsafe { text(api.contribution, 128)? } != manifest.contribution
        {
            return Err(LoadError::native(
                "negotiate",
                "callbacks or dynamic declarations disagree with manifest",
            ));
        }
        event(
            "negotiated",
            serde_json::json!({"abi_major": ABI_MAJOR, "abi_minor": ABI_MINOR}),
        );
        let mut loaded = Self {
            api,
            userdata: ptr::null_mut(),
        };
        let result = invoke("init", |error| unsafe {
            (api.init.unwrap())(&mut loaded.userdata, error)
        });
        if !loaded.userdata.is_null() && api.release.is_none() {
            return Err(LoadError::native(
                "init",
                "nonnull userdata has no Mod-owned release",
            ));
        }
        if let Err(error) = result {
            if let Err(cleanup) = loaded.release() {
                event(
                    "release-failed",
                    serde_json::json!(cleanup.owner(&manifest.id, None)),
                );
            }
            return Err(error);
        }
        Ok(loaded)
    }

    pub(crate) fn policy(&self, input: &PolicyInput) -> Result<u32, LoadError> {
        let mut storage = OutputStorage {
            before: [0x5a; 16],
            output: PolicyOutput {
                header: Header::of::<PolicyOutput>(),
                decision: KEEP,
                reserved: 0,
            },
            after: [0xa5; 16],
        };
        invoke("policy", |error| unsafe {
            (self.api.policy.unwrap())(self.userdata, input, &mut storage.output, error)
        })?;
        if storage.before != [0x5a; 16] || storage.after != [0xa5; 16] {
            return Err(LoadError::native("policy", "policy output canary changed"));
        }
        let output = storage.output;
        if output.header.struct_size != size_of::<PolicyOutput>() as u32
            || output.header.major != ABI_MAJOR
            || output.header.minor != ABI_MINOR
            || output.reserved != 0
            || ![KEEP, FORCE_SERIAL].contains(&output.decision)
        {
            return Err(LoadError::native(
                "policy",
                "invalid policy output/header/decision",
            ));
        }
        Ok(output.decision)
    }

    pub(crate) fn release(&mut self) -> Result<(), LoadError> {
        let userdata = std::mem::take(&mut self.userdata);
        if !userdata.is_null() {
            let release = self
                .api
                .release
                .ok_or_else(|| LoadError::native("release", "missing release"))?;
            invoke("release", |error| unsafe { release(userdata, error) })?;
            event("userdata-released", serde_json::json!({"count": 1}));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_header_and_error_lengths_are_rejected() {
        assert!(
            header(
                Header {
                    struct_size: 8,
                    major: 1,
                    minor: 0,
                },
                size_of::<ModApi>(),
            )
            .is_err()
        );
        assert!(
            header(
                Header {
                    struct_size: 72,
                    major: 2,
                    minor: 0,
                },
                72,
            )
            .is_err()
        );
        assert!(
            invoke("test", |error| {
                unsafe { (*error).len = 1025 };
                OK
            })
            .is_err()
        );
        assert!(invoke("test", |_| 99).is_err());
        assert!(
            unsafe {
                text(
                    Bytes {
                        data: ptr::null(),
                        len: 1,
                    },
                    128,
                )
            }
            .is_err()
        );
        assert_eq!(
            unsafe {
                text(
                    Bytes {
                        data: ptr::null(),
                        len: 0,
                    },
                    128,
                )
            }
            .unwrap(),
            ""
        );
    }
}
