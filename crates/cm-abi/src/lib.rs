//! Linux x86_64 C ABI v1. All views are borrowed only until the call returns.
//! Native callers must supply valid allocations; validation is not a sandbox.
use core::ffi::c_void;

pub const ABI_MAJOR: u16 = 1;
pub const ABI_MINOR: u16 = 0;
pub const OK: u32 = 0;
pub const FAILED: u32 = 1;
pub const PANICKED: u32 = 2;
pub const KEEP: u32 = 0;
pub const FORCE_SERIAL: u32 = 1;
pub const ERROR_CAPACITY: usize = 1024;
pub const CAPABILITY: &str = "core.tool_parallel_eligibility.v1";
pub const CONTRIBUTION: &str = "core.tool_parallel_eligibility.v1";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    pub struct_size: u32,
    pub major: u16,
    pub minor: u16,
}

impl Header {
    pub const fn of<T>() -> Self {
        Self {
            struct_size: core::mem::size_of::<T>() as u32,
            major: ABI_MAJOR,
            minor: ABI_MINOR,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    pub data: *const u8,
    pub len: u64,
}

impl Bytes {
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            data: value.as_ptr(),
            len: value.len() as u64,
        }
    }

    pub fn borrowed(value: &str) -> Self {
        Self {
            data: value.as_ptr(),
            len: value.len() as u64,
        }
    }
}

#[repr(C)]
pub struct ErrorBuffer {
    pub data: *mut u8,
    pub capacity: u64,
    pub len: u64,
}

#[repr(C)]
pub struct HostApi {
    pub header: Header,
    pub capability: Bytes,
    pub reserved: u64,
}

#[repr(C)]
pub struct PolicyInput {
    pub header: Header,
    pub namespace: Bytes,
    pub tool: Bytes,
    pub call_id: Bytes,
    pub thread_id: Bytes,
    pub turn_id: Bytes,
    pub original_parallel: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct PolicyOutput {
    pub header: Header,
    pub decision: u32,
    pub reserved: u32,
}

pub type Init = unsafe extern "C" fn(*mut *mut c_void, *mut ErrorBuffer) -> u32;
pub type Policy = unsafe extern "C" fn(
    *mut c_void,
    *const PolicyInput,
    *mut PolicyOutput,
    *mut ErrorBuffer,
) -> u32;
pub type Release = unsafe extern "C" fn(*mut c_void, *mut ErrorBuffer) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModApi {
    pub header: Header,
    pub mod_id: Bytes,
    pub contribution: Bytes,
    pub init: Option<Init>,
    pub policy: Option<Policy>,
    pub release: Option<Release>,
    pub reserved: u64,
}

pub type Entry = unsafe extern "C" fn(*const HostApi, *mut *const Header, *mut ErrorBuffer) -> u32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_x64_layout() {
        assert_eq!(core::mem::size_of::<Header>(), 8);
        assert_eq!(core::mem::size_of::<Bytes>(), 16);
        assert_eq!(core::mem::size_of::<ErrorBuffer>(), 24);
        assert_eq!(core::mem::size_of::<HostApi>(), 32);
        assert_eq!(core::mem::size_of::<ModApi>(), 72);
        assert_eq!(core::mem::size_of::<PolicyInput>(), 96);
        assert_eq!(core::mem::size_of::<PolicyOutput>(), 16);
        assert_eq!(core::mem::align_of::<ModApi>(), 8);
        assert_eq!(core::mem::offset_of!(ModApi, policy), 48);
        assert_eq!(core::mem::offset_of!(PolicyInput, original_parallel), 88);
    }
}
