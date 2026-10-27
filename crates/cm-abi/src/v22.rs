//! Additive ABI 2.2. All borrowed buffers expire when the receiving call returns.
use std::ffi::c_void;
use std::mem::size_of;

use crate::{Bytes, ErrorBuffer, Header, v21};

pub const LIFECYCLE: &str = "runtime.lifecycle.v1";
pub const TOOL: &str = "runtime.tool.v1";
pub const CONTEXT_SECTION: &str = "runtime.context_section.v1";
pub const CAPABILITIES: [&str; 3] = [LIFECYCLE, TOOL, CONTEXT_SECTION];
pub const KIND_LIFECYCLE: u32 = 6;
pub const KIND_TOOL: u32 = 7;
pub const KIND_CONTEXT_SECTION: u32 = 8;
pub const THREAD_START: u32 = 1;
pub const THREAD_READY: u32 = 2;
pub const THREAD_RESUME: u32 = 3;
pub const THREAD_IDLE: u32 = 4;
pub const THREAD_STOP: u32 = 5;
pub const TURN_START: u32 = 6;
pub const TURN_STOP: u32 = 7;
pub const TURN_ABORT: u32 = 8;
pub const TURN_ERROR: u32 = 9;
pub const TOOL_CALL: u32 = 10;
pub const SECTION: u32 = 11;
pub const SUCCEEDED: u32 = 0;
pub const FAILED: u32 = 1;
pub const CANCELLED: u32 = 2;
pub const QUIESCENT: u32 = 1;
pub const INVALID: u32 = 4;
pub const STALE: u32 = 5;
pub const WRONG_OWNER: u32 = 6;
pub const ALREADY_COMPLETED: u32 = 7;
pub const REQUEST_CANCELLED: u32 = 8;
pub const LIMIT: u32 = 9;
pub const NOT_FOUND: u32 = 10;
pub const REENTRANT: u32 = 11;
pub const MAX_INPUT: usize = 64 * 1024;
pub const MAX_RESULT: usize = 256 * 1024;
pub const MAX_STATE: usize = 1024 * 1024;
pub const MAX_MOD_REQUESTS: usize = 64;
pub const MAX_REQUESTS: usize = 1024;
pub const MAX_SCOPES: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle {
    pub epoch: u64,
    pub slot: u32,
    pub generation: u32,
}

impl Handle {
    pub const NONE: Self = Self {
        epoch: 0,
        slot: 0,
        generation: 0,
    };
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Buffer {
    pub data: *mut u8,
    pub capacity: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Request {
    pub header: Header,
    pub handle: Handle,
    pub mod_scope: Handle,
    pub thread_scope: Handle,
    pub turn_scope: Handle,
    pub route: u64,
    pub event: u32,
    pub reserved: u32,
    pub input: Bytes,
    pub thread_id: Bytes,
    pub turn_id: Bytes,
    pub call_id: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Completion {
    pub header: Header,
    pub request: Handle,
    pub status: u32,
    pub flags: u32,
    pub result: Bytes,
}

pub type Complete = unsafe extern "C" fn(Handle, *const Completion, *mut ErrorBuffer) -> u32;
pub type StateGet =
    unsafe extern "C" fn(Handle, Handle, Handle, Bytes, *mut Buffer, *mut ErrorBuffer) -> u32;
pub type StateSet =
    unsafe extern "C" fn(Handle, Handle, Handle, Bytes, Bytes, *mut ErrorBuffer) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostRuntimeApi {
    pub header: Header,
    pub instance: Handle,
    pub complete: Option<Complete>,
    pub state_get: Option<StateGet>,
    pub state_set: Option<StateSet>,
    pub reserved: u64,
}

pub type Dispatch = unsafe extern "C" fn(*mut c_void, *const Request, *mut ErrorBuffer) -> u32;
pub type Cancel = unsafe extern "C" fn(*mut c_void, Handle, *mut ErrorBuffer) -> u32;
pub type RequestRelease = unsafe extern "C" fn(*mut c_void, Handle, *mut ErrorBuffer) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModRuntimeApi {
    pub header: Header,
    pub dispatch: Option<Dispatch>,
    pub cancel: Option<Cancel>,
    pub request_release: Option<RequestRelease>,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuntimeContribution {
    pub header: Header,
    pub id: Bytes,
    pub capability: Bytes,
    pub resource: Bytes,
    pub kind: u32,
    pub reserved: u32,
    pub route: u64,
}

#[repr(C)]
pub struct HostApi {
    pub base: v21::HostApi,
    pub runtime: *const HostRuntimeApi,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModApi {
    pub base: v21::ModApi,
    pub runtime: *const ModRuntimeApi,
    pub contributions: *const RuntimeContribution,
    pub contribution_count: u64,
    pub contribution_stride: u64,
    pub reserved: u64,
}

pub const fn header<T>() -> Header {
    Header {
        struct_size: size_of::<T>() as u32,
        major: 2,
        minor: 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn linux_x64_layout_and_unchanged_prefixes() {
        macro_rules! layout {
            ($ty:ty, $size:expr, $($field:ident: $offset:expr),+ $(,)?) => {
                assert_eq!(size_of::<$ty>(), $size);
                assert_eq!(align_of::<$ty>(), 8);
                $(assert_eq!(offset_of!($ty, $field), $offset);)+
            };
        }
        layout!(Handle, 16, epoch: 0, slot: 8, generation: 12);
        layout!(Buffer, 24, data: 0, capacity: 8, len: 16);
        layout!(Request, 152, header: 0, handle: 8, mod_scope: 24, thread_scope: 40,
            turn_scope: 56, route: 72, event: 80, reserved: 84, input: 88, thread_id: 104,
            turn_id: 120, call_id: 136);
        layout!(Completion, 48, header: 0, request: 8, status: 24, flags: 28, result: 32);
        layout!(HostRuntimeApi, 56, header: 0, instance: 8, complete: 24, state_get: 32,
            state_set: 40, reserved: 48);
        layout!(ModRuntimeApi, 40, header: 0, dispatch: 8, cancel: 16, request_release: 24, reserved: 32);
        layout!(RuntimeContribution, 72, header: 0, id: 8, capability: 24, resource: 40,
            kind: 56, reserved: 60, route: 64);
        layout!(HostApi, 88, base: 0, runtime: 80);
        layout!(ModApi, 136, base: 0, runtime: 96, contributions: 104,
            contribution_count: 112, contribution_stride: 120, reserved: 128);
        assert_eq!(offset_of!(HostApi, runtime), size_of::<v21::HostApi>());
        assert_eq!(offset_of!(ModApi, runtime), size_of::<v21::ModApi>());
    }
}
