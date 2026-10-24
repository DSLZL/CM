//! Explicit composition ABI. v1 remains byte-for-byte independent.
use core::ffi::c_void;

use crate::Bytes;
use crate::ErrorBuffer;
use crate::Header;
use crate::PolicyInput;
use crate::Release;

pub const ABI_MAJOR: u16 = 2;
pub const ABI_MINOR: u16 = 0;
pub const CAPABILITY: &str = "core.tool_parallel_eligibility.compose.v1";
pub const CANCELLED: u32 = 3;
pub const BEFORE: u32 = 1;
pub const AROUND: u32 = 2;
pub const REPLACEMENT: u32 = 3;
pub const AFTER: u32 = 4;
pub const SUCCEEDED: u32 = 0;
pub const FAILED: u32 = 1;
pub const CANCELLED_OUTCOME: u32 = 2;

pub const fn header<T>() -> Header {
    Header {
        struct_size: core::mem::size_of::<T>() as u32,
        major: ABI_MAJOR,
        minor: ABI_MINOR,
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Decision {
    pub header: Header,
    pub decision: u32,
    pub reserved: u32,
}

/// Synchronous around-only token; initialized 2.0 output and 1024-byte error storage.
pub type Next = unsafe extern "C" fn(u64, *mut Decision, *mut ErrorBuffer) -> u32;

#[repr(C)]
pub struct HostApi {
    pub header: Header,
    pub capability: Bytes,
    pub host_build_id: Bytes,
    pub next: Option<Next>,
    pub reserved: u64,
}

#[repr(C)]
pub struct Resource {
    pub path: Bytes,
    /// Raw bounded bytes; resource content need not be UTF-8.
    pub content: Bytes,
}

#[repr(C)]
pub struct InitContext {
    pub header: Header,
    pub resources: *const Resource,
    pub resource_count: u64,
    pub config: Bytes,
    pub reserved: u64,
}

#[repr(C)]
pub struct Input {
    pub header: Header,
    /// The original v1 DTO; its nested header remains 1.0.
    pub policy: PolicyInput,
    pub phase: u32,
    pub outcome: u32,
    pub decision: u32,
    pub reserved: u32,
    pub next_token: u64,
}

pub type Hook = unsafe extern "C" fn(
    *mut c_void,
    *const Input,
    *mut Decision,
    *mut ErrorBuffer,
) -> u32;
pub type Init =
    unsafe extern "C" fn(*const InitContext, *mut *mut c_void, *mut ErrorBuffer) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Contribution {
    pub header: Header,
    pub id: Bytes,
    pub capability: Bytes,
    pub resource: Bytes,
    pub kind: u32,
    pub reserved: u32,
    pub callback: Option<Hook>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModApi {
    pub header: Header,
    pub mod_id: Bytes,
    pub contributions: *const Contribution,
    pub contribution_count: u64,
    pub init: Option<Init>,
    pub release: Option<Release>,
    pub reserved: u64,
}

pub type Entry = unsafe extern "C" fn(*const HostApi, *mut *const Header, *mut ErrorBuffer) -> u32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_x64_composition_layout() {
        assert_eq!(core::mem::size_of::<Decision>(), 16);
        assert_eq!(core::mem::size_of::<HostApi>(), 56);
        assert_eq!(core::mem::size_of::<Resource>(), 32);
        assert_eq!(core::mem::size_of::<InitContext>(), 48);
        assert_eq!(core::mem::size_of::<Input>(), 128);
        assert_eq!(core::mem::size_of::<Contribution>(), 72);
        assert_eq!(core::mem::size_of::<ModApi>(), 64);
        assert_eq!(core::mem::align_of::<ModApi>(), 8);
        assert_eq!(core::mem::offset_of!(Input, next_token), 120);
        assert_eq!(core::mem::offset_of!(Contribution, callback), 64);
        assert_eq!(core::mem::offset_of!(ModApi, init), 40);
        assert_eq!(core::mem::align_of::<Decision>(), 4);
        assert_eq!(core::mem::align_of::<HostApi>(), 8);
        assert_eq!(core::mem::align_of::<Resource>(), 8);
        assert_eq!(core::mem::align_of::<InitContext>(), 8);
        assert_eq!(core::mem::align_of::<Input>(), 8);
        assert_eq!(core::mem::align_of::<Contribution>(), 8);
        assert_eq!(core::mem::offset_of!(Decision, decision), 8);
        assert_eq!(core::mem::offset_of!(Decision, reserved), 12);
        assert_eq!(core::mem::offset_of!(HostApi, capability), 8);
        assert_eq!(core::mem::offset_of!(HostApi, host_build_id), 24);
        assert_eq!(core::mem::offset_of!(HostApi, next), 40);
        assert_eq!(core::mem::offset_of!(HostApi, reserved), 48);
        assert_eq!(core::mem::offset_of!(Resource, content), 16);
        assert_eq!(core::mem::offset_of!(InitContext, resources), 8);
        assert_eq!(core::mem::offset_of!(InitContext, resource_count), 16);
        assert_eq!(core::mem::offset_of!(InitContext, config), 24);
        assert_eq!(core::mem::offset_of!(InitContext, reserved), 40);
        assert_eq!(core::mem::offset_of!(Input, policy), 8);
        assert_eq!(core::mem::offset_of!(Input, phase), 104);
        assert_eq!(core::mem::offset_of!(Input, outcome), 108);
        assert_eq!(core::mem::offset_of!(Input, decision), 112);
        assert_eq!(core::mem::offset_of!(Input, reserved), 116);
        assert_eq!(core::mem::offset_of!(Contribution, id), 8);
        assert_eq!(core::mem::offset_of!(Contribution, capability), 24);
        assert_eq!(core::mem::offset_of!(Contribution, resource), 40);
        assert_eq!(core::mem::offset_of!(Contribution, kind), 56);
        assert_eq!(core::mem::offset_of!(Contribution, reserved), 60);
        assert_eq!(core::mem::offset_of!(ModApi, mod_id), 8);
        assert_eq!(core::mem::offset_of!(ModApi, contributions), 24);
        assert_eq!(core::mem::offset_of!(ModApi, contribution_count), 32);
        assert_eq!(core::mem::offset_of!(ModApi, release), 48);
        assert_eq!(core::mem::offset_of!(ModApi, reserved), 56);
    }
}
