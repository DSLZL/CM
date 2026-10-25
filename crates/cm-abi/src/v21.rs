//! Additive ABI 2.1. The v2.0 prefix and all eligibility DTOs stay unchanged.
use core::ffi::c_void;

use crate::Bytes;
use crate::ErrorBuffer;
use crate::Header;
use crate::v2;

pub const CAPABILITY: &str = "core.exec_output_limit.v1";
pub const KEEP: u64 = 0;
pub const LIMIT: u64 = 1;

pub const fn header<T>() -> Header {
    Header {
        struct_size: core::mem::size_of::<T>() as u32,
        major: 2,
        minor: 1,
    }
}

#[repr(C)]
pub struct HostApi {
    pub base: v2::HostApi,
    pub capabilities: *const Bytes,
    pub capability_count: u64,
    pub reserved: u64,
}

#[repr(C)]
pub struct Input {
    pub header: Header,
    pub namespace: Bytes,
    pub tool: Bytes,
    pub call_id: Bytes,
    pub thread_id: Bytes,
    pub turn_id: Bytes,
    pub original_limit: u64,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Output {
    pub header: Header,
    pub decision: u64,
    pub limit: u64,
    pub reserved: u64,
}

pub type Hook =
    unsafe extern "C" fn(*mut c_void, *const Input, *mut Output, *mut ErrorBuffer) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Limiter {
    pub header: Header,
    pub id: Bytes,
    pub capability: Bytes,
    pub resource: Bytes,
    pub callback: Option<Hook>,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModApi {
    pub base: v2::ModApi,
    pub limiters: *const Limiter,
    pub limiter_count: u64,
    pub limiter_stride: u64,
    pub reserved: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::align_of;
    use core::mem::offset_of;
    use core::mem::size_of;

    #[test]
    fn linux_x64_additive_layout() {
        assert_eq!(size_of::<HostApi>(), 80);
        assert_eq!(offset_of!(HostApi, base), 0);
        assert_eq!(offset_of!(HostApi, capabilities), 56);
        assert_eq!(offset_of!(HostApi, capability_count), 64);
        assert_eq!(offset_of!(HostApi, reserved), 72);
        assert_eq!(size_of::<ModApi>(), 96);
        assert_eq!(offset_of!(ModApi, base), 0);
        assert_eq!(offset_of!(ModApi, limiters), 64);
        assert_eq!(offset_of!(ModApi, limiter_count), 72);
        assert_eq!(offset_of!(ModApi, limiter_stride), 80);
        assert_eq!(offset_of!(ModApi, reserved), 88);
        assert_eq!(size_of::<Limiter>(), 72);
        assert_eq!(offset_of!(Limiter, header), 0);
        assert_eq!(offset_of!(Limiter, id), 8);
        assert_eq!(offset_of!(Limiter, capability), 24);
        assert_eq!(offset_of!(Limiter, resource), 40);
        assert_eq!(offset_of!(Limiter, callback), 56);
        assert_eq!(offset_of!(Limiter, reserved), 64);
        assert_eq!(size_of::<Input>(), 104);
        assert_eq!(offset_of!(Input, header), 0);
        assert_eq!(offset_of!(Input, namespace), 8);
        assert_eq!(offset_of!(Input, tool), 24);
        assert_eq!(offset_of!(Input, call_id), 40);
        assert_eq!(offset_of!(Input, thread_id), 56);
        assert_eq!(offset_of!(Input, turn_id), 72);
        assert_eq!(offset_of!(Input, original_limit), 88);
        assert_eq!(offset_of!(Input, reserved), 96);
        assert_eq!(size_of::<Output>(), 32);
        assert_eq!(offset_of!(Output, header), 0);
        assert_eq!(offset_of!(Output, decision), 8);
        assert_eq!(offset_of!(Output, limit), 16);
        assert_eq!(offset_of!(Output, reserved), 24);
        assert_eq!(align_of::<HostApi>(), 8);
        assert_eq!(align_of::<ModApi>(), 8);
        assert_eq!(align_of::<Limiter>(), 8);
        assert_eq!(align_of::<Input>(), 8);
        assert_eq!(align_of::<Output>(), 8);
    }
}
