//! Experimental ABI 2.3. The embedded 2.2 request tables keep their own version.
use crate::{ErrorBuffer, Header, v22};
use v22::Handle;

pub const TOOL_CONTINUATION: &str = "core.tool_continuation.v1";
pub const RESPONSE_STREAM: &str = "core.response_stream_observe.v1";
pub const CLI_COMMAND: &str = "cli.command.v1";
pub const TUI_COMMAND: &str = "tui.command.v1";
pub const CAPABILITIES: [&str; 4] = [TOOL_CONTINUATION, RESPONSE_STREAM, CLI_COMMAND, TUI_COMMAND];
pub const KIND_TOOL_AROUND: u32 = 12;
pub const KIND_TOOL_REPLACEMENT: u32 = 13;
pub const KIND_RESPONSE_STREAM: u32 = 14;
pub const KIND_CLI_COMMAND: u32 = 15;
pub const KIND_TUI_COMMAND: u32 = 16;
pub const TOOL_AROUND: u32 = 15;
pub const STREAM_EVENT: u32 = 16;
pub const CLI_CALL: u32 = 17;
pub const TUI_CALL: u32 = 18;
pub const PENDING: u32 = 3;

/// Caller owns the result buffer. Poll never replaces its pointer or capacity.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NextOutput {
    pub header: Header,
    pub status: u32,
    pub reserved: u32,
    pub result: v22::Buffer,
}

pub type Start = unsafe extern "C" fn(Handle, Handle, *mut Handle, *mut ErrorBuffer) -> u32;
pub type Poll = unsafe extern "C" fn(Handle, Handle, Handle, *mut NextOutput, *mut ErrorBuffer) -> u32;
pub type Task = unsafe extern "C" fn(Handle, Handle, Handle, *mut ErrorBuffer) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContinuationApi {
    pub header: Header,
    pub start: Option<Start>,
    pub poll: Option<Poll>,
    pub cancel: Option<Task>,
    pub release: Option<Task>,
    pub reserved: u64,
}

#[repr(C)]
pub struct HostApi {
    pub base: v22::HostApi,
    pub continuation: *const ContinuationApi,
}

pub type ModApi = v22::ModApi;

pub const fn header<T>() -> Header {
    Header { struct_size: core::mem::size_of::<T>() as u32, major: 2, minor: 3 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn additive_layout_keeps_the_legacy_prefix() {
        assert_eq!(size_of::<HostApi>(), 96);
        assert_eq!(offset_of!(HostApi, base), 0);
        assert_eq!(offset_of!(HostApi, continuation), size_of::<v22::HostApi>());
        assert_eq!(size_of::<ContinuationApi>(), 48);
        assert_eq!(offset_of!(ContinuationApi, start), 8);
        assert_eq!(offset_of!(ContinuationApi, reserved), 40);
        assert_eq!(size_of::<NextOutput>(), 40);
        assert_eq!(offset_of!(NextOutput, result), 16);
        assert_eq!(align_of::<NextOutput>(), 8);
        assert_eq!(size_of::<ModApi>(), 136);
    }
}
