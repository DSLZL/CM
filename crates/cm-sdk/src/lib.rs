//! Author-side helpers. Only `cm-abi` data crosses the native library boundary.
pub use cm_abi as abi;
pub use cm_abi::v22;

use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use abi::{Bytes, ErrorBuffer, Header};
use v22::Handle;

#[derive(Clone, Copy)]
pub struct Host {
    instance: Handle,
    complete: v22::Complete,
    state_get: v22::StateGet,
    state_set: v22::StateSet,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub code: u32,
    pub message: String,
}

fn bytes(value: &[u8]) -> Bytes {
    Bytes {
        data: value.as_ptr(),
        len: value.len() as u64,
    }
}

fn call(f: impl FnOnce(*mut ErrorBuffer) -> u32) -> Result<(), Error> {
    let mut storage = [0_u8; abi::ERROR_CAPACITY];
    let mut error = ErrorBuffer {
        data: storage.as_mut_ptr(),
        capacity: storage.len() as u64,
        len: 0,
    };
    let code = f(&mut error);
    if error.data != storage.as_mut_ptr()
        || error.capacity != storage.len() as u64
        || error.len > error.capacity
    {
        return Err(Error {
            code: v22::INVALID,
            message: "invalid Host error buffer".into(),
        });
    }
    if code == abi::OK {
        return Ok(());
    }
    Err(Error {
        code,
        message: String::from_utf8_lossy(&storage[..error.len as usize]).into_owned(),
    })
}

impl Host {
    /// # Safety
    /// `api` must point to a live Host table of its advertised readable size.
    pub unsafe fn negotiate(api: *const abi::v2::HostApi) -> Result<Self, String> {
        if api.is_null() || !(api as usize).is_multiple_of(align_of::<v22::HostApi>()) {
            return Err("null/misaligned Host".into());
        }
        if unsafe { api.cast::<u32>().read() } < size_of::<Header>() as u32 {
            return Err("short Host header".into());
        }
        let header = unsafe { api.cast::<Header>().read() };
        if header.major != 2
            || header.minor != 2
            || header.struct_size < size_of::<v22::HostApi>() as u32
            || header.struct_size > 4096
        {
            return Err("ABI 2.2 Host required".into());
        }
        let api = unsafe { api.cast::<v22::HostApi>().read() };
        if api.runtime.is_null()
            || !(api.runtime as usize).is_multiple_of(align_of::<v22::HostRuntimeApi>())
        {
            return Err("missing runtime services".into());
        }
        if unsafe { api.runtime.cast::<u32>().read() } < size_of::<Header>() as u32 {
            return Err("short runtime services header".into());
        }
        let header = unsafe { api.runtime.cast::<Header>().read() };
        if !valid_header::<v22::HostRuntimeApi>(header) {
            return Err("invalid runtime services header".into());
        }
        let runtime = unsafe { api.runtime.read() };
        if runtime.reserved != 0 || runtime.instance == Handle::NONE {
            return Err("invalid runtime instance".into());
        }
        Ok(Self {
            instance: runtime.instance,
            complete: runtime.complete.ok_or("missing complete")?,
            state_get: runtime.state_get.ok_or("missing state_get")?,
            state_set: runtime.state_set.ok_or("missing state_set")?,
        })
    }

    /// `quiescent` promises this Mod will never again access this request or its scopes.
    pub fn complete(
        self,
        request: Handle,
        status: u32,
        result: &[u8],
        quiescent: bool,
    ) -> Result<(), Error> {
        let completion = v22::Completion {
            header: v22::header::<v22::Completion>(),
            request,
            status,
            flags: if quiescent { v22::QUIESCENT } else { 0 },
            result: bytes(result),
        };
        call(|error| unsafe { (self.complete)(self.instance, &completion, error) })
    }

    pub fn state(self, request: Handle, scope: Handle, key: &str) -> Result<Vec<u8>, Error> {
        let mut storage = vec![0; v22::MAX_INPUT];
        let mut output = v22::Buffer {
            data: storage.as_mut_ptr(),
            capacity: storage.len() as u64,
            len: 0,
        };
        call(|error| unsafe {
            (self.state_get)(
                self.instance,
                request,
                scope,
                bytes(key.as_bytes()),
                &mut output,
                error,
            )
        })?;
        if output.data != storage.as_mut_ptr()
            || output.capacity != storage.len() as u64
            || output.len > output.capacity
        {
            return Err(Error {
                code: v22::INVALID,
                message: "invalid state output".into(),
            });
        }
        storage.truncate(output.len as usize);
        Ok(storage)
    }

    pub fn set_state(
        self,
        request: Handle,
        scope: Handle,
        key: &str,
        value: &[u8],
    ) -> Result<(), Error> {
        call(|error| unsafe {
            (self.state_set)(
                self.instance,
                request,
                scope,
                bytes(key.as_bytes()),
                bytes(value),
                error,
            )
        })
    }
}

pub struct Request {
    pub handle: Handle,
    pub mod_scope: Handle,
    pub thread_scope: Handle,
    pub turn_scope: Handle,
    pub route: u64,
    pub event: u32,
    pub input: Vec<u8>,
    pub thread_id: String,
    pub turn_id: String,
    pub call_id: String,
}

pub struct Init {
    pub host: Host,
    pub config: Vec<u8>,
    pub resources: Vec<(String, Vec<u8>)>,
}

/// Ordinary methods are serialized by Host; background workers must own their data.
/// An accepted request must eventually complete with QUIESCENT, including cancellation.
pub trait Mod: Send + 'static {
    fn dispatch(&mut self, request: Request) -> Result<(), String>;
    fn cancel(&mut self, request: Handle) -> Result<(), String>;
    fn request_release(&mut self, _request: Handle) -> Result<(), String> {
        Ok(())
    }
}

pub fn valid_header<T>(value: Header) -> bool {
    value.struct_size == size_of::<T>() as u32 && value.major == 2 && value.minor == 2
}

unsafe fn copy(value: Bytes, limit: usize) -> Result<Vec<u8>, String> {
    if value.len > limit as u64 || (value.len != 0 && value.data.is_null()) {
        return Err("invalid borrowed buffer".into());
    }
    Ok(if value.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(value.data, value.len as usize) }.to_vec()
    })
}

unsafe fn text(value: Bytes, limit: usize) -> Result<String, String> {
    String::from_utf8(unsafe { copy(value, limit)? }).map_err(|_| "invalid UTF-8".into())
}

/// # Safety
/// Error storage must follow the ABI allocation contract.
pub unsafe fn boundary(error: *mut ErrorBuffer, f: impl FnOnce() -> Result<(), String>) -> u32 {
    let (code, message) = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => return abi::OK,
        Ok(Err(message)) => (abi::FAILED, message),
        Err(_) => (abi::PANICKED, "Mod panic".into()),
    };
    if let Some(error) = unsafe { error.as_mut() }
        && error.capacity <= abi::ERROR_CAPACITY as u64
        && !error.data.is_null()
    {
        let len = message.len().min(error.capacity as usize);
        unsafe { ptr::copy_nonoverlapping(message.as_ptr(), error.data, len) };
        error.len = len as u64;
    }
    code
}

/// # Safety
/// All pointers must satisfy the negotiated ABI and userdata must be initially null.
pub unsafe fn initialize<T: Mod>(
    context: *const abi::v2::InitContext,
    userdata: *mut *mut c_void,
    error: *mut ErrorBuffer,
    host: Host,
    factory: fn(Init) -> Result<T, String>,
) -> u32 {
    unsafe {
        boundary(error, || {
            if context.is_null()
                || userdata.is_null()
                || !(context as usize).is_multiple_of(align_of::<abi::v2::InitContext>())
                || !(userdata as usize).is_multiple_of(align_of::<*mut c_void>())
            {
                return Err("null/misaligned init".into());
            }
            if context.cast::<u32>().read() < size_of::<Header>() as u32 {
                return Err("short init header".into());
            }
            let header = context.cast::<Header>().read();
            if header.struct_size != size_of::<abi::v2::InitContext>() as u32
                || header.major != 2
                || header.minor != 0
            {
                return Err("invalid init header".into());
            }
            let context = &*context;
            if context.header.major != 2
                || context.header.minor != 0
                || context.header.struct_size != size_of::<abi::v2::InitContext>() as u32
                || context.reserved != 0
                || context.resource_count > 64
                || (context.resource_count != 0 && context.resources.is_null())
                || !(context.resources as usize).is_multiple_of(align_of::<abi::v2::Resource>())
            {
                return Err("invalid init context".into());
            }
            let mut resources = Vec::new();
            for index in 0..context.resource_count as usize {
                let resource = context.resources.add(index).read();
                resources.push((
                    text(resource.path, 512)?,
                    copy(resource.content, 16 * 1024 * 1024)?,
                ));
            }
            let module = factory(Init {
                host,
                config: copy(context.config, v22::MAX_INPUT)?,
                resources,
            })?;
            *userdata = Box::into_raw(Box::new(module)).cast();
            Ok(())
        })
    }
}

/// # Safety
/// Userdata and request pointers must come from this export's init and Host.
pub unsafe extern "C" fn dispatch<T: Mod>(
    userdata: *mut c_void,
    request: *const v22::Request,
    error: *mut ErrorBuffer,
) -> u32 {
    unsafe {
        boundary(error, || {
            if userdata.is_null()
                || request.is_null()
                || !(userdata as usize).is_multiple_of(align_of::<T>())
                || !(request as usize).is_multiple_of(align_of::<v22::Request>())
            {
                return Err("null/misaligned dispatch".into());
            }
            if request.cast::<u32>().read() < size_of::<Header>() as u32 {
                return Err("short request header".into());
            }
            if !valid_header::<v22::Request>(request.cast::<Header>().read()) {
                return Err("invalid request header".into());
            }
            let request = &*request;
            if !valid_header::<v22::Request>(request.header)
                || request.reserved != 0
                || !(v22::THREAD_START..=v22::SUBMIT_REVIEW).contains(&request.event)
                || request.handle == Handle::NONE
                || request.mod_scope == Handle::NONE
                || request.route == 0
                || !valid_request_scopes(request.event, request.thread_scope, request.turn_scope)
                || (request.event == v22::SUBMIT_REVIEW
                    && (request.thread_id.len != 0 || request.turn_id.len != 0 || request.call_id.len != 0))
            {
                return Err("invalid request".into());
            }
            let owned = Request {
                handle: request.handle,
                mod_scope: request.mod_scope,
                thread_scope: request.thread_scope,
                turn_scope: request.turn_scope,
                route: request.route,
                event: request.event,
                input: copy(request.input, v22::MAX_INPUT)?,
                thread_id: text(request.thread_id, 128)?,
                turn_id: text(request.turn_id, 128)?,
                call_id: text(request.call_id, 512)?,
            };
            (&mut *userdata.cast::<T>()).dispatch(owned)
        })
    }
}

fn valid_request_scopes(event: u32, thread: Handle, turn: Handle) -> bool {
    match event {
        v22::THREAD_START..=v22::THREAD_STOP => thread != Handle::NONE && turn == Handle::NONE,
        v22::TURN_START..=v22::SAMPLING_BUDGET => thread != Handle::NONE && turn != Handle::NONE,
        v22::SUBMIT_REVIEW => thread == Handle::NONE && turn == Handle::NONE,
        _ => false,
    }
}

/// # Safety
/// Userdata must be this export's live Mod allocation; ordinary entries cannot overlap.
pub unsafe extern "C" fn cancel<T: Mod>(
    userdata: *mut c_void,
    request: Handle,
    error: *mut ErrorBuffer,
) -> u32 {
    unsafe {
        boundary(error, || {
            if userdata.is_null() {
                return Err("null cancel".into());
            }
            (&mut *userdata.cast::<T>()).cancel(request)
        })
    }
}

/// # Safety
/// Host calls once after quiescence and all ordinary entries have returned.
pub unsafe extern "C" fn request_release<T: Mod>(
    userdata: *mut c_void,
    request: Handle,
    error: *mut ErrorBuffer,
) -> u32 {
    unsafe {
        boundary(error, || {
            if userdata.is_null() {
                return Err("null request release".into());
            }
            (&mut *userdata.cast::<T>()).request_release(request)
        })
    }
}

/// # Safety
/// Host calls once, after every accepted request has been released.
pub unsafe extern "C" fn release<T: Mod>(userdata: *mut c_void, error: *mut ErrorBuffer) -> u32 {
    unsafe {
        boundary(error, || {
            if !userdata.is_null() {
                drop(Box::from_raw(userdata.cast::<T>()));
            }
            Ok(())
        })
    }
}

pub struct ExportTable(pub v22::ModApi);
pub struct Contributions(pub &'static [v22::RuntimeContribution]);
// These tables contain only immutable static byte views and function pointers.
unsafe impl Sync for ExportTable {}
unsafe impl Sync for Contributions {}

#[macro_export]
macro_rules! export_mod {
    ($module:ty, $id:literal, $factory:path, $contributions:expr) => {
        mod cm_export {
            use super::*;
            use $crate::{abi, v22};
            static HOST: std::sync::OnceLock<$crate::Host> = std::sync::OnceLock::new();
            static CONTRIBUTIONS: $crate::Contributions = $crate::Contributions($contributions);
            unsafe extern "C" fn init(
                context: *const abi::v2::InitContext,
                userdata: *mut *mut std::ffi::c_void,
                error: *mut abi::ErrorBuffer,
            ) -> u32 {
                match HOST.get().copied() {
                    Some(host) => unsafe {
                        $crate::initialize::<$module>(context, userdata, error, host, $factory)
                    },
                    None => abi::FAILED,
                }
            }
            static RUNTIME: v22::ModRuntimeApi = v22::ModRuntimeApi {
                header: v22::header::<v22::ModRuntimeApi>(),
                dispatch: Some($crate::dispatch::<$module>),
                cancel: Some($crate::cancel::<$module>),
                request_release: Some($crate::request_release::<$module>),
                reserved: 0,
            };
            static TABLE: $crate::ExportTable = $crate::ExportTable(v22::ModApi {
                base: abi::v21::ModApi {
                    base: abi::v2::ModApi {
                        header: v22::header::<v22::ModApi>(),
                        mod_id: abi::Bytes::from_static($id),
                        contributions: std::ptr::null(),
                        contribution_count: 0,
                        init: Some(init),
                        release: Some($crate::release::<$module>),
                        reserved: 0,
                    },
                    limiters: std::ptr::null(),
                    limiter_count: 0,
                    limiter_stride: std::mem::size_of::<abi::v21::Limiter>() as u64,
                    reserved: 0,
                },
                runtime: &RUNTIME,
                contributions: CONTRIBUTIONS.0.as_ptr(),
                contribution_count: CONTRIBUTIONS.0.len() as u64,
                contribution_stride: std::mem::size_of::<v22::RuntimeContribution>() as u64,
                reserved: 0,
            });
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn cm_mod_entry_v2(
                host: *const abi::v2::HostApi,
                table: *mut *const abi::Header,
                error: *mut abi::ErrorBuffer,
            ) -> u32 {
                unsafe {
                    $crate::boundary(error, || {
                        if table.is_null() {
                            return Err("null table output".into());
                        }
                        let host = $crate::Host::negotiate(host)?;
                        HOST.set(host).map_err(|_| "entry already called")?;
                        *table = (&TABLE.0 as *const v22::ModApi).cast();
                        Ok(())
                    })
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_and_core_requests_have_distinct_scope_shapes() {
        let owned = Handle { epoch: 1, slot: 2, generation: 1 };
        assert!(valid_request_scopes(v22::SUBMIT_REVIEW, Handle::NONE, Handle::NONE));
        assert!(!valid_request_scopes(v22::SUBMIT_REVIEW, owned, Handle::NONE));
        assert!(!valid_request_scopes(v22::SUBMIT_REVIEW, owned, owned));
        assert!(valid_request_scopes(v22::THREAD_START, owned, Handle::NONE));
        assert!(!valid_request_scopes(v22::THREAD_START, Handle::NONE, Handle::NONE));
        assert!(!valid_request_scopes(v22::THREAD_READY, owned, owned));
        assert!(valid_request_scopes(v22::SAMPLING_BUDGET, owned, owned));
        assert!(!valid_request_scopes(v22::SAMPLING_BUDGET, owned, Handle::NONE));
        assert!(!valid_request_scopes(v22::SUBMIT_REVIEW + 1, owned, owned));
    }

    #[test]
    fn panic_does_not_unwind_and_error_bytes_belong_to_caller() {
        let mut storage = [0_u8; abi::ERROR_CAPACITY];
        let mut error = ErrorBuffer {
            data: storage.as_mut_ptr(),
            capacity: storage.len() as u64,
            len: 0,
        };
        assert_eq!(
            unsafe { boundary(&mut error, || panic!("fixture")) },
            abi::PANICKED
        );
        assert_eq!(&storage[..error.len as usize], b"Mod panic");
        assert_eq!(
            unsafe {
                copy(
                    Bytes {
                        data: ptr::null(),
                        len: 0,
                    },
                    1,
                )
            }
            .unwrap(),
            b""
        );
        assert!(
            unsafe {
                copy(
                    Bytes {
                        data: ptr::null(),
                        len: 1,
                    },
                    1,
                )
            }
            .is_err()
        );
    }
}
