//! Independent ABI-only author. Each negative payload is frozen at build time.
use std::ffi::c_void;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::ptr;

use cm_abi::Bytes;
use cm_abi::ErrorBuffer;
use cm_abi::FAILED;
use cm_abi::Header;
use cm_abi::OK;
use cm_abi::PANICKED;
use cm_abi::v2;
use cm_abi::v21;

const VARIANT: &str = match option_env!("CM_LIMIT_VARIANT") {
    Some(value) => value,
    None => "normal",
};

fn wrapped(call: impl FnOnce() -> u32) -> u32 {
    catch_unwind(AssertUnwindSafe(call)).unwrap_or(PANICKED)
}

unsafe extern "C" fn init(
    context: *const v2::InitContext,
    userdata: *mut *mut c_void,
    _error: *mut ErrorBuffer,
) -> u32 {
    wrapped(|| {
        if userdata.is_null() {
            return FAILED;
        }
        let limit = if VARIANT == "config" {
            if context.is_null() {
                return FAILED;
            }
            let context = unsafe { &*context };
            if context.config.data.is_null() || context.config.len > 65536 {
                return FAILED;
            }
            let view = unsafe {
                std::slice::from_raw_parts(context.config.data, context.config.len as usize)
            };
            if view != br#"{"labels":["parameter"],"limit":128,"token":"M01_OWN_SECRET"}"# {
                return FAILED;
            }
            if let Some(path) = std::env::var_os("CM_CONFIG_OBSERVATION") {
                if std::fs::write(
                    path,
                    br#"{"owner_view_only":true,"four_layer_result":true}"#,
                )
                .is_err()
                {
                    return FAILED;
                }
            }
            128_u64
        } else {
            256_u64
        };
        unsafe { *userdata = Box::into_raw(Box::new(limit)).cast() };
        if VARIANT == "init-fail" { FAILED } else { OK }
    })
}

unsafe extern "C" fn release(userdata: *mut c_void, _error: *mut ErrorBuffer) -> u32 {
    wrapped(|| {
        if userdata.is_null() {
            return FAILED;
        }
        drop(unsafe { Box::from_raw(userdata.cast::<u64>()) });
        OK
    })
}

unsafe extern "C" fn limit(
    userdata: *mut c_void,
    input: *const v21::Input,
    output: *mut v21::Output,
    error: *mut ErrorBuffer,
) -> u32 {
    wrapped(|| {
        if userdata.is_null() || input.is_null() || output.is_null() || error.is_null() {
            return FAILED;
        }
        let input = unsafe { &*input };
        let output = unsafe { &mut *output };
        if input.header.struct_size != std::mem::size_of::<v21::Input>() as u32
            || input.header.major != 2
            || input.header.minor != 1
            || input.reserved != 0
        {
            return FAILED;
        }
        for (view, maximum) in [
            (input.namespace, 128),
            (input.tool, 128),
            (input.call_id, 512),
            (input.thread_id, 128),
            (input.turn_id, 128),
        ] {
            if view.len > maximum || (view.len != 0 && view.data.is_null()) {
                return FAILED;
            }
            let bytes = if view.len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(view.data, view.len as usize) }
            };
            if std::str::from_utf8(bytes).is_err() {
                return FAILED;
            }
        }
        if input.original_limit > 0 {
            output.decision = v21::LIMIT;
            output.limit = input.original_limit.min(unsafe { *userdata.cast::<u64>() });
        }
        match VARIANT {
            "callback-fail" => return FAILED,
            "status" => return 99,
            "cancelled" => return v2::CANCELLED,
            "increase" => {
                output.decision = v21::LIMIT;
                output.limit = u64::MAX;
            }
            "zero" => {
                output.decision = v21::LIMIT;
                output.limit = 0;
            }
            "keep-nonzero" => {
                output.decision = v21::KEEP;
                output.limit = 1;
            }
            "decision" => output.decision = u64::MAX,
            "output-header" => output.header.minor = 0,
            "output-reserved" => output.reserved = 1,
            "output-canary" => unsafe { (output as *mut v21::Output).add(1).cast::<u8>().write(0) },
            "error-length" => unsafe { (*error).len = u64::MAX },
            "error-null" => unsafe { (*error).data = ptr::null_mut() },
            "error-utf8" => unsafe {
                (*error).data.write(0xff);
                (*error).len = 1;
            },
            "error-canary" => unsafe { (*error).data.add(cm_abi::ERROR_CAPACITY).write(0) },
            _ => {}
        }
        OK
    })
}

unsafe extern "C" fn smaller(
    userdata: *mut c_void,
    input: *const v21::Input,
    output: *mut v21::Output,
    error: *mut ErrorBuffer,
) -> u32 {
    let status = unsafe { limit(userdata, input, output, error) };
    if status == OK && !output.is_null() && unsafe { (*output).decision } == v21::LIMIT {
        unsafe { (*output).limit = (*output).limit.min(128) };
    }
    status
}

/// # Safety
/// Pointers must satisfy cm_mod_v21.h for this synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cm_mod_entry_v2(
    host: *const v2::HostApi,
    table: *mut *const Header,
    _error: *mut ErrorBuffer,
) -> u32 {
    wrapped(|| {
        if host.is_null() || table.is_null() {
            return FAILED;
        }
        let prefix = unsafe { &*host };
        if prefix.header.struct_size < std::mem::size_of::<v21::HostApi>() as u32
            || prefix.header.major != 2
            || prefix.header.minor != 1
            || prefix.reserved != 0
        {
            return FAILED;
        }
        let host = unsafe { &*host.cast::<v21::HostApi>() };
        if host.reserved != 0
            || host.capability_count == 0
            || host.capability_count > 128
            || host.capabilities.is_null()
            || !(host.capabilities as usize).is_multiple_of(std::mem::align_of::<Bytes>())
        {
            return FAILED;
        }
        let mut found = false;
        for index in 0..host.capability_count as usize {
            let view = unsafe { host.capabilities.add(index).read() };
            if view.len > 128 || (view.len != 0 && view.data.is_null()) {
                return FAILED;
            }
            let bytes = if view.len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(view.data, view.len as usize) }
            };
            let Ok(value) = std::str::from_utf8(bytes) else {
                return FAILED;
            };
            found |= value == v21::CAPABILITY;
        }
        if !found {
            return FAILED;
        }
        let mut descriptor = v21::Limiter {
            header: v21::header::<v21::Limiter>(),
            id: Bytes::from_static("limit"),
            capability: Bytes::from_static(v21::CAPABILITY),
            resource: Bytes::from_static(v21::CAPABILITY),
            callback: Some(limit),
            reserved: 0,
        };
        match VARIANT {
            "descriptor-size" => descriptor.header.struct_size = 8,
            "descriptor-minor" => descriptor.header.minor = 99,
            "descriptor-reserved" => descriptor.reserved = 1,
            "null-callback" => descriptor.callback = None,
            "null-view" => {
                descriptor.id = Bytes {
                    data: ptr::null(),
                    len: 1,
                }
            }
            "huge-view" => descriptor.id.len = u64::MAX,
            "utf8" => {
                descriptor.id = Bytes {
                    data: b"\xff".as_ptr(),
                    len: 1,
                }
            }
            _ => {}
        }
        let count = if VARIANT == "two-limiters" { 2 } else { 1 };
        let mut descriptors = vec![descriptor];
        if count == 2 {
            descriptors.push(v21::Limiter {
                id: Bytes::from_static("a-smaller"),
                callback: Some(smaller),
                ..descriptor
            });
        }
        let descriptors = Box::leak(descriptors.into_boxed_slice());
        let mut api = Box::new(v21::ModApi {
            base: v2::ModApi {
                header: v21::header::<v21::ModApi>(),
                mod_id: Bytes::from_static("output-fixture"),
                contributions: ptr::null(),
                contribution_count: 0,
                init: Some(init),
                release: Some(release),
                reserved: 0,
            },
            limiters: descriptors.as_ptr(),
            limiter_count: count,
            limiter_stride: std::mem::size_of::<v21::Limiter>() as u64,
            reserved: 0,
        });
        match VARIANT {
            "short-prefix" => {
                unsafe { *table = Box::into_raw(Box::new(4_u32)).cast() };
                return OK;
            }
            "short-tail" => api.base.header.struct_size = std::mem::size_of::<v2::ModApi>() as u32,
            "future-minor" => api.base.header.minor = 99,
            "stride" => api.limiter_stride = 1,
            "count" => api.limiter_count = u64::MAX,
            "null-array" => api.limiters = ptr::null(),
            "misaligned-array" => api.limiters = unsafe { api.limiters.cast::<u8>().add(1).cast() },
            "reserved" => api.reserved = 1,
            _ => {}
        }
        unsafe { *table = Box::into_raw(api).cast() };
        OK
    })
}
