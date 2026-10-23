//! Independent author fixture: depends only on cm-abi, never Core/runtime.
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::ptr;
use std::sync::Mutex;

use cm_abi::*;

static EVENTS: Mutex<()> = Mutex::new(());

fn mode() -> String {
    std::env::var("CM_FIXTURE_MODE").unwrap_or_default()
}

fn record(event: &str) {
    let Ok(_guard) = EVENTS.lock() else {
        return;
    };
    if let Some(path) = std::env::var_os("CM_FIXTURE_EVENTS")
        && let Ok(mut file) = OpenOptions::new().append(true).create(true).open(path)
    {
        unsafe extern "C" {
            fn gettid() -> i32;
        }
        let thread = unsafe { gettid() };
        let _ = writeln!(file, "{{\"event\":\"{event}\",\"os_thread\":{thread}}}");
    }
}

extern "C" fn constructor() {
    let _ = catch_unwind(|| record("constructor"));
}

extern "C" fn finalizer() {
    let _ = catch_unwind(|| record("process-finalizer"));
}

#[used]
#[unsafe(link_section = ".init_array")]
static CONSTRUCTOR: extern "C" fn() = constructor;
#[used]
#[unsafe(link_section = ".fini_array")]
static FINALIZER: extern "C" fn() = finalizer;

unsafe fn error_text(error: *mut ErrorBuffer, message: &str) {
    if error.is_null() {
        return;
    }
    let error = unsafe { &mut *error };
    let count = message.len().min(error.capacity as usize);
    if !error.data.is_null() {
        unsafe { ptr::copy_nonoverlapping(message.as_ptr(), error.data, count) };
        error.len = count as u64;
    }
}

fn wrapped(error: *mut ErrorBuffer, call: impl FnOnce() -> u32) -> u32 {
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(status) => status,
        Err(_) => {
            unsafe { error_text(error, "caught fixture panic inside Mod wrapper") };
            record("caught-panic");
            PANICKED
        }
    }
}

unsafe fn view<'a>(value: Bytes) -> Result<&'a str, ()> {
    if value.len > 512 || (value.len != 0 && value.data.is_null()) {
        return Err(());
    }
    let bytes = if value.len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(value.data, value.len as usize) }
    };
    std::str::from_utf8(bytes).map_err(|_| ())
}

unsafe extern "C" fn init(userdata: *mut *mut c_void, error: *mut ErrorBuffer) -> u32 {
    wrapped(error, || {
        record("init");
        if userdata.is_null() {
            return FAILED;
        }
        unsafe { *userdata = Box::into_raw(Box::new(0_u64)).cast() };
        match mode().as_str() {
            "init-fail" => FAILED,
            "init-panic" => panic!("catchable init fixture"),
            _ => OK,
        }
    })
}

unsafe extern "C" fn policy(
    userdata: *mut c_void,
    input: *const PolicyInput,
    output: *mut PolicyOutput,
    error: *mut ErrorBuffer,
) -> u32 {
    wrapped(error, || {
        record("callback-enter");
        if userdata.is_null() || input.is_null() || output.is_null() {
            return FAILED;
        }
        let input = unsafe { &*input };
        if input.header.struct_size < std::mem::size_of::<PolicyInput>() as u32
            || input.header.major != ABI_MAJOR
            || input.header.minor != ABI_MINOR
            || input.original_parallel > 1
            || input.reserved != 0
        {
            return FAILED;
        }
        for field in [
            input.namespace,
            input.tool,
            input.call_id,
            input.thread_id,
            input.turn_id,
        ] {
            if unsafe { view(field) }.is_err() {
                return FAILED;
            }
        }
        let current = mode();
        match current.as_str() {
            "callback-fail" => return FAILED,
            "callback-panic" => panic!("catchable policy fixture"),
            "abort" => std::process::abort(),
            "segfault" => {
                unsafe extern "C" {
                    fn raise(signal: i32) -> i32;
                }
                unsafe { raise(11) };
                return FAILED;
            }
            "hold" | "stuck" => {
                let mut socket =
                    UnixStream::connect(std::env::var_os("CM_FIXTURE_SOCKET").unwrap()).unwrap();
                socket.write_all(b"callback-entered\n").unwrap();
                let mut release = [0];
                socket.read_exact(&mut release).unwrap();
                record("callback-returned-from-barrier");
            }
            "error-length" => {
                unsafe { (*error).len = ERROR_CAPACITY as u64 + 1 };
                return OK;
            }
            "error-null" => {
                unsafe { (*error).data = ptr::null_mut() };
                return OK;
            }
            "error-utf8" => {
                unsafe {
                    (*error).data.write(0xff);
                    (*error).len = 1;
                }
                return FAILED;
            }
            "error-canary" => {
                unsafe { (*error).data.add(ERROR_CAPACITY).write(0) };
                return OK;
            }
            "output-canary" => {
                unsafe {
                    output
                        .cast::<u8>()
                        .add(std::mem::size_of::<PolicyOutput>())
                        .write(0)
                };
                return OK;
            }
            _ => {}
        }
        unsafe { *userdata.cast::<u64>() += 1 };
        let output = unsafe { &mut *output };
        if output.header.struct_size < std::mem::size_of::<PolicyOutput>() as u32 {
            return FAILED;
        }
        output.decision = if unsafe { view(input.tool) } == Ok("exec_command") {
            FORCE_SERIAL
        } else {
            KEEP
        };
        if current == "bad-decision" {
            output.decision = 99;
        }
        if current == "output-size" {
            output.header.struct_size = 8;
        }
        record("callback-exit");
        if current == "bad-status" { 99 } else { OK }
    })
}

unsafe extern "C" fn release(userdata: *mut c_void, error: *mut ErrorBuffer) -> u32 {
    wrapped(error, || {
        if userdata.is_null() {
            return FAILED;
        }
        drop(unsafe { Box::from_raw(userdata.cast::<u64>()) });
        record("release");
        match mode().as_str() {
            "release-fail" => FAILED,
            "release-panic" => panic!("catchable release fixture"),
            _ => OK,
        }
    })
}

/// # Safety
/// Host and output pointers must satisfy cm_mod_v1.h for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cm_mod_entry_v1(
    host: *const HostApi,
    table: *mut *const Header,
    error: *mut ErrorBuffer,
) -> u32 {
    wrapped(error, || {
        record("entry");
        if host.is_null() || table.is_null() {
            return FAILED;
        }
        let host = unsafe { &*host };
        if host.header.struct_size < std::mem::size_of::<HostApi>() as u32
            || host.header.major != ABI_MAJOR
            || host.header.minor != ABI_MINOR
            || host.reserved != 0
            || unsafe { view(host.capability) } != Ok(CAPABILITY)
        {
            return FAILED;
        }
        let current = mode();
        if current == "entry-fail" {
            return FAILED;
        }
        if current == "entry-panic" {
            panic!("catchable entry fixture");
        }
        if current == "entry-status" {
            return 99;
        }
        if current == "short-prefix" {
            let prefix = Box::new(4_u32);
            unsafe { *table = Box::into_raw(prefix).cast() };
            return OK;
        }
        let mut api = Box::new(ModApi {
            header: Header::of::<ModApi>(),
            mod_id: Bytes::from_static("serial-fixture"),
            contribution: Bytes::from_static(CONTRIBUTION),
            init: Some(init),
            policy: Some(policy),
            release: Some(release),
            reserved: 0,
        });
        match current.as_str() {
            "short-table" => api.header.struct_size = 8,
            "wrong-major" => api.header.major = 2,
            "wrong-minor" => api.header.minor = 99,
            "null-policy" => api.policy = None,
            "null-init" => api.init = None,
            "no-release" => api.release = None,
            "declaration-drift" => api.mod_id = Bytes::from_static("other-mod"),
            "null-view" => {
                api.mod_id = Bytes {
                    data: ptr::null(),
                    len: 1,
                }
            }
            "huge-view" => api.mod_id.len = u64::MAX,
            "invalid-utf8" => {
                api.mod_id = Bytes {
                    data: b"\xff".as_ptr(),
                    len: 1,
                }
            }
            "reserved" => api.reserved = 1,
            "null-table" => {
                unsafe { *table = ptr::null() };
                return OK;
            }
            _ => {}
        }
        unsafe { *table = Box::into_raw(api).cast() };
        OK
    })
}
