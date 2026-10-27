use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::ptr;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use cm_abi::Bytes;
use cm_abi::ErrorBuffer;
use cm_abi::FAILED;
use cm_abi::FORCE_SERIAL;
use cm_abi::Header;
use cm_abi::KEEP;
use cm_abi::OK;
use cm_abi::PANICKED;
use cm_abi::v2;

const VARIANT: &str = env!("CM_COMPOSITION_VARIANT");
static NEXT: OnceLock<v2::Next> = OnceLock::new();
static PREVIOUS: AtomicU64 = AtomicU64::new(0);
static EVENTS: Mutex<()> = Mutex::new(());

fn record(event: &str, input: Option<&v2::Input>) {
    let _guard = EVENTS.lock().unwrap();
    if let Some(path) = std::env::var_os("CM_FIXTURE_EVENTS") {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let (phase, outcome, decision, token) = input.map_or((0, 0, 0, 0), |value| {
            (value.phase, value.outcome, value.decision, value.next_token)
        });
        writeln!(file, "{{\"event\":{event:?},\"mod\":{MOD_ID:?},\"variant\":{VARIANT:?},\"phase\":{phase},\"outcome\":{outcome},\"decision\":{decision},\"token\":{token}}}").unwrap();
    }
}

extern "C" fn constructor() {
    let _ = catch_unwind(|| record("constructor", None));
}
#[used]
#[unsafe(link_section = ".init_array")]
static CONSTRUCTOR: extern "C" fn() = constructor;

fn wrapped(error: *mut ErrorBuffer, call: impl FnOnce() -> u32) -> u32 {
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(status) => status,
        Err(_) => {
            let message = b"caught composition fixture panic";
            if !error.is_null() {
                unsafe {
                    if !(*error).data.is_null() && (*error).capacity >= message.len() as u64 {
                        ptr::copy_nonoverlapping(message.as_ptr(), (*error).data, message.len());
                        (*error).len = message.len() as u64;
                    }
                }
            }
            PANICKED
        }
    }
}

unsafe fn view<'a>(value: Bytes) -> &'a str {
    if value.len == 0 {
        return "";
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(value.data, value.len as usize) })
        .unwrap()
}

fn mode() -> String {
    let value = std::env::var("CM_COMPOSE_MODE").unwrap_or_default();
    value
        .split(',')
        .find_map(|item| item.strip_prefix(&format!("{MOD_ID}:")))
        .unwrap_or("")
        .into()
}

fn advance(token: u64) -> (u32, u32) {
    let mut bytes = [0_u8; cm_abi::ERROR_CAPACITY];
    let mut error = ErrorBuffer {
        data: bytes.as_mut_ptr(),
        capacity: bytes.len() as u64,
        len: 0,
    };
    let mut output = v2::Decision {
        header: v2::header::<v2::Decision>(),
        decision: KEEP,
        reserved: 0,
    };
    let current = mode();
    if current == "next-bad-header" {
        output.header.major = 1;
    }
    if current == "next-error-cap" {
        error.capacity += 1;
    }
    let pointer = if current == "next-null-output" {
        ptr::null_mut()
    } else {
        &mut output
    };
    let status = unsafe { (NEXT.get().unwrap())(token, pointer, &mut error) };
    (status, output.decision)
}

unsafe extern "C" fn init(
    context: *const v2::InitContext,
    userdata: *mut *mut c_void,
    error: *mut ErrorBuffer,
) -> u32 {
    wrapped(error, || {
        record("init", None);
        let context = unsafe { &*context };
        assert_eq!(context.header.major, 2);
        assert!(context.resource_count <= 64);
        for index in 0..context.resource_count as usize {
            let resource = unsafe { &*context.resources.add(index) };
            assert_eq!(unsafe { view(resource.path) }, "data.txt");
            assert_eq!(
                unsafe { view(resource.content) },
                "composition-resource-v1\n"
            );
        }
        if context.config.len != 0 {
            let config = unsafe { view(context.config) };
            assert!(config.contains("format_version"));
            assert!(
                !config.contains("M01_")
                    && !config.contains("profiles")
                    && !config.contains("token")
            );
            if let Some(path) = std::env::var_os("CM_LEGACY_CONFIG_OBSERVATION") {
                std::fs::write(path, br#"{"selection_projection_only":true}"#).unwrap();
            }
        }
        unsafe { *userdata = Box::into_raw(Box::new(0_u64)).cast() };
        if VARIANT == "init-fail" { FAILED } else { OK }
    })
}

unsafe extern "C" fn hook(
    userdata: *mut c_void,
    input: *const v2::Input,
    output: *mut v2::Decision,
    error: *mut ErrorBuffer,
) -> u32 {
    wrapped(error, || {
        let input = unsafe { &*input };
        assert!(!userdata.is_null());
        assert_eq!(input.header.major, 2);
        assert_eq!(input.policy.header.major, 1);
        assert!(input.policy.original_parallel <= 1);
        for value in [
            input.policy.namespace,
            input.policy.tool,
            input.policy.call_id,
            input.policy.thread_id,
            input.policy.turn_id,
        ] {
            assert!(!unsafe { view(value) }.is_empty());
        }
        record("callback-enter", Some(input));
        let mode = mode();
        let fail_phase = match mode.as_str() {
            "before-fail" => v2::BEFORE,
            "inner-fail" | "callback-panic" => v2::AROUND,
            "after-fail" => v2::AFTER,
            _ => 0,
        };
        if input.phase == fail_phase {
            if mode == "callback-panic" {
                panic!("composition caught callback panic");
            }
            return FAILED;
        }
        if (mode == "next-before" && input.phase == v2::BEFORE)
            || (mode == "next-after" && input.phase == v2::AFTER)
        {
            let _ = advance(PREVIOUS.load(Ordering::Acquire));
        }
        let output = unsafe { &mut *output };
        match input.phase {
            v2::AROUND => {
                if mode == "hold" || mode == "stuck" {
                    let mut socket =
                        UnixStream::connect(std::env::var_os("CM_FIXTURE_SOCKET").unwrap())
                            .unwrap();
                    socket.write_all(b"callback-entered\n").unwrap();
                    let mut release = [0];
                    socket.read_exact(&mut release).unwrap();
                }
                if VARIANT == "short" || mode == "short-keep" {
                    output.decision = if mode == "short-keep" {
                        KEEP
                    } else {
                        FORCE_SERIAL
                    };
                } else {
                    let previous = PREVIOUS.swap(input.next_token, Ordering::AcqRel);
                    let mut token = input.next_token;
                    if let Some(path) = std::env::var_os("CM_TOKEN_FILE") {
                        if MOD_ID == "compose-a" {
                            std::fs::write(&path, token.to_string()).unwrap();
                        }
                        if mode == "cross-owner" {
                            token = std::fs::read_to_string(path).unwrap().parse().unwrap();
                        }
                    }
                    if mode == "stale" && previous != 0 {
                        token = previous;
                    }
                    let (status, downstream) = if mode == "wrong-thread" {
                        std::thread::spawn(move || advance(token)).join().unwrap()
                    } else {
                        advance(token)
                    };
                    if mode == "repeat" {
                        let _ = advance(token);
                    }
                    if status == v2::CANCELLED {
                        return status;
                    }
                    if mode == "swallow-error" {
                        return OK;
                    }
                    if status != OK
                        && !["repeat", "stale", "wrong-thread", "cross-owner"]
                            .contains(&mode.as_str())
                    {
                        return status;
                    }
                    // A deliberately returns KEEP: Host must retain B's downstream restriction.
                    output.decision = if MOD_ID == "compose-b"
                        && unsafe { view(input.policy.tool) } == "exec_command"
                    {
                        FORCE_SERIAL
                    } else {
                        KEEP
                    };
                    if downstream == FORCE_SERIAL {
                        record("observed-downstream-force", Some(input));
                    }
                }
            }
            v2::REPLACEMENT => {
                output.decision = FORCE_SERIAL;
            }
            _ => {
                output.decision = KEEP;
            }
        }
        if mode == "bad-decision" {
            output.decision = 99;
        }
        if mode == "bad-header" {
            output.header.struct_size = 8;
        }
        if mode == "error-exact" {
            unsafe {
                ptr::write_bytes((*error).data, b'x', 1024);
                (*error).len = 1024;
            }
        }
        if mode == "error-length" {
            unsafe { (*error).len = 1025 };
        }
        if mode == "error-canary" {
            unsafe { (*error).data.add(1024).write(0) };
        }
        if mode == "output-canary" {
            unsafe { (output as *mut v2::Decision).cast::<u8>().add(16).write(0) };
        }
        record("callback-exit", Some(input));
        match mode.as_str() {
            "bad-status" => 99,
            "fake-cancel" => v2::CANCELLED,
            _ => OK,
        }
    })
}

unsafe extern "C" fn release(userdata: *mut c_void, error: *mut ErrorBuffer) -> u32 {
    wrapped(error, || {
        drop(unsafe { Box::from_raw(userdata.cast::<u64>()) });
        record("release", None);
        if VARIANT == "release-fail" || VARIANT == "init-fail" {
            FAILED
        } else {
            OK
        }
    })
}

/// # Safety
/// Host must supply the valid allocations specified in cm_mod_v2.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cm_mod_entry_v2(
    host: *const v2::HostApi,
    table: *mut *const Header,
    error: *mut ErrorBuffer,
) -> u32 {
    wrapped(error, || {
        record("entry", None);
        let host = unsafe { &*host };
        assert_eq!(host.header.major, 2);
        assert_eq!(unsafe { view(host.capability) }, v2::CAPABILITY);
        assert!(unsafe { view(host.host_build_id) }.starts_with("sha256:"));
        let _ = NEXT.set(host.next.unwrap());
        if VARIANT == "entry-next" {
            let _ = advance(0);
        }
        if VARIANT == "entry-fail" {
            return FAILED;
        }
        if VARIANT == "entry-status" {
            return 99;
        }
        if VARIANT == "short-prefix" {
            unsafe { *table = Box::into_raw(Box::new(4_u32)).cast() };
            return OK;
        }
        let mut definitions = if VARIANT == "replacement" {
            vec![("terminal", v2::REPLACEMENT)]
        } else {
            vec![
                ("before", v2::BEFORE),
                ("around", v2::AROUND),
                ("after", v2::AFTER),
            ]
        };
        if VARIANT == "nested-next" {
            definitions.insert(2, ("around-inner", v2::AROUND));
        }
        let mut hooks: Vec<_> = definitions
            .into_iter()
            .map(|(id, kind)| v2::Contribution {
                header: v2::header::<v2::Contribution>(),
                id: Bytes::from_static(id),
                capability: Bytes::from_static(v2::CAPABILITY),
                resource: Bytes::from_static(cm_abi::CAPABILITY),
                kind,
                reserved: 0,
                callback: Some(hook),
            })
            .collect();
        match VARIANT {
            "extra" => hooks.push(hooks[0]),
            "missing" => {
                hooks.pop();
            }
            "duplicate" => hooks[1].id = hooks[0].id,
            "kind" => hooks[0].kind = v2::AFTER,
            "capability" => hooks[0].capability = Bytes::from_static("unknown.capability"),
            "resource" => hooks[0].resource = Bytes::from_static("unknown.resource"),
            "null-callback" => hooks[0].callback = None,
            "descriptor-size" => hooks[0].header.struct_size = 8,
            "descriptor-version" => hooks[0].header.minor = 99,
            _ => {}
        }
        let hooks = Box::leak(hooks.into_boxed_slice());
        let mut api = Box::new(v2::ModApi {
            header: v2::header::<v2::ModApi>(),
            mod_id: Bytes::from_static(MOD_ID),
            contributions: hooks.as_ptr(),
            contribution_count: hooks.len() as u64,
            init: Some(init),
            release: Some(release),
            reserved: 0,
        });
        match VARIANT {
            "short-table" => api.header.struct_size = 8,
            "table-overflow" => api.header.struct_size = 4097,
            "misaligned-array" => {
                api.contributions = unsafe { api.contributions.cast::<u8>().add(4).cast() }
            }
            "zero-array" => api.contribution_count = 0,
            "major" => api.header.major = 1,
            "minor" => api.header.minor = 1,
            "mod-id" => api.mod_id = Bytes::from_static("wrong-mod"),
            "null-view" => {
                api.mod_id = Bytes {
                    data: ptr::null(),
                    len: 1,
                }
            }
            "huge-view" => api.mod_id.len = u64::MAX,
            "utf8" => {
                api.mod_id = Bytes {
                    data: b"\xff".as_ptr(),
                    len: 1,
                }
            }
            "null-init" => api.init = None,
            "null-release" => api.release = None,
            "null-array" => api.contributions = ptr::null(),
            "huge-array" => api.contribution_count = 129,
            "reserved" => api.reserved = 1,
            _ => {}
        }
        if VARIANT == "max-table" {
            api.header.struct_size = 4096;
            let mut extended = Box::new([0_u64; 512]);
            unsafe {
                extended.as_mut_ptr().cast::<v2::ModApi>().write(*api);
                *table = Box::into_raw(extended).cast();
            }
            return OK;
        }
        if VARIANT == "misaligned-table" {
            let mut allocation = Box::new([0_u64; 9]);
            let pointer = unsafe {
                allocation
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(4)
                    .cast::<v2::ModApi>()
            };
            unsafe {
                pointer.write_unaligned(*api);
            }
            let _allocation = Box::leak(allocation);
            unsafe {
                *table = pointer.cast();
            }
            return OK;
        }
        if VARIANT == "null-table" {
            unsafe {
                *table = ptr::null();
            }
            return OK;
        }
        unsafe { *table = Box::into_raw(api).cast() };
        OK
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn author_has_no_core_or_runtime_dependency() {
        assert!(matches!(super::MOD_ID, "compose-a" | "compose-b"));
        assert!(!super::VARIANT.is_empty());
    }
}
