//! Host-owned immutable native runtime. Libraries and sealed payloads stay pinned.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
compile_error!("CM P02 only supports Linux x86_64 GNU");

use std::cell::Cell;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use serde::Serialize;
use serde_json::Value;
use serde_json::json;

mod loader;
pub mod tool_policy;

use loader::native::NativeMod;

#[derive(Clone, Debug, Serialize)]
pub struct LoadError {
    pub stage: String,
    pub already_native_executed: bool,
    pub message: String,
}

impl LoadError {
    fn new(stage: &str, already_native_executed: bool, message: &str) -> Self {
        Self {
            stage: stage.into(),
            already_native_executed,
            message: message.into(),
        }
    }

    pub(crate) fn native(stage: &str, message: &str) -> Self {
        Self::new(stage, true, message)
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "CM {} (already_native_executed={}): {}",
            self.stage, self.already_native_executed, self.message
        )
    }
}

impl std::error::Error for LoadError {}

struct Trace {
    file: File,
    sequence: u64,
}

static TRACE: OnceLock<Option<Mutex<Trace>>> = OnceLock::new();
static STARTED: AtomicBool = AtomicBool::new(false);
static RUNTIME: OnceLock<Result<Runtime, LoadError>> = OnceLock::new();

thread_local! {
    static IN_NATIVE: Cell<bool> = const { Cell::new(false) };
}

pub(crate) struct NativeCall;

impl NativeCall {
    fn enter() -> Result<Self, String> {
        if IN_NATIVE.with(|flag| flag.replace(true)) {
            return Err("reentrant native callback rejected".into());
        }
        Ok(Self)
    }
}

impl Drop for NativeCall {
    fn drop(&mut self) {
        IN_NATIVE.with(|flag| flag.set(false));
    }
}

pub(crate) fn event(kind: &str, detail: Value) {
    if let Some(Some(trace)) = TRACE.get() {
        match trace.lock() {
            Ok(mut trace) => {
                trace.sequence += 1;
                let value = json!({
                    "event": kind, "seq": trace.sequence, "detail": detail,
                    "os_thread": unsafe { libc::syscall(libc::SYS_gettid) },
                });
                if let Err(error) = writeln!(trace.file, "{value}") {
                    eprintln!("CM trace write failed: {error}");
                }
            }
            Err(_) => eprintln!("CM trace lock poisoned"),
        }
    }
}

struct State {
    registration: Option<NativeMod>,
    stopping: bool,
    failed: Option<String>,
    active_tools: usize,
}

struct Runtime {
    stopping: AtomicBool,
    state: Mutex<State>,
    drained: Condvar,
}

pub struct ShutdownGuard {
    active: bool,
}

/// Initialize exactly once before opening Core business sessions.
/// P02 admits Core Mods only for the local embedded exec backend.
pub fn initialize(home: &Path, embedded_exec: bool) -> Result<ShutdownGuard, LoadError> {
    if STARTED.swap(true, Ordering::AcqRel) {
        return Err(LoadError::new(
            "startup",
            false,
            "runtime initialization is terminal and cannot be retried",
        ));
    }
    let result = (|| {
        let trace = std::env::var_os("CM_NATIVE_TRACE")
            .map(|path| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map(|file| Mutex::new(Trace { file, sequence: 0 }))
                    .map_err(|e| LoadError::new("trace", false, &e.to_string()))
            })
            .transpose()?;
        let _ = TRACE.set(trace);
        let candidate =
            loader::prepare(home).map_err(|e| LoadError::new("preflight", false, &e))?;
        if candidate.is_some() && !embedded_exec {
            return Err(LoadError::new(
                "backend",
                false,
                "P02 Core Mods require local embedded exec; Remote/LocalDaemon and other session paths lack a verified handshake",
            ));
        }
        let registration = candidate
            .map(|candidate| {
                let _call =
                    NativeCall::enter().map_err(|e| LoadError::new("startup", false, &e))?;
                NativeMod::load(candidate)
            })
            .transpose()?;
        event(
            "ready",
            json!({"mod_count": usize::from(registration.is_some()), "immutable": true}),
        );
        Ok(Runtime {
            stopping: AtomicBool::new(false),
            state: Mutex::new(State {
                registration,
                stopping: false,
                failed: None,
                active_tools: 0,
            }),
            drained: Condvar::new(),
        })
    })();
    if let Err(error) = &result {
        event("startup-failed", json!(error));
    }
    let failure = result.as_ref().err().cloned();
    let _ = RUNTIME.set(result);
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(ShutdownGuard { active: true })
}

fn shutdown() -> Result<(), LoadError> {
    let Some(Ok(runtime)) = RUNTIME.get() else {
        return Ok(());
    };
    runtime.stopping.store(true, Ordering::Release);
    event("stopping-requested", json!({}));
    let _call = NativeCall::enter().map_err(|e| LoadError::native("shutdown", &e))?;
    let mut state = runtime
        .state
        .lock()
        .map_err(|_| LoadError::native("shutdown", "poisoned runtime"))?;
    if state.stopping {
        return Ok(());
    }
    state.stopping = true;
    event("stopping", json!({"active_tools": state.active_tools}));
    while state.active_tools != 0 {
        state = runtime
            .drained
            .wait(state)
            .map_err(|_| LoadError::native("shutdown", "poisoned drain"))?;
    }
    if let Some(mut registration) = state.registration.take() {
        registration.release()?;
    }
    event(
        "stopped",
        json!({"active_tools": 0, "libraries_unloaded": 0}),
    );
    Ok(())
}

/// Preserve terminal CLI exits while draining any initialized native runtime first.
pub fn exit_after_shutdown(code: i32) -> ! {
    if let Err(error) = shutdown() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    std::process::exit(code);
}

impl ShutdownGuard {
    pub fn finish(mut self) -> Result<(), LoadError> {
        self.active = false;
        shutdown()
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = shutdown()
        {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NativeCall;

    #[test]
    fn native_entry_rejects_reentry_and_does_not_require_init_thread_tls() {
        let outer = NativeCall::enter().unwrap();
        assert!(NativeCall::enter().is_err());
        assert!(
            std::thread::spawn(|| NativeCall::enter().is_ok())
                .join()
                .unwrap()
        );
        drop(outer);
        assert!(NativeCall::enter().is_ok());
    }
}
