//! Host-owned immutable native runtime. Libraries and sealed payloads stay pinned.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
compile_error!("CM only supports Linux x86_64 GNU");

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

pub mod config;
mod diagnostics;
pub mod launcher;
mod loader;
mod manifest;
pub mod metadata;
pub mod mod_install;
pub mod mod_lock;
pub mod output_limit;
pub mod package;
pub mod profile;
pub mod runtime;
pub mod runtime_plan;
pub mod sampling_budget;
pub mod state;
pub mod tool_policy;
pub mod tool_concurrency;
pub mod tui_review;

use loader::registration::RegistrationSet;

#[derive(Clone)]
pub struct LoadError {
    pub stage: String,
    pub already_native_executed: bool,
    pub message: String,
    pub code: String,
    pub mod_id: Option<String>,
    pub contribution: Option<String>,
    pub related_contributions: Vec<String>,
    pub resource: Option<String>,
    pub field: Option<String>,
    pub graph: Option<String>,
    pub native_status: Option<u32>,
}

impl LoadError {
    pub(crate) fn new(stage: &str, already_native_executed: bool, message: &str) -> Self {
        Self {
            stage: stage.into(),
            already_native_executed,
            message: message.into(),
            code: stage.into(),
            mod_id: None,
            contribution: None,
            related_contributions: Vec::new(),
            resource: None,
            field: None,
            graph: None,
            native_status: None,
        }
    }

    pub(crate) fn input(code: &str, owner: &str, message: &str) -> Self {
        let mut error = Self::new("preflight", false, message);
        error.code = code.into();
        error.field = Some(
            message
                .split_once(':')
                .map(|(field, _)| field)
                .filter(|field| {
                    [
                        "config",
                        "compat",
                        "binary",
                        "dependencies",
                        "state",
                        "provenance",
                    ]
                    .iter()
                    .any(|prefix| field.starts_with(prefix))
                        && field
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
                })
                .unwrap_or(code)
                .into(),
        );
        error.graph = if code.starts_with("dependency")
            || code == "missing_dependency"
            || code == "unsupported_version"
        {
            Some("initialization".into())
        } else if code.contains("hook")
            || code.starts_with("contribution")
            || code == "exclusive_conflict"
        {
            Some("contribution".into())
        } else {
            None
        };
        error.owner(owner, None)
    }

    pub(crate) fn owner(mut self, owner: &str, contribution: Option<&str>) -> Self {
        self.mod_id = (!owner.is_empty()).then(|| owner.to_string());
        if let Some(contribution) = contribution {
            self.contribution = Some(contribution.into());
        }
        self.resource = Some(cm_abi::CAPABILITY.into());
        self
    }

    pub(crate) fn native(stage: &str, message: &str) -> Self {
        Self::new(stage, true, message)
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let diagnostic = crate::diagnostics::error(self);
        write!(
            output,
            "CM {} [{}] mod={} (already_native_executed={}): {}; next_action={}",
            diagnostic["stage"].as_str().unwrap_or("unknown"),
            diagnostic["code"].as_str().unwrap_or("unknown"),
            diagnostic["mod_id"].as_str().unwrap_or("-"),
            self.already_native_executed,
            diagnostic["message"]
                .as_str()
                .unwrap_or("operation rejected"),
            diagnostic["next_action"]
                .as_str()
                .unwrap_or("inspect the verified receipt")
        )
    }
}

impl std::fmt::Debug for LoadError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, output)
    }
}

impl Serialize for LoadError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::diagnostics::error(self).serialize(serializer)
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
    registration: Option<RegistrationSet>,
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

static PENDING_TUI: OnceLock<Mutex<Option<runtime_plan::PreparedPlan>>> = OnceLock::new();
// Retain through startup failure and drain: native libraries/work may remain pinned.
static STATE_LEASE: OnceLock<Option<state::Guard>> = OnceLock::new();

/// Prepare without executing native code until the actual TUI backend is known.
pub fn defer_tui(home: &Path, options: &config::Options) -> Result<ShutdownGuard, LoadError> {
    let prepared = runtime_plan::prepare_options(home, options)?;
    prepared.validate_backend()?;
    if prepared.plan().mods.is_empty() && !profile::managed(home)? {
        return initialize_prepared(prepared, false);
    }
    PENDING_TUI
        .set(Mutex::new(Some(prepared)))
        .map_err(|_| LoadError::new("startup", false, "TUI preparation is terminal"))?;
    Ok(ShutdownGuard { active: true })
}

pub fn tui_embedded_required() -> bool {
    PENDING_TUI.get().is_some()
}

/// Called only on the real Embedded start branch, before opening Core sessions.
pub fn initialize_tui_embedded() -> Result<(), LoadError> {
    let Some(pending) = PENDING_TUI.get() else {
        return Ok(());
    };
    if STARTED.load(Ordering::Acquire) {
        return match RUNTIME.get() {
            Some(Ok(_)) => Ok(()),
            _ => Err(LoadError::new(
                "startup",
                false,
                "previous TUI initialization failed",
            )),
        };
    }
    let prepared = pending
        .lock()
        .map_err(|_| LoadError::new("startup", false, "poisoned TUI preparation"))?
        .take()
        .ok_or_else(|| {
            LoadError::new("startup", false, "TUI initialization was already consumed")
        })?;
    let mut guard = initialize_prepared(prepared, true)?;
    // The CLI owns the outer guard and drains on all normal TUI exit paths.
    guard.active = false;
    Ok(())
}

pub fn confirm_tui_embedded() {
    if tui_embedded_required() {
        event(
            "backend-selected",
            json!({"backend":"Embedded", "transport":"InProcess", "pid":std::process::id()}),
        );
    }
}

/// Initialize exactly once before opening Core business sessions.
pub fn initialize(home: &Path, embedded_exec: bool) -> Result<ShutdownGuard, LoadError> {
    initialize_with(embedded_exec, || runtime_plan::prepare(home))
}

pub fn initialize_options(
    home: &Path,
    embedded_exec: bool,
    options: &config::Options,
) -> Result<ShutdownGuard, LoadError> {
    initialize_with(embedded_exec, || {
        runtime_plan::prepare_options(home, options)
    })
}

/// Actions probe seam: only an owned, previously prepared snapshot can be committed.
pub fn initialize_prepared(
    prepared: runtime_plan::PreparedPlan,
    embedded_exec: bool,
) -> Result<ShutdownGuard, LoadError> {
    initialize_with(embedded_exec, || Ok(prepared))
}

fn initialize_with(
    embedded_exec: bool,
    prepare: impl FnOnce() -> Result<runtime_plan::PreparedPlan, LoadError>,
) -> Result<ShutdownGuard, LoadError> {
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
        let prepared = prepare()?;
        event(
            "planned",
            json!({
                "plan_sha256": prepared.plan().sha256(), "plan": prepared.plan(),
                "already_native_executed": false,
            }),
        );
        prepared.validate_backend()?;
        if prepared.plan().phases.contains_key("submit_review") && !tui_embedded_required() {
            return Err(LoadError::new(
                "backend",
                false,
                "tui.submit_review.v1 requires the local Embedded TUI; exec/stdio are unsupported",
            ));
        }
        if (prepared.managed() || !prepared.plan().mods.is_empty()) && !embedded_exec {
            return Err(LoadError::new(
                "backend",
                false,
                "CM requires local Embedded execution; other backends lack a verified handshake",
            ));
        }
        let state_lease = prepared.acquire_state()?;
        STATE_LEASE
            .set(state_lease)
            .map_err(|_| LoadError::new("startup", false, "state lease was already initialized"))?;
        let (plan, modules, config) = prepared.commit()?;
        let _call = NativeCall::enter().map_err(|e| LoadError::new("startup", false, &e))?;
        let registration = RegistrationSet::load(plan, modules, config)?;
        event(
            "ready",
            json!({
                "mod_count": registration.len(), "immutable": true,
                "plan_sha256": registration.digest, "plan": registration.plan,
            }),
        );
        Ok(Runtime {
            stopping: AtomicBool::new(false),
            state: Mutex::new(State {
                registration: Some(registration),
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
    let runtime_cleanup = crate::runtime::shutdown();
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
    runtime_cleanup?;
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
