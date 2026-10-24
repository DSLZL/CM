use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use cm_abi::Bytes;
use cm_abi::FORCE_SERIAL;
use cm_abi::Header;
use cm_abi::KEEP;
use cm_abi::PolicyInput;
use cm_abi::v2;
use serde_json::Value;
use serde_json::json;

use crate::LoadError;
use crate::NativeCall;
use crate::RUNTIME;
use crate::Runtime;
use crate::event;
use crate::loader::Kind;
use crate::loader::registration::RegistrationSet;

pub struct Context<'a> {
    pub namespace: &'a str,
    pub tool: &'a str,
    pub call_id: &'a str,
    pub thread_id: &'a str,
    pub turn_id: &'a str,
}

#[derive(Debug)]
pub enum PolicyError {
    Cancelled,
    Failed(String),
}

pub struct ToolDecision {
    pub supports_parallel: bool,
    detail: Value,
    runtime: &'static Runtime,
}

impl ToolDecision {
    pub fn record(&self, kind: &str) { event(kind, self.detail.clone()); }
}

impl Drop for ToolDecision {
    fn drop(&mut self) {
        self.record("dispatch-finished");
        match self.runtime.state.lock() {
            Ok(mut state) => {
                state.active_tools -= 1;
                self.runtime.drained.notify_all();
            }
            Err(_) => eprintln!("CM runtime poisoned while releasing tool lease"),
        }
    }
}

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
pub(crate) static NEXT_VIOLATION: AtomicBool = AtomicBool::new(false);
thread_local! {
    static DISPATCH: Cell<*mut c_void> = const { Cell::new(std::ptr::null_mut()) };
}

struct DispatchScope(*mut c_void);

impl DispatchScope {
    fn enter(pointer: *mut c_void) -> Self {
        Self(DISPATCH.with(|slot| slot.replace(pointer)))
    }
}

impl Drop for DispatchScope {
    fn drop(&mut self) { DISPATCH.with(|slot| slot.set(self.0)); }
}

struct Frame {
    token: u64,
    owner: String,
    next_index: usize,
    used: bool,
    downstream: u32,
}

impl Frame {
    fn consume(&mut self, token: u64, owner: &str) -> bool {
        if token == 0 || token != self.token || owner != self.owner || self.used {
            return false;
        }
        self.used = true;
        true
    }
}

struct Dispatch<'a> {
    registration: &'a RegistrationSet,
    input: &'a PolicyInput,
    detail: &'a Value,
    cancelled: &'a dyn Fn() -> bool,
    frames: Vec<Frame>,
    active: Option<(String, u64)>,
    fatal: Option<LoadError>,
    cancelled_seen: bool,
    force_serial: bool,
}

impl Dispatch<'_> {
    fn fail(&mut self, message: &str) {
        let mut error = LoadError::native("policy", message);
        if let Some((key, _)) = &self.active {
            let binding = &self.registration.bindings[key];
            error = error.owner(&binding.owner, Some(&binding.local_id));
        }
        self.latch(error);
    }

    fn latch(&mut self, error: LoadError) {
        if self.fatal.is_none() { self.fatal = Some(error); }
    }

    fn boundary(&mut self) -> bool {
        if NEXT_VIOLATION.load(Ordering::Acquire) {
            self.fail("invalid Next use outside its active thread/scope");
        }
        self.cancelled_seen |= (self.cancelled)();
        self.fatal.is_none() && !self.cancelled_seen
    }

    fn trace(&self, event_name: &str, key: &str, extra: Value) {
        let binding = &self.registration.bindings[key];
        event(event_name, json!({
            "plan_sha256": self.registration.digest,
            "mod": binding.owner, "contribution": binding.local_id, "phase": binding.kind,
            "call_id": self.detail["call_id"], "thread_id": self.detail["thread_id"],
            "turn_id": self.detail["turn_id"], "original_parallel": self.input.original_parallel,
            "extra": extra,
        }));
    }

    fn callback(&mut self, key: &str, token: u64) -> u32 {
        let registration = self.registration;
        let binding = &registration.bindings[key];
        let previous = self.active.replace((key.into(), token));
        let outcome = if self.fatal.is_some() { v2::FAILED }
            else if self.cancelled_seen { v2::CANCELLED_OUTCOME } else { v2::SUCCEEDED };
        let input = v2::Input {
            header: v2::header::<v2::Input>(),
            policy: PolicyInput {
                header: self.input.header, namespace: self.input.namespace,
                tool: self.input.tool, call_id: self.input.call_id, thread_id: self.input.thread_id,
                turn_id: self.input.turn_id, original_parallel: self.input.original_parallel, reserved: 0,
            },
            phase: binding.kind.abi(), outcome, decision: u32::from(self.force_serial),
            reserved: 0, next_token: token,
        };
        self.trace("hook-enter", key, json!({"outcome": outcome, "token": token}));
        // No TLS RefCell borrow or Runtime mutex acquisition occurs inside controlled Next.
        let _scope = DispatchScope::enter((self as *mut Self).cast());
        let result = registration.hook(key, &input);
        self.boundary();
        let decision = match result {
            Ok((decision, reported_cancelled)) => {
                if reported_cancelled && !self.cancelled_seen {
                    self.fail("Mod returned CANCELLED without observed Host cancellation");
                }
                if matches!(binding.kind, Kind::Before | Kind::After) && decision != KEEP {
                    self.fail("before/after must return KEEP");
                }
                decision
            }
            Err(error) => { self.latch(error); KEEP }
        };
        self.trace("hook-exit", key, json!({
            "decision": decision, "cancelled": self.cancelled_seen,
            "failed": self.fatal.is_some(),
        }));
        self.active = previous;
        decision
    }

    fn body(&mut self, index: usize) -> u32 {
        if !self.boundary() { return u32::from(self.force_serial); }
        let keys = &self.registration.plan.phases["body"];
        if index == keys.len() { return KEEP; }
        let key = keys[index].clone();
        let kind = self.registration.bindings[&key].kind.clone();
        if kind == Kind::Replacement {
            let decision = self.callback(&key, 0);
            self.force_serial |= decision == FORCE_SERIAL;
            return decision;
        }
        let token = match NEXT_GENERATION.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1)) {
            Ok(token) => token,
            Err(_) => { self.fail("Next generation exhausted"); return KEEP; }
        };
        self.frames.push(Frame { token, owner: key.clone(), next_index: index + 1, used: false, downstream: KEEP });
        let decision = self.callback(&key, token);
        let frame = self.frames.pop().expect("controlled callback frame");
        if !frame.used && decision != FORCE_SERIAL && self.fatal.is_none() && !self.cancelled_seen {
            let previous = self.active.replace((key.clone(), token));
            self.fail("around without Next must FORCE_SERIAL");
            self.active = previous;
        }
        self.force_serial |= decision == FORCE_SERIAL || frame.downstream == FORCE_SERIAL;
        self.trace("around-complete", &key, json!({
            "next_count": u32::from(frame.used), "short_circuit": !frame.used,
            "decision": u32::from(self.force_serial),
        }));
        u32::from(self.force_serial)
    }

    fn advance(&mut self, token: u64) -> u32 {
        let active = self.active.clone();
        let valid = match (&active, self.frames.last_mut()) {
            (Some((owner, active_token)), Some(frame)) if *active_token == token => frame.consume(token, owner),
            _ => false,
        };
        if !valid {
            self.fail("Next token is repeated, stale, wrong owner or wrong scope");
            return cm_abi::FAILED;
        }
        let frame_index = self.frames.len() - 1;
        let index = self.frames[frame_index].next_index;
        self.trace("hook-next", &active.unwrap().0, json!({"token": token, "count": 1}));
        let decision = self.body(index);
        self.frames[frame_index].downstream = decision;
        self.boundary();
        if self.fatal.is_some() { cm_abi::FAILED }
            else if self.cancelled_seen { v2::CANCELLED } else { cm_abi::OK }
    }

    fn run(mut self) -> Result<u32, PolicyError> {
        if !self.boundary() {
            return self.finish();
        }
        for key in self.registration.plan.phases["before"].clone() {
            if !self.boundary() { break; }
            self.callback(&key, 0);
        }
        self.body(0);
        // Legacy filters are outside the v2 body and cannot be skipped by around.
        for key in self.registration.plan.phases["legacy_filter"].clone() {
            if !self.boundary() { break; }
            self.trace("hook-enter", &key, json!({}));
            match self.registration.legacy(&key, self.input) {
                Ok(decision) => self.force_serial |= decision == FORCE_SERIAL,
                Err(error) => self.latch(error),
            }
            self.boundary();
            self.trace("hook-exit", &key, json!({"decision": u32::from(self.force_serial)}));
        }
        // Once a chain started, every after observer is attempted, preserving first fatal.
        for key in self.registration.plan.phases["after"].clone() {
            self.boundary();
            self.callback(&key, 0);
        }
        self.finish()
    }

    fn finish(self) -> Result<u32, PolicyError> {
        if let Some(error) = self.fatal {
            event("policy-failed", json!({"call_id": self.detail["call_id"], "error": error}));
            Err(PolicyError::Failed(error.to_string()))
        } else if self.cancelled_seen {
            event("policy-cancelled", json!({"call_id": self.detail["call_id"], "boundary": "callback-chain"}));
            Err(PolicyError::Cancelled)
        } else { Ok(u32::from(self.force_serial)) }
    }
}

unsafe fn next_buffers(output: *mut v2::Decision, error: *mut cm_abi::ErrorBuffer) -> bool {
    if output.is_null() || error.is_null()
        || !(output as usize).is_multiple_of(std::mem::align_of::<v2::Decision>())
        || !(error as usize).is_multiple_of(std::mem::align_of::<cm_abi::ErrorBuffer>())
    { return false; }
    let value = unsafe { &*output };
    let error = unsafe { &*error };
    value.header.struct_size == std::mem::size_of::<v2::Decision>() as u32
        && value.header.major == 2 && value.header.minor == 0 && value.reserved == 0
        && !error.data.is_null() && error.capacity == cm_abi::ERROR_CAPACITY as u64
        && error.len <= error.capacity
}

/// The only native-to-Host reentry allowed; it never locks the Runtime again.
pub(crate) unsafe extern "C" fn next(
    token: u64,
    output: *mut v2::Decision,
    error: *mut cm_abi::ErrorBuffer,
) -> u32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pointer = DISPATCH.with(Cell::get);
        if pointer.is_null() {
            NEXT_VIOLATION.store(true, Ordering::Release);
            event("next-rejected", json!({"token": token, "reason": "no active dispatch on this OS thread"}));
            return cm_abi::FAILED;
        }
        // The scope guard installs this pointer only during synchronous callback execution.
        let dispatch = unsafe { &mut *pointer.cast::<Dispatch<'_>>() };
        if !unsafe { next_buffers(output, error) } {
            dispatch.fail("invalid Next output/error buffer");
            return cm_abi::FAILED;
        }
        let status = dispatch.advance(token);
        unsafe {
            (*output).decision = u32::from(dispatch.force_serial);
            (*error).len = 0;
            if status == cm_abi::FAILED {
                let message = b"controlled Next failed; Host fatal latch retained";
                std::ptr::copy_nonoverlapping(message.as_ptr(), (*error).data, message.len());
                (*error).len = message.len() as u64;
            }
        }
        status
    }));
    result.unwrap_or_else(|_| {
        NEXT_VIOLATION.store(true, Ordering::Release);
        cm_abi::FAILED
    })
}

pub fn evaluate(
    context: Context<'_>,
    original: bool,
    cancelled: impl Fn() -> bool,
) -> Result<ToolDecision, PolicyError> {
    if cancelled() { return Err(PolicyError::Cancelled); }
    let _call = NativeCall::enter().map_err(PolicyError::Failed)?;
    let runtime = RUNTIME.get().ok_or_else(|| PolicyError::Failed(
        "Core entry must explicitly initialize the CM runtime before tool dispatch".into()))?
        .as_ref().map_err(|e| PolicyError::Failed(e.to_string()))?;
    let mut state = runtime.state.lock().map_err(|_| PolicyError::Failed("poisoned CM runtime".into()))?;
    if runtime.stopping.load(Ordering::Acquire) || state.stopping || state.failed.is_some() {
        return Err(PolicyError::Failed("CM runtime is stopping or failed".into()));
    }
    let registration = state.registration.as_ref().expect("ready collection");
    if registration.len() != 0 {
        for (value, limit) in [
            (context.namespace, 128), (context.tool, 128), (context.call_id, 512),
            (context.thread_id, 128), (context.turn_id, 128),
        ] {
            if value.len() > limit {
                return Err(PolicyError::Failed("policy input exceeds ABI field limit".into()));
            }
        }
    }
    if cancelled() { return Err(PolicyError::Cancelled); }
    let input = PolicyInput {
        header: Header::of::<PolicyInput>(),
        namespace: Bytes::borrowed(context.namespace), tool: Bytes::borrowed(context.tool),
        call_id: Bytes::borrowed(context.call_id), thread_id: Bytes::borrowed(context.thread_id),
        turn_id: Bytes::borrowed(context.turn_id), original_parallel: u32::from(original), reserved: 0,
    };
    let detail = json!({
        "namespace": context.namespace, "tool": context.tool, "call_id": context.call_id,
        "thread_id": context.thread_id, "turn_id": context.turn_id,
    });
    let decision = Dispatch {
        registration, input: &input, detail: &detail, cancelled: &cancelled,
        frames: Vec::new(), active: None, fatal: None, cancelled_seen: false, force_serial: false,
    }.run();
    let decision = match decision {
        Ok(decision) => decision,
        Err(error) => {
            if let PolicyError::Failed(message) = &error { state.failed = Some(message.clone()); }
            return Err(error);
        }
    };
    let supports_parallel = original && decision != FORCE_SERIAL;
    let mut detail = detail;
    detail.as_object_mut().unwrap().extend(json!({
        "original_parallel": original, "decision": decision, "final_parallel": supports_parallel,
        "guard": if supports_parallel { "read" } else { "write" },
        "mod_loaded": registration.len() != 0, "plan_sha256": registration.digest,
    }).as_object().unwrap().clone());
    event("policy-decision", detail.clone());
    state.active_tools += 1;
    Ok(ToolDecision { supports_parallel, detail, runtime })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_frame_binds_owner_generation_and_single_use() {
        let mut frame = Frame { token: 42, owner: "a::around".into(), next_index: 0, used: false, downstream: KEEP };
        assert!(!frame.consume(0, "a::around"));
        assert!(!frame.consume(41, "a::around"));
        assert!(!frame.consume(42, "b::around"));
        assert!(frame.consume(42, "a::around"));
        assert!(!frame.consume(42, "a::around"));
    }

    #[test]
    fn empty_runtime_preserves_core_inputs_and_stops_admission() {
        let context = || Context {
            namespace: "functions", tool: "exec_command", call_id: "default-call",
            thread_id: "default-thread", turn_id: "default-turn",
        };
        assert!(evaluate(context(), true, || false).is_err());
        let home = std::env::temp_dir().join(format!("cm-empty-runtime-{}", std::process::id()));
        let guard = crate::initialize(&home, true).unwrap();
        for original in [false, true] {
            let decision = evaluate(context(), original, || false).unwrap();
            assert_eq!(decision.supports_parallel, original);
            drop(decision);
        }
        assert!(matches!(evaluate(context(), true, || true), Err(PolicyError::Cancelled)));
        guard.finish().unwrap();
        assert!(evaluate(context(), true, || false).is_err());
        assert!(crate::initialize(&home, true).is_err(), "shutdown is terminal");
    }
}
