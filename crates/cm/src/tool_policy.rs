use cm_abi::Bytes;
use cm_abi::FORCE_SERIAL;
use cm_abi::Header;
use cm_abi::KEEP;
use cm_abi::PolicyInput;
use serde_json::Value;
use serde_json::json;

use crate::NativeCall;
use crate::RUNTIME;
use crate::Runtime;
use crate::event;

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
    pub fn record(&self, kind: &str) {
        event(kind, self.detail.clone());
    }
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

pub fn evaluate(
    context: Context<'_>,
    original: bool,
    cancelled: impl Fn() -> bool,
) -> Result<ToolDecision, PolicyError> {
    if cancelled() {
        return Err(PolicyError::Cancelled);
    }
    let _call = NativeCall::enter().map_err(PolicyError::Failed)?;
    let runtime = RUNTIME
        .get()
        .ok_or_else(|| {
            PolicyError::Failed(
                "Core entry must explicitly initialize the CM runtime before tool dispatch".into(),
            )
        })?
        .as_ref()
        .map_err(|e| PolicyError::Failed(e.to_string()))?;
    let mut state = runtime
        .state
        .lock()
        .map_err(|_| PolicyError::Failed("poisoned CM runtime".into()))?;
    if runtime.stopping.load(std::sync::atomic::Ordering::Acquire)
        || state.stopping
        || state.failed.is_some()
    {
        return Err(PolicyError::Failed(
            "CM runtime is stopping or failed".into(),
        ));
    }
    if state.registration.is_some() {
        for (value, limit) in [
            (context.namespace, 128),
            (context.tool, 128),
            (context.call_id, 512),
            (context.thread_id, 128),
            (context.turn_id, 128),
        ] {
            if value.len() > limit {
                return Err(PolicyError::Failed(
                    "policy input exceeds ABI field limit".into(),
                ));
            }
        }
    }
    // Cancellation may have arrived while another native callback held this mutex.
    if cancelled() {
        return Err(PolicyError::Cancelled);
    }
    let input = PolicyInput {
        header: Header::of::<PolicyInput>(),
        namespace: Bytes::borrowed(context.namespace),
        tool: Bytes::borrowed(context.tool),
        call_id: Bytes::borrowed(context.call_id),
        thread_id: Bytes::borrowed(context.thread_id),
        turn_id: Bytes::borrowed(context.turn_id),
        original_parallel: u32::from(original),
        reserved: 0,
    };
    let decision = match &state.registration {
        None => KEEP,
        Some(registration) => match registration.policy(&input) {
            Ok(value) => value,
            Err(error) => {
                event(
                    "policy-failed",
                    json!({"call_id": context.call_id, "error": error}),
                );
                state.failed = Some(error.to_string());
                return Err(PolicyError::Failed(error.to_string()));
            }
        },
    };
    if cancelled() {
        event(
            "policy-cancelled",
            json!({"call_id": context.call_id, "boundary": "after-callback"}),
        );
        return Err(PolicyError::Cancelled);
    }
    let supports_parallel = original && decision != FORCE_SERIAL;
    let detail = json!({
        "namespace": context.namespace, "tool": context.tool, "call_id": context.call_id,
        "thread_id": context.thread_id, "turn_id": context.turn_id,
        "original_parallel": original, "decision": decision, "final_parallel": supports_parallel,
        "guard": if supports_parallel { "read" } else { "write" },
        "mod_loaded": state.registration.is_some(),
    });
    event("policy-decision", detail.clone());
    state.active_tools += 1;
    Ok(ToolDecision {
        supports_parallel,
        detail,
        runtime,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_runtime_preserves_core_inputs_and_stops_admission() {
        let context = || super::Context {
            namespace: "functions",
            tool: "exec_command",
            call_id: "default-call",
            thread_id: "default-thread",
            turn_id: "default-turn",
        };
        assert!(super::evaluate(context(), true, || false).is_err());
        let home = std::env::temp_dir().join(format!("cm-empty-runtime-{}", std::process::id()));
        let guard = crate::initialize(&home, true).unwrap();
        for original in [false, true] {
            let decision = super::evaluate(context(), original, || false).unwrap();
            assert_eq!(decision.supports_parallel, original);
            drop(decision);
        }
        assert!(matches!(
            super::evaluate(context(), true, || true),
            Err(super::PolicyError::Cancelled)
        ));
        guard.finish().unwrap();
        assert!(super::evaluate(context(), true, || false).is_err());
        assert!(
            crate::initialize(&home, true).is_err(),
            "shutdown is terminal"
        );
    }
}
