//! Synchronous narrowing policy for the initial exec_command output only.
use std::mem::size_of;
use std::sync::atomic::Ordering;

use cm_abi::Bytes;
use cm_abi::v21;
use serde_json::json;

use crate::LoadError;
use crate::NativeCall;
use crate::RUNTIME;
use crate::event;
use crate::tool_policy::Context;
use crate::tool_policy::NEXT_VIOLATION;
use crate::tool_policy::PolicyError;

pub(crate) fn validate(output: &v21::Output, original: u64) -> Result<(), LoadError> {
    if output.header.struct_size != size_of::<v21::Output>() as u32
        || output.header.major != 2
        || output.header.minor != 1
        || output.reserved != 0
        || !match output.decision {
            v21::KEEP => output.limit == 0,
            v21::LIMIT => output.limit != 0 && output.limit <= original,
            _ => false,
        }
    {
        return Err(LoadError::native(
            "output_limit",
            "invalid output decision/header/bounds",
        ));
    }
    Ok(())
}

/// None is KEEP: the caller retains its original Option, including Some(0).
pub fn evaluate(
    context: Context<'_>,
    original: u64,
    cancelled: impl Fn() -> bool,
) -> Result<Option<u64>, PolicyError> {
    if cancelled() {
        return Err(PolicyError::Cancelled);
    }
    let _call = NativeCall::enter().map_err(PolicyError::Failed)?;
    let runtime = RUNTIME
        .get()
        .ok_or_else(|| PolicyError::Failed("CM runtime not initialized".into()))?
        .as_ref()
        .map_err(|error| PolicyError::Failed(error.to_string()))?;
    let mut state = runtime
        .state
        .lock()
        .map_err(|_| PolicyError::Failed("poisoned CM runtime".into()))?;
    if runtime.stopping.load(Ordering::Acquire) || state.stopping || state.failed.is_some() {
        return Err(PolicyError::Failed(
            "CM runtime is stopping or failed".into(),
        ));
    }
    let registration = state.registration.as_ref().expect("ready collection");
    let result = (|| {
        let mut limit = None;
        if let Some(keys) = registration.plan.phases.get("output_limit") {
            for (value, maximum) in [
                (context.namespace, 128),
                (context.tool, 128),
                (context.call_id, 512),
                (context.thread_id, 128),
                (context.turn_id, 128),
            ] {
                if value.len() > maximum {
                    return Err(PolicyError::Failed(
                        "output-limit identity exceeds ABI field limit".into(),
                    ));
                }
            }
            let input = v21::Input {
                header: v21::header::<v21::Input>(),
                namespace: Bytes::borrowed(context.namespace),
                tool: Bytes::borrowed(context.tool),
                call_id: Bytes::borrowed(context.call_id),
                thread_id: Bytes::borrowed(context.thread_id),
                turn_id: Bytes::borrowed(context.turn_id),
                original_limit: original,
                reserved: 0,
            };
            for key in keys {
                if cancelled() {
                    return Err(PolicyError::Cancelled);
                }
                let binding = &registration.bindings[key];
                let detail = json!({
                    "mod": binding.owner, "contribution": binding.local_id,
                    "resource": v21::CAPABILITY, "call_id": context.call_id,
                    "thread_id": context.thread_id, "turn_id": context.turn_id,
                    "original_limit": original, "plan_sha256": registration.digest,
                });
                event("output-limit-enter", detail.clone());
                let result = registration.limit(key, &input);
                let observed_cancel = cancelled();
                let (output, reported_cancel) = result.map_err(|error| {
                    event(
                        "output-limit-failed",
                        json!({"context":detail,"error":error}),
                    );
                    PolicyError::Failed(error.to_string())
                })?;
                if NEXT_VIOLATION.load(Ordering::Acquire) || (reported_cancel && !observed_cancel) {
                    let mut error = LoadError::native(
                        "output_limit",
                        "invalid Next or unobserved cancellation",
                    )
                    .owner(&binding.owner, Some(&binding.local_id));
                    error.resource = Some(v21::CAPABILITY.into());
                    event(
                        "output-limit-failed",
                        json!({"context":detail,"error":error}),
                    );
                    return Err(PolicyError::Failed(error.to_string()));
                }
                event(
                    "output-limit-exit",
                    json!({"context": detail, "decision": output.decision,
                        "limit": output.limit, "cancelled": observed_cancel}),
                );
                if observed_cancel {
                    return Err(PolicyError::Cancelled);
                }
                if output.decision == v21::LIMIT {
                    limit = Some(
                        limit.map_or(output.limit, |previous: u64| previous.min(output.limit)),
                    );
                }
            }
        }
        if cancelled() {
            return Err(PolicyError::Cancelled);
        }
        event(
            "output-limit-decision",
            json!({"call_id": context.call_id, "thread_id": context.thread_id,
                "turn_id": context.turn_id, "tool": context.tool, "original_limit": original,
                "limit": limit, "plan_sha256": registration.digest}),
        );
        Ok(limit)
    })();
    if let Err(PolicyError::Failed(message)) = &result {
        state.failed = Some(message.clone());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_narrowing_and_zero_only_allows_keep() {
        let mut value = v21::Output {
            header: v21::header::<v21::Output>(),
            decision: v21::KEEP,
            limit: 0,
            reserved: 0,
        };
        for original in [0, 1, 10, u64::MAX] {
            assert!(validate(&value, original).is_ok());
        }
        value.decision = v21::LIMIT;
        for original in [0, 1, 10] {
            assert!(validate(&value, original).is_err());
        }
        value.limit = 1;
        assert!(validate(&value, 0).is_err());
        assert!(validate(&value, 1).is_ok());
        value.limit = u64::MAX;
        assert!(validate(&value, 10).is_err());
        assert!(validate(&value, u64::MAX).is_ok());
        value.decision = 2;
        assert!(validate(&value, u64::MAX).is_err());
        value.decision = v21::KEEP;
        assert!(validate(&value, u64::MAX).is_err());
        value.limit = 0;
        value.reserved = 1;
        assert!(validate(&value, 10).is_err());
        value.reserved = 0;
        value.header.minor = 0;
        assert!(validate(&value, 10).is_err());
        value.header = v21::header::<v21::Output>();
        value.header.struct_size -= 1;
        assert!(validate(&value, 10).is_err());
    }

    #[test]
    fn cancellation_prevents_native_dispatch_before_runtime_lookup() {
        let context = Context {
            namespace: "functions",
            tool: "exec_command",
            call_id: "cancelled",
            thread_id: "thread",
            turn_id: "turn",
        };
        assert!(matches!(
            evaluate(context, 10, || true),
            Err(PolicyError::Cancelled)
        ));
    }
}
