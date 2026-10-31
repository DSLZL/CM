//! Turn-local leaf capacity. No scheduler or Rust object crosses the Mod ABI.
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};

use cm_abi::v22;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::runtime::{self, Contribution, Kind, Scope};
use crate::sampling_budget::TurnScope;
use crate::{LoadError, event};

/// Inserted by Core before opening this actual turn's extension scope.
pub struct RequestedLimit(pub Option<u32>);

pub fn validate(limit: Option<u32>) -> Result<(), LoadError> {
    if limit.is_some_and(|value| !(1..=v22::MAX_TOOL_CONCURRENCY).contains(&value)) {
        return Err(error("tool concurrency must be an integer in 1..=1024"));
    }
    Ok(())
}

fn error(message: &str) -> LoadError {
    let mut error = LoadError::native("tool_concurrency", message);
    error.resource = Some(v22::TOOL_CONCURRENCY_CAPABILITY.into());
    error
}

/// Explicit requests cannot silently fall back to the Host default.
pub fn require_provider(limit: Option<u32>) -> Result<(), LoadError> {
    validate(limit)?;
    if limit.is_some() && provider()?.is_none() {
        return Err(error(
            "cmToolConcurrency requires an enabled tool-concurrency provider",
        ));
    }
    Ok(())
}

fn provider() -> Result<Option<Contribution>, LoadError> {
    let mut providers = runtime::contributions()?
        .into_iter()
        .filter(|item| item.kind == Kind::ToolConcurrency);
    let provider = providers.next();
    if providers.next().is_some() {
        return Err(error("multiple tool-concurrency providers"));
    }
    Ok(provider)
}

pub fn provider_enabled() -> Result<bool, LoadError> {
    provider().map(|provider| provider.is_some())
}

pub fn validate_backend(
    version: u32,
    build_id: &str,
    capability: &str,
    enabled: bool,
) -> Result<(), LoadError> {
    if version != 1
        || build_id != crate::runtime_plan::embedded_build_id()?
        || capability != v22::TOOL_CONCURRENCY_CAPABILITY
        || !enabled
    {
        return Err(error(
            "backend identity/capability/provider does not support cmToolConcurrency",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    limit: Option<u32>,
}

fn parse_policy(bytes: &[u8], requested: Option<u32>) -> Result<Option<u32>, LoadError> {
    // Option fields otherwise accept omission, which is not the versioned wire contract.
    let value: Value = serde_json::from_slice(bytes).map_err(|_| error("invalid policy JSON"))?;
    if !value
        .as_object()
        .is_some_and(|object| object.contains_key("limit"))
    {
        return Err(error("policy must contain limit"));
    }
    let policy: Policy = serde_json::from_slice(bytes).map_err(|_| error("invalid policy fields"))?;
    validate(policy.limit)?;
    if policy.version != 1 || policy.limit != requested {
        return Err(error(
            "policy version/limit differs from the admitted turn request",
        ));
    }
    Ok(policy.limit)
}

#[derive(Default)]
struct State {
    requested: Option<Option<u32>>,
    initializing: bool,
    policy: Option<Result<Option<Arc<Semaphore>>, LoadError>>,
    closed: bool,
    waiters: Vec<Waker>,
    leases: BTreeMap<String, Weak<Mutex<Option<Acquired>>>>,
}

#[derive(Default)]
pub(crate) struct Gate(Mutex<State>);

impl Gate {
    pub(crate) fn native_lease(&self, call_id: &str) -> Result<Option<Lease>, LoadError> {
        let state = self.0.lock().map_err(|_| error("poisoned turn gate"))?;
        Ok(state.leases.get(call_id).and_then(Weak::upgrade).map(Lease))
    }

    pub(crate) fn retain(&self, call_id: &str, lease: &Lease) -> Result<(), LoadError> {
        let mut state = self.0.lock().map_err(|_| error("poisoned turn gate"))?;
        if state.closed {
            return Err(error("actual turn scope is closed"));
        }
        state.leases.retain(|_, lease| lease.strong_count() != 0);
        if state.leases.len() >= v22::MAX_REQUESTS || state.leases.contains_key(call_id) {
            return Err(error("duplicate or excessive active invocation"));
        }
        state.leases.insert(call_id.into(), Arc::downgrade(&lease.0));
        Ok(())
    }

    pub(crate) fn bind(&self, requested: Option<u32>) -> Result<(), LoadError> {
        validate(requested)?;
        let mut state = self.0.lock().map_err(|_| error("poisoned turn gate"))?;
        if state.closed || state.requested.is_some_and(|bound| bound != requested) {
            return Err(error("turn gate closed or already bound to another request"));
        }
        state.requested = Some(requested);
        Ok(())
    }

    pub(crate) fn close(&self) -> Result<(), LoadError> {
        let waiters = {
            let mut state = self.0.lock().map_err(|_| error("poisoned turn gate"))?;
            state.closed = true;
            if let Some(Ok(Some(semaphore))) = &state.policy {
                semaphore.close();
            }
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
        Ok(())
    }

    pub(crate) fn check(&self) -> Result<(), LoadError> {
        if self.0.lock().map_err(|_| error("poisoned turn gate"))?.closed {
            return Err(error("actual turn scope is closed"));
        }
        Ok(())
    }

    pub(crate) async fn prepare(
        &self,
        scope: &Scope,
        provider: Contribution,
    ) -> Result<Prepared, LoadError> {
        let initialize = poll_fn(|cx| {
            let mut state = match self.0.lock() {
                Ok(state) => state,
                Err(_) => return Poll::Ready(Err(error("poisoned turn gate"))),
            };
            if state.closed {
                return Poll::Ready(Err(error("actual turn scope is closed")));
            }
            let Some(requested) = state.requested else {
                return Poll::Ready(Err(error("typed turn concurrency request is missing")));
            };
            if state.policy.is_some() {
                return Poll::Ready(Ok(None));
            }
            if !state.initializing {
                state.initializing = true;
                return Poll::Ready(Ok(Some(requested)));
            }
            if !state.waiters.iter().any(|waiter| waiter.will_wake(cx.waker())) {
                if state.waiters.len() >= v22::MAX_REQUESTS {
                    return Poll::Ready(Err(error("too many policy waiters")));
                }
                state.waiters.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await?;
        if let Some(requested) = initialize {
            let initializer = Initializer(self);
            let input = json!({"version":1,"requested_limit":requested}).to_string();
            let result = async {
                let bytes = runtime::dispatch(
                    scope,
                    &provider,
                    v22::TOOL_CONCURRENCY,
                    input.as_bytes(),
                    "",
                )?
                .await?;
                parse_policy(&bytes, requested)
                    .map(|limit| limit.map(|limit| Arc::new(Semaphore::new(limit as usize))))
            }
            .await;
            initializer.finish(result)?;
        }
        let (semaphore, limit) = {
            let state = self.0.lock().map_err(|_| error("poisoned turn gate"))?;
            if state.closed {
                return Err(error("actual turn scope is closed"));
            }
            let semaphore = state
                .policy
                .as_ref()
                .ok_or_else(|| error("policy was not initialized"))?
                .as_ref()
                .map_err(Clone::clone)?
                .clone();
            (semaphore, state.requested.flatten())
        };
        let (thread, turn, handle) = scope.identity(provider.instance)?;
        Ok(Prepared {
            scope: scope.clone(),
            semaphore,
            detail: json!({"thread":thread,"turn":turn,"turn_handle":handle,
                "mod":provider.owner,"limit":limit}),
        })
    }
}

struct Initializer<'a>(&'a Gate);

impl Initializer<'_> {
    fn finish(self, result: Result<Option<Arc<Semaphore>>, LoadError>) -> Result<(), LoadError> {
        let waiters = {
            let mut state = self.0.0.lock().map_err(|_| error("poisoned turn gate"))?;
            if state.closed
                && let Ok(Some(semaphore)) = &result
            {
                semaphore.close();
            }
            state.policy = Some(result);
            state.initializing = false;
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
        Ok(())
    }
}

impl Drop for Initializer<'_> {
    fn drop(&mut self) {
        let waiters = if let Ok(mut state) = self.0.0.lock() {
            if state.initializing {
                state.policy = Some(Err(error(
                    "policy initialization cancelled; this turn cannot restart it",
                )));
                state.initializing = false;
            }
            std::mem::take(&mut state.waiters)
        } else {
            Vec::new()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

/// Must be called before the original runtime read/write gate.
pub async fn prepare(
    level: &str,
    turn: Option<&TurnScope>,
    call_id: &str,
    source: &str,
    runtime_id: &str,
) -> Result<Option<Prepared>, LoadError> {
    runtime::check_level(level)?;
    let Some(provider) = provider()? else {
        return Ok(None);
    };
    let scope = turn
        .ok_or_else(|| error("actual typed turn scope is missing"))?
        .0
        .as_ref()
        .map_err(Clone::clone)?;
    let mut prepared = scope.prepare_tool_concurrency(provider).await?;
    prepared.detail["call_id"] = json!(call_id);
    prepared.detail["source"] = json!(source);
    prepared.detail["runtime"] = json!(runtime_id);
    Ok(Some(prepared))
}

pub struct Prepared {
    scope: Scope,
    semaphore: Option<Arc<Semaphore>>,
    detail: Value,
}

impl Prepared {
    pub async fn acquire(self, lease: &Lease) -> Result<(), LoadError> {
        event("tool-concurrency-wait", self.detail.clone());
        let permit = match self.semaphore {
            Some(semaphore) => Some(
                semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| error("actual turn gate closed while waiting"))?,
            ),
            None => None,
        };
        self.scope.check_tool_concurrency()?;
        let mut slot = lease.0.lock().map_err(|_| error("poisoned invocation lease"))?;
        if slot.is_some() {
            return Err(error("invocation acquired twice"));
        }
        let call_id = self.detail["call_id"]
            .as_str()
            .ok_or_else(|| error("missing invocation identity"))?;
        self.scope.retain_tool_lease(call_id, lease)?;
        event("tool-concurrency-acquired", self.detail.clone());
        *slot = Some(Acquired {
            _permit: permit,
            _scope: self.scope,
            detail: self.detail,
        });
        Ok(())
    }
}

/// Both dispatch and result handoff own a clone, so either one can outlive cancellation.
#[derive(Clone, Default)]
pub struct Lease(Arc<Mutex<Option<Acquired>>>);

struct Acquired {
    _permit: Option<OwnedSemaphorePermit>,
    _scope: Scope,
    detail: Value,
}

impl Drop for Acquired {
    fn drop(&mut self) {
        event("tool-concurrency-released", self.detail.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy_and_input_bounds() {
        for value in [0, 1025, u32::MAX] {
            assert!(validate(Some(value)).is_err());
        }
        for value in [None, Some(1), Some(1024)] {
            assert!(validate(value).is_ok());
            let bytes = json!({"version":1,"limit":value}).to_string();
            assert_eq!(parse_policy(bytes.as_bytes(), value).unwrap(), value);
        }
        for bytes in [
            r#"{}"#,
            r#"{"version":1}"#,
            r#"{"version":2,"limit":1}"#,
            r#"{"version":1,"limit":1,"extra":true}"#,
            r#"{"version":1,"limit":1.0}"#,
            r#"{"version":1,"limit":-1}"#,
            r#"{"version":1,"limit":4294967296}"#,
            r#"{"version":1,"limit":1,"limit":1}"#,
            r#"{"version":1,"limit":null}"#,
        ] {
            assert!(parse_policy(bytes.as_bytes(), Some(1)).is_err(), "{bytes}");
        }
    }

    #[test]
    fn close_is_terminal_and_cannot_rebind() {
        let gate = Gate::default();
        gate.bind(Some(1)).unwrap();
        gate.bind(Some(1)).unwrap();
        assert!(gate.bind(Some(2)).is_err());
        gate.close().unwrap();
        assert!(gate.check().is_err());
        assert!(gate.bind(Some(1)).is_err());
    }

    #[test]
    fn cancelled_initializer_does_not_restart() {
        let gate = Gate::default();
        gate.bind(Some(1)).unwrap();
        gate.0.lock().unwrap().initializing = true;
        drop(Initializer(&gate));
        assert!(gate.0.lock().unwrap().policy.as_ref().unwrap().is_err());
    }

    #[test]
    fn close_wakes_a_pending_semaphore_waiter_without_releasing_running_slots() {
        use std::future::Future;
        use std::task::Context;

        let semaphore = Arc::new(Semaphore::new(1));
        let running = semaphore.clone().try_acquire_owned().unwrap();
        let mut waiting = Box::pin(semaphore.clone().acquire_owned());
        let mut context = Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        let gate = Gate::default();
        gate.bind(Some(1)).unwrap();
        gate.0.lock().unwrap().policy = Some(Ok(Some(semaphore.clone())));
        gate.close().unwrap();
        assert!(matches!(
            waiting.as_mut().poll(&mut context),
            Poll::Ready(Err(_))
        ));
        assert_eq!(semaphore.available_permits(), 0);
        drop(running);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[test]
    fn a_policy_finishing_after_close_cannot_reopen_the_semaphore() {
        let gate = Gate::default();
        gate.bind(Some(1)).unwrap();
        gate.0.lock().unwrap().initializing = true;
        gate.close().unwrap();
        let semaphore = Arc::new(Semaphore::new(1));
        Initializer(&gate)
            .finish(Ok(Some(semaphore.clone())))
            .unwrap();
        assert!(semaphore.is_closed());
        assert!(gate.check().is_err());
        assert!(!gate.0.lock().unwrap().initializing);
    }

    #[test]
    fn backend_is_bound_to_this_build_and_an_enabled_provider() {
        let id = crate::runtime_plan::embedded_build_id().unwrap();
        let cap = v22::TOOL_CONCURRENCY_CAPABILITY;
        assert!(validate_backend(1, &id, cap, true).is_ok());
        for (version, build, capability, enabled) in [
            (0, id.as_str(), cap, true),
            (1, "wrong-build", cap, true),
            (1, id.as_str(), "wrong-capability", true),
            (1, id.as_str(), cap, false),
        ] {
            assert!(validate_backend(version, build, capability, enabled).is_err());
        }
    }
}
