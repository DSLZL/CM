//! Main logical sampling admission. The Host owns the ledger; the Mod supplies policy.
use std::future::poll_fn;
use std::sync::Mutex;
use std::task::{Poll, Waker};

use cm_abi::v22;
use serde::Deserialize;
use serde_json::json;

use crate::runtime::{self, Contribution, Kind, Scope};
use crate::{LoadError, event};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    max_main_samples: u32,
    session_sources: Vec<String>,
    request_kinds: Vec<String>,
}

impl Policy {
    fn parse(bytes: &[u8]) -> Result<Option<Self>, LoadError> {
        let policy: Option<Self> = serde_json::from_slice(bytes)
            .map_err(|_| error("sampling_budget_policy", "invalid policy JSON"))?;
        if let Some(policy) = &policy
            && (policy.max_main_samples == 0
                || !valid_labels(&policy.session_sources, &["cli", "vscode", "exec"])
                || !valid_labels(&policy.request_kinds, &["turn"]))
        {
            return Err(error("sampling_budget_policy", "invalid policy fields"));
        }
        Ok(policy)
    }

    fn matches(&self, source: &str, request_kind: &str) -> bool {
        self.session_sources.iter().any(|label| label == source)
            && self.request_kinds.iter().any(|label| label == request_kind)
    }
}

fn valid_labels(labels: &[String], allowed: &[&str]) -> bool {
    !labels.is_empty()
        && labels.len() <= allowed.len()
        && labels.iter().enumerate().all(|(index, label)| {
            allowed.contains(&label.as_str()) && !labels[..index].contains(label)
        })
}

fn error(code: &str, message: &str) -> LoadError {
    LoadError::native(code, message)
}

#[derive(Default)]
struct State {
    initializing: bool,
    policy: Option<Result<Option<Policy>, LoadError>>,
    used: u32,
    closed: bool,
    waiters: Vec<Waker>,
}

#[derive(Default)]
pub(crate) struct Gate(Mutex<State>);

impl Gate {
    pub(crate) fn close(&self) -> Result<(), LoadError> {
        let waiters = {
            let mut state = self
                .0
                .lock()
                .map_err(|_| error("sampling_budget", "poisoned budget state"))?;
            state.closed = true;
            std::mem::take(&mut state.waiters)
        };
        for waker in waiters {
            waker.wake();
        }
        Ok(())
    }

    async fn initialize(&self, scope: &Scope, provider: &Contribution) -> Result<(), LoadError> {
        let initialize = poll_fn(|cx| {
            let mut state = match self.0.lock() {
                Ok(state) => state,
                Err(_) => {
                    return Poll::Ready(Err(error("sampling_budget", "poisoned budget state")));
                }
            };
            if state.closed {
                return Poll::Ready(Err(error("sampling_budget", "turn scope closed")));
            }
            if state.policy.is_some() {
                return Poll::Ready(Ok(false));
            }
            if !state.initializing {
                state.initializing = true;
                return Poll::Ready(Ok(true));
            }
            if !state
                .waiters
                .iter()
                .any(|waker| waker.will_wake(cx.waker()))
            {
                if state.waiters.len() >= v22::MAX_REQUESTS {
                    return Poll::Ready(Err(error("sampling_budget", "admission waiter limit")));
                }
                state.waiters.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await?;
        if initialize {
            // Dropping the initializing future must wake every concurrent admission.
            let guard = Initializer(self);
            let result = async {
                let output = runtime::dispatch(
                    scope,
                    provider,
                    v22::SAMPLING_BUDGET,
                    br#"{"request_kind":"turn","policy_version":1}"#,
                    "",
                )?
                .await?;
                Policy::parse(&output)
            }
            .await;
            guard.finish(result)?;
        }
        Ok(())
    }

    fn charge(
        &self,
        source: &str,
        request_kind: &str,
        cancelled: impl Fn() -> bool,
    ) -> Result<Option<(u32, u32)>, LoadError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| error("sampling_budget", "poisoned budget state"))?;
        if state.closed {
            return Err(error("sampling_budget", "turn scope closed"));
        }
        if cancelled() {
            return Err(error(
                "sampling_budget_cancelled",
                "sampling admission cancelled",
            ));
        }
        let policy = state
            .policy
            .as_ref()
            .ok_or_else(|| error("sampling_budget", "policy not initialized"))?
            .as_ref()
            .map_err(Clone::clone)?;
        let Some(policy) = policy else {
            return Ok(None);
        };
        if !policy.matches(source, request_kind) {
            return Ok(None);
        }
        let limit = policy.max_main_samples;
        if state.used >= limit {
            return Err(error(
                "sampling_budget_exhausted",
                "main sampling limit reached for this runtime turn",
            ));
        }
        state.used = state
            .used
            .checked_add(1)
            .ok_or_else(|| error("sampling_budget", "sampling count overflow"))?;
        Ok(Some((state.used, limit)))
    }

    pub(crate) async fn admit(
        &self,
        scope: &Scope,
        source: &str,
        request_kind: &str,
        cancelled: impl Fn() -> bool,
    ) -> Result<(), LoadError> {
        if cancelled() {
            return Err(error(
                "sampling_budget_cancelled",
                "sampling admission cancelled",
            ));
        }
        let providers: Vec<_> = runtime::contributions()?
            .into_iter()
            .filter(|contribution| contribution.kind == Kind::SamplingBudget)
            .collect();
        let Some(provider) = providers.first() else {
            return Ok(());
        };
        if providers.len() != 1 {
            return Err(error(
                "sampling_budget",
                "multiple sampling budget providers",
            ));
        }
        let result = self
            .initialize(scope, provider)
            .await
            .and_then(|()| self.charge(source, request_kind, cancelled))
            .map_err(|error| {
                let mut error = error.owner(&provider.owner, Some(&provider.id));
                error.resource = Some(v22::SAMPLING_BUDGET_CAPABILITY.into());
                error
            });
        let (thread, turn, turn_handle) = scope.identity(provider.instance)?;
        let detail = match &result {
            Ok(Some((used, limit))) => json!({"used":used, "limit":limit, "charged":true}),
            Ok(None) => json!({"charged":false}),
            Err(error) => json!({"charged":false, "error":error}),
        };
        event(
            "sampling-budget-admission",
            json!({"thread":thread, "turn":turn, "turn_handle":turn_handle, "source":source,
                "request_kind":request_kind, "mod":provider.owner, "detail":detail}),
        );
        result.map(|_| ())
    }
}

struct Initializer<'a>(&'a Gate);

impl Initializer<'_> {
    fn finish(self, result: Result<Option<Policy>, LoadError>) -> Result<(), LoadError> {
        let waiters = {
            let mut state = self
                .0
                .0
                .lock()
                .map_err(|_| error("sampling_budget", "poisoned budget state"))?;
            state.policy = Some(result);
            state.initializing = false;
            std::mem::take(&mut state.waiters)
        };
        for waker in waiters {
            waker.wake();
        }
        Ok(())
    }
}

impl Drop for Initializer<'_> {
    fn drop(&mut self) {
        let waiters = if let Ok(mut state) = self.0.0.lock() {
            if state.initializing {
                state.policy = Some(Err(error(
                    "sampling_budget_cancelled",
                    "policy initialization cancelled; this turn cannot restart its budget",
                )));
                state.initializing = false;
            }
            std::mem::take(&mut state.waiters)
        } else {
            Vec::new()
        };
        for waker in waiters {
            waker.wake();
        }
    }
}

/// Called only before a main logical request, outside the transport retry loop.
pub async fn admit(
    level: &str,
    source: &str,
    request_kind: &str,
    cancelled: impl Fn() -> bool,
) -> Result<(), LoadError> {
    if let Some(scope) = runtime::scope_for_level(level)? {
        scope
            .admit_sampling(source, request_kind, cancelled)
            .await?;
    }
    Ok(())
}

/// Old unfinished-turn budgets are never reconstructed from a text turn ID.
pub fn require_persistent_recovery() -> Result<(), LoadError> {
    Err(LoadError::input(
        "sampling_budget_recovery_unsupported",
        "",
        "cross-process recovery of an unfinished sampling budget is unsupported; start a new turn",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const POLICY: &[u8] =
        br#"{"max_main_samples":2,"session_sources":["exec"],"request_kinds":["turn"]}"#;

    fn ready_gate() -> Gate {
        Gate(Mutex::new(State {
            policy: Some(Policy::parse(POLICY)),
            ..State::default()
        }))
    }

    #[test]
    fn concurrent_admissions_and_unmatched_requests_do_not_reset_or_overspend() {
        let gate = Arc::new(ready_gate());
        assert_eq!(gate.charge("exec", "compaction", || false).unwrap(), None);
        assert_eq!(gate.charge("internal", "turn", || false).unwrap(), None);
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let gate = Arc::clone(&gate);
                std::thread::spawn(move || gate.charge("exec", "turn", || false).is_ok())
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|accepted| *accepted)
                .count(),
            2
        );
        assert_eq!(
            gate.charge("exec", "turn", || false).unwrap_err().code,
            "sampling_budget_exhausted"
        );
        assert_eq!(
            ready_gate().charge("exec", "turn", || false).unwrap(),
            Some((1, 2))
        );
    }

    #[test]
    fn cancellation_close_and_dropped_initialization_fail_closed() {
        let gate = ready_gate();
        assert!(gate.charge("exec", "turn", || true).is_err());
        assert_eq!(gate.charge("exec", "turn", || false).unwrap(), Some((1, 2)));
        gate.close().unwrap();
        assert!(gate.charge("exec", "turn", || false).is_err());
        let pending = Gate(Mutex::new(State {
            initializing: true,
            ..State::default()
        }));
        drop(Initializer(&pending));
        assert_eq!(
            pending.charge("exec", "turn", || false).unwrap_err().code,
            "sampling_budget_cancelled"
        );
        assert_eq!(
            require_persistent_recovery().unwrap_err().code,
            "sampling_budget_recovery_unsupported"
        );
    }

    #[test]
    fn policy_validation_rejects_ambiguous_or_unbounded_values() {
        for bytes in [
            br#"{"max_main_samples":0,"session_sources":["exec"],"request_kinds":["turn"]}"#.as_slice(),
            br#"{"max_main_samples":4294967296,"session_sources":["exec"],"request_kinds":["turn"]}"#,
            br#"{"max_main_samples":1,"session_sources":[],"request_kinds":["turn"]}"#,
            br#"{"max_main_samples":1,"session_sources":["exec","exec"],"request_kinds":["turn"]}"#,
            br#"{"max_main_samples":1,"session_sources":["unknown"],"request_kinds":["turn"]}"#,
            br#"{"max_main_samples":1,"session_sources":["exec"],"request_kinds":["review"]}"#,
            br#"{"max_main_samples":1,"session_sources":["exec"],"request_kinds":["turn"],"extra":true}"#,
        ] {
            assert!(Policy::parse(bytes).is_err());
        }
        assert!(Policy::parse(b"null").unwrap().is_none());
    }
}
