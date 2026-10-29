use cm_sdk::{Host, Init, Mod, Request, abi::Bytes, v22};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BudgetPolicy {
    max_main_samples: u32,
    session_sources: Vec<String>,
    request_kinds: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    policy: Option<BudgetPolicy>,
}

fn labels(values: &[String], allowed: &[&str]) -> bool {
    !values.is_empty()
        && values.len() <= allowed.len()
        && values.iter().enumerate().all(|(index, value)| {
            allowed.contains(&value.as_str()) && !values[..index].contains(value)
        })
}

fn policy(config: &[u8]) -> Result<Vec<u8>, String> {
    let config: Config = serde_json::from_slice(config).map_err(|_| "invalid turn-budget config")?;
    if let Some(policy) = &config.policy
        && (policy.max_main_samples == 0
            || !labels(&policy.session_sources, &["cli", "vscode", "exec"])
            || !labels(&policy.request_kinds, &["turn"]))
    {
        return Err("turn-budget policy requires a positive u32 and explicit supported labels".into());
    }
    serde_json::to_vec(&config.policy).map_err(|_| "cannot encode turn-budget policy".into())
}

struct TurnBudget {
    host: Host,
    policy: Vec<u8>,
}

fn create(init: Init) -> Result<TurnBudget, String> {
    Ok(TurnBudget {
        host: init.host,
        policy: policy(&init.config)?,
    })
}

impl Mod for TurnBudget {
    fn dispatch(&mut self, request: Request) -> Result<(), String> {
        if request.event != v22::SAMPLING_BUDGET || request.route != 1 {
            return Err("unsupported turn-budget request".into());
        }
        self.host
            .complete(request.handle, v22::SUCCEEDED, &self.policy, true)
            .map_err(|_| "turn-budget completion rejected".into())
    }

    fn cancel(&mut self, _request: v22::Handle) -> Result<(), String> {
        // Dispatch completes synchronously and retains no request or callback.
        Ok(())
    }
}

const CONTRIBUTIONS: &[v22::RuntimeContribution] = &[v22::RuntimeContribution {
    header: v22::header::<v22::RuntimeContribution>(),
    id: Bytes::from_static("main-sampling"),
    capability: Bytes::from_static(v22::SAMPLING_BUDGET_CAPABILITY),
    resource: Bytes::from_static(v22::SAMPLING_BUDGET_CAPABILITY),
    kind: v22::KIND_SAMPLING_BUDGET,
    reserved: 0,
    route: 1,
}];

cm_sdk::export_mod!(
    TurnBudget,
    "org.example.turn-budget",
    create,
    crate::CONTRIBUTIONS
);

#[cfg(test)]
mod tests {
    use super::policy;

    #[test]
    fn absent_policy_is_disabled_and_invalid_policy_is_not_defaulted() {
        assert_eq!(policy(b"{}").unwrap(), b"null");
        for input in [
            br#"{"policy":{"max_main_samples":0,"session_sources":["exec"],"request_kinds":["turn"]}}"#.as_slice(),
            br#"{"policy":{"max_main_samples":-1,"session_sources":["exec"],"request_kinds":["turn"]}}"#,
            br#"{"policy":{"max_main_samples":4294967296,"session_sources":["exec"],"request_kinds":["turn"]}}"#,
            br#"{"policy":{"max_main_samples":1,"session_sources":[],"request_kinds":["turn"]}}"#,
            br#"{"policy":{"max_main_samples":1,"session_sources":["exec","exec"],"request_kinds":["turn"]}}"#,
            br#"{"policy":{"max_main_samples":1,"session_sources":["cli"],"request_kinds":["review"]}}"#,
            br#"{"policy":{"max_main_samples":1,"session_sources":["exec"],"request_kinds":["turn"],"extra":true}}"#,
        ] {
            assert!(policy(input).is_err());
        }
        let valid = concat!(
            r#"{"policy":{"max_main_samples":2,"session_sources":["cli","vscode","exec"],"#,
            r#""request_kinds":["turn"]}}"#
        );
        assert!(policy(valid.as_bytes()).is_ok());
    }
}
