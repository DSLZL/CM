use cm_sdk::{Bytes, Host, Init, Mod, Request, v22};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyConfig {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u32,
    requested_limit: Option<u32>,
}

fn policy(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if !value
        .as_object()
        .is_some_and(|object| object.contains_key("requested_limit"))
    {
        return Err("missing requested_limit".into());
    }
    let input: Input = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if input.version != 1
        || input
            .requested_limit
            .is_some_and(|value| !(1..=v22::MAX_TOOL_CONCURRENCY).contains(&value))
    {
        return Err("invalid concurrency version/limit".into());
    }
    serde_json::to_vec(&json!({"version":1,"limit":input.requested_limit}))
        .map_err(|error| error.to_string())
}

pub struct ToolConcurrency(Host);

fn create(init: Init) -> Result<ToolConcurrency, String> {
    if !init.config.is_empty() {
        serde_json::from_slice::<EmptyConfig>(&init.config).map_err(|error| error.to_string())?;
    }
    Ok(ToolConcurrency(init.host))
}

impl Mod for ToolConcurrency {
    fn dispatch(&mut self, request: Request) -> Result<(), String> {
        if request.event != v22::TOOL_CONCURRENCY || request.route != 1 {
            return Err("unsupported concurrency request".into());
        }
        let output = policy(&request.input)?;
        self.0
            .complete(request.handle, v22::SUCCEEDED, &output, true)
            .map_err(|_| "tool-concurrency completion rejected".into())
    }

    fn cancel(&mut self, _request: v22::Handle) -> Result<(), String> {
        Ok(())
    }
}

const CONTRIBUTIONS: &[v22::RuntimeContribution] = &[v22::RuntimeContribution {
    header: v22::header::<v22::RuntimeContribution>(),
    id: Bytes::from_static("turn-leaves"),
    capability: Bytes::from_static(v22::TOOL_CONCURRENCY_CAPABILITY),
    resource: Bytes::from_static(v22::TOOL_CONCURRENCY_CAPABILITY),
    kind: v22::KIND_TOOL_CONCURRENCY,
    reserved: 0,
    route: 1,
}];

cm_sdk::export_mod!(
    ToolConcurrency,
    "org.example.tool-concurrency",
    create,
    crate::CONTRIBUTIONS
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_request_and_exact_policy() {
        for limit in [None, Some(1), Some(2), Some(1024)] {
            let input = json!({"version":1,"requested_limit":limit}).to_string();
            let output: Value = serde_json::from_slice(&policy(input.as_bytes()).unwrap()).unwrap();
            assert_eq!(output, json!({"version":1,"limit":limit}));
        }
        for input in [
            r#"{}"#,
            r#"{"version":1}"#,
            r#"{"version":2,"requested_limit":1}"#,
            r#"{"version":1,"requested_limit":0}"#,
            r#"{"version":1,"requested_limit":1025}"#,
            r#"{"version":1,"requested_limit":-1}"#,
            r#"{"version":1,"requested_limit":1.5}"#,
            r#"{"version":1,"requested_limit":4294967296}"#,
            r#"{"version":1,"requested_limit":1,"requested_limit":1}"#,
            r#"{"version":1,"requested_limit":1,"unknown":true}"#,
        ] {
            assert!(policy(input.as_bytes()).is_err(), "{input}");
        }
    }
}
