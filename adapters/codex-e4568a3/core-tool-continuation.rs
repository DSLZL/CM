//! Saved handler continuations live entirely inside the Host compilation unit.
use super::*;
use cm_runtime::runtime::{self, Continuation, Contribution, Kind, Scope};
use serde::Deserialize;
use std::sync::Mutex;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Decision {
    Keep {
        version: u32,
    },
    Text {
        version: u32,
        text: String,
        success: bool,
    },
    Error {
        version: u32,
        message: String,
    },
}

fn fail(scope: &Scope, contribution: &Contribution, message: &str) -> FunctionCallError {
    let error = runtime::registration_error(&contribution.owner, &contribution.id, message);
    scope.fail(error.clone());
    FunctionCallError::Fatal(error.to_string())
}

pub(super) async fn handle(
    tool: Arc<dyn CoreToolRuntime>,
    invocation: ToolInvocation,
    call_state: Option<Arc<ToolCallState>>,
) -> Result<AnyToolResult, FunctionCallError> {
    let name = invocation.tool_name.clone().with_default_namespace();
    if name.name != "exec_command" || !name.is_default_namespace() {
        return handle_any_tool(tool.as_ref(), invocation, call_state.as_deref()).await;
    }
    let mut chain = runtime::ordered_contributions(Kind::ToolAround)
        .map_err(|error| FunctionCallError::Fatal(error.to_string()))?;
    chain.extend(
        runtime::ordered_contributions(Kind::ToolReplacement)
            .map_err(|error| FunctionCallError::Fatal(error.to_string()))?,
    );
    chain.retain(|item| item.name == name.name);
    if chain.is_empty() {
        return handle_any_tool(tool.as_ref(), invocation, call_state.as_deref()).await;
    }
    let scope = runtime::scope_for_level(invocation.turn.extension_data.level_id())
        .map_err(|error| FunctionCallError::Fatal(error.to_string()))?
        .ok_or_else(|| {
            FunctionCallError::Fatal("CM continuation has no actual turn scope".into())
        })?;
    if tool.is_third_party_tool() || !matches!(&invocation.payload, ToolPayload::Function { .. }) {
        return Err(fail(
            &scope,
            &chain[0],
            "unsupported continuation target/payload",
        ));
    }
    layer(0, Arc::new(chain), scope, tool, invocation, call_state).await
}

fn layer(
    index: usize,
    chain: Arc<Vec<Contribution>>,
    scope: Scope,
    tool: Arc<dyn CoreToolRuntime>,
    invocation: ToolInvocation,
    call_state: Option<Arc<ToolCallState>>,
) -> BoxFuture<'static, Result<AnyToolResult, FunctionCallError>> {
    Box::pin(async move {
        if index == chain.len() {
            cm_runtime::runtime::original_tool_event(&invocation.call_id, true);
            let result =
                handle_any_tool(tool.as_ref(), invocation.clone(), call_state.as_deref()).await;
            cm_runtime::runtime::original_tool_event(&invocation.call_id, false);
            return result;
        }
        let contribution = chain[index].clone();
        let ToolPayload::Function { arguments } = &invocation.payload else {
            return Err(fail(
                &scope,
                &contribution,
                "continuation requires JSON function input",
            ));
        };
        let input: Value = serde_json::from_str(arguments)
            .map_err(|_| fail(&scope, &contribution, "continuation input is not JSON"))?;
        if !input.is_object() {
            return Err(fail(
                &scope,
                &contribution,
                "continuation input must be an object",
            ));
        }
        let input =
            serde_json::json!({"version": 1, "target": contribution.name, "arguments": input})
                .to_string();
        let saved = Arc::new(Mutex::new(None));
        let output = Arc::clone(&saved);
        let cancel = invocation.cancellation_token.clone();
        let next_scope = scope.clone();
        let next_tool = Arc::clone(&tool);
        let next_invocation = invocation.clone();
        let next = Continuation::new(
            tokio::runtime::Handle::current(),
            move || async move {
                let result = layer(
                    index + 1,
                    chain,
                    next_scope,
                    next_tool,
                    next_invocation,
                    call_state,
                )
                .await;
                let preview = match &result {
                    Ok(result) => {
                        let text = result.result.log_output();
                        let mut end = text.len().min(16 * 1024);
                        while !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        Ok(serde_json::json!({"version": 1, "success": result.result.success_for_logging(), "text": &text[..end], "truncated": end != text.len()}).to_string().into_bytes())
                    }
                    Err(error) => Err(runtime::registration_error("", "", &error.to_string())),
                };
                *output.lock().map_err(|_| {
                    runtime::registration_error("", "", "poisoned original result")
                })? = Some(result);
                preview
            },
            move || cancel.cancel(),
        );
        let request = runtime::dispatch_with_next(
            &scope,
            &contribution,
            input.as_bytes(),
            &invocation.call_id,
            Arc::clone(&next),
        )
        .map_err(|error| fail(&scope, &contribution, &error.to_string()))?;
        let output = request
            .await
            .map_err(|error| fail(&scope, &contribution, &error.to_string()))?;
        let decision: Decision = serde_json::from_slice(&output)
            .map_err(|_| fail(&scope, &contribution, "invalid continuation decision"))?;
        match decision {
            Decision::Keep { version: 1 } => {
                if !next.completed() {
                    return Err(fail(
                        &scope,
                        &contribution,
                        "keep requires a completed next",
                    ));
                }
                let result = saved
                    .lock()
                    .map_err(|_| fail(&scope, &contribution, "poisoned original result"))?
                    .take()
                    .ok_or_else(|| fail(&scope, &contribution, "original result missing"))?;
                result
            }
            Decision::Text {
                version: 1,
                text,
                success,
            } if text.len() <= 64 * 1024 => {
                let result = Box::new(FunctionToolOutput::from_text(text, Some(success)));
                let post_tool_use_payload = CoreToolRuntime::post_tool_use_payload(
                    tool.as_ref(),
                    &invocation,
                    result.as_ref(),
                );
                Ok(AnyToolResult {
                    call_id: invocation.call_id,
                    payload: invocation.payload,
                    result,
                    post_tool_use_payload,
                })
            }
            Decision::Error {
                version: 1,
                message,
            } if message.len() <= 64 * 1024 => Err(FunctionCallError::RespondToModel(message)),
            _ => Err(fail(
                &scope,
                &contribution,
                "unsupported continuation version/result limit",
            )),
        }
    })
}
