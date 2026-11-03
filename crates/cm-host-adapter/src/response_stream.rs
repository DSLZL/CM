use super::*;
use codex_protocol::models::ResponseItem;
use futures::StreamExt;

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CmRuntimeAdapter")
    }
}

struct Observer {
    scope: Result<Scope, LoadError>,
    contributions: Vec<Contribution>,
    request: String,
    attempt: u64,
}

impl ModelRequestContributor for Adapter {
    fn request(&self, input: ModelRequestInput<'_>) -> Option<Box<dyn ModelResponseInterceptor>> {
        if input.kind != ModelRequestKind::Generation {
            return None;
        }
        let (Some(level), Some(request)) = (input.turn_level_id, input.request_id) else {
            return None;
        };
        let contributions = match runtime::ordered_contributions(Kind::ResponseStream) {
            Ok(items) if items.is_empty() => return None,
            Ok(items) => items,
            Err(error) => {
                runtime::fail_registration(error.clone());
                return Some(Box::new(Observer {
                    scope: Err(error),
                    contributions: Vec::new(),
                    request: request.into(),
                    attempt: input.attempt,
                }));
            }
        };
        let scope = runtime::scope_for_level(level).and_then(|scope| {
            scope.ok_or_else(|| error("response observer has no actual turn scope"))
        });
        Some(Box::new(Observer {
            scope,
            contributions,
            request: request.into(),
            attempt: input.attempt,
        }))
    }
}

fn identifier(value: &str) -> Result<&str, LoadError> {
    if value.len() > 512 {
        Err(error("response identifier exceeds 512 bytes"))
    } else {
        Ok(value)
    }
}

fn metadata(
    event: Option<&Result<ResponseEvent, ModelResponseError>>,
) -> Result<(Value, String), LoadError> {
    let mut call_id = String::new();
    let value = match event {
        None => json!({"kind": "stream_end"}),
        Some(Err(_)) => json!({"kind": "error"}),
        Some(Ok(ResponseEvent::Created { response_id })) => {
            json!({"kind": "created", "response_id": response_id.as_deref().map(identifier).transpose()?})
        }
        Some(Ok(ResponseEvent::Completed { response_id, .. })) => {
            json!({"kind": "completed", "response_id": identifier(response_id)?})
        }
        Some(Ok(ResponseEvent::ToolCallInputDelta {
            item_id,
            call_id: id,
            delta,
        })) => {
            call_id = id
                .as_deref()
                .map(identifier)
                .transpose()?
                .unwrap_or("")
                .into();
            json!({"kind": "tool_call_delta", "item_id": identifier(item_id)?, "call_id": call_id, "bytes": delta.len()})
        }
        Some(Ok(ResponseEvent::OutputItemAdded(item) | ResponseEvent::OutputItemDone(item))) => {
            let done = matches!(event, Some(Ok(ResponseEvent::OutputItemDone(_))));
            let tool = match item {
                ResponseItem::FunctionCall { call_id: id, .. }
                | ResponseItem::CustomToolCall { call_id: id, .. } => {
                    call_id = identifier(id)?.into();
                    true
                }
                _ => false,
            };
            let item_id = item.id().map(ToString::to_string);
            if let Some(id) = &item_id {
                identifier(id)?;
            }
            json!({"kind": match (tool, done) { (true, false) => "tool_call_added", (true, true) => "tool_call_done", (false, false) => "opaque_item_added", (false, true) => "opaque_item_done" }, "item_id": item_id, "call_id": call_id})
        }
        Some(Ok(ResponseEvent::OutputTextDelta(text))) => {
            json!({"kind": "text_delta", "bytes": text.len()})
        }
        Some(Ok(_)) => json!({"kind": "opaque"}),
    };
    Ok((value, call_id))
}

impl Observer {
    async fn acknowledge(
        &self,
        sequence: u64,
        event: Option<&Result<ResponseEvent, ModelResponseError>>,
    ) -> Result<(), LoadError> {
        let scope = self.scope.as_ref().map_err(Clone::clone)?;
        let (metadata, call_id) = metadata(event)?;
        let input = json!({"version": 1, "request_id": self.request, "attempt": self.attempt, "sequence": sequence, "event": metadata}).to_string();
        for contribution in &self.contributions {
            let output = runtime::dispatch(
                scope,
                contribution,
                v23::STREAM_EVENT,
                input.as_bytes(),
                &call_id,
            )?
            .await?;
            let value: Value = serde_json::from_slice(&output)
                .map_err(|_| error("invalid stream acknowledgement JSON"))?;
            if value.as_object().is_none_or(|object| object.len() != 2)
                || value["version"] != 1
                || value["ack"].as_u64() != Some(sequence)
            {
                return Err(runtime::registration_error(
                    &contribution.owner,
                    &contribution.id,
                    "invalid stream acknowledgement sequence/version",
                ));
            }
        }
        Ok(())
    }
}

impl ModelResponseInterceptor for Observer {
    fn intercept(self: Box<Self>, stream: ModelResponseStream) -> ModelResponseStream {
        Box::pin(futures::stream::unfold(
            (Some(stream), self, 0_u64, false),
            |(mut upstream, observer, sequence, completed)| async move {
                let event = upstream.as_mut()?.next().await;
                let finished =
                    completed || matches!(event, Some(Ok(ResponseEvent::Completed { .. })));
                let result = if event.is_none() && !completed {
                    Err(error("response ended before completion"))
                } else {
                    match sequence.checked_add(1) {
                        Some(sequence) => observer.acknowledge(sequence, event.as_ref()).await,
                        None => Err(error("response sequence exhausted")),
                    }
                };
                if let Err(error) = result {
                    if let Ok(scope) = &observer.scope {
                        scope.fail(error.clone());
                    }
                    drop(upstream.take());
                    return Some((
                        Err(ModelResponseError::Stream(error.to_string())),
                        (None, observer, sequence, finished),
                    ));
                }
                event.map(|event| (event, (upstream, observer, sequence + 1, finished)))
            },
        ))
    }
}
