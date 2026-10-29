//! Generic Host proxies; this crate never links a concrete Mod or Core.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use cm_abi::v22;
use cm_runtime::LoadError;
use cm_runtime::runtime::{self, Contribution, Kind, Registry, Scope};
use codex_extension_api::*;
use codex_protocol::models::ContentItem;
use codex_tools::{
    FunctionCallError, JsonSchema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolExecutor,
    ToolExecutorFuture, ToolExposure, ToolName, ToolSpec,
};
use serde_json::{Value, json};

static SECTION_IDS: OnceLock<Mutex<BTreeMap<String, &'static str>>> = OnceLock::new();

struct Adapter {
    registry: Registry,
    contributions: Vec<Contribution>,
    sections: BTreeMap<String, &'static str>,
}

/// Call after built-ins and before `builder.build()` in the real composition root.
pub fn append<C: Send + Sync + 'static>(builder: &mut ExtensionRegistryBuilder<C>) {
    let result = (|| {
        let contributions = runtime::contributions()?;
        if contributions.is_empty() {
            return Ok(None);
        }
        let mut sections = BTreeMap::new();
        for contribution in &contributions {
            if !(runtime::valid_name(&contribution.owner, &contribution.name)
                || contribution.kind == Kind::SamplingBudget
                    && contribution.name == v22::SAMPLING_BUDGET_CAPABILITY)
            {
                return Err(runtime::registration_error(
                    &contribution.owner,
                    &contribution.id,
                    "invalid declared runtime name",
                ));
            }
            if contribution.kind == Kind::ContextSection {
                let mut ids = SECTION_IDS
                    .get_or_init(|| Mutex::new(BTreeMap::new()))
                    .lock()
                    .map_err(|_| {
                        runtime::registration_error(
                            &contribution.owner,
                            &contribution.id,
                            "section ID lock poisoned",
                        )
                    })?;
                if !ids.contains_key(&contribution.name) && ids.len() >= 128 {
                    return Err(runtime::registration_error(
                        &contribution.owner,
                        &contribution.id,
                        "section ID limit",
                    ));
                }
                let id = *ids
                    .entry(contribution.name.clone())
                    .or_insert_with(|| Box::leak(contribution.name.clone().into_boxed_str()));
                sections.insert(contribution.name.clone(), id);
            }
        }
        Ok(Some(Arc::new(Adapter {
            registry: Registry::new()?,
            contributions,
            sections,
        })))
    })();
    match result {
        Ok(Some(adapter)) => {
            builder.thread_lifecycle_contributor(adapter.clone());
            builder.turn_lifecycle_contributor(adapter.clone());
            builder.tool_contributor(adapter.clone());
            builder.prompt_contributor(adapter);
        }
        Ok(None) => {}
        Err(error) => runtime::fail_registration(error),
    }
}

struct ThreadHolder {
    level: String,
    scope: Result<Scope, LoadError>,
    turns: Mutex<BTreeMap<String, Scope>>,
    ended: AtomicBool,
}
struct TurnHolder {
    level: String,
    turn_id: String,
    thread: Weak<ThreadHolder>,
    scope: Result<Scope, LoadError>,
    ended: AtomicBool,
}

fn error(message: &str) -> LoadError {
    runtime::registration_error("", "", message)
}

fn thread(store: &ExtensionData) -> Result<Arc<ThreadHolder>, LoadError> {
    store
        .get::<ThreadHolder>()
        .filter(|holder| holder.level == store.level_id())
        .ok_or_else(|| error("CM thread holder missing or inherited from another runtime"))
}

fn turn(store: &ExtensionData) -> Result<Arc<TurnHolder>, LoadError> {
    store
        .get::<TurnHolder>()
        .filter(|holder| holder.level == store.level_id())
        .ok_or_else(|| error("CM turn holder missing or inherited from another runtime"))
}

fn latch(store: &ExtensionData, result: Result<(), LoadError>) {
    if let Err(error) = result {
        if let Some(holder) = store.get::<TurnHolder>()
            && let Ok(scope) = &holder.scope
        {
            scope.fail(error);
            return;
        }
        if let Some(holder) = store.get::<ThreadHolder>()
            && let Ok(scope) = &holder.scope
        {
            scope.fail(error);
            return;
        }
        if let Err(error) = runtime::bind_level(store.level_id(), &Err(error)) {
            runtime::fail_registration(error);
        }
    }
}

impl Adapter {
    async fn lifecycle(&self, scope: &Scope, event: u32, input: Value) {
        let bytes = input.to_string();
        // Cleanup visits every owner even after a previous owner's failure.
        for contribution in self
            .contributions
            .iter()
            .filter(|item| item.kind == Kind::Lifecycle)
        {
            let result = match runtime::dispatch(scope, contribution, event, bytes.as_bytes(), "") {
                Ok(request) => request.await.map(|_| ()),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                scope.fail(error);
            }
        }
    }

    async fn thread_event(&self, store: &ExtensionData, event: u32, input: Value) {
        let result = async {
            let holder = thread(store)?;
            if event == v22::THREAD_STOP && holder.ended.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            let scope = holder.scope.as_ref().map_err(Clone::clone)?;
            if event == v22::THREAD_STOP {
                scope.begin_close()?;
            }
            self.lifecycle(scope, event, input).await;
            if event == v22::THREAD_STOP {
                scope.close()?;
            }
            scope.check()
        }
        .await;
        latch(store, result);
    }

    async fn end_turn(&self, store: &ExtensionData, event: u32) {
        let result = async {
            let holder = turn(store)?;
            if holder.ended.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            let scope = holder.scope.as_ref().map_err(Clone::clone)?;
            scope.begin_close()?;
            self.lifecycle(scope, event, json!({})).await;
            let closed = scope.close();
            if let Some(thread) = holder.thread.upgrade() {
                thread
                    .turns
                    .lock()
                    .map_err(|_| error("turn map poisoned"))?
                    .remove(&holder.turn_id);
            }
            closed
        }
        .await;
        latch(store, result);
        // Keep the level gate until the real turn object is discarded.
    }
}

impl<C: Send + Sync> ThreadLifecycleContributor<C> for Adapter {
    fn on_thread_start<'a>(&'a self, input: ThreadStartInput<'a, C>) -> ExtensionFuture<'a, ()> {
        Box::pin(async move {
            let scope = self.registry.thread(input.thread_store.level_id());
            if let Err(error) = runtime::bind_level(input.thread_store.level_id(), &scope) {
                runtime::fail_registration(error);
            }
            input.thread_store.insert(ThreadHolder {
                level: input.thread_store.level_id().into(),
                scope: scope.clone(),
                turns: Mutex::new(BTreeMap::new()),
                ended: AtomicBool::new(false),
            });
            if let Ok(scope) = scope {
                self.lifecycle(&scope, v22::THREAD_START, json!({"persistent_thread_state_available": input.persistent_thread_state_available,
                    "session": input.session_store.level_id()})).await;
            }
        })
    }
    fn on_thread_ready<'a>(&'a self, input: ThreadReadyInput<'a, C>) -> ExtensionFuture<'a, ()> {
        Box::pin(self.thread_event(input.thread_store, v22::THREAD_READY, json!({})))
    }
    fn on_thread_resume<'a>(&'a self, input: ThreadResumeInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(self.thread_event(input.thread_store, v22::THREAD_RESUME, json!({})))
    }
    fn on_thread_idle<'a>(&'a self, input: ThreadIdleInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(self.thread_event(
            input.thread_store,
            v22::THREAD_IDLE,
            json!({"cause": format!("{:?}", input.cause)}),
        ))
    }
    fn on_thread_stop<'a>(&'a self, input: ThreadStopInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(self.thread_event(input.thread_store, v22::THREAD_STOP, json!({})))
    }
}

impl TurnLifecycleContributor for Adapter {
    fn on_turn_start<'a>(&'a self, input: TurnStartInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(async move {
            let result = async {
                let holder = thread(input.thread_store)?;
                if let Some(existing) = input.turn_store.get::<TurnHolder>()
                    && existing.level == input.turn_store.level_id()
                    && existing.turn_id == input.turn_id
                    && existing
                        .thread
                        .upgrade()
                        .is_some_and(|owner| Arc::ptr_eq(&owner, &holder))
                {
                    return existing.scope.as_ref().map(|_| ()).map_err(Clone::clone);
                }
                let scope = holder
                    .scope
                    .as_ref()
                    .map_err(Clone::clone)?
                    .turn(input.turn_id);
                runtime::bind_level(input.turn_store.level_id(), &scope)?;
                input.turn_store.insert(TurnHolder {
                    level: input.turn_store.level_id().into(),
                    turn_id: input.turn_id.into(),
                    thread: Arc::downgrade(&holder),
                    scope: scope.clone(),
                    ended: AtomicBool::new(false),
                });
                let scope = scope?;
                holder
                    .turns
                    .lock()
                    .map_err(|_| error("turn map poisoned"))?
                    .insert(input.turn_id.into(), scope.clone());
                self.lifecycle(&scope, v22::TURN_START, json!({})).await;
                scope.check()
            }
            .await;
            latch(input.turn_store, result);
        })
    }
    fn on_turn_stop<'a>(&'a self, input: TurnStopInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(self.end_turn(input.turn_store, v22::TURN_STOP))
    }
    fn on_turn_abort<'a>(&'a self, input: TurnAbortInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(self.end_turn(input.turn_store, v22::TURN_ABORT))
    }
    fn on_turn_error<'a>(&'a self, input: TurnErrorInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(self.end_turn(input.turn_store, v22::TURN_ERROR))
    }
}

impl ToolContributor for Adapter {
    fn tools(
        &self,
        _session_store: &ExtensionData,
        thread_store: &ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        let holder = match thread(thread_store) {
            Ok(holder) => holder,
            Err(error) => {
                latch(thread_store, Err(error));
                return Vec::new();
            }
        };
        self.contributions
            .iter()
            .filter(|item| item.kind == Kind::Tool)
            .map(|contribution| {
                Arc::new(Tool {
                    contribution: contribution.clone(),
                    thread: holder.clone(),
                }) as Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>
            })
            .collect()
    }
}

struct Tool {
    contribution: Contribution,
    thread: Arc<ThreadHolder>,
}

fn json_value(bytes: &[u8]) -> Result<Value, String> {
    fn depth(value: &Value, level: usize) -> bool {
        level <= 16
            && match value {
                Value::Array(values) => values.iter().all(|value| depth(value, level + 1)),
                Value::Object(values) => values.values().all(|value| depth(value, level + 1)),
                _ => true,
            }
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if !depth(&value, 0) {
        return Err("JSON depth exceeds 16".into());
    }
    Ok(value)
}

impl<'call> ToolExecutor<ToolCall<'call>> for Tool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(&self.contribution.name)
    }
    fn exposure(&self) -> ToolExposure {
        ToolExposure::DirectModelOnly
    }
    fn spec(&self) -> ToolSpec {
        ToolSpec::Function(ResponsesApiTool {
            name: self.contribution.name.clone(),
            description: format!("JSON tool supplied by CM Mod {}", self.contribution.owner),
            strict: false,
            defer_loading: None,
            parameters: JsonSchema::object(BTreeMap::new(), None, Some(true.into())),
            output_schema: None,
        })
    }
    fn handle<'a>(&'a self, invocation: ToolCall<'call>) -> ToolExecutorFuture<'a>
    where
        ToolCall<'call>: 'a,
    {
        Box::pin(async move {
            let arguments = invocation.function_arguments()?;
            if arguments.len() > v22::MAX_INPUT {
                return Err(FunctionCallError::RespondToModel(
                    "CM JSON input exceeds 64 KiB".into(),
                ));
            }
            let input =
                json_value(arguments.as_bytes()).map_err(FunctionCallError::RespondToModel)?;
            if !input.is_object() {
                return Err(FunctionCallError::RespondToModel(
                    "CM tool requires a JSON object".into(),
                ));
            }
            let scope = self
                .thread
                .turns
                .lock()
                .map_err(|_| FunctionCallError::Fatal("CM turn map poisoned".into()))?
                .get(&invocation.turn_id)
                .cloned()
                .ok_or_else(|| {
                    FunctionCallError::Fatal("CM tool invoked outside its active turn".into())
                })?;
            let request = runtime::dispatch(
                &scope,
                &self.contribution,
                v22::TOOL_CALL,
                arguments.as_bytes(),
                &invocation.call_id,
            )
            .map_err(|error| FunctionCallError::Fatal(error.to_string()))?;
            let output = request.await.map_err(|error| {
                if error.code == "mod_error" {
                    FunctionCallError::RespondToModel(error.to_string())
                } else {
                    scope.fail(error.clone());
                    FunctionCallError::Fatal(error.to_string())
                }
            })?;
            let value = json_value(&output).map_err(|message| {
                let error = runtime::registration_error(
                    &self.contribution.owner,
                    &self.contribution.id,
                    &format!("invalid JSON tool result: {message}"),
                );
                scope.fail(error.clone());
                FunctionCallError::Fatal(error.to_string())
            })?;
            Ok(Box::new(JsonToolOutput::new(value)) as Box<dyn codex_tools::ToolOutput>)
        })
    }
}

impl ContextContributor for Adapter {
    fn contribute_world_state<'a>(
        &'a self,
        input: WorldStateContributionInput<'a>,
    ) -> ExtensionFuture<'a, Vec<WorldStateSectionContribution>> {
        Box::pin(async move {
            let result = async {
                let holder = turn(input.turn_store)?;
                let scope = holder.scope.as_ref().map_err(Clone::clone)?;
                let mut sections = Vec::new();
                for contribution in self
                    .contributions
                    .iter()
                    .filter(|item| item.kind == Kind::ContextSection)
                {
                    let output =
                        runtime::dispatch(scope, contribution, v22::SECTION, b"{}", "")?.await?;
                    if output.len() > v22::MAX_INPUT {
                        return Err(runtime::registration_error(
                            &contribution.owner,
                            &contribution.id,
                            "section exceeds 64 KiB",
                        ));
                    }
                    let text = String::from_utf8(output).map_err(|_| {
                        runtime::registration_error(
                            &contribution.owner,
                            &contribution.id,
                            "section is not UTF-8",
                        )
                    })?;
                    let id = self.sections[&contribution.name];
                    sections.push(WorldStateSectionContribution::new(id, move |_| {
                        (
                            Some(Value::String(text.clone())),
                            Some(RenderedWorldStateFragment::new(
                                "user",
                                ("<cm_context>", "</cm_context>"),
                                ContentItem::InputText { text: text.clone() },
                            )),
                        )
                    }));
                }
                Ok(sections)
            }
            .await;
            match result {
                Ok(sections) => sections,
                Err(error) => {
                    latch(input.turn_store, Err(error));
                    Vec::new()
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_exact_and_json_depth_is_bounded() {
        assert!(runtime::valid_name("example-tool", "example-tool__echo"));
        assert!(!runtime::valid_name("example-tool", "exec_command"));
        assert!(!runtime::valid_name("example-tool", "other__echo"));
        assert!(!runtime::valid_name("example-tool", "example-tool__Echo"));
        assert!(json_value(b"{\"input\":\"ok\"}").is_ok());
        assert!(json_value(format!("{}0{}", "[".repeat(17), "]".repeat(17)).as_bytes()).is_err());
    }
}
