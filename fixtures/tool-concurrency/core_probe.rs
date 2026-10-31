// Included only in the separately identified Core libtest executable.
mod cm_concurrency_probe {
    use super::*;
    use crate::session::session::Session;
    use crate::session::step_context::StepContext;
    use crate::session::turn_context::TurnContext;
    use crate::tools::context::{FunctionToolOutput, ToolInvocation, ToolPayload};
    use crate::tools::parallel::ToolCallRuntime;
    use crate::tools::registry::{CoreToolRuntime, ToolExecutor, ToolRegistry};
    use crate::tools::router::{ToolCall, ToolRouter};
    use crate::turn_diff_tracker::TurnDiffTracker;
    use codex_extension_api::{TurnStartInput, TurnStopInput};
    use codex_protocol::openai_models::ToolMode;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;
    use tokio::sync::{Semaphore, mpsc};
    use tokio_util::sync::CancellationToken;

    struct Leaf {
        name: &'static str,
        parallel: bool,
        finish: bool,
        entered: mpsc::UnboundedSender<String>,
        release: Arc<Semaphore>,
    }

    impl ToolExecutor<ToolInvocation> for Leaf {
        fn tool_name(&self) -> codex_tools::ToolName {
            codex_tools::ToolName::plain(self.name)
        }

        fn spec(&self) -> codex_tools::ToolSpec {
            codex_tools::ToolSpec::Function(codex_tools::ResponsesApiTool {
                name: self.name.into(),
                description: "Controlled Core leaf".into(),
                strict: false,
                defer_loading: None,
                parameters: codex_tools::JsonSchema::default(),
                output_schema: None,
            })
        }

        fn supports_parallel_tool_calls(&self) -> bool { self.parallel }

        fn handle<'a>(&'a self, invocation: ToolInvocation) -> codex_tools::ToolExecutorFuture<'a>
        where ToolInvocation: 'a {
            Box::pin(async move {
                self.entered.send(invocation.call_id.clone()).expect("entered");
                if invocation.call_id == "panic" { panic!("controlled leaf panic"); }
                self.release.acquire().await.expect("release").forget();
                Ok(Box::new(FunctionToolOutput::from_text("ok".into(), Some(true)))
                    as Box<dyn crate::tools::context::ToolOutput>)
            })
        }
    }

    impl CoreToolRuntime for Leaf {
        fn finishes_on_cancellation(&self) -> bool { self.finish }
    }

    async fn lifecycle(session: &Session, turn: &TurnContext, start: bool) {
        for contributor in session.services.extensions.turn_lifecycle_contributors() {
            if start {
                let mode = turn.collaboration_mode();
                contributor.on_turn_start(TurnStartInput {
                    turn_id: &turn.sub_id, collaboration_mode: &mode, token_usage_at_turn_start: None,
                    session_store: &session.services.session_extension_data,
                    thread_store: &session.services.thread_extension_data, turn_store: &turn.extension_data,
                }).await;
            } else {
                contributor.on_turn_stop(TurnStopInput {
                    session_store: &session.services.session_extension_data,
                    thread_store: &session.services.thread_extension_data, turn_store: &turn.extension_data,
                }).await;
            }
        }
    }

    fn runtime(session: Arc<Session>, turn: Arc<TurnContext>,
        entered: &mpsc::UnboundedSender<String>, release: &Arc<Semaphore>, finish: bool) -> ToolCallRuntime {
        let tools = [("reader", true), ("writer", false)].map(|(name, parallel)|
            Arc::new(Leaf { name, parallel, finish, entered: entered.clone(), release: release.clone() })
                as Arc<dyn CoreToolRuntime>);
        let router = Arc::new(ToolRouter::from_parts(ToolRegistry::from_tools(tools),
            Vec::new(), ToolMode::Direct, BTreeMap::new(), None, &[]));
        let step = StepContext::for_test(turn).with_tool_router_for_test(router);
        ToolCallRuntime::new(session, step, Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::new())))
    }

    fn call(name: &str, id: &str) -> ToolCall {
        ToolCall {
            tool_name: codex_tools::ToolName::plain(name), call_id: id.into(),
            payload: ToolPayload::Function { arguments: "{}".into() }, encrypted_function_args: None,
        }
    }

    async fn entered(receiver: &mut mpsc::UnboundedReceiver<String>, expected: &str) {
        assert_eq!(tokio::time::timeout(Duration::from_secs(10), receiver.recv()).await
            .expect("entry timeout").expect("entry"), expected);
    }

    async fn traced(event: &str, call_id: &str) {
        let trace = std::env::var_os("CM_NATIVE_TRACE").expect("trace");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let text = std::fs::read_to_string(&trace).unwrap_or_default();
                if text.lines().filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .any(|row| row["event"] == event && row["detail"]["call_id"] == call_id) { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("observed admission barrier");
    }

    async fn native_event(event: &str, count: usize) {
        let path = std::env::var_os("CM_RUNTIME_EVENTS").expect("fixture events");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                let found = text.lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .filter(|row| row["owner"] == "example-tool" && row["event"] == event)
                    .count();
                if found >= count { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("actual native worker barrier");
    }

    async fn native_quiet(turn: &TurnContext) {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        let typed = turn.extension_data.get::<cm_runtime::sampling_budget::TurnScope>()
            .expect("actual scope");
        let scope = typed.0.as_ref().expect("native scope");
        let tool = cm_runtime::runtime::contributions().expect("contributions").into_iter()
            .find(|item| item.kind == cm_runtime::runtime::Kind::Tool).expect("native tool");
        let barrier = std::path::PathBuf::from(std::env::var_os("CM_RUNTIME_BARRIER").expect("barrier"));
        for (index, call_id) in ["native-terminal", "native-cancel"].into_iter().enumerate() {
            let lease = cm_runtime::tool_concurrency::Lease::default();
            cm_runtime::tool_concurrency::prepare(turn.extension_data.level_id(), Some(&typed),
                call_id, "direct", "native-quiet-probe").await.expect("policy").expect("C")
                .acquire(&lease).await.expect("native leaf permit");
            let handoff = lease.clone();
            // ABI 2.2 TOOL_CALL, through the public Host dispatcher.
            let request = cm_runtime::runtime::dispatch(scope, &tool, 10,
                b"{}", call_id).expect("actual native dispatch");
            native_event("worker-entered", index + 1).await;
            if index == 0 {
                request.await.expect("terminal result before quiet");
            } else {
                drop(request);
                native_event("cancel-return", 1).await;
            }
            drop(lease);
            let next_lease = cm_runtime::tool_concurrency::Lease::default();
            let prepared = cm_runtime::tool_concurrency::prepare(turn.extension_data.level_id(),
                Some(&typed), "after-native", "direct", "native-quiet-probe")
                .await.expect("next policy").expect("C");
            let mut next = Box::pin(prepared.acquire(&next_lease));
            assert!(poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx).is_pending())).await);
            if index == 1 {
                drop(handoff);
                assert!(poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx).is_pending())).await,
                    "cancelled native work retains capacity until quiet");
                std::fs::write(&barrier, b"release").expect("release native worker");
            } else {
                std::fs::write(&barrier, b"release").expect("release native worker");
                native_event("request-release", 1).await;
                assert!(poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx).is_pending())).await,
                    "result handoff retains capacity after native quiet");
                drop(handoff);
            }
            tokio::time::timeout(Duration::from_secs(10), next).await
                .expect("native quiet admission timeout").expect("native quiet released capacity");
            drop(next_lease);
            native_event("request-release", index + 1).await;
            std::fs::remove_file(&barrier).expect("reset native barrier");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires independently produced hosted G03 fixtures"]
    async fn cm_tool_concurrency_core() {
        let case = std::env::var("CM_CONCURRENCY_PROBE_CASE").expect("case");
        let limit = if case == "lock-domains" { 2 } else { 1 };
        let profile = std::path::PathBuf::from(std::env::var_os("CM_CONCURRENCY_PROBE_PROFILE").expect("profile"));
        let guard = cm_runtime::initialize(&profile, true).expect("C registration");
        let mut config = test_config().await;
        config.tool_concurrency = Some(limit);
        config.model_catalog = Some(codex_models_manager::bundled_models_response().expect("models"));
        config.codex_home = profile.clone().abs();
        config.cwd = profile.join("work").abs();
        std::fs::create_dir_all(&config.cwd).expect("work");
        let mut builder = codex_extension_api::ExtensionRegistryBuilder::<Config>::new();
        cm_host_adapter::append(&mut builder);
        let registry = Arc::new(builder.build());
        let auth = AuthManager::from_auth_for_testing(CodexAuth::from_api_key("cm-fixture"));
        let models = build_models_manager(&config, auth.clone());
        let manager = ThreadManager::new(
            &config, auth, models.clone(), crate::CodexAppsToolsCache::default(), SessionSource::Exec,
            Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()), registry,
            Arc::new(crate::test_support::EmptyUserInstructionsProvider), None, passthrough_image_store(),
            thread_store_from_config(&config, None), None, TEST_INSTALLATION_ID.to_string(), None, None,
        );
        let parent = manager.start_thread(StartThreadOptions {
            environments: Some(Vec::new()), ..StartThreadOptions::new(config)
        }).await.expect("thread");
        let session = Arc::clone(&parent.thread.session);
        let turn = session.new_default_turn().await;
        assert_eq!(turn.cm_tool_concurrency, Some(limit));
        lifecycle(&session, &turn, true).await;
        let derived = turn.with_model("gpt-5.4".into(), &models).await;
        assert_eq!(derived.cm_tool_concurrency, turn.cm_tool_concurrency);
        assert!(Arc::ptr_eq(&derived.extension_data, &turn.extension_data));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let first = runtime(session.clone(), turn.clone(), &tx, &release, true);
        let other = runtime(session.clone(), turn.clone(), &tx, &release, true);
        let token = CancellationToken::new();
        let a = tokio::spawn(first.clone().handle_tool_call(call("reader", "a"), token.clone()));
        entered(&mut rx, "a").await;
        if case == "lock-domains" {
            let writer = tokio::spawn(first.handle_tool_call(call("writer", "same-writer"), CancellationToken::new()));
            traced("write-gate-blocked", "same-writer").await;
            let separate = tokio::spawn(other.handle_tool_call(call("writer", "other-writer"), CancellationToken::new()));
            entered(&mut rx, "other-writer").await;
            assert!(rx.try_recv().is_err(), "writer in the original runtime must still wait");
            release.add_permits(2);
            a.await.expect("reader join").expect("reader");
            separate.await.expect("other runtime join").expect("other runtime");
            entered(&mut rx, "same-writer").await;
            release.add_permits(1);
            writer.await.expect("writer join").expect("writer");
        } else {
            let waiting_token = CancellationToken::new();
            let waiting = tokio::spawn(other.clone().handle_tool_call(call("reader", "wait-cancel"), waiting_token.clone()));
            traced("tool-concurrency-wait", "wait-cancel").await;
            waiting_token.cancel();
            waiting.await.expect("waiter join").expect("cancel response");
            let next = tokio::spawn(other.clone().handle_tool_call(call("reader", "next"), CancellationToken::new()));
            traced("tool-concurrency-wait", "next").await;
            token.cancel();
            assert!(!a.is_finished() && rx.try_recv().is_err(), "finishing handler still owns its slot");
            release.add_permits(1);
            a.await.expect("finisher join").expect("finisher response");
            entered(&mut rx, "next").await;
            release.add_permits(1);
            next.await.expect("next join").expect("next");

            let panic = tokio::spawn(other.clone().handle_tool_call(call("reader", "panic"), CancellationToken::new()));
            entered(&mut rx, "panic").await;
            assert!(panic.await.expect("panic joined by runtime").is_err());
            let dropped = tokio::spawn(other.handle_tool_call(call("reader", "drop"), CancellationToken::new()));
            entered(&mut rx, "drop").await;
            dropped.abort();
            assert!(dropped.await.expect_err("outer abort").is_cancelled());

            native_quiet(&turn).await;
            let closing = runtime(session.clone(), turn.clone(), &tx, &release, true);
            let running = tokio::spawn(closing.clone().handle_tool_call(
                call("reader", "closing-active"), CancellationToken::new()));
            entered(&mut rx, "closing-active").await;
            let waiter = tokio::spawn(closing.handle_tool_call(
                call("reader", "closing-waiter"), CancellationToken::new()));
            traced("tool-concurrency-wait", "closing-waiter").await;
            lifecycle(&session, &turn, false).await;
            assert!(tokio::time::timeout(Duration::from_secs(10), waiter).await
                .expect("close wakes waiter").expect("waiter join").is_err());
            assert!(!running.is_finished() && rx.try_recv().is_err(),
                "scope close does not release running capacity or start its waiter");
            release.add_permits(1);
            running.await.expect("running join").expect("running handoff");
            let old = runtime(session.clone(), turn.clone(), &tx, &release, false);
            assert!(old.handle_tool_call(call("reader", "old-late"), CancellationToken::new()).await.is_err());
            let same_id = session.new_turn_with_default_settings(turn.sub_id.clone(), Default::default()).await;
            assert!(!Arc::ptr_eq(&turn.extension_data, &same_id.extension_data));
            lifecycle(&session, &same_id, true).await;
            let fresh = runtime(session.clone(), same_id.clone(), &tx, &release, false);
            release.add_permits(1);
            fresh.handle_tool_call(call("reader", "fresh"), CancellationToken::new()).await.expect("fresh turn");
            entered(&mut rx, "fresh").await;
            let old = runtime(session.clone(), turn.clone(), &tx, &release, false);
            assert!(old.handle_tool_call(call("reader", "old-after-new"), CancellationToken::new()).await.is_err());
            assert!(rx.try_recv().is_err(), "old cell must not rebind to the new turn");
            lifecycle(&session, &same_id, false).await;
        }
        lifecycle(&session, &turn, false).await;
        let shutdown = manager.shutdown_all_threads_bounded(Duration::from_secs(10)).await;
        assert!(shutdown.submit_failed.is_empty() && shutdown.timed_out.is_empty());
        guard.finish().expect("native quiet");
        let report = serde_json::json!({"status":"pass","case":case,"limit":limit,
            "actual_core_tool_call_runtime":true,"independent_runtime_locks":case == "lock-domains",
            "cancelled_waiter":case != "lock-domains","finishes_on_cancellation":case != "lock-domains",
            "panic_and_outer_drop":case != "lock-domains","old_scope_rejected":case != "lock-domains",
            "same_text_new_scope":case != "lock-domains","native_quiet_and_result_handoff":case != "lock-domains",
            "scope_close_rejects_waiters":case != "lock-domains",
            "separate_from_cli":true});
        std::fs::write(std::env::var_os("CM_CONCURRENCY_PROBE_REPORT").expect("report"),
            serde_json::to_vec_pretty(&report).expect("JSON")).expect("report write");
    }
}

#[tokio::test]
#[ignore = "requires independently produced hosted G03 fixtures"]
async fn cm_tool_concurrency_backend() {
    use codex_hooks::HookMcpExecutor;
    let profile = std::path::PathBuf::from(std::env::var_os("CM_CONCURRENCY_PROBE_PROFILE").expect("profile"));
    let guard = cm_runtime::initialize(&profile, true).expect("C registration");
    let trace = std::env::var_os("CM_NATIVE_TRACE").expect("trace");
    let before = std::fs::read_to_string(&trace).unwrap_or_default();
    let executor = crate::hook_mcp_executor::CoreHookMcpExecutor {
        runtime: Arc::new(codex_mcp::McpRuntime::empty(false)),
        thread_id: codex_protocol::ThreadId::new(),
    };
    let error = executor.execute(codex_hooks::HookMcpCall {
        server: "unregistered-boundary-probe".into(), tool: "echo".into(),
        environment_id: None, metadata: None, input: Default::default(),
        timeout: Duration::from_secs(1),
    }).await.err().expect("actual hook executor reports the missing server");
    let after = std::fs::read_to_string(&trace).unwrap_or_default();
    assert_eq!(before.matches("tool-concurrency-acquired").count(),
        after.matches("tool-concurrency-acquired").count());
    assert!(!error.to_string().is_empty());
    guard.finish().expect("native drain");
    std::fs::write(std::env::var_os("CM_CONCURRENCY_PROBE_REPORT").expect("report"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "status":"pass","case":"backend-scope","actual_core_hook_mcp_executor":true,
            "hook_result":"unknown server rejected","hook_leaf_permits":0,
            "hook_concurrency_support":"unsupported","separate_from_cli":true
        })).expect("JSON")).expect("write report");
}
