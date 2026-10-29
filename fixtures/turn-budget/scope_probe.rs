// Included in the existing private Core test executable; never linked into H.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires hosted Linux turn-budget fixtures"]
async fn cm_turn_budget_scopes() {
    use crate::session::session::Session;
    use crate::session::turn_context::TurnContext;
    use codex_extension_api::{TurnStartInput, TurnStopInput};
    use tokio_util::sync::CancellationToken;

    async fn start(session: &Session, turn: &TurnContext) {
        let mode = turn.collaboration_mode();
        for contributor in session.services.extensions.turn_lifecycle_contributors() {
            contributor.on_turn_start(TurnStartInput {
                turn_id: &turn.sub_id,
                collaboration_mode: &mode,
                token_usage_at_turn_start: None,
                session_store: &session.services.session_extension_data,
                thread_store: &session.services.thread_extension_data,
                turn_store: &turn.extension_data,
            }).await;
        }
    }

    async fn stop(session: &Session, turn: &TurnContext) {
        for contributor in session.services.extensions.turn_lifecycle_contributors() {
            contributor.on_turn_stop(TurnStopInput {
                session_store: &session.services.session_extension_data,
                thread_store: &session.services.thread_extension_data,
                turn_store: &turn.extension_data,
            }).await;
        }
    }

    let profile = std::path::PathBuf::from(std::env::var_os("CM_BUDGET_PROBE_PROFILE").expect("profile"));
    let guard = cm_runtime::initialize(&profile, true).expect("budget registration");
    let mut config = test_config().await;
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
        environments: Some(Vec::new()), ..StartThreadOptions::new(config.clone())
    }).await.expect("parent");
    let session = &parent.thread.session;
    let turn = session.new_default_turn().await;
    start(session, &turn).await;
    let level = turn.extension_data.level_id();
    cm_runtime::sampling_budget::admit(level, "exec", "compaction", || false).await.expect("unmatched kind");
    cm_runtime::sampling_budget::admit(level, "subagent", "turn", || false).await.expect("unmatched source");
    let token = CancellationToken::new();
    let first = session.capture_step_context(turn.clone(), &token).await.expect("first step");
    cm_runtime::sampling_budget::admit(first.turn.extension_data.level_id(), "exec", "turn", || false)
        .await.expect("first sample");
    start(session, &turn).await;
    let second = session.capture_step_context(turn.clone(), &token).await.expect("rebuilt step");
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&first.turn, &second.turn));
    cm_runtime::sampling_budget::admit(second.turn.extension_data.level_id(), "exec", "turn", || false)
        .await.expect("second sample");
    let model = if turn.model_info().slug == "gpt-5.4" { "gpt-5.2" } else { "gpt-5.4" };
    let changed = turn.with_model(model.into(), &models).await;
    assert_ne!(turn.model_info().slug, changed.model_info().slug);
    assert!(Arc::ptr_eq(&turn.extension_data, &changed.extension_data));
    assert!(Arc::ptr_eq(&turn.terminal_error, &changed.terminal_error));
    assert_eq!(cm_runtime::sampling_budget::admit(changed.extension_data.level_id(), "exec", "turn", || false)
        .await.expect_err("model change must not reset").code, "sampling_budget_exhausted");
    stop(session, &turn).await;

    let same_id = session.new_turn_with_default_settings(turn.sub_id.clone(), Default::default()).await;
    assert_eq!(same_id.sub_id, turn.sub_id);
    assert_ne!(same_id.extension_data.level_id(), level);
    start(session, &same_id).await;
    let same_level = same_id.extension_data.level_id();
    let (a, b, c) = tokio::join!(
        cm_runtime::sampling_budget::admit(same_level, "exec", "turn", || false),
        cm_runtime::sampling_budget::admit(same_level, "exec", "turn", || false),
        cm_runtime::sampling_budget::admit(same_level, "exec", "turn", || false),
    );
    assert_eq!([a, b, c].iter().filter(|result| result.is_ok()).count(), 2);
    stop(session, &same_id).await;
    assert!(cm_runtime::sampling_budget::admit(same_level, "exec", "turn", || false).await.is_err());

    let cancelled = session.new_default_turn().await;
    start(session, &cancelled).await;
    assert_eq!(cm_runtime::sampling_budget::admit(cancelled.extension_data.level_id(), "exec", "turn", || true)
        .await.expect_err("cancelled admission").code, "sampling_budget_cancelled");
    cm_runtime::sampling_budget::admit(cancelled.extension_data.level_id(), "exec", "turn", || false)
        .await.expect("cancelled attempt did not charge");
    stop(session, &cancelled).await;

    let mut isolated = codex_extension_api::ExtensionDataInit::new();
    isolated.insert(SessionIsolation::Isolated);
    let empty = manager.start_thread(StartThreadOptions {
        thread_extension_init: isolated, environments: Some(Vec::new()),
        ..StartThreadOptions::new(config)
    }).await.expect("isolated");
    assert!(empty.thread.session.services.extensions.turn_lifecycle_contributors().is_empty());
    let isolated_turn = empty.thread.session.new_default_turn().await;
    for _ in 0..4 {
        cm_runtime::sampling_budget::admit(isolated_turn.extension_data.level_id(), "exec", "turn", || false)
            .await.expect("isolated default");
    }
    let recovery = cm_runtime::sampling_budget::require_persistent_recovery().expect_err("unsupported restoration");
    assert_eq!(recovery.code, "sampling_budget_recovery_unsupported");
    let shutdown = manager.shutdown_all_threads_bounded(Duration::from_secs(10)).await;
    assert!(shutdown.submit_failed.is_empty() && shutdown.timed_out.is_empty());
    guard.finish().expect("native quiet and release");
    let report = serde_json::json!({
        "status":"pass", "step_rebuild":true, "model_change":true, "same_object_reentry":true,
        "same_text_id_new_scope":true, "concurrent_limit":true, "unmatched_kind":true,
        "undeclared_isolated_default":true, "cancel_before_charge":true, "closed_scope_rejected":true,
        "persistent_recovery_error":recovery.code, "shutdown":true,
        "boundary":"private instrumented Core executable; actual ThreadManager and TurnContext; not CLI H"
    });
    std::fs::write(std::env::var_os("CM_BUDGET_PROBE_REPORT").expect("report"),
        serde_json::to_vec_pretty(&report).expect("JSON")).expect("write report");
}
