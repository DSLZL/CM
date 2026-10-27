// Included only in a separately built upstream Core test fixture, never in the CLI.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the hosted Linux native Mod fixtures"]
async fn cm_runtime_native_scopes() {
    let profile = std::path::PathBuf::from(std::env::var_os("CM_RUNTIME_PROBE_PROFILE").expect("probe profile"));
    let guard = cm_runtime::initialize(&profile, true).expect("native fixture registration");
    let mut config = test_config().await;
    config.model_catalog = Some(codex_models_manager::bundled_models_response().expect("bundled models"));
    config.codex_home = profile.clone().abs();
    config.cwd = profile.join("work").abs();
    std::fs::create_dir_all(&config.cwd).expect("probe work");

    struct Builtin;
    impl codex_extension_api::ThreadLifecycleContributor<Config> for Builtin {
        fn on_thread_start<'a>(&'a self, input: codex_extension_api::ThreadStartInput<'a, Config>)
            -> codex_extension_api::ExtensionFuture<'a, ()>
        {
            Box::pin(async move {
                use std::io::Write;
                let path = std::env::var_os("CM_RUNTIME_EVENTS").expect("events");
                let mut file = std::fs::OpenOptions::new().append(true).create(true).open(path).expect("event file");
                writeln!(file, "{}", serde_json::json!({"owner":"host-builtin","event":"thread-start",
                    "thread":input.thread_store.level_id()})).expect("event write");
            })
        }
    }
    let mut builder = codex_extension_api::ExtensionRegistryBuilder::<Config>::new();
    builder.thread_lifecycle_contributor(Arc::new(Builtin));
    cm_host_adapter::append(&mut builder);
    let registry = Arc::new(builder.build());
    let auth = AuthManager::from_auth_for_testing(CodexAuth::from_api_key("cm-fixture"));
    let manager = ThreadManager::new(
        &config, auth.clone(), build_models_manager(&config, auth), crate::CodexAppsToolsCache::default(),
        SessionSource::Exec, Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        registry.clone(), Arc::new(crate::test_support::EmptyUserInstructionsProvider), None,
        passthrough_image_store(), thread_store_from_config(&config, None), None,
        TEST_INSTALLATION_ID.to_string(), None, None,
    );
    let parent = manager.start_thread(StartThreadOptions {
        environments: Some(Vec::new()), ..StartThreadOptions::new(config.clone())
    }).await.expect("parent");
    let child = manager.start_thread(StartThreadOptions {
        internal_parent: Some(InternalSessionParent {
            thread_id: parent.thread_id,
            auth_manager: Arc::clone(&parent.thread.session.services.auth_manager),
            agent_control: AgentControlInit::Provided {
                control: Arc::clone(&parent.thread.session.services.agent_control),
                runtime: parent.thread.session.services.local_agent_runtime.clone(),
            },
            originator: "cm-native-probe".into(), inherited_instructions: None,
        }),
        session_source: Some(SessionSource::SubAgent(SubAgentSource::Review)),
        environments: Some(Vec::new()), ..StartThreadOptions::new(config.clone())
    }).await.expect("inherited local child");
    assert!(Arc::ptr_eq(&registry, &child.thread.session.services.extensions));
    assert_ne!(parent.thread_id, child.thread_id);

    let mut empty_init = codex_extension_api::ExtensionDataInit::new();
    empty_init.insert(SessionIsolation::Isolated);
    let empty = manager.start_thread(StartThreadOptions {
        thread_extension_init: empty_init, environments: Some(Vec::new()),
        ..StartThreadOptions::new(config.clone())
    }).await.expect("isolated empty");
    assert!(empty.thread.session.services.extensions.thread_lifecycle_contributors().is_empty());

    let mut explicit_builder = codex_extension_api::ExtensionRegistryBuilder::<Config>::new();
    cm_host_adapter::append(&mut explicit_builder);
    let explicit_registry = Arc::new(explicit_builder.build());
    let mut explicit_init = codex_extension_api::ExtensionDataInit::new();
    explicit_init.insert(SessionIsolation::Isolated);
    explicit_init.insert(codex_extension_api::IsolatedSessionExtensions(explicit_registry.clone()));
    let explicit = manager.start_thread(StartThreadOptions {
        thread_extension_init: explicit_init, environments: Some(Vec::new()),
        ..StartThreadOptions::new(config)
    }).await.expect("isolated explicit");
    assert!(Arc::ptr_eq(&explicit_registry, &explicit.thread.session.services.extensions));
    assert!(!Arc::ptr_eq(&registry, &explicit.thread.session.services.extensions));
    for thread in [&parent, &child, &empty, &explicit] {
        crate::cm_runtime_check(thread.thread.session.services.thread_extension_data.level_id()).expect("scope gate");
    }
    let shutdown = manager.shutdown_all_threads_bounded(Duration::from_secs(10)).await;
    assert!(shutdown.submit_failed.is_empty() && shutdown.timed_out.is_empty());
    guard.finish().expect("native quiescence");
    let session = &parent.thread.session;
    let executor = registry.tool_contributors().iter().flat_map(|contributor| contributor.tools(
        &session.services.session_extension_data, &session.services.thread_extension_data))
        .find(|tool| tool.tool_name().name == "example-tool__echo").expect("actual CM tool proxy");
    let runtime: Arc<dyn crate::tools::registry::CoreToolRuntime> = Arc::new(
        crate::tools::handlers::extension_tools::ExtensionToolAdapter::new(executor));
    let mut tool_registry = crate::tools::registry::ToolRegistry::default();
    tool_registry.register_trusted(runtime.clone());
    assert!(!tool_registry.register_external_with_exposure(runtime, codex_tools::ToolExposure::DirectModelOnly));
    assert_eq!(tool_registry.entries().count(), 1);
    let tool_collision = crate::cm_runtime_check("cm-collision-test").expect_err("tool collision must latch").to_string();
    assert!(tool_collision.contains("example-tool") && tool_collision.contains("existing Host"));
    let mut world = crate::context::world_state::WorldState::default();
    for _ in 0..2 {
        world.add_extension_section(codex_extension_api::WorldStateSectionContribution::new(
            "example-tool__context", |_| (None, None)));
    }
    let report = serde_json::json!({"status":"pass","test":"actual upstream ThreadManager",
        "parent":parent.thread_id.to_string(),"local_child":child.thread_id.to_string(),
        "isolated_empty":empty.thread_id.to_string(),"isolated_explicit":explicit.thread_id.to_string(),
        "shared_inherited_registry":true,"independent_explicit_registry":true,
        "isolated_default_empty":true,"shutdown":true,
        "actual_tool_registry_collision_rejected":true,"actual_world_state_collision_rejected":true,
        "tool_collision_diagnostic":tool_collision,
        "boundary":"separate native Core integration executable; not the packaged CLI H"});
    std::fs::write(std::env::var_os("CM_RUNTIME_PROBE_REPORT").expect("report"),
        serde_json::to_vec_pretty(&report).expect("encode report")).expect("write report");
}
