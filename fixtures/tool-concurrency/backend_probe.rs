// Included only in the private TUI probe, which contains a controlled initialize responder.
mod cm_concurrency_backend_probe {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires independent hosted G03 profile and backend fault"]
    async fn cm_tool_concurrency_backend_rejection() -> Result<()> {
        let home = std::path::PathBuf::from(
            std::env::var_os("CM_CONCURRENCY_PROBE_PROFILE").expect("profile"),
        );
        let guard = cm_runtime::initialize(&home, true).expect("C registration");
        let mut config = crate::legacy_core::config::ConfigBuilder::default()
            .codex_home(home)
            .build()
            .await?;
        config.tool_concurrency = Some(1);
        config.model_catalog = Some(codex_models_manager::bundled_models_response()?);
        let mut server = crate::start_embedded_app_server_for_picker(&config).await?;
        let error = server
            .bootstrap(&config)
            .await
            .err()
            .expect("old or mismatched initialize response must fail before account/business requests");
        assert!(
            error.to_string().contains("capability")
                || error.to_string().contains("[tool_concurrency]"),
            "{error}"
        );
        server.shutdown().await?;
        guard.finish().expect("native quiet");
        std::fs::write(
            std::env::var_os("CM_CONCURRENCY_PROBE_REPORT").expect("report"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "status": "pass", "case": "backend-scope", "separate_from_cli": true,
                "fault": std::env::var("CM_CONCURRENCY_BACKEND_FAULT").expect("fault"),
                "actual_embedded_initialize_connection": true,
                "actual_tui_bootstrap_rejected": true,
                "controlled_responder_only_in_private_probe": true,
            }))?,
        )?;
        Ok(())
    }
}
