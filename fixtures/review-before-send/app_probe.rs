// Included under app::tests in the isolated probe executable.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_programmatic_events() -> Result<()> {
    let home = std::path::PathBuf::from(std::env::var_os("CM_REVIEW_PROBE_PROFILE").expect("profile"));
    let _guard = cm_runtime::defer_tui(&home, &Default::default()).expect("prepare B");
    cm_runtime::initialize_tui_embedded().expect("real native B");
    assert!(cm_runtime::tui_review::configured());
    let (mut app, mut events, mut ops) = make_test_app_with_channels().await;
    let mut server = start_config_write_test_app_server(&app).await?;
    let mut tui = crate::tui::test_support::make_test_tui()?;
    let thread = ThreadId::new();
    app.active_thread_id = Some(thread);
    app.primary_thread_id = Some(thread);
    app.transcript_cells = vec![plain_line_cell("Existing conversation")];
    app.chat_widget
        .restore_user_message_to_composer("existing draft".into());
    let draft = app.chat_widget.composer_text_with_pending();
    let mode = app.chat_widget.effective_collaboration_mode();
    let cell = Arc::clone(&app.transcript_cells[0]);
    while events.try_recv().is_ok() {}
    while ops.try_recv().is_ok() {}
    for event in [
        AppEvent::ClearUiAndSubmitUserMessage {
            text: "generated clear prompt".into(),
        },
        AppEvent::SubmitUserMessageWithMode {
            text: "generated mode prompt".into(),
            collaboration_mode: codex_protocol::config_types::CollaborationModeMask {
                name: "Plan".into(),
                mode: Some(ModeKind::Plan),
                model: Some("different-model".into()),
                reasoning_effort: None,
                developer_instructions: None,
            },
        },
    ] {
        app.handle_event(&mut tui, &mut server, event).await?;
        std::assert_eq!(app.chat_widget.composer_text_with_pending(), draft);
        std::assert_eq!(app.chat_widget.effective_collaboration_mode(), mode);
        assert!(app.chat_widget.queued_user_message_texts().is_empty());
        std::assert_eq!(app.active_thread_id, Some(thread));
        std::assert_eq!(app.primary_thread_id, Some(thread));
        std::assert_eq!(app.transcript_cells.len(), 1);
        assert!(Arc::ptr_eq(&app.transcript_cells[0], &cell));
        assert!(
            ops.try_recv().is_err(),
            "programmatic event emitted an operation"
        );
        let mut diagnosed = false;
        while let Ok(event) = events.try_recv() {
            if let AppEvent::InsertHistoryCell(cell) = event {
                diagnosed |= cell.display_lines(120).iter().any(|line| {
                    line.to_string().contains("Current draft and session retained.")
                });
            }
        }
        assert!(diagnosed, "programmatic event missed the review boundary");
    }
    server.shutdown().await?;
    Ok(())
}
