// Included inside the existing private session::turn_input::tests module.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires independently produced hosted G03 fixtures"]
async fn cm_tool_concurrency_steer() {
    let profile = std::path::PathBuf::from(std::env::var_os("CM_CONCURRENCY_PROBE_PROFILE").expect("profile"));
    let guard = cm_runtime::initialize(&profile, true).expect("C registration");
    let mut results = Vec::new();
    for limit in [1, 2] {
        let (session, mut turn, _rx) = make_session_and_context_with_rx().await;
        Arc::get_mut(&mut turn).expect("unshared turn").cm_tool_concurrency = Some(limit);
        let original_config = session.get_config().await;
        session.spawn_task(Arc::clone(&turn), Vec::new(), NeverEndingTask {
            kind: TaskKind::Regular, listen_to_cancellation_token: true,
        }).await;
        let admission = session.active_turn.lock().await;
        let mut jobs = Vec::new();
        for (name, requested) in [("inherit", None), ("same", Some(limit)), ("rejected", Some(3 - limit))] {
            let session = Arc::clone(&session);
            let expected = turn.sub_id.clone();
            jobs.push(tokio::spawn(async move {
                let result = handle(&session,
                    TurnInputRequest::user_input(vec![UserInput::Text {
                        text: name.into(), text_elements: Vec::new(),
                    }]).on_start(TurnStartOptions {
                        cm_tool_concurrency: requested, ..Default::default()
                    }),
                    TurnInputMode::Steer { expected_turn_id: expected }, name.into(),
                ).await.expect("valid typed request");
                (name, result)
            }));
        }
        drop(admission);
        for job in jobs {
            let (name, result) = job.await.expect("concurrent admission");
            if name == "rejected" {
                assert_eq!(result, TurnInputSubmission::NotSubmitted {
                    reason: NotSubmittedReason::ActiveTurnToolConcurrencyMismatch {
                        requested: 3 - limit, active: Some(limit),
                    },
                });
            } else {
                assert!(matches!(result, TurnInputSubmission::Steered { .. }));
            }
        }
        assert_eq!(turn.cm_tool_concurrency, Some(limit));
        assert_eq!(session.get_config().await.tool_concurrency, original_config.tool_concurrency);
        let (pending, _) = session.input_queue.get_pending_input(&session.active_turn).await;
        assert_eq!(pending.len(), 2, "rejected input must never enter the queue");
        assert!(!format!("{pending:?}").contains("rejected"));
        let wrong = handle(&session,
            TurnInputRequest::user_input(vec![UserInput::Text {
                text: "wrong expected turn".into(), text_elements: Vec::new(),
            }]).on_start(TurnStartOptions { cm_tool_concurrency: Some(limit), ..Default::default() }),
            TurnInputMode::Steer { expected_turn_id: "wrong".into() }, "wrong".into(),
        ).await.expect("wrong expected turn result");
        assert!(matches!(wrong, TurnInputSubmission::NotSubmitted {
            reason: NotSubmittedReason::ExpectedTurnMismatch { .. }
        }));
        assert!(session.input_queue.get_pending_input(&session.active_turn).await.0.is_empty());
        session.abort_all_tasks(TurnAbortReason::Interrupted).await;
        results.push(limit);
    }
    guard.finish().expect("native drain");
    std::fs::write(std::env::var_os("CM_CONCURRENCY_PROBE_REPORT").expect("report"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "status":"pass","case":"steer","limits":results,"same_and_none":true,
            "different_rejected_under_core_admission":true,"rejected_queue_and_config_unchanged":true,
            "wrong_expected_turn_rejected":true,"separate_from_cli":true
        })).expect("JSON")).expect("write report");
}
