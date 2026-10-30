// Included only in the separately built TUI test executable.
use super::*;
use tokio::sync::mpsc::UnboundedReceiver;

fn runtime() -> cm_runtime::ShutdownGuard {
    let home = PathBuf::from(std::env::var_os("CM_REVIEW_PROBE_PROFILE").expect("profile"));
    let guard = cm_runtime::defer_tui(&home, &Default::default()).expect("prepare real B");
    assert!(cm_runtime::tui_review::configured());
    cm_runtime::initialize_tui_embedded().expect("initialize real B");
    guard
}

fn new_composer(text: &str) -> (ChatComposer, UnboundedReceiver<AppEvent>) {
    let (mut composer, rx) = super::super::tests::new_test_composer();
    composer.draft.disable_paste_burst = true;
    composer.set_text_content(text.into(), Vec::new(), Vec::new());
    composer.cm_review_context("probe-route".into(), true);
    (composer, rx)
}

fn snapshot(composer: &ChatComposer) -> String {
    let mut mentions: Vec<_> = composer.draft.mention_bindings.iter()
        .map(|(id, binding)| (*id, binding.sigil, &binding.mention, &binding.path)).collect();
    mentions.sort_by_key(|(id, ..)| *id);
    format!("{:?} {:?}", (
        composer.current_text(), composer.current_cursor(), composer.current_text_elements(),
        composer.draft.textarea.element_payloads(), &composer.draft.prompt_prefix,
        &composer.draft.slash_command_element_id, &composer.attachments, mentions,
        &composer.draft.pending_pastes, &composer.history, &composer.pending_slash_command_history,
    ), (&composer.draft.recent_submission_mention_bindings, &composer.draft.paste_burst))
}

async fn completion(rx: &mut UnboundedReceiver<AppEvent>) -> ReviewCompletion {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        loop {
            if let AppEvent::CmReviewCompleted(value) = rx.recv().await.expect("event stream") {
                return *value;
            }
        }
    }).await.expect("native review deadline")
}

async fn prepared(composer: &mut ChatComposer, rx: &mut UnboundedReceiver<AppEvent>) {
    let value = completion(rx).await;
    assert!(!value.confirm);
    assert!(value.result.is_ok(), "{:?}", value.result);
    assert!(composer.cm_review_completed(value).is_none());
    assert!(composer.cm_review.pending.as_ref().expect("pending").work.is_some());
}

async fn confirm(composer: &mut ChatComposer, rx: &mut UnboundedReceiver<AppEvent>) -> InputResult {
    assert!(composer.cm_review_key(KeyCode::Char('y').into()));
    let value = completion(rx).await;
    assert!(value.confirm);
    composer.cm_review_completed(value).expect("one confirmed result")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_nondestructive() {
    let _guard = runtime();
    let (mut composer, mut rx) = new_composer("  Unicode 中文 draft\nsecond line  ");
    composer.handle_paste("x".repeat(LARGE_PASTE_CHAR_THRESHOLD + 200));
    composer.insert_selected_mention(0..0, "$docs", Some("/skills/original/SKILL.md"));
    let image = PathBuf::from(std::env::var_os("CM_REVIEW_IMAGE").expect("image fixture"));
    composer.attach_image(image.clone());
    composer.attach_image(image);
    composer.set_remote_image_urls(vec!["https://example.invalid/review.png".into()]);
    assert_eq!(composer.attachments.local_images().len(), 2);
    assert!(!composer.draft.mention_bindings.is_empty());
    let before = snapshot(&composer);
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    assert_eq!(snapshot(&composer), before);
    prepared(&mut composer, &mut rx).await;
    assert_eq!(snapshot(&composer), before);
    let area = Rect::new(0, 0, 100, 14);
    let mut buffer = Buffer::empty(area);
    assert!(composer.cm_render_review(area, &mut buffer));
    assert_eq!(snapshot(&composer), before);
    assert!(composer.cm_review_key(KeyCode::Esc.into()));
    assert_eq!(snapshot(&composer), before);
    assert!(composer.cm_take_receipt().is_none());
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    prepared(&mut composer, &mut rx).await;
    assert!(matches!(confirm(&mut composer, &mut rx).await, InputResult::Submitted { .. }));
    assert!(composer.cm_take_receipt().is_some());
    assert!(composer.cm_take_receipt().is_none());

    let (mut composer, mut rx) = new_composer("");
    let pasted = format!("!echo {}\n  ", "x".repeat(LARGE_PASTE_CHAR_THRESHOLD + 200));
    composer.handle_paste(pasted.clone());
    assert!(!composer.draft.pending_pastes.is_empty());
    let before = snapshot(&composer);
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    prepared(&mut composer, &mut rx).await;
    assert_eq!(snapshot(&composer), before);
    let pending = composer.cm_review.pending.as_ref().expect("literal paste review");
    assert_eq!(pending.text, pasted);
    assert_eq!(pending.intent, "queue");
    let InputResult::Queued { text, text_elements, pending_pastes, .. } = confirm(&mut composer, &mut rx).await else {
        panic!("pasted shell syntax remains a literal queued prompt");
    };
    let (expanded, _) = ChatComposer::expand_pending_pastes(&text, text_elements, &pending_pastes);
    assert_eq!(expanded, pasted);
    assert_eq!(composer.cm_take_receipt().expect("literal receipt").text, expanded);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_invalidation() {
    let _guard = runtime();
    let (mut composer, mut rx) = new_composer("first draft");
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    let old = completion(&mut rx).await;
    composer.set_text_content("second draft".into(), Vec::new(), Vec::new());
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    let current = composer.cm_review.generation;
    assert!(composer.cm_review_completed(old).is_none());
    assert_eq!(composer.cm_review.pending.as_ref().expect("new review retained").generation, current);
    prepared(&mut composer, &mut rx).await;
    composer.cm_review_context("other-thread".into(), true);
    assert!(!composer.cm_review_pending());
    assert!(composer.cm_take_receipt().is_none());
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    prepared(&mut composer, &mut rx).await;
    composer.draft.textarea.set_cursor(1);
    assert!(composer.cm_review_key(KeyCode::Char('y').into()));
    assert!(!composer.cm_review_pending());
    assert!(composer.cm_take_receipt().is_none());
    let image = PathBuf::from(std::env::var_os("CM_REVIEW_IMAGE").expect("image fixture"));
    composer.set_text_content("attachment identity".into(), Vec::new(), Vec::new());
    composer.attach_image(image.clone());
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    prepared(&mut composer, &mut rx).await;
    let before = snapshot(&composer);
    let mut changed = std::fs::read(&image).expect("image bytes");
    changed.push(0);
    std::fs::write(&image, changed).expect("mutate real image file");
    assert!(composer.cm_review_key(KeyCode::Char('y').into()));
    let failed = completion(&mut rx).await;
    assert!(failed.confirm && failed.result.is_err());
    assert!(composer.cm_review_completed(failed).is_none());
    assert!(composer.cm_take_receipt().is_none());
    assert_eq!(snapshot(&composer), before);

    let actor = composer.cm_review.actor.clone();
    composer.cm_review.generation = u64::MAX;
    composer.cm_invalidate_review();
    assert_ne!(composer.cm_review.actor, actor);
    assert_eq!(composer.cm_review.generation, 1);
    assert!(composer.cm_take_receipt().is_none());
    assert_eq!(snapshot(&composer), before);

    for validating in [false, true] {
        for change in ["paste-payload", "mention-target", "element", "attachment", "remote-url", "command", "queue-intent"] {
            let (mut composer, mut rx) = new_composer("$docs ");
            composer.insert_selected_mention(0..5, "$docs", Some("/skills/original/SKILL.md"));
            composer.handle_paste("p".repeat(LARGE_PASTE_CHAR_THRESHOLD + 200));
            composer.attach_image(image.clone());
            composer.set_remote_image_urls(vec!["https://example.invalid/original.png".into()]);
            assert!(!composer.draft.pending_pastes.is_empty());
            assert!(!composer.draft.mention_bindings.is_empty());
            assert!(composer.cm_review_key(KeyCode::Enter.into()));
            prepared(&mut composer, &mut rx).await;
            let late = if validating {
                assert!(composer.cm_review_key(KeyCode::Char('y').into()));
                Some(completion(&mut rx).await)
            } else {
                None
            };
            let visible = composer.current_text();
            match change {
                "paste-payload" => {
                    composer.draft.pending_pastes[0].1.push('q');
                    assert_eq!(composer.current_text(), visible);
                }
                "mention-target" => {
                    for binding in composer.draft.mention_bindings.values_mut() {
                        binding.path = "/skills/replaced/SKILL.md".into();
                    }
                    assert_eq!(composer.current_text(), visible);
                }
                "element" => { composer.draft.textarea.insert_element("atomic"); }
                "attachment" => composer.attach_image(image.clone()),
                "remote-url" => composer.set_remote_image_urls(vec!["https://example.invalid/replaced.png".into()]),
                "command" => composer.set_text_content("/init".into(), Vec::new(), Vec::new()),
                "queue-intent" => composer.queue_submissions = true,
                _ => unreachable!(),
            }
            let edited = snapshot(&composer);
            if let Some(late) = late {
                assert!(composer.cm_review_completed(late).is_none(), "{change}: late confirmation");
            } else {
                let _ = composer.cm_review_key(KeyCode::Char('y').into());
            }
            assert!(!composer.cm_review_pending(), "{change}: stale review retained");
            assert!(composer.cm_take_receipt().is_none(), "{change}: stale receipt");
            assert_eq!(snapshot(&composer), edited, "{change}: stale confirmation edited the draft");
            assert!(composer.cm_review_key(KeyCode::Enter.into()));
            prepared(&mut composer, &mut rx).await;
            assert_eq!(snapshot(&composer), edited, "{change}: re-review edited the draft");
            assert!(composer.cm_review_key(KeyCode::Esc.into()));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_key_events() {
    let _guard = runtime();
    let (mut composer, mut rx) = new_composer("keys");
    for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
        assert!(composer.cm_review_key(KeyEvent { kind, ..KeyCode::Enter.into() }));
        assert!(!composer.cm_review_pending());
    }
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    prepared(&mut composer, &mut rx).await;
    for code in [KeyCode::Enter, KeyCode::Tab, KeyCode::Char('y')] {
        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            assert!(composer.cm_review_key(KeyEvent { kind, ..code.into() }));
            assert!(!composer.cm_review.pending.as_ref().expect("pending").validating);
        }
    }
    for code in [KeyCode::Enter, KeyCode::Tab] {
        assert!(composer.cm_review_key(code.into()));
        assert!(composer.cm_take_receipt().is_none());
    }
    assert!(composer.cm_review_key(KeyCode::Char('y').into()));
    assert!(composer.cm_review_key(KeyCode::Char('y').into()));
    let value = completion(&mut rx).await;
    assert!(composer.cm_review_completed(value).is_some());
    let receipt = composer.cm_take_receipt().expect("receipt");
    let admission = std::sync::Arc::new(ReviewAdmission::new(receipt, "keys".into()));
    assert!(admission.deliver());
    assert!(!admission.clone().deliver());
    let (mut custom, mut custom_rx) = new_composer("custom submit binding");
    let mut keymap = RuntimeKeymap::defaults();
    keymap.composer.submit = vec![crate::key_hint::ctrl(KeyCode::Enter)];
    custom.set_keymap_bindings(&keymap);
    assert!(!custom.cm_review_key(KeyCode::Enter.into()));
    assert!(custom.cm_review_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL)));
    prepared(&mut custom, &mut custom_rx).await;
    let before = snapshot(&custom);
    assert!(custom.cm_review_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL)));
    assert_eq!(snapshot(&custom), before);
    assert!(custom.cm_take_receipt().is_none());
    assert!(matches!(confirm(&mut custom, &mut custom_rx).await, InputResult::Submitted { .. }));
    keymap.app.open_transcript = vec![crate::key_hint::KeyBinding::new(KeyCode::Char('y'), KeyModifiers::NONE)];
    assert!(keymap.cm_review_key_conflict());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_entry_coverage() {
    let _guard = runtime();
    for (case, text, key) in [
        ("bare", "/init", KeyCode::Enter),
        ("popup", "/di", KeyCode::Enter),
        ("inline", "/plan investigate this", KeyCode::Enter),
        ("selected-tail", "/plan investigate this", KeyCode::Enter),
        ("service-tier", "/fast", KeyCode::Enter),
        ("skills-tab", "/skills", KeyCode::Tab),
    ] {
        let (mut composer, mut rx) = new_composer("");
        composer.set_collaboration_modes_enabled(true);
        composer.set_service_tier_commands_enabled(true);
        composer.set_service_tier_commands(vec![ServiceTierCommand {
            id: "priority".into(), name: "fast".into(), description: "Fast inference".into(),
        }]);
        composer.set_text_content(text.into(), Vec::new(), Vec::new());
        if matches!(case, "bare" | "inline") {
            composer.popups.active = ActivePopup::None;
        } else {
            assert!(matches!(composer.popups.active, ActivePopup::Command(_)), "{case}: command popup");
        }
        let before = snapshot(&composer);
        assert!(composer.cm_review_key(key.into()), "{case}: review intercepted");
        assert_eq!(snapshot(&composer), before, "{case}: first key side effect");
        prepared(&mut composer, &mut rx).await;
        assert_eq!(snapshot(&composer), before, "{case}: preparation side effect");
        let result = confirm(&mut composer, &mut rx).await;
        match (case, result) {
            ("bare", InputResult::Command(SlashCommand::Init))
            | ("popup", InputResult::Command(SlashCommand::Diff))
            | ("skills-tab", InputResult::Command(SlashCommand::Skills)) => {}
            ("inline" | "selected-tail", InputResult::CommandWithArgs(SlashCommand::Plan, args, elements)) => {
                assert_eq!(args, "investigate this");
                assert!(elements.is_empty());
            }
            ("service-tier", InputResult::ServiceTierCommand(command)) => {
                assert_eq!(command.id, "priority");
                assert_eq!(command.name, "fast");
            }
            (case, result) => panic!("{case}: unexpected confirmed action {result:?}"),
        }
        assert!(composer.cm_take_receipt().is_some(), "{case}: reviewed command receipt");
        assert!(composer.cm_take_receipt().is_none(), "{case}: duplicate receipt");
    }
    let (mut completion_only, _) = new_composer("/di");
    assert!(!completion_only.cm_review_key(KeyCode::Tab.into()));
    assert_eq!(completion_only.handle_key_event(KeyCode::Tab.into()).0, InputResult::None);
    assert_eq!(completion_only.current_text(), "/diff ");
    assert!(!completion_only.cm_review_pending());
    assert!(completion_only.cm_take_receipt().is_none());
    for (text, intent) in [("prompt", "send"), ("!echo retained", "send"), ("/init", "command")] {
        let (mut composer, mut rx) = new_composer(text);
        let before = snapshot(&composer);
        assert!(composer.cm_review_key(KeyCode::Enter.into()));
        assert_eq!(composer.cm_review.pending.as_ref().expect("review").intent, intent);
        prepared(&mut composer, &mut rx).await;
        assert_eq!(snapshot(&composer), before);
        composer.cm_review_key(KeyCode::Esc.into());
        assert_eq!(snapshot(&composer), before);
    }
    let (mut composer, mut rx) = new_composer("startup handoff");
    composer.cm_review_context("pending".into(), false);
    let before = snapshot(&composer);
    assert!(composer.cm_startup_review());
    assert!(!composer.cm_review_pending());
    assert_eq!(snapshot(&composer), before);
    composer.cm_review_context("embedded-ready".into(), true);
    assert!(composer.cm_startup_review());
    prepared(&mut composer, &mut rx).await;
    assert!(matches!(confirm(&mut composer, &mut rx).await, InputResult::Submitted { .. }));
    let (mut question, _) = new_composer("question answer");
    question.config.slash_commands_enabled = false;
    assert!(!question.cm_review_key(KeyCode::Enter.into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_queue_lifecycle() {
    let _guard = runtime();
    let (mut composer, mut rx) = new_composer("queued input");
    composer.is_task_running = true;
    assert!(composer.cm_review_key(KeyCode::Tab.into()));
    prepared(&mut composer, &mut rx).await;
    assert_eq!(composer.cm_review.pending.as_ref().expect("review").intent, "queue");
    assert!(matches!(confirm(&mut composer, &mut rx).await, InputResult::Queued { .. }));
    let receipt = composer.cm_take_receipt().expect("queue receipt");
    let admission = ReviewAdmission::new(receipt, "original".into());
    let derived = admission.derive_init("derived".into());
    assert!(admission.claim_command());
    assert!(!derived.claim_command());
    assert!(derived.deliver());
    assert!(!admission.deliver());
    let retry = admission.retry_after_rejection().expect("one rejected-steer retry");
    assert!(admission.retry_after_rejection().is_none());
    assert!(retry.deliver());
    assert!(!retry.deliver());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_plug_and_play() {
    let _guard = runtime();
    let (mut composer, _) = new_composer("conflicting binding retains draft");
    composer.cm_review.conflict = true;
    let before = snapshot(&composer);
    assert!(composer.cm_review_key(KeyCode::Enter.into()));
    assert!(!composer.cm_review_pending());
    assert_eq!(snapshot(&composer), before);
    let scope = cm_runtime::runtime::UiScope::new().expect("real UI owner");
    scope.check().expect("owner remains valid");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux fault profile"]
async fn cm_review_protocol() {
    let guard = runtime();
    let mode = std::env::var("CM_REVIEW_FAULT").expect("fault mode");
    let scope = cm_runtime::runtime::UiScope::new().expect("UI owner");
    let input = cm_runtime::tui_review::ReviewInput {
        schema_version: 1, actor: "probe-ui".into(), review_id: 1, edit_version: 1,
        origin: "probe".into(), intent: "send".into(), content_sha256: "a".repeat(64),
        text_bytes: 5, attachments: 0, mentions: 0, preview: "draft".into(), preview_truncated: false,
    };
    if mode == "cancel" {
        let provider = cm_runtime::runtime::contributions().expect("contributions").into_iter()
            .find(|item| item.name == "tui.submit_review.v1").expect("provider");
        let future = cm_runtime::runtime::dispatch_ui(&scope, &provider, &input.encode().expect("input")).expect("dispatch");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(scope);
        assert!(future.await.is_err());
    } else {
        let result = cm_runtime::tui_review::request(&scope, &input).await;
        if matches!(mode.as_str(), "duplicate" | "stale") {
            result.expect("one valid decision despite rejected callback");
            scope.check().expect("valid owner");
        } else {
            assert!(result.is_err());
            assert!(scope.check().is_err(), "failure remains latched");
            let later = cm_runtime::runtime::UiScope::new().expect("later actor");
            assert!(cm_runtime::tui_review::request(&later, &input).await.is_err(), "new UI actor cannot clear failure");
        }
    }
    tokio::time::sleep(std::time::Duration::from_secs(if mode == "late" { 3 } else { 1 })).await;
    let shutdown = guard.finish();
    if matches!(mode.as_str(), "duplicate" | "stale" | "cancel") {
        shutdown.expect("quiet normal release");
    } else {
        let error = shutdown.expect_err("protocol failure remains visible at shutdown");
        if matches!(mode.as_str(), "error" | "panic") {
            assert!(error.to_string().contains("pinned"));
        }
        eprintln!("controlled shutdown failure: {error}");
    }
}
