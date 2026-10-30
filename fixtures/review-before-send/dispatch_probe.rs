// Included under chatwidget::tests in the isolated probe executable.
use super::*;

fn runtime() -> cm_runtime::ShutdownGuard {
    let home = std::path::PathBuf::from(std::env::var_os("CM_REVIEW_PROBE_PROFILE").expect("profile"));
    let guard = cm_runtime::defer_tui(&home, &Default::default()).expect("prepare B");
    cm_runtime::initialize_tui_embedded().expect("real native B");
    guard
}

fn message(text: &str) -> UserMessage {
    UserMessage { text: text.into(), text_elements: Vec::new(), local_images: Vec::new(),
        remote_image_urls: Vec::new(), mention_bindings: Vec::new() }
}

async fn review_event(chat: &mut ChatWidget, rx: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>, confirm: bool) {
    let value = tokio::time::timeout(std::time::Duration::from_secs(40), async {
        loop {
            if let AppEvent::CmReviewCompleted(value) = rx.recv().await.expect("events") {
                break value;
            }
        }
    }).await.expect("native deadline");
    assert_eq!(value.confirm, confirm);
    assert!(value.result.is_ok(), "{:?}", value.result);
    chat.on_cm_review_completed(*value);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_programmatic() {
    let _guard = runtime();
    let (mut chat, _rx, mut ops) = make_chatwidget_manual(None).await;
    chat.thread_id = Some(ThreadId::new());
    chat.bottom_pane.insert_str("existing draft");
    let before = chat.bottom_pane.composer_draft_snapshot();
    assert!(chat.cm_reject_programmatic_prompt());
    assert_eq!(chat.bottom_pane.composer_draft_snapshot(), before);
    assert_no_submit_op(&mut ops);
    let source = UserMessageSource::Prompt;
    assert!(!chat.cm_validate_message(&message("generated"), &[], &source));
    assert!(!chat.cm_deliver_message(&source));
    assert!(chat.cm_validate_message(&message("answer"), &[], &UserMessageSource::QuestionAnswer));
    assert!(chat.cm_deliver_message(&UserMessageSource::QuestionAnswer));
    assert_eq!(chat.bottom_pane.composer_draft_snapshot(), before);
    assert_no_submit_op(&mut ops);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_admission() {
    let _guard = runtime();
    let (mut chat, mut rx, mut ops) = make_chatwidget_manual(None).await;
    chat.thread_id = Some(ThreadId::new());
    chat.bottom_pane.insert_str("reviewed once");
    let before = chat.bottom_pane.composer_draft_snapshot();
    chat.handle_key_event(KeyCode::Enter.into());
    assert_eq!(chat.bottom_pane.composer_draft_snapshot(), before);
    assert_no_submit_op(&mut ops);
    review_event(&mut chat, &mut rx, false).await;
    chat.handle_key_event(KeyCode::Enter.into());
    assert_no_submit_op(&mut ops);
    chat.handle_key_event(KeyCode::Char('y').into());
    review_event(&mut chat, &mut rx, true).await;
    assert!(matches!(next_submit_op(&mut ops), Op::UserTurn { .. }));
    assert_no_submit_op(&mut ops);
    assert_eq!(chat.bottom_pane.composer_text(), "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux B profile"]
async fn cm_review_queue() {
    let _guard = runtime();
    let (mut chat, mut rx, mut ops) = make_chatwidget_manual(None).await;
    chat.thread_id = Some(ThreadId::new());
    chat.input_queue.user_turn_pending_start = true;
    chat.bottom_pane.set_queue_submissions(true);
    chat.bottom_pane.insert_str("queued once");
    chat.handle_key_event(KeyCode::Tab.into());
    review_event(&mut chat, &mut rx, false).await;
    assert!(chat.input_queue.queued_user_messages.is_empty());
    chat.handle_key_event(KeyCode::Char('y').into());
    review_event(&mut chat, &mut rx, true).await;
    let queued = chat.input_queue.queued_user_messages.front().expect("admitted queue").clone();
    assert!(chat.cm_validate_message(&queued.user_message, &queued.pending_pastes, &queued.source));
    let mut rewritten = queued.user_message.clone();
    rewritten.text.push_str(" changed");
    assert!(!chat.cm_validate_message(&rewritten, &queued.pending_pastes, &queued.source));
    let mut whitespace_changed = queued.user_message.clone();
    whitespace_changed.text.push(' ');
    assert!(!chat.cm_validate_message(&whitespace_changed, &queued.pending_pastes, &queued.source));
    assert!(!chat.cm_validate_message(&queued.user_message, &[], &UserMessageSource::Prompt));
    assert!(chat.cm_deliver_message(&queued.source));
    assert!(!chat.cm_deliver_message(&queued.source.clone()));
    chat.thread_id = Some(ThreadId::new());
    assert!(!chat.cm_validate_message(&queued.user_message, &[], &queued.source));
    chat.input_queue.user_turn_pending_start = false;
    chat.bottom_pane.insert_str("current draft retained");
    let draft = chat.bottom_pane.composer_draft_snapshot();
    let queue = chat.input_queue.queued_user_messages.clone();
    assert!(!chat.maybe_send_next_queued_input());
    assert!(chat.input_queue.recovered_queue);
    assert_eq!(chat.input_queue.queued_user_messages, queue);
    assert_eq!(chat.bottom_pane.composer_draft_snapshot(), draft);
    assert_no_submit_op(&mut ops);
}
