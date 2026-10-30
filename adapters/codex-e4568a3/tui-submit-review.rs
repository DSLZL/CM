//! Private TUI ownership bridge. Native code receives only a bounded projection.
use super::*;
use codex_app_server_protocol::UserInput;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ReviewAction {
    Key(KeyEvent),
    Startup,
}

#[derive(Debug)]
pub(crate) struct ReviewWork {
    pub(crate) images: Vec<UserInput>,
    pub(crate) files: Vec<(PathBuf, String)>,
}

#[derive(Debug)]
pub(crate) struct ReviewCompletion {
    pub(crate) actor: String,
    pub(crate) generation: u64,
    pub(crate) confirm: bool,
    pub(crate) result: Result<ReviewWork, String>,
}

struct PendingReview {
    generation: u64,
    action: ReviewAction,
    key: String,
    text: String,
    intent: &'static str,
    message_key: String,
    display: String,
    scroll: u16,
    work: Option<ReviewWork>,
    validating: bool,
    task: JoinHandle<()>,
}

impl Drop for PendingReview {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) struct ReviewState {
    actor: String,
    generation: u64,
    route: String,
    ready: bool,
    pub(super) conflict: bool,
    pending: Option<PendingReview>,
    receipt: Option<ReviewReceipt>,
}

impl Default for ReviewState {
    fn default() -> Self {
        Self {
            actor: uuid::Uuid::new_v4().to_string(),
            generation: 0,
            route: String::new(),
            ready: false,
            conflict: false,
            pending: None,
            receipt: None,
        }
    }
}

/// Move-only until admitted to one message/command. Clones thereafter share one delivery gate.
#[derive(Debug)]
pub(crate) struct ReviewReceipt {
    pub(crate) actor: String,
    pub(crate) route: String,
    pub(crate) digest: String,
    pub(crate) text: String,
    pub(crate) intent: &'static str,
    pub(crate) message_key: String,
    pub(crate) images: Vec<UserInput>,
}

#[derive(Debug)]
pub(crate) struct ReviewAdmission {
    pub(crate) actor: String,
    pub(crate) route: String,
    pub(crate) digest: String,
    pub(crate) message_key: String,
    pub(crate) images: Vec<UserInput>,
    delivered: std::sync::Arc<AtomicBool>,
    command_used: std::sync::Arc<AtomicBool>,
    retry_used: AtomicBool,
}

impl PartialEq for ReviewAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.actor == other.actor && self.digest == other.digest
    }
}

impl Eq for ReviewAdmission {}

impl ReviewAdmission {
    pub(crate) fn new(receipt: ReviewReceipt, message_key: String) -> Self {
        Self {
            actor: receipt.actor,
            route: receipt.route,
            digest: receipt.digest,
            message_key,
            images: receipt.images,
            delivered: std::sync::Arc::new(AtomicBool::new(false)),
            command_used: std::sync::Arc::new(AtomicBool::new(false)),
            retry_used: AtomicBool::new(false),
        }
    }

    pub(crate) fn deliver(&self) -> bool {
        self.delivered
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn derive_init(&self, message_key: String) -> Self {
        Self {
            actor: self.actor.clone(),
            route: self.route.clone(),
            digest: self.digest.clone(),
            message_key,
            images: Vec::new(),
            delivered: self.delivered.clone(),
            command_used: self.command_used.clone(),
            retry_used: AtomicBool::new(false),
        }
    }

    pub(crate) fn retry_after_rejection(&self) -> Option<Self> {
        if !self.delivered.load(Ordering::Acquire)
            || self
                .retry_used
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        Some(Self {
            actor: self.actor.clone(),
            route: self.route.clone(),
            digest: self.digest.clone(),
            message_key: self.message_key.clone(),
            images: self.images.clone(),
            delivered: std::sync::Arc::new(AtomicBool::new(false)),
            command_used: self.command_used.clone(),
            retry_used: AtomicBool::new(false),
        })
    }

    pub(crate) fn claim_command(&self) -> bool {
        self.command_used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

pub(super) fn project_text(
    mut text: String,
    mut elements: Vec<TextElement>,
    pastes: &[(String, String)],
    trim: bool,
    expand: bool,
) -> (String, Vec<TextElement>) {
    if expand {
        (text, elements) = ChatComposer::expand_pending_pastes(&text, elements, pastes);
    }
    if trim {
        let original = text;
        text = original.trim().to_owned();
        elements = ChatComposer::trim_text_elements(&original, &text, elements);
    }
    (text, elements)
}

impl ChatComposer {
    pub(crate) fn cm_review_context(&mut self, route: String, ready: bool) {
        if self.cm_review.route != route || self.cm_review.ready != ready {
            self.cm_invalidate_review();
            self.cm_review.route = route;
            self.cm_review.ready = ready;
        }
    }

    pub(crate) fn cm_invalidate_review(&mut self) {
        if let Some(generation) = self.cm_review.generation.checked_add(1) {
            self.cm_review.generation = generation;
        } else {
            self.cm_review.actor = uuid::Uuid::new_v4().to_string();
            self.cm_review.generation = 1;
        }
        self.cm_review.pending = None;
        self.cm_review.receipt = None;
    }

    pub(crate) fn cm_take_receipt(&mut self) -> Option<ReviewReceipt> {
        self.cm_review.receipt.take()
    }

    pub(crate) fn cm_review_pending(&self) -> bool {
        self.cm_review.pending.is_some()
    }

    fn cm_snapshot_key(&self, action: ReviewAction) -> String {
        let mut bindings: Vec<_> = self
            .draft
            .mention_bindings
            .iter()
            .map(|(id, binding)| (*id, binding.sigil, &binding.mention, &binding.path))
            .collect();
        bindings.sort_by_key(|(id, ..)| *id);
        let value = serde_json::json!({
            "domain": "cm-tui-review-v1",
            "actor": self.cm_review.actor,
            "version": self.cm_review.generation,
            "route": self.cm_review.route,
            "ready": self.cm_review.ready,
            "action": format!("{action:?}"),
            "text": self.current_text(),
            "cursor": self.current_cursor(),
            "elements": self.current_text_elements(),
            "prefix": format!("{:?}", self.draft.prompt_prefix),
            "slash_element": self.draft.slash_command_element_id,
            "bindings": bindings,
            "recent_bindings": format!("{:?}", self.draft.recent_submission_mention_bindings),
            "attachments": format!("{:?}", self.attachments),
            "pastes": self.draft.pending_pastes,
            "pending_history": format!("{:?}", self.pending_slash_command_history),
            "startup_history": format!("{:?}", self.history.startup_local_history()),
            "task_running": self.is_task_running,
            "queue_submissions": self.queue_submissions,
            "parent_owned": self.blocks_direct_input,
            "input_enabled": self.draft.input_enabled,
            "submit_keys": format!("{:?}", self.submit_keys),
            "queue_keys": format!("{:?}", self.queue_keys),
            "commands": format!("{:?}", self.service_tier_commands),
            "selected": match &self.popups.active {
                ActivePopup::Command(popup) => format!("{:?}", popup.selected_item()),
                _ => String::new(),
            },
        });
        cm_runtime::tui_review::digest(value.to_string().as_bytes())
    }

    fn cm_projection(
        &self,
        action: ReviewAction,
    ) -> Option<(String, Vec<TextElement>, &'static str)> {
        if self.history_search.is_some() || self.is_empty() || self.is_in_paste_burst() {
            return None;
        }
        let mut text = self.current_text();
        let mut queue = matches!(action, ReviewAction::Startup) || self.queue_submissions;
        let mut popup_command = false;
        if let ReviewAction::Key(key) = action {
            match &self.popups.active {
                ActivePopup::Command(popup) => {
                    let selected = popup.selected_item();
                    let dispatch = key.code == KeyCode::Enter && key.modifiers.is_empty()
                        || key.code == KeyCode::Tab
                            && selected.as_ref().is_some_and(
                                slash_input::selected_command_dispatches_immediately_on_tab,
                            );
                    if !dispatch {
                        return None;
                    }
                    if let Some(selected) = selected {
                        if self.blocks_direct_input
                            && !matches!(&selected,
                            CommandItem::Builtin(cmd) if parse_slash_name(&text)
                                .is_some_and(|(_, args, _)| parent_owned_command_is_allowed(*cmd, args)))
                        {
                            return None;
                        }
                        if let Some((end, replacement)) = self.slash_inline_replacement(&selected) {
                            text.replace_range(0..end, &replacement);
                        } else if let Some(completed) = slash_input::selected_command_completion(
                            text.lines().next().unwrap_or(""),
                            &selected,
                        ) {
                            text = completed;
                        }
                        popup_command = true;
                        queue = false;
                    }
                }
                ActivePopup::None => {
                    if self.queue_keys.is_pressed(key)
                        && (self.is_task_running
                            || self.queue_submissions
                            || !self.is_bang_shell_command())
                    {
                        queue = self.is_task_running || self.queue_submissions;
                    } else if !self.submit_keys.is_pressed(key) {
                        return None;
                    }
                    if self.draft.textarea.is_vim_operator_pending() {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        if self.blocks_direct_input
            && !popup_command
            && !parse_slash_name(&text).is_some_and(|(name, args, _)| {
                matches!(self.slash_input().command(name),
                    Some(crate::bottom_pane::slash_commands::SlashCommandItem::Builtin(command))
                        if parent_owned_command_is_allowed(command, args))
            })
        {
            return None;
        }
        let command = popup_command
            || !queue
                && (self.slash_input().bare_command(&text).is_some()
                    || self.slash_input().inline_command(&text).is_some());
        let (expanded, expanded_elements) = project_text(
            text.clone(),
            self.current_text_elements(),
            &self.draft.pending_pastes,
            self.config.trim_submission,
            true,
        );
        let literal_paste = self.config.slash_commands_enabled
            && expanded.starts_with('!')
            && !text.trim_start().starts_with('!');
        let preserved_goal = queue
            && self.slash_input().should_parse_on_dequeue(&text)
            && !self.draft.pending_pastes.is_empty()
            && parse_slash_name(&text)
                .is_some_and(|(name, _, _)| name == SlashCommand::Goal.command());
        let (text, elements) = if literal_paste || preserved_goal {
            // Formal queue preparation trims placeholders before expanding their payloads.
            let (text, elements) = project_text(
                text,
                self.current_text_elements(),
                &[],
                literal_paste || self.config.trim_submission,
                false,
            );
            project_text(text, elements, &self.draft.pending_pastes, false, true)
        } else {
            (expanded, expanded_elements)
        };
        queue |= literal_paste;
        if text.chars().count() > MAX_USER_INPUT_TEXT_CHARS {
            return None;
        }
        Some((
            text,
            elements,
            if queue {
                "queue"
            } else if command {
                "command"
            } else {
                "send"
            },
        ))
    }

    fn cm_begin_review(&mut self, action: ReviewAction) -> bool {
        let Some((text, elements, intent)) = self.cm_projection(action) else {
            return false;
        };
        if !self.cm_review.ready {
            self.cm_review_notice("Waiting for the Embedded review bridge; draft retained.");
            return true;
        }
        if self.cm_review.conflict {
            self.cm_review_notice("Review requires an unbound Y key. Change the conflicting submit/queue/global binding.");
            return true;
        }
        self.cm_invalidate_review();
        let key = self.cm_snapshot_key(action);
        let generation = self.cm_review.generation;
        let actor = self.cm_review.actor.clone();
        let mut local_images = self.attachments.local_images();
        let placeholders: std::collections::HashSet<_> = elements
            .iter()
            .filter_map(|element| element.placeholder(&text))
            .collect();
        local_images.retain(|image| placeholders.contains(image.placeholder.as_str()));
        let remote_urls = self.attachments.remote_image_urls();
        let mentions = self.snapshot_mention_bindings();
        let message_key =
            review_message_key(&text, elements, &local_images, &remote_urls, &mentions, &[]);
        let display = format!(
            "{}\n\n{}\n\nLocal attachments: {:?}\nRemote URLs: {:?}\nMentions: {:?}\n\nY confirm · Esc edit · ↑/↓ scroll",
            if intent == "queue" {
                "Queue admission review (final model request may resolve later)"
            } else {
                "Review before send"
            },
            text,
            local_images,
            remote_urls,
            mentions,
        );
        let tx = self.app_event_tx.clone();
        let preview: String = text
            .chars()
            .scan(0_usize, |bytes, character| {
                *bytes += character.len_utf8();
                (*bytes <= 8192).then_some(character)
            })
            .collect();
        let input = cm_runtime::tui_review::ReviewInput {
            schema_version: 1,
            actor: actor.clone(),
            review_id: generation,
            edit_version: generation,
            origin: match action {
                ReviewAction::Key(_) => "composer-key",
                ReviewAction::Startup => "startup-handoff",
            }
            .into(),
            intent: intent.into(),
            content_sha256: key.clone(),
            text_bytes: text.len(),
            attachments: local_images.len() + remote_urls.len(),
            mentions: mentions.len(),
            preview_truncated: preview.len() != text.len(),
            preview,
        };
        let task = tokio::spawn(async move {
            let result = async {
                let work =
                    crate::chatwidget::prepare_cm_review_images(local_images, remote_urls).await?;
                let scope =
                    cm_runtime::runtime::UiScope::new().map_err(|error| error.to_string())?;
                let mut input = input;
                input.content_sha256 = review_digest(&input.content_sha256, &work);
                cm_runtime::tui_review::request(&scope, &input)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(work)
            }
            .await;
            tx.send(AppEvent::CmReviewCompleted(Box::new(ReviewCompletion {
                actor,
                generation,
                confirm: false,
                result,
            })));
        });
        self.cm_review.pending = Some(PendingReview {
            generation,
            action,
            key,
            text,
            intent,
            message_key,
            display,
            scroll: 0,
            work: None,
            validating: false,
            task,
        });
        true
    }

    fn cm_review_notice(&self, text: &str) {
        self.app_event_tx.send(AppEvent::InsertHistoryCell(Box::new(
            history_cell::new_info_event(text.to_owned(), None),
        )));
    }

    pub(crate) fn cm_startup_review(&mut self) -> bool {
        if self.cm_review.pending.is_some() {
            return true;
        }
        self.cm_begin_review(ReviewAction::Startup)
    }

    pub(super) fn cm_review_key(&mut self, key: KeyEvent) -> bool {
        if !self.config.slash_commands_enabled {
            return false;
        }
        let enabled = cm_runtime::tui_review::configured();
        if !enabled {
            return false;
        }
        let Some(pending) = &self.cm_review.pending else {
            if key.kind != KeyEventKind::Press {
                return self
                    .cm_projection(ReviewAction::Key(KeyEvent {
                        kind: KeyEventKind::Press,
                        ..key
                    }))
                    .is_some();
            }
            return key.kind == KeyEventKind::Press && self.cm_begin_review(ReviewAction::Key(key));
        };
        if key.kind != KeyEventKind::Press {
            return true;
        }
        if key.code != KeyCode::Esc
            && (self.submit_keys.is_pressed(key) || self.queue_keys.is_pressed(key))
        {
            return true;
        }
        match key.code {
            KeyCode::Esc => {
                self.cm_invalidate_review();
                return true;
            }
            KeyCode::Enter | KeyCode::Tab => return true,
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown => {
                let Some(pending) = self.cm_review.pending.as_mut() else {
                    return true;
                };
                let amount = if matches!(key.code, KeyCode::PageUp | KeyCode::PageDown) {
                    10
                } else {
                    1
                };
                pending.scroll = if matches!(key.code, KeyCode::Up | KeyCode::PageUp) {
                    pending.scroll.saturating_sub(amount)
                } else {
                    pending.scroll.saturating_add(amount)
                };
                return true;
            }
            KeyCode::Char('y' | 'Y')
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                if pending.validating || pending.work.is_none() {
                    return true;
                }
                if self.cm_snapshot_key(pending.action) != pending.key
                    || !self.cm_review.ready
                    || cm_runtime::runtime::check_ui().is_err()
                {
                    self.cm_invalidate_review();
                    self.cm_review_notice(
                        "Draft or destination changed. Review again before sending.",
                    );
                    return true;
                }
                let Some(pending) = self.cm_review.pending.as_mut() else {
                    return true;
                };
                let Some(work) = pending.work.as_ref() else {
                    return true;
                };
                let files = work.files.clone();
                let images = work.images.clone();
                pending.validating = true;
                let tx = self.app_event_tx.clone();
                let actor = self.cm_review.actor.clone();
                let generation = pending.generation;
                pending.task = tokio::spawn(async move {
                    let result = crate::chatwidget::revalidate_cm_review_images(&files)
                        .await
                        .map(|()| ReviewWork { images, files });
                    tx.send(AppEvent::CmReviewCompleted(Box::new(ReviewCompletion {
                        actor,
                        generation,
                        confirm: true,
                        result,
                    })));
                });
                return true;
            }
            _ => self.cm_invalidate_review(),
        }
        false
    }

    pub(crate) fn cm_review_completed(
        &mut self,
        completion: ReviewCompletion,
    ) -> Option<InputResult> {
        if completion.actor != self.cm_review.actor {
            return None;
        }
        let pending = self.cm_review.pending.as_ref()?;
        if completion.generation != pending.generation {
            return None;
        }
        if cm_runtime::runtime::check_ui().is_err() {
            self.cm_invalidate_review();
            self.cm_review_notice("Review runtime failed; draft retained.");
            return None;
        }
        if self.cm_snapshot_key(pending.action) != pending.key {
            self.cm_invalidate_review();
            return None;
        }
        let work = match completion.result {
            Ok(work) => work,
            Err(error) => {
                self.cm_invalidate_review();
                self.cm_review_notice(&format!("Review failed; draft retained: {error}"));
                return None;
            }
        };
        if !completion.confirm {
            if pending.work.is_some() {
                return None;
            }
            self.cm_review.pending.as_mut()?.work = Some(work);
            cm_runtime::tui_review::panel_ready(&self.cm_review.actor, completion.generation);
            return None;
        }
        if !pending.validating {
            return None;
        }
        let pending = self.cm_review.pending.take()?;
        self.cm_review.receipt = Some(ReviewReceipt {
            actor: self.cm_review.actor.clone(),
            route: self.cm_review.route.clone(),
            digest: review_digest(&pending.key, &work),
            text: pending.text.clone(),
            intent: pending.intent,
            message_key: pending.message_key.clone(),
            images: work.images,
        });
        // Only this branch runs destructive preparation. The receipt is taken by the UI consumer.
        Some(match pending.action {
            ReviewAction::Key(key) => self.handle_key_event_inner(key).0,
            ReviewAction::Startup => self.prepare_startup_submission(),
        })
    }

    pub(super) fn cm_render_review(&self, area: Rect, buf: &mut Buffer) -> bool {
        let Some(pending) = &self.cm_review.pending else {
            return false;
        };
        let title = if pending.validating {
            "Validating confirmation…"
        } else if pending.work.is_none() {
            "Preparing review…"
        } else {
            "Review · Y confirm · Esc edit"
        };
        ratatui::widgets::Clear.render(area, buf);
        ratatui::widgets::Paragraph::new(pending.display.as_str())
            .block(ratatui::widgets::Block::bordered().title(title))
            .wrap(ratatui::widgets::Wrap { trim: false })
            .scroll((pending.scroll, 0))
            .render(area, buf);
        true
    }
}

fn review_digest(key: &str, work: &ReviewWork) -> String {
    cm_runtime::tui_review::digest(
        serde_json::json!({
            "domain": "cm-tui-review-content-v1", "draft": key,
            "files": work.files, "images": work.images,
        })
        .to_string()
        .as_bytes(),
    )
}

pub(crate) fn review_message_key(
    text: &str,
    elements: Vec<TextElement>,
    images: &[LocalImageAttachment],
    remote_urls: &[String],
    mentions: &[MentionBinding],
    pastes: &[(String, String)],
) -> String {
    let (text, elements) = project_text(text.to_owned(), elements, pastes, false, true);
    cm_runtime::tui_review::digest(
        serde_json::json!({
            "domain": "cm-reviewed-message-v1", "text": text, "elements": elements,
            "local_images": format!("{images:?}"), "remote_images": remote_urls,
            "mentions": format!("{mentions:?}"),
        })
        .to_string()
        .as_bytes(),
    )
}
