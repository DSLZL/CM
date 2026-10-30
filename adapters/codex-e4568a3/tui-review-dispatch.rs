//! Host-only review admission. Recovered or rewritten messages never mint authorization.
use super::*;
use crate::bottom_pane::{ReviewAdmission, ReviewCompletion, ReviewReceipt};
use std::sync::Arc;

impl ChatWidget {
    pub(super) fn cm_restore_unreviewed(
        &mut self,
        mut message: UserMessage,
        pastes: &[(String, String)],
    ) {
        (message.text, message.text_elements) =
            crate::bottom_pane::ChatComposer::expand_pending_pastes(
                &message.text,
                message.text_elements,
                pastes,
            );
        self.restore_user_message_to_composer(message);
    }

    fn cm_review_route(&self) -> String {
        format!(
            "{:?}:{}:{}",
            self.thread_id,
            match &self.codex_op_target {
                CodexOpTarget::Direct(_) => "direct",
                CodexOpTarget::AppEvent => "app-event",
            },
            self.effective_collaboration_mode().model()
        )
    }

    pub(super) fn cm_refresh_review_context(&mut self) {
        let ready = self.is_session_configured()
            && !self.blocks_direct_input
            && self.bottom_pane.composer_input_enabled()
            && !self.startup_submission_has_protected_input()
            && !self
                .effective_collaboration_mode()
                .model()
                .trim()
                .is_empty();
        self.bottom_pane
            .cm_review_context(self.cm_review_route(), ready);
    }

    pub(crate) fn on_cm_review_completed(&mut self, completion: ReviewCompletion) {
        self.cm_refresh_review_context();
        if let Some(result) = self.bottom_pane.cm_review_completed(completion) {
            crate::startup_recovery::submitted(&result);
            self.handle_composer_input_result(result, false);
        }
        self.request_redraw();
    }

    pub(crate) fn cm_reject_programmatic_prompt(&mut self) -> bool {
        if !cm_runtime::tui_review::configured() {
            return false;
        }
        self.add_error_message(
            "Review before send: put this generated prompt in the composer and review it before sending. Current draft and session retained.".into(),
        );
        true
    }

    pub(super) fn cm_admit_message(
        &mut self,
        message: &UserMessage,
        pastes: &[(String, String)],
        receipt: Option<ReviewReceipt>,
    ) -> Option<UserMessageSource> {
        if !cm_runtime::tui_review::configured() {
            return Some(UserMessageSource::Prompt);
        }
        let receipt = receipt?;
        let (text, _) = crate::bottom_pane::ChatComposer::expand_pending_pastes(
            &message.text,
            message.text_elements.clone(),
            pastes,
        );
        if receipt.route != self.cm_review_route()
            || text != receipt.text
            || receipt.message_key != cm_message_key(message, pastes)
            || !matches!(receipt.intent, "send" | "queue")
        {
            self.add_error_message(
                "Reviewed input changed before admission; review the restored draft again.".into(),
            );
            return None;
        }
        Some(UserMessageSource::ReviewedPrompt(Arc::new(
            ReviewAdmission::new(receipt, cm_message_key(message, pastes)),
        )))
    }

    pub(super) fn cm_admit_command(
        &self,
        receipt: Option<ReviewReceipt>,
    ) -> Option<Arc<ReviewAdmission>> {
        receipt
            .filter(|receipt| {
                receipt.route == self.cm_review_route() && receipt.intent == "command"
            })
            .map(|receipt| Arc::new(ReviewAdmission::new(receipt, String::new())))
    }

    pub(super) fn cm_claim_command(&mut self, command: Option<Arc<ReviewAdmission>>) -> bool {
        if cm_runtime::tui_review::configured()
            && (cm_runtime::runtime::check_ui().is_err()
                || command
                    .as_ref()
                    .is_none_or(|admission| !admission.claim_command()))
        {
            self.add_error_message("Command requires a fresh review.".into());
            return false;
        }
        self.cm_reviewed_command = command;
        true
    }

    pub(super) fn cm_submit_queued_message(
        &mut self,
        message: UserMessage,
        source: UserMessageSource,
    ) {
        self.submit_user_message_with_history_and_shell_escape_policy(
            message,
            UserMessageHistoryRecord::UserMessageText,
            ShellEscapePolicy::Allow,
            source,
        );
    }

    pub(super) fn cm_validate_message(
        &self,
        message: &UserMessage,
        pastes: &[(String, String)],
        source: &UserMessageSource,
    ) -> bool {
        if !cm_runtime::tui_review::configured() || !source.is_prompt() {
            return true;
        }
        if cm_runtime::runtime::check_ui().is_err() {
            return false;
        }
        matches!(source, UserMessageSource::ReviewedPrompt(admission)
            if admission.route == self.cm_review_route()
                && admission.message_key == cm_message_key(message, pastes))
    }

    pub(super) fn cm_deliver_message(&mut self, source: &UserMessageSource) -> bool {
        if !cm_runtime::tui_review::configured() || !source.is_prompt() {
            return true;
        }
        if cm_runtime::runtime::check_ui().is_err() {
            self.add_error_message("Review runtime failed; input retained for editing.".into());
            return false;
        }
        if let UserMessageSource::ReviewedPrompt(admission) = source
            && admission.route == self.cm_review_route()
            && admission.deliver()
        {
            return true;
        }
        self.add_error_message("This review was already consumed or its destination changed. Review again before resending.".into());
        false
    }

    pub(super) fn cm_submit_init_prompt(&mut self, message: UserMessage) {
        let source = if cm_runtime::tui_review::configured() {
            let Some(command) = self.cm_reviewed_command.take() else {
                self.cm_reject_programmatic_prompt();
                return;
            };
            UserMessageSource::ReviewedPrompt(Arc::new(
                command.derive_init(cm_message_key(&message, &[])),
            ))
        } else {
            UserMessageSource::Prompt
        };
        self.submit_user_message_with_history_and_shell_escape_policy(
            message,
            UserMessageHistoryRecord::UserMessageText,
            ShellEscapePolicy::Disallow,
            source,
        );
    }
}

fn cm_message_key(message: &UserMessage, pastes: &[(String, String)]) -> String {
    crate::bottom_pane::review_message_key(
        &message.text,
        message.text_elements.clone(),
        &message.local_images,
        &message.remote_image_urls,
        &message.mention_bindings,
        pastes,
    )
}
