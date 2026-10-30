//! The UI owns content and authorization; native code can only require review.
use cm_abi::v22;
use serde::{Deserialize, Serialize};
use crate::runtime::{self, Kind, UiScope};
use crate::{LoadError, event};

#[derive(Debug, Serialize)]
pub struct ReviewInput {
    pub schema_version: u32,
    pub actor: String,
    pub review_id: u64,
    pub edit_version: u64,
    pub origin: String,
    pub intent: String,
    pub content_sha256: String,
    pub text_bytes: usize,
    pub attachments: usize,
    pub mentions: usize,
    pub preview: String,
    pub preview_truncated: bool,
}

impl ReviewInput {
    pub fn encode(&self) -> Result<Vec<u8>, LoadError> {
        if self.schema_version != 1 || self.actor.is_empty() || self.actor.len() > 128
            || self.review_id == 0 || self.content_sha256.len() != 64
            || !self.content_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !["send", "queue", "command"].contains(&self.intent.as_str())
            || self.origin.len() > 128 || self.preview.len() > 8192
        {
            return Err(error("invalid UI review input"));
        }
        let bytes = serde_json::to_vec(self).map_err(|_| error("cannot encode UI review input"))?;
        if bytes.len() > v22::MAX_INPUT {
            return Err(error("UI review input exceeds ABI budget"));
        }
        Ok(bytes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    schema_version: u32,
    require_review: bool,
}

fn error(message: &str) -> LoadError {
    let mut error = LoadError::native("submit_review", message);
    error.resource = Some(v22::SUBMIT_REVIEW_CAPABILITY.into());
    error
}

pub fn digest(bytes: &[u8]) -> String {
    crate::loader::hash(bytes)
}

pub fn enabled() -> Result<bool, LoadError> {
    Ok(runtime::contributions()?.iter().any(|item| item.kind == Kind::SubmitReview))
}

pub fn configured() -> bool {
    if enabled().unwrap_or(true) {
        return true;
    }
    crate::PENDING_TUI.get().and_then(|pending| pending.lock().ok())
        .and_then(|pending| pending.as_ref().map(|plan| plan.plan().phases.contains_key("submit_review")))
        .unwrap_or(false)
}

pub fn panel_ready(actor: &str, review_id: u64) {
    event("tui-review-ready", serde_json::json!({
        "actor": actor, "review_id": review_id,
    }));
}

pub async fn request(scope: &UiScope, input: &ReviewInput) -> Result<(), LoadError> {
    runtime::check_ui()?;
    let providers: Vec<_> = runtime::contributions()?.into_iter()
        .filter(|item| item.kind == Kind::SubmitReview).collect();
    if providers.len() != 1 {
        return Err(error("expected one exclusive UI review provider"));
    }
    let provider = &providers[0];
    let bytes = runtime::dispatch_ui(scope, provider, &input.encode()?)?
        .await.map_err(|error| scope.fail(error))?;
    scope.check()?;
    let fail = |message| {
        let mut error = error(message).owner(&provider.owner, Some(&provider.id));
        error.resource = Some(v22::SUBMIT_REVIEW_CAPABILITY.into());
        scope.fail(error)
    };
    let decision: Decision = serde_json::from_slice(&bytes)
        .map_err(|_| fail("invalid UI review decision"))?;
    if decision.schema_version != 1 || !decision.require_review {
        return Err(fail("UI provider must require review, never authorize submission"));
    }
    event("tui-review-required", serde_json::json!({
        "actor": input.actor, "review_id": input.review_id,
        "content_sha256": input.content_sha256, "intent": input.intent,
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_decision_cannot_supply_authorization_or_extra_fields() {
        for bytes in [
            br#"{"schema_version":1,"require_review":true,"authorized":true}"#.as_slice(),
            br#"{"schema_version":1,"require_review":"true"}"#,
        ] {
            assert!(serde_json::from_slice::<Decision>(bytes).is_err());
        }
    }

    #[test]
    fn abi_preview_is_bounded_independently_of_full_host_content() {
        let mut input = ReviewInput {
            schema_version: 1, actor: "ui-1".into(), review_id: 1, edit_version: 0,
            origin: "composer".into(), intent: "send".into(),
            content_sha256: "a".repeat(64), text_bytes: 1024 * 1024,
            attachments: 0, mentions: 0, preview: "x".repeat(8192),
            preview_truncated: true,
        };
        assert!(input.encode().unwrap().len() < v22::MAX_INPUT);
        input.preview.push('x');
        assert!(input.encode().is_err());
        input.preview.clear();
        input.intent = "approve".into();
        assert!(input.encode().is_err());
    }
}
