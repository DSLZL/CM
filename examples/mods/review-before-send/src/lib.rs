use cm_sdk::{Host, Init, Mod, Request, abi::Bytes, v22};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewInput {
    schema_version: u32,
    actor: String,
    review_id: u64,
    edit_version: u64,
    origin: String,
    intent: String,
    content_sha256: String,
    text_bytes: usize,
    attachments: usize,
    mentions: usize,
    preview: String,
    preview_truncated: bool,
}

fn validate(input: &[u8]) -> Result<(), String> {
    let input: ReviewInput = serde_json::from_slice(input).map_err(|_| "invalid review request")?;
    if input.schema_version != 1 || input.actor.is_empty() || input.actor.len() > 128
        || input.review_id == 0 || input.origin.len() > 128 || input.preview.len() > 8192
        || !["send", "queue", "command"].contains(&input.intent.as_str())
        || input.content_sha256.len() != 64
        || !input.content_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid review identity or bounded preview".into());
    }
    // Counts describe the Host-owned full snapshot; the preview cannot authorize it.
    let _ = (input.edit_version, input.text_bytes, input.attachments, input.mentions, input.preview_truncated);
    Ok(())
}

struct ReviewBeforeSend(Host);

fn create(init: Init) -> Result<ReviewBeforeSend, String> {
    if init.config != b"{}" {
        return Err("review-before-send has no configuration".into());
    }
    Ok(ReviewBeforeSend(init.host))
}

impl Mod for ReviewBeforeSend {
    fn dispatch(&mut self, request: Request) -> Result<(), String> {
        if request.event != v22::SUBMIT_REVIEW || request.route != 1
            || request.thread_scope != v22::Handle::NONE || request.turn_scope != v22::Handle::NONE
            || !request.thread_id.is_empty() || !request.turn_id.is_empty()
        {
            return Err("review requires an owned UI request without Core scopes".into());
        }
        validate(&request.input)?;
        self.0.complete(request.handle, v22::SUCCEEDED,
            br#"{"schema_version":1,"require_review":true}"#, true)
            .map_err(|_| "review completion rejected".into())
    }

    fn cancel(&mut self, _request: v22::Handle) -> Result<(), String> {
        Ok(())
    }
}

const CONTRIBUTIONS: &[v22::RuntimeContribution] = &[v22::RuntimeContribution {
    header: v22::header::<v22::RuntimeContribution>(),
    id: Bytes::from_static("draft-review"),
    capability: Bytes::from_static(v22::SUBMIT_REVIEW_CAPABILITY),
    resource: Bytes::from_static(v22::SUBMIT_REVIEW_CAPABILITY),
    kind: v22::KIND_SUBMIT_REVIEW,
    reserved: 0,
    route: 1,
}];

cm_sdk::export_mod!(ReviewBeforeSend, "org.example.review-before-send", create, crate::CONTRIBUTIONS);

#[cfg(test)]
mod tests {
    use super::validate;

    #[test]
    fn malformed_or_authorizing_requests_are_rejected() {
        assert!(validate(b"{}").is_err());
        assert!(validate(br#"{"authorized":true}"#).is_err());
        assert!(validate(&vec![b'x'; 65537]).is_err());
    }

    #[test]
    fn valid_request_requires_review_without_configuration() {
        let mut input = serde_json::json!({
            "schema_version": 1, "actor": "ui-1", "review_id": 1, "edit_version": 2,
            "origin": "composer-key", "intent": "send", "content_sha256": "a".repeat(64),
            "text_bytes": 10000, "attachments": 1, "mentions": 2,
            "preview": "preview", "preview_truncated": true,
        });
        assert!(validate(&serde_json::to_vec(&input).unwrap()).is_ok());
        input["authorized"] = true.into();
        assert!(validate(&serde_json::to_vec(&input).unwrap()).is_err());
        input.as_object_mut().unwrap().remove("authorized");
        input["intent"] = "approve".into();
        assert!(validate(&serde_json::to_vec(&input).unwrap()).is_err());
    }
}
