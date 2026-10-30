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
    if input.schema_version != 1
        || input.actor.is_empty()
        || input.actor.len() > 128
        || input.review_id == 0
        || input.origin.len() > 128
        || input.preview.len() > 8192
        || !["send", "queue", "command"].contains(&input.intent.as_str())
        || input.content_sha256.len() != 64
        || !input
            .content_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid review identity or bounded preview".into());
    }
    // Counts describe the Host-owned full snapshot; the preview cannot authorize it.
    let _ = (
        input.edit_version,
        input.text_bytes,
        input.attachments,
        input.mentions,
        input.preview_truncated,
    );
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
        if request.event != v22::SUBMIT_REVIEW
            || request.route != 1
            || request.thread_scope != v22::Handle::NONE
            || request.turn_scope != v22::Handle::NONE
            || !request.thread_id.is_empty()
            || !request.turn_id.is_empty()
        {
            return Err("review requires an owned UI request without Core scopes".into());
        }
        validate(&request.input)?;
        match self.0.complete(
            request.handle,
            v22::SUCCEEDED,
            br#"{"schema_version":1,"require_review":true}"#,
            true,
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.code == v22::REQUEST_CANCELLED => Ok(()),
            Err(_) => Err("review completion rejected".into()),
        }
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

cm_sdk::export_mod!(
    ReviewBeforeSend,
    "org.example.review-before-send",
    create,
    crate::CONTRIBUTIONS
);

#[cfg(test)]
mod tests {
    use super::*;

    fn review_input() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1, "actor": "ui-1", "review_id": 1, "edit_version": 2,
            "origin": "composer-key", "intent": "send", "content_sha256": "a".repeat(64),
            "text_bytes": 10000, "attachments": 1, "mentions": 2,
            "preview": "preview", "preview_truncated": true,
        })
    }

    #[test]
    fn malformed_or_authorizing_requests_are_rejected() {
        assert!(validate(b"{}").is_err());
        assert!(validate(br#"{"authorized":true}"#).is_err());
        assert!(validate(&vec![b'x'; 65537]).is_err());
    }

    #[test]
    fn valid_request_requires_review_without_configuration() {
        let mut input = review_input();
        assert!(validate(&serde_json::to_vec(&input).unwrap()).is_ok());
        input["authorized"] = true.into();
        assert!(validate(&serde_json::to_vec(&input).unwrap()).is_err());
        input.as_object_mut().unwrap().remove("authorized");
        input["intent"] = "approve".into();
        assert!(validate(&serde_json::to_vec(&input).unwrap()).is_err());
    }

    #[test]
    fn cancellation_completes_quiescent_without_hiding_other_host_errors() {
        unsafe extern "C" fn complete(
            instance: v22::Handle,
            completion: *const v22::Completion,
            _: *mut cm_sdk::abi::ErrorBuffer,
        ) -> u32 {
            let completion = unsafe { &*completion };
            let result = br#"{"schema_version":1,"require_review":true}"#;
            if !cm_sdk::valid_header::<v22::Completion>(completion.header)
                || completion.request.slot != 1
                || completion.status != v22::SUCCEEDED
                || completion.flags != v22::QUIESCENT
                || completion.result.data.is_null()
                || completion.result.len != result.len() as u64
            {
                return v22::INVALID;
            }
            let actual =
                unsafe { std::slice::from_raw_parts(completion.result.data, result.len()) };
            if actual != result {
                return v22::INVALID;
            }
            instance.slot
        }
        unsafe extern "C" fn state_get(
            _: v22::Handle,
            _: v22::Handle,
            _: v22::Handle,
            _: Bytes,
            _: *mut v22::Buffer,
            _: *mut cm_sdk::abi::ErrorBuffer,
        ) -> u32 {
            v22::INVALID
        }
        unsafe extern "C" fn state_set(
            _: v22::Handle,
            _: v22::Handle,
            _: v22::Handle,
            _: Bytes,
            _: Bytes,
            _: *mut cm_sdk::abi::ErrorBuffer,
        ) -> u32 {
            v22::INVALID
        }
        for code in [
            cm_sdk::abi::OK,
            v22::REQUEST_CANCELLED,
            v22::STALE,
            v22::INVALID,
            v22::ALREADY_COMPLETED,
        ] {
            let handle = v22::Handle {
                epoch: 1,
                slot: 1,
                generation: 1,
            };
            let runtime = v22::HostRuntimeApi {
                header: v22::header::<v22::HostRuntimeApi>(),
                instance: v22::Handle {
                    slot: code,
                    ..handle
                },
                complete: Some(complete),
                state_get: Some(state_get),
                state_set: Some(state_set),
                reserved: 0,
            };
            let host = v22::HostApi {
                base: cm_sdk::abi::v21::HostApi {
                    base: cm_sdk::abi::v2::HostApi {
                        header: v22::header::<v22::HostApi>(),
                        capability: Bytes::from_static(v22::SUBMIT_REVIEW_CAPABILITY),
                        host_build_id: Bytes::from_static("test"),
                        next: None,
                        reserved: 0,
                    },
                    capabilities: std::ptr::null(),
                    capability_count: 0,
                    reserved: 0,
                },
                runtime: &runtime,
            };
            let host = unsafe { Host::negotiate(&host.base.base) }.unwrap();
            let mut module = create(Init {
                host,
                config: b"{}".to_vec(),
                resources: Vec::new(),
            })
            .unwrap();
            let result = module.dispatch(Request {
                handle,
                mod_scope: handle,
                thread_scope: v22::Handle::NONE,
                turn_scope: v22::Handle::NONE,
                route: 1,
                event: v22::SUBMIT_REVIEW,
                input: serde_json::to_vec(&review_input()).unwrap(),
                thread_id: String::new(),
                turn_id: String::new(),
                call_id: String::new(),
            });
            assert_eq!(
                result.is_ok(),
                code == cm_sdk::abi::OK || code == v22::REQUEST_CANCELLED,
                "completion status {code}"
            );
        }
    }
}
