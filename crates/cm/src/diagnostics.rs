//! Public diagnostics are a projection, never a second canonical plan or a log export.
use serde_json::{Value, json};

use crate::LoadError;

fn identifier(value: &str) -> &str {
    if !value.is_empty()
        && value.len() <= 160
        && value.split("::").all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
    {
        value
    } else {
        "<redacted>"
    }
}

fn optional(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(identifier)
}

pub(crate) fn error(error: &LoadError) -> Value {
    let related_contributions: Vec<_> = error
        .related_contributions
        .iter()
        .take(128)
        .map(|value| identifier(value))
        .collect();
    let (expected, next) = match error.code.as_str() {
        "backend" => (
            "local Embedded execution",
            "Use this Host's local cm launch; remote backends are unsupported.",
        ),
        "mod_lock" | "input_drift" => (
            "unchanged inputs matching the selected generation and lock",
            "Restore the intended inputs; refresh the lock explicitly only after review.",
        ),
        code if code.starts_with("state") => (
            "compatible owned state and an available runtime lease",
            "Stop this home's runtimes and inspect state/checkpoints before an explicit retry.",
        ),
        code if code.starts_with("dependency") || code == "missing_dependency" => (
            "a complete compatible dependency graph",
            "Install compatible precompiled dependencies or disable the conflicting selection.",
        ),
        _ if error.already_native_executed => (
            "a compatible native module completing the negotiated ABI operation",
            "Stop the failed runtime; inspect the Mod's verified author receipt and initialization stage.",
        ),
        _ => (
            "an intact precompiled package compatible with this Host, ABI and capabilities",
            "Run cm-host-identity and cm doctor; compare the package and verified CI receipt. Do not build locally.",
        ),
    };
    json!({
        "stage": identifier(&error.stage), "code": identifier(&error.code),
        "already_native_executed": error.already_native_executed,
        "mod_id": optional(&error.mod_id), "contribution": optional(&error.contribution),
        "related_contributions": related_contributions,
        "resource": optional(&error.resource), "field": optional(&error.field),
        "graph": optional(&error.graph),
        "native_status": error.native_status,
        "message": "CM operation rejected; raw error text is omitted from public diagnostics.",
        "reason": if error.native_status == Some(cm_abi::PANICKED) {
            "native_reported_panic"
        } else if error.already_native_executed { "native_failure" } else { "input_rejected" },
        "expected": expected,
        "actual": {"stage": identifier(&error.stage), "code": identifier(&error.code),
            "native_executed": error.already_native_executed},
        "next_action": next,
        "origin": {"verified": false, "ci_url": null,
            "next_action": "Verify the exact worker run, artifact digest and receipt; manifest URLs are declarations."}
    })
}

fn redact_provenance(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if key == "provenance" {
                    let digest = crate::loader::hash(value.to_string().as_bytes());
                    *value = json!({"declared": true, "verified": false,
                        "declaration_sha256": digest, "free_text": "<redacted>"});
                } else {
                    redact_provenance(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact_provenance),
        _ => {}
    }
}

pub(crate) fn metadata(mut value: Value) -> Value {
    value["schema_version"] = json!(2);
    // Hashes above this boundary still identify the original immutable plan/lock.
    if let Some(mut plan) = value
        .as_object_mut()
        .and_then(|fields| fields.remove("plan"))
    {
        redact_provenance(&mut plan);
        value["plan_projection"] = plan;
        value["projection"] = json!({"canonical": false, "redacted": ["provenance"],
            "identity_fields": ["plan_sha256", "lock_sha256"]});
    } else {
        redact_provenance(&mut value);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_errors_omit_untrusted_text_and_control_sequences() {
        let secret = "CM_DIAGNOSTIC_TEST_SECRET";
        let mut failure = LoadError::input("manifest_contract", "example-tool", secret);
        failure.resource = Some(format!("https://user:{secret}@invalid/\u{1b}[2J"));
        failure.already_native_executed = true;
        failure.native_status = Some(cm_abi::PANICKED);
        failure.contribution = Some("example-tool::greet".into());
        failure.related_contributions = vec![
            "example-tool::greet".into(),
            format!("https://user:{secret}@invalid/"),
        ];
        let diagnostic = serde_json::to_value(&failure).unwrap();
        assert!(!diagnostic.to_string().contains(secret));
        assert!(!format!("{failure:?} {failure}").contains(secret));
        assert_eq!(diagnostic["code"], "manifest_contract");
        assert_eq!(diagnostic["mod_id"], "example-tool");
        assert_eq!(diagnostic["already_native_executed"], true);
        assert_eq!(diagnostic["reason"], "native_reported_panic");
        assert_eq!(diagnostic["contribution"], "example-tool::greet");
        assert_eq!(
            diagnostic["related_contributions"],
            json!(["example-tool::greet", "<redacted>"])
        );
        assert_eq!(diagnostic["origin"]["verified"], false);
        assert!(
            diagnostic["next_action"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
    }

    #[test]
    fn metadata_projection_preserves_canonical_identity_without_exporting_provenance() {
        let original = json!({"mods":{"example-tool":{"metadata":{"provenance":{
            "repository":"https://user:secret@invalid", "release_notes":"secret\u{1b}[2J"}}}}});
        let before = original.to_string();
        let value = metadata(
            json!({"plan": original.clone(), "plan_sha256":"canonical-hash",
            "lock_sha256":"canonical-lock", "qualification":{"verified":false}}),
        );
        assert_eq!(original.to_string(), before);
        assert!(value.get("plan").is_none());
        assert!(!value.to_string().contains("secret"));
        assert_eq!(value["plan_sha256"], "canonical-hash");
        assert_eq!(value["lock_sha256"], "canonical-lock");
        assert_eq!(value["projection"]["canonical"], false);
        assert_eq!(value["qualification"]["verified"], false);
    }
}
