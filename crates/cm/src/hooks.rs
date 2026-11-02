//! Prepared policy slots only; this module never resolves addresses or patches code.
use serde_json::Value;

use crate::loader;

pub(crate) const SLOT: &str = cm_abi::CAPABILITY;
pub(crate) const CAPABILITY: &str = cm_abi::v2::CAPABILITY;

pub(crate) fn identity(value: &Value) -> Result<(Option<String>, Vec<String>), String> {
    let map = &value["patch_map"];
    let declared = &value["patch_map_sha256"];
    if map.is_null() && declared.is_null() {
        return Ok((None, Vec::new()));
    }
    let digest = declared.as_str().ok_or("patch_map_sha256: required")?;
    if !loader::digest(digest) || loader::hash(&crate::config::json_bytes(map)) != digest {
        return Err("patch_map_sha256: embedded map digest differs".into());
    }
    let descriptor = &map["descriptor"];
    if map["schema_version"] != 1
        || map["domain"] != "cm.hook-map.v1"
        || descriptor["schema_version"] != 1
        || descriptor["domain"] != "cm.prepared-slots.v1"
        || descriptor["backend"] != "prepared_slots"
        || descriptor["upstream"] != "e4568a3538c9cab6627d64ff8cdfc7d98b79b7db"
        || descriptor["adapter"] != "codex-e4568a3"
        || descriptor["bridge_contract"] != 1
        || descriptor["target"] != loader::TARGET
        || map["build"]["target"] != loader::TARGET
    {
        return Err("patch_map: unsupported prepared-slot identity".into());
    }
    let slots = descriptor["slots"]
        .as_array()
        .ok_or("patch_map.slots: required")?;
    if slots.len() != 1 {
        return Err("patch_map.slots: unsupported registry".into());
    }
    let slot = &slots[0];
    if slot["id"] != SLOT
        || slot["resource"] != SLOT
        || slot["capability"] != CAPABILITY
        || slot["kinds"] != serde_json::json!(["before", "around", "replacement", "after"])
        || slot["abi_major"] != 2
        || slot["abi_minor_min"] != 0
        || slot["abi_minor_max"] != 2
        || slot["continuation_contract"] != "cm.policy-next.v1"
        || slot["thread_contract"] != "synchronous-owner-thread.v1"
        || slot["cancellation_contract"] != "first-failure-drain.v1"
    {
        return Err("patch_map.slots: unsupported policy contract".into());
    }
    let sources = map["source_fingerprints"]
        .as_object()
        .ok_or("patch_map.source_fingerprints: required")?;
    for path in [
        "codex-rs/core/src/tools/parallel.rs",
        "codex-rs/cm/src/tool_policy.rs",
        "codex-rs/cm/src/loader/registration.rs",
        "codex-rs/cm-abi/src/lib.rs",
        "codex-rs/cm-abi/src/v2.rs",
        "codex-rs/Cargo.toml",
    ] {
        if !sources
            .get(path)
            .and_then(Value::as_str)
            .is_some_and(loader::digest)
        {
            return Err("patch_map.source_fingerprints: missing prepared bridge input".into());
        }
    }
    for key in [
        "toolchain",
        "profiles",
        "profile_definitions",
        "flags",
        "cargo_configuration",
    ] {
        if !map["build"][key]
            .as_object()
            .is_some_and(|value| !value.is_empty())
        {
            return Err("patch_map.build: missing compiler contract".into());
        }
    }
    Ok((Some(digest.into()), vec![SLOT.into()]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_tampered_maps_fail_closed() {
        assert_eq!(identity(&serde_json::json!({})).unwrap(), (None, vec![]));
        let mut value: Value =
            serde_json::from_str(include_str!(env!("CM_HOST_IDENTITY_JSON"))).unwrap();
        assert_eq!(identity(&value).unwrap().1, vec![SLOT.to_string()]);
        value["patch_map"]["descriptor"]["slots"][0]["id"] = "unknown.slot".into();
        assert!(identity(&value).is_err());
        value["patch_map_sha256"] =
            loader::hash(&crate::config::json_bytes(&value["patch_map"])).into();
        assert!(identity(&value).is_err());
        value["patch_map"] = Value::Null;
        assert!(identity(&value).is_err());
    }

    #[test]
    fn matching_digest_does_not_qualify_an_incomplete_contract() {
        let original: Value =
            serde_json::from_str(include_str!(env!("CM_HOST_IDENTITY_JSON"))).unwrap();
        for pointer in [
            "/patch_map/build/target",
            "/patch_map/build/profile_definitions",
            "/patch_map/source_fingerprints/codex-rs~1Cargo.toml",
        ] {
            let mut value = original.clone();
            *value.pointer_mut(pointer).unwrap() = Value::Null;
            value["patch_map_sha256"] =
                loader::hash(&crate::config::json_bytes(&value["patch_map"])).into();
            assert!(identity(&value).is_err(), "{pointer}");
        }
    }
}
