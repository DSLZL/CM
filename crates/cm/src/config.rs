//! CM-owned configuration, separate from CoreConfigToml. Values never enter reports.
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;

use crate::loader;

type Resolution = (BTreeMap<String, Vec<u8>>, BTreeMap<String, Identity>);

fn failure(owner: &str, message: &str) -> crate::LoadError {
    crate::LoadError::input("configuration", owner, message)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contract {
    pub schema_version: u32,
    pub schema: toml::Value,
    pub defaults: toml::Value,
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    pub profile: Option<String>,
    pub overrides: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    #[serde(default)]
    mods: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub format_version: u32,
    pub enabled: Vec<String>,
    pub profile: Option<String>,
    #[serde(default)]
    mods: BTreeMap<String, toml::Value>,
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub sha256: String,
    pub schema_sha256: String,
    pub defaults_sha256: String,
    pub sources: Vec<Source>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Source {
    pub layer: String,
    pub sha256: String,
    pub fields: Vec<String>,
}

pub(crate) fn json_bytes(value: &Value) -> Vec<u8> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let ordered: BTreeMap<_, _> = map.iter().map(|(k, v)| (k, sorted(v))).collect();
                serde_json::to_value(ordered).expect("JSON map serializes")
            }
            Value::Array(array) => Value::Array(array.iter().map(sorted).collect()),
            value => value.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).expect("bounded JSON serializes")
}

fn convert(value: &toml::Value, depth: usize) -> Result<Value, String> {
    if depth > 16 {
        return Err("config: maximum nesting depth is 16".into());
    }
    Ok(match value {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(n) => json!(n),
        toml::Value::Float(n) if n.is_finite() => json!(n),
        toml::Value::Boolean(b) => json!(b),
        toml::Value::Array(a) if a.len() <= 1024 => Value::Array(
            a.iter()
                .map(|v| convert(v, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        toml::Value::Table(t) if t.len() <= 1024 => {
            let sorted: BTreeMap<_, _> = t
                .iter()
                .map(|(k, v)| Ok((k.clone(), convert(v, depth + 1)?)))
                .collect::<Result<_, String>>()?;
            serde_json::to_value(sorted).expect("JSON map serializes")
        }
        _ => return Err("config: datetime/nonfinite/oversized value is unsupported".into()),
    })
}

fn schema(value: &Value, depth: usize) -> Result<(), String> {
    if depth > 16 {
        return Err("config.schema: depth limit".into());
    }
    let obj = value.as_object().ok_or("config.schema: expected object")?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or("config.schema.type: required")?;
    let allowed: &[&str] = match kind {
        "object" => &[
            "type",
            "properties",
            "required",
            "additionalProperties",
            "enum",
        ],
        "array" => &["type", "items", "minItems", "maxItems", "enum"],
        "string" => &["type", "minLength", "maxLength", "enum"],
        "integer" | "number" => &["type", "minimum", "maximum", "enum"],
        "boolean" => &["type", "enum"],
        _ => return Err("config.schema.type: unsupported".into()),
    };
    if obj.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("config.schema: unknown keyword".into());
    }
    if kind == "object" {
        if obj.get("additionalProperties") != Some(&Value::Bool(false)) {
            return Err("config.schema.additionalProperties must be false".into());
        }
        let properties = obj
            .get("properties")
            .and_then(Value::as_object)
            .ok_or("config.schema.properties: required object")?;
        for (key, child) in properties {
            if !loader::identifier(key) {
                return Err("config.schema.properties: invalid key".into());
            }
            schema(child, depth + 1)?;
        }
        if let Some(required) = obj.get("required") {
            let keys = required
                .as_array()
                .ok_or("config.schema.required: expected array")?;
            let mut seen = BTreeSet::new();
            for key in keys {
                let key = key
                    .as_str()
                    .ok_or("config.schema.required: expected field names")?;
                if !properties.contains_key(key) || !seen.insert(key) {
                    return Err("config.schema.required: unknown/duplicate field".into());
                }
            }
        }
    }
    if kind == "array" {
        schema(
            obj.get("items").ok_or("config.schema.items: required")?,
            depth + 1,
        )?;
    }
    for (lo, hi) in [
        ("minimum", "maximum"),
        ("minLength", "maxLength"),
        ("minItems", "maxItems"),
    ] {
        for key in [lo, hi] {
            if let Some(bound) = obj.get(key)
                && (bound.as_f64().is_none_or(|n| !n.is_finite())
                    || (lo != "minimum" && bound.as_u64().is_none())
                    || (lo == "minimum" && kind == "integer" && bound.as_i64().is_none()))
            {
                return Err("config.schema: invalid bound".into());
            }
        }
        if let (Some(lo), Some(hi)) = (obj.get(lo), obj.get(hi))
            && (lo.as_i64().zip(hi.as_i64()).is_some_and(|(a, b)| a > b)
                || lo.as_f64() > hi.as_f64())
        {
            return Err("config.schema: inverted bounds".into());
        }
    }
    if let Some(values) = obj.get("enum") {
        let values = values
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 128)
            .ok_or("config.schema.enum: bounded nonempty array required")?;
        for (i, v) in values.iter().enumerate() {
            if values[..i].contains(v) {
                return Err("config.schema.enum: duplicate value".into());
            }
            let mut without = value.clone();
            without.as_object_mut().unwrap().remove("enum");
            validate(&without, v, false, "config.schema.enum")?;
        }
    }
    Ok(())
}

fn validate(schema: &Value, value: &Value, partial: bool, path: &str) -> Result<(), String> {
    let fail = || format!("{path}: unknown field, invalid type or constraint");
    let kind = schema["type"].as_str().ok_or_else(fail)?;
    let valid = match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        _ => false,
    };
    if !valid {
        return Err(fail());
    }
    if !(partial && value.is_object())
        && schema
            .get("enum")
            .is_some_and(|e| !e.as_array().unwrap().contains(value))
    {
        return Err(fail());
    }
    if let Some(obj) = value.as_object() {
        let props = schema["properties"].as_object().ok_or_else(fail)?;
        for (key, v) in obj {
            let child = props.get(key).ok_or_else(|| {
                if loader::identifier(key) {
                    format!("{path}.{key}: unknown field")
                } else {
                    format!("{path}: invalid field name")
                }
            })?;
            validate(child, v, partial, &format!("{path}.{key}"))?;
        }
        if !partial && let Some(required) = schema.get("required") {
            for key in required.as_array().unwrap() {
                if !obj.contains_key(key.as_str().unwrap()) {
                    return Err(format!(
                        "{path}.{}: missing required field",
                        key.as_str().unwrap()
                    ));
                }
            }
        }
    }
    if let Some(a) = value.as_array() {
        for v in a {
            validate(&schema["items"], v, false, path)?;
        }
        bounds(schema, a.len() as f64, "minItems", "maxItems").map_err(|_| fail())?;
    }
    if let Some(s) = value.as_str() {
        bounds(schema, s.chars().count() as f64, "minLength", "maxLength").map_err(|_| fail())?;
    }
    if kind == "integer" {
        let n = value.as_i64().ok_or_else(fail)?;
        if schema
            .get("minimum")
            .and_then(Value::as_i64)
            .is_some_and(|v| n < v)
            || schema
                .get("maximum")
                .and_then(Value::as_i64)
                .is_some_and(|v| n > v)
        {
            return Err(fail());
        }
    } else if let Some(n) = value.as_f64() {
        bounds(schema, n, "minimum", "maximum").map_err(|_| fail())?;
    }
    Ok(())
}

fn bounds(schema: &Value, value: f64, min: &str, max: &str) -> Result<(), ()> {
    if schema
        .get(min)
        .and_then(Value::as_f64)
        .is_some_and(|n| value < n)
        || schema
            .get(max)
            .and_then(Value::as_f64)
            .is_some_and(|n| value > n)
    {
        Err(())
    } else {
        Ok(())
    }
}

fn merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (k, v) in overlay {
                merge(base.entry(k).or_insert(Value::Null), v);
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn fields(value: &Value, prefix: &str, result: &mut Vec<String>) {
    if let Some(obj) = value.as_object() {
        for (key, v) in obj {
            fields(v, &format!("{prefix}.{key}"), result);
        }
    } else {
        result.push(prefix.trim_start_matches('.').into());
    }
}

impl Contract {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("config.schema_version: unsupported".into());
        }
        let schema_value = convert(&self.schema, 0)?;
        let defaults = convert(&self.defaults, 0)?;
        if json_bytes(&schema_value).len() > 32 * 1024 || json_bytes(&defaults).len() > 32 * 1024 {
            return Err("config: contract byte limit".into());
        }
        schema(&schema_value, 0)?;
        if schema_value["type"] != "object" {
            return Err("config.schema.type must be object".into());
        }
        validate(&schema_value, &defaults, true, "config.defaults")
    }

    pub(crate) fn identity(&self) -> Value {
        json!({"schema_version": self.schema_version,
            "schema_sha256": loader::hash(&json_bytes(&convert(&self.schema, 0).expect("validated schema"))),
            "defaults_sha256": loader::hash(&json_bytes(&convert(&self.defaults, 0).expect("validated defaults")))})
    }

    fn effective(
        &self,
        layers: Vec<(&str, Value)>,
        complete: bool,
    ) -> Result<(Vec<u8>, Identity), String> {
        let schema = convert(&self.schema, 0)?;
        let defaults = convert(&self.defaults, 0)?;
        let schema_sha256 = loader::hash(&json_bytes(&schema));
        let defaults_sha256 = loader::hash(&json_bytes(&defaults));
        let mut value = defaults;
        let mut sources = Vec::new();
        for (layer, overlay) in std::iter::once(("defaults", value.clone())).chain(layers) {
            validate(&schema, &overlay, true, "config")?;
            let mut names = Vec::new();
            fields(&overlay, "", &mut names);
            names.sort();
            sources.push(Source {
                layer: layer.into(),
                sha256: loader::hash(&json_bytes(&overlay)),
                fields: names,
            });
            merge(&mut value, overlay);
        }
        validate(&schema, &value, !complete, "config")?;
        let bytes = json_bytes(&value);
        if bytes.len() > loader::MAX_MANIFEST as usize {
            return Err("config: effective byte limit".into());
        }
        Ok((
            bytes.clone(),
            Identity {
                sha256: loader::hash(&bytes),
                schema_sha256,
                defaults_sha256,
                sources,
            },
        ))
    }
}

impl Selection {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "selection: invalid UTF-8")?;
        let value: toml::Value = toml::from_str(text).map_err(|_| "selection: invalid TOML")?;
        convert(&value, 0)?;
        if value
            .get("format_version")
            .and_then(toml::Value::as_integer)
            == Some(1)
            && value.as_table().is_some_and(|t| {
                t.keys()
                    .any(|k| !["format_version", "enabled"].contains(&k.as_str()))
            })
        {
            return Err("selection: format 1 only supports enabled".into());
        }
        let selection: Self = value.try_into().map_err(|_| "selection: invalid fields")?;
        if ![1, 2].contains(&selection.format_version) {
            return Err("selection.format_version: unsupported".into());
        }
        Ok(selection)
    }

    pub(crate) fn resolve(
        &self,
        options: &Options,
        manifests: &BTreeMap<String, loader::Manifest>,
        original: &[u8],
        retain_uninstalled: bool,
    ) -> Result<Resolution, crate::LoadError> {
        for id in self
            .mods
            .keys()
            .chain(self.profiles.values().flat_map(|p| p.mods.keys()))
        {
            if !loader::identifier(id) || (!retain_uninstalled && !manifests.contains_key(id)) {
                return Err(failure("", "config: unknown Mod namespace"));
            }
        }
        if options.overrides.len() > 128
            || options.overrides.iter().map(String::len).sum::<usize>() > 64 * 1024
        {
            return Err(failure("", "config: override limit"));
        }
        let name = options.profile.as_ref().or(self.profile.as_ref());
        if self.profiles.keys().any(|name| !loader::identifier(name))
            || name.is_some_and(|name| !loader::identifier(name))
        {
            return Err(failure("", "config.profile: invalid name"));
        }
        let profile = name
            .map(|name| {
                self.profiles.get(name).ok_or_else(|| {
                    failure("", "config.profile: selected CM profile does not exist")
                })
            })
            .transpose()?;
        let mut cli: BTreeMap<String, Value> = BTreeMap::new();
        for input in &options.overrides {
            let (path, text) = input
                .split_once('=')
                .ok_or_else(|| failure("", "config.parameters: expected Mod.field=TOML-value"))?;
            let parts: Vec<_> = path.split('.').collect();
            // Mod IDs can contain dots: choose the longest installed namespace.
            let owner = manifests
                .keys()
                .filter(|id| path.starts_with(&format!("{id}.")))
                .max_by_key(|id| id.len())
                .ok_or_else(|| failure("", "config.parameters: unknown override namespace"))?;
            let suffix = &path[owner.len() + 1..];
            if parts.len() > 18 || !suffix.split('.').all(loader::identifier) {
                return Err(failure(owner, "config.parameters: invalid override path"));
            }
            let parsed: toml::Table = toml::from_str(&format!("value={text}"))
                .map_err(|_| failure(owner, "config.parameters: invalid override TOML value"))?;
            if parsed.len() != 1 {
                return Err(failure(
                    owner,
                    "config.parameters: override must contain one value",
                ));
            }
            let mut value = convert(
                parsed
                    .get("value")
                    .ok_or_else(|| failure(owner, "config.parameters: missing override value"))?,
                0,
            )
            .map_err(|e| failure(owner, &e))?;
            for key in suffix.split('.').rev() {
                value = json!({key: value});
            }
            merge(cli.entry(owner.clone()).or_insert_with(|| json!({})), value);
        }
        let legacy = if self.format_version == 1 || original.is_empty() {
            original.to_vec()
        } else {
            let mut enabled = self.enabled.clone();
            enabled.sort();
            toml::to_string(&LegacySelection {
                format_version: 1,
                enabled,
            })
            .map_err(|_| failure("", "config: selection projection failed"))?
            .into_bytes()
        };
        let mut values = BTreeMap::new();
        let mut identities = BTreeMap::new();
        for (id, manifest) in manifests {
            let contract = manifest
                .binary_manifest
                .as_ref()
                .and_then(|m| m.config.as_ref());
            let user = self.mods.get(id);
            let selected = profile.and_then(|p| p.mods.get(id));
            let parameters = cli.remove(id);
            if let Some(contract) = contract {
                let mut layers = Vec::new();
                if let Some(v) = user {
                    layers.push(("user", convert(v, 0).map_err(|e| failure(id, &e))?));
                }
                if let Some(v) = selected {
                    layers.push(("profile", convert(v, 0).map_err(|e| failure(id, &e))?));
                }
                if let Some(v) = parameters {
                    layers.push(("parameters", v));
                }
                let (bytes, identity) = contract
                    .effective(layers, self.enabled.contains(id))
                    .map_err(|e| failure(id, &e))?;
                values.insert(id.clone(), bytes);
                identities.insert(id.clone(), identity);
            } else {
                if user.is_some() || selected.is_some() || parameters.is_some() {
                    return Err(failure(id, "config: Mod has no configuration contract"));
                }
                values.insert(
                    id.clone(),
                    if manifest.format_version < 3 {
                        legacy.clone()
                    } else {
                        b"{}".to_vec()
                    },
                );
            }
        }
        Ok((values, identities))
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn managed_removed_configuration_is_inert_and_unmanaged_remains_strict() {
        let bytes = br#"format_version = 2
enabled = []
[mods.removed]
value = "preserved"
[profiles.review.mods.removed]
value = "also-preserved"
"#;
        let selection = Selection::parse(bytes).unwrap();
        let manifests = BTreeMap::new();
        assert!(selection.resolve(&Options::default(), &manifests, bytes, false).is_err());
        let options = Options { profile: Some("review".into()), overrides: Vec::new() };
        let (values, identities) = selection.resolve(&options, &manifests, bytes, true).unwrap();
        assert!(values.is_empty() && identities.is_empty());
        let options = Options { overrides: vec!["removed.value=1".into()], ..Options::default() };
        assert!(selection.resolve(&options, &manifests, bytes, true).is_err());
    }
}

#[derive(Serialize)]
struct LegacySelection {
    format_version: u32,
    enabled: Vec<String>,
}

pub(crate) fn absent(enabled: Vec<String>) -> Selection {
    Selection {
        format_version: 2,
        enabled,
        profile: None,
        mods: BTreeMap::new(),
        profiles: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layers_merge_objects_replace_arrays_and_enforce_required_after_merge() {
        let contract: Contract = toml::from_str(
            r#"
schema_version=1
[schema]
type="object"
additionalProperties=false
required=["token", "count"]
[schema.properties.token]
type="string"
[schema.properties.count]
type="integer"
minimum=1
[defaults]
count=2
"#,
        )
        .unwrap();
        contract.validate().unwrap();
        assert!(contract.effective(vec![], true).is_err());
        let (bytes, identity) = contract
            .effective(
                vec![
                    ("user", json!({"token":"secret"})),
                    ("parameters", json!({"count":3})),
                ],
                true,
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"count":3,"token":"secret"})
        );
        assert!(!serde_json::to_string(&identity).unwrap().contains("secret"));
        assert!(
            contract
                .effective(vec![("user", json!({"token":"secret","count":0}))], true)
                .is_err()
        );
        let mut value = json!({"nested":{"a":1}, "arr":[1,2]});
        merge(&mut value, json!({"nested":{"b":2}, "arr":[3]}));
        assert_eq!(value, json!({"nested":{"a":1,"b":2}, "arr":[3]}));
    }

    #[test]
    fn malformed_secret_unknown_keywords_and_toml_dates_are_redacted() {
        assert!(
            !Selection::parse(b"format_version=2\nenabled=[]\ntoken=SECRET")
                .err()
                .unwrap()
                .contains("SECRET")
        );
        assert!(schema(&json!({"type":"string","$ref":"https://example.com"}), 0).is_err());
        let date: toml::Value = toml::from_str("date=2020-01-01").unwrap();
        assert!(convert(&date, 0).is_err());
    }

    #[test]
    fn integer_bounds_do_not_round_at_the_float_precision_boundary() {
        let schema_value = json!({"type":"integer", "minimum":9007199254740993_i64});
        schema(&schema_value, 0).unwrap();
        assert!(
            validate(
                &schema_value,
                &json!(9007199254740992_i64),
                false,
                "config.count"
            )
            .is_err()
        );
        assert!(
            validate(
                &schema_value,
                &json!(9007199254740993_i64),
                false,
                "config.count"
            )
            .is_ok()
        );
        assert!(schema(&json!({"type":"integer", "minimum":9007199254740993_i64, "maximum":9007199254740992_i64}), 0).is_err());
    }
}
