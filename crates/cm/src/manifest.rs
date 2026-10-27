//! Versioned, non-executable package metadata. Legacy formats retain their contracts.
use serde::Deserialize;
use serde::Serialize;

use crate::config::Contract;
use crate::loader::Contribution;
use crate::loader::Dependency;
use crate::loader::Manifest;
use crate::loader::Resource;
use crate::loader::{self, Kind};
use crate::runtime_plan::HostIdentity;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ModKind {
    Sdk,
    ExactHost,
    AdvancedHook,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binary {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub target: String,
    pub entry: String,
    pub glibc_min: String,
    pub cpu: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExactHost {
    pub build_id: String,
    pub executable_sha256: String,
    pub patch_map_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Compatibility {
    pub abi_major: u16,
    pub abi_minor_min: u16,
    pub abi_minor_max: u16,
    pub host_api_min: String,
    pub required_capabilities: Vec<String>,
    pub exact_host: Option<ExactHost>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    pub repository: String,
    pub revision: String,
    pub release_notes: String,
    pub license: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub owner: String,
    pub schema: String,
    pub version: u32,
    pub preserve: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BinaryManifest {
    pub format_version: u32,
    pub id: String,
    pub version: String,
    pub kind: ModKind,
    pub binary: Binary,
    pub compat: Compatibility,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    pub contributions: Vec<Contribution>,
    #[serde(default)]
    pub resources: Vec<Resource>,
    pub config: Option<Contract>,
    pub state: Option<State>,
    pub provenance: Provenance,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Manifest, crate::LoadError> {
    let invalid =
        |owner: &str, message: &str| crate::LoadError::input("manifest_parse", owner, message);
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("", "manifest: invalid UTF-8"))?;
    let value: toml::Value =
        toml::from_str(text).map_err(|_| invalid("", "manifest: invalid TOML"))?;
    let owner = value
        .get("id")
        .and_then(toml::Value::as_str)
        .filter(|id| loader::identifier(id))
        .unwrap_or("")
        .to_string();
    if value
        .get("format_version")
        .and_then(toml::Value::as_integer)
        == Some(3)
    {
        let external: BinaryManifest = value
            .try_into()
            .map_err(|_| invalid(&owner, "manifest: invalid format 3 fields"))?;
        external.validate().map_err(|e| invalid(&owner, &e))?;
        let legacy = external.compat.abi_major == 1;
        Ok(Manifest {
            format_version: 3,
            id: external.id.clone(),
            version: external.version.clone(),
            payload: external.binary.path.clone(),
            payload_size: external.binary.size,
            payload_sha256: external.binary.sha256.clone(),
            target: external.binary.target.clone(),
            abi_major: external.compat.abi_major,
            abi_minor: external.compat.abi_minor_min,
            required_capabilities: external.compat.required_capabilities.clone(),
            dependencies: external.dependencies.clone(),
            contribution: if legacy {
                cm_abi::CONTRIBUTION.into()
            } else {
                String::new()
            },
            conflicts: external.conflicts.clone(),
            contributions: if legacy {
                Vec::new()
            } else {
                external.contributions.clone()
            },
            resources: external.resources.clone(),
            binary_manifest: Some(external),
        })
    } else {
        // Adding optional dependencies must not silently expand the old grammar.
        if value
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .is_some_and(|deps| deps.iter().any(|dep| dep.get("optional").is_some()))
        {
            return Err(invalid(
                &owner,
                "manifest.dependencies.optional requires format 3",
            ));
        }
        value
            .try_into()
            .map_err(|_| invalid(&owner, "manifest: invalid legacy fields"))
    }
}

impl BinaryManifest {
    fn validate(&self) -> Result<(), String> {
        let abi = &self.compat;
        let minor_max = match abi.abi_major {
            1 => 0,
            2 => 2,
            _ => return Err("compat.abi_major: unsupported".into()),
        };
        if self.format_version != 3
            || !loader::identifier(&self.id)
            || semver::Version::parse(&self.version).is_err()
        {
            return Err("identity: invalid format/id/SemVer".into());
        }
        if abi.abi_minor_min > abi.abi_minor_max
            || abi.abi_minor_max > minor_max
            || semver::Version::parse(&abi.host_api_min).is_err()
        {
            return Err("compat: invalid ABI interval or Host API SemVer".into());
        }
        let entry = if abi.abi_major == 1 {
            "cm_mod_entry_v1"
        } else {
            "cm_mod_entry_v2"
        };
        if self.binary.entry != entry
            || !self.binary.path.ends_with(".so")
            || self.binary.target != loader::TARGET
            || self.binary.cpu != "x86-64"
            || system_version(&self.binary.glibc_min).is_none()
        {
            return Err("binary: unsupported entry/path/target/CPU/glibc declaration".into());
        }
        loader::payload_path(std::path::Path::new("/package"), &self.binary.path)?;
        if self.contributions.is_empty()
            || self.contributions.len() > 128
            || self.dependencies.len() > 32
            || self.conflicts.len() > 32
            || self.resources.len() > 64
        {
            return Err("manifest: collection limit".into());
        }
        for dependency in &self.dependencies {
            if !loader::identifier(&dependency.id)
                || dependency.version.is_empty()
                || dependency.version.len() > 128
                || semver::VersionReq::parse(&dependency.version).is_err()
            {
                return Err("dependencies.version: invalid ID or SemVer range".into());
            }
        }
        if abi.required_capabilities.is_empty()
            || abi.required_capabilities.len() > 6
            || abi
                .required_capabilities
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != abi.required_capabilities.len()
        {
            return Err("compat.required_capabilities: empty/duplicate/oversized".into());
        }
        if abi.abi_major == 1
            && (self.config.is_some()
                || self.contributions.len() != 1
                || self.contributions[0].id != cm_abi::CONTRIBUTION
                || self.contributions[0].kind != Kind::LegacyFilter
                || self.contributions[0].capability != cm_abi::CAPABILITY
                || self.contributions[0].resource != cm_abi::CAPABILITY
                || !self.contributions[0].order_before.is_empty()
                || !self.contributions[0].order_after.is_empty()
                || self.contributions[0].priority != 0
                || abi.required_capabilities != [cm_abi::CAPABILITY])
        {
            return Err(
                "compat.abi_major: ABI 1.0 cannot receive configuration or composition".into(),
            );
        }
        match (&self.kind, &abi.exact_host) {
            (ModKind::Sdk, None) => {}
            (ModKind::ExactHost | ModKind::AdvancedHook, Some(exact))
                if exact.build_id.starts_with("sha256:")
                    && loader::digest(&exact.build_id[7..])
                    && loader::digest(&exact.executable_sha256)
                    && exact
                        .patch_map_sha256
                        .as_ref()
                        .is_none_or(|s| loader::digest(s))
                    && (self.kind != ModKind::AdvancedHook || exact.patch_map_sha256.is_some()) => {
            }
            _ => return Err("compat.exact_host: invalid binding for Mod kind".into()),
        }
        let p = &self.provenance;
        if !p.repository.starts_with("https://")
            || p.repository.len() > 512
            || ![40, 64].contains(&p.revision.len())
            || !p
                .revision
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            || p.license.is_empty()
            || p.license.len() > 128
            || p.release_notes.is_empty()
            || p.release_notes.len() > 2048
        {
            return Err("provenance: invalid source/revision/license/release notes".into());
        }
        if let Some(state) = &self.state
            && (state.owner != self.id || !loader::identifier(&state.schema) || state.version == 0)
        {
            return Err("state: invalid owner/schema/version".into());
        }
        if let Some(config) = &self.config {
            config.validate()?;
        }
        Ok(())
    }

    pub(crate) fn compatible(&self, host: &HostIdentity) -> Result<(), String> {
        if self.kind == ModKind::AdvancedHook {
            return Err("kind: advanced_hook is unsupported until G01 qualification".into());
        }
        let minimum =
            semver::Version::parse(&self.compat.host_api_min).map_err(|_| "compat.host_api_min")?;
        if semver::Version::parse(&host.api_version).map_err(|_| "Host API identity")? < minimum {
            return Err("compat.host_api_min: Host API is too old".into());
        }
        if let Some(exact) = &self.compat.exact_host
            && (exact.build_id != host.build_id
                || exact.executable_sha256 != host.executable_sha256)
        {
            return Err("compat.exact_host: Host build or executable digest differs".into());
        }
        let actual = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) }
            .to_str()
            .map_err(|_| "glibc identity")?;
        if system_version(actual) < system_version(&self.binary.glibc_min) {
            return Err("binary.glibc_min: current system is too old".into());
        }
        Ok(())
    }

    pub(crate) fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind, "binary": self.binary, "compat": self.compat,
            "dependencies": self.dependencies, "conflicts": self.conflicts,
            "state": self.state, "provenance": self.provenance,
            "config": self.config.as_ref().map(Contract::identity),
            "qualification": {"declared": true, "verified": false,
                "unsupported": self.kind == ModKind::AdvancedHook},
        })
    }
}

fn system_version(value: &str) -> Option<(u32, u32)> {
    let (major, minor) = value.split_once('.')?;
    if value.len() > 16
        || major.is_empty()
        || minor.is_empty()
        || !major
            .bytes()
            .chain(minor.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

#[cfg(test)]
mod tests {
    #[test]
    fn semver_prereleases_and_build_metadata_use_the_locked_library() {
        let req = semver::VersionReq::parse(">=1.2.3, <2.0.0").unwrap();
        assert!(req.matches(&semver::Version::parse("1.4.0+release").unwrap()));
        assert!(!req.matches(&semver::Version::parse("1.4.0-rc.1").unwrap()));
        assert!(
            super::parse(b"format_version = 3\npostinstall = 'secret'\n")
                .unwrap_err()
                .message
                .contains("format 3 fields")
        );
    }
}
