//! Data-only planning and owned input snapshots. No native entry runs here.
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use cm_abi::v2;
use serde::Serialize;

use crate::LoadError;
use crate::loader;
use crate::loader::Contribution;
use crate::loader::InputPin;
use crate::loader::Inventory;
use crate::loader::Kind;
use crate::loader::Manifest;
use crate::loader::Preflighted;

const IDENTITY: &str = include_str!(env!("CM_HOST_IDENTITY_JSON"));
const DOMAIN: &str = "cm.runtime-plan.v1";

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HostIdentity {
    pub build_id: String,
    pub executable_sha256: String,
    pub target: String,
    pub api_version: String,
    pub capabilities: Vec<String>,
    pub abis: Vec<String>,
}

impl HostIdentity {
    pub(crate) fn read(executable: &Path) -> Result<Self, LoadError> {
        let value: serde_json::Value = serde_json::from_str(IDENTITY)
            .map_err(|e| LoadError::input("host_identity", "", &e.to_string()))?;
        let field = |name: &str| -> Result<String, LoadError> {
            value[name]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| LoadError::input("host_identity", "", name))
        };
        let mut capabilities: Vec<String> =
            serde_json::from_value(value["capabilities"].clone())
                .map_err(|e| LoadError::input("host_identity", "", &e.to_string()))?;
        capabilities.sort();
        Ok(Self {
            build_id: field("host_build_id")?,
            executable_sha256: loader::executable_hash(executable)
                .map_err(|e| LoadError::input("host_identity", "", &e))?,
            target: loader::TARGET.into(),
            api_version: field("host_api_version")?,
            capabilities,
            abis: vec!["1.0".into(), "2.0".into(), "2.1".into(), "2.2".into()],
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigIdentity {
    pub present: bool,
    pub sha256: Option<String>,
    pub mods: BTreeMap<String, crate::config::Identity>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlannedMod {
    pub version: String,
    pub manifest_sha256: String,
    pub payload_sha256: String,
    pub payload_size: u64,
    pub abi: String,
    pub content_tree_sha256: String,
    pub package_format: String,
    pub format_version: u32,
    pub(crate) dependencies: Vec<loader::Dependency>,
    pub metadata: Option<serde_json::Value>,
    pub(crate) contributions: Vec<Contribution>,
    pub(crate) resources: Vec<loader::Resource>,
}

/// Canonical arrays/maps never contain paths, inode numbers, or discovery order.
#[derive(Clone, Debug, Serialize)]
pub struct RuntimePlan {
    pub schema_version: u32,
    pub domain: String,
    pub host: HostIdentity,
    pub config: ConfigIdentity,
    pub candidate_manifests: BTreeMap<String, String>,
    pub candidate_contents: BTreeMap<String, String>,
    pub mods: BTreeMap<String, PlannedMod>,
    pub dependency_edges: Vec<(String, String)>,
    pub initialization_order: Vec<String>,
    pub hook_edges: Vec<(String, String)>,
    pub phases: BTreeMap<String, Vec<String>>,
    pub exclusive: Option<String>,
}

impl RuntimePlan {
    pub fn sha256(&self) -> String {
        // Serialization of these fixed DTOs cannot fail.
        loader::hash(&serde_json::to_vec(self).expect("RuntimePlan serializes"))
    }
}

type CommittedPlan = (RuntimePlan, Vec<Preflighted>, BTreeMap<String, Vec<u8>>);

/// Opaque, process-owned inputs. A serialized RuntimePlan cannot construct this.
pub struct PreparedPlan {
    home: PathBuf,
    inventory: Inventory,
    pins: Vec<(String, InputPin)>,
    config_present: bool,
    config: BTreeMap<String, Vec<u8>>,
    trees: Vec<(PathBuf, BTreeSet<String>)>,
    plan: RuntimePlan,
    modules: BTreeMap<String, Preflighted>,
}

impl PreparedPlan {
    pub fn plan(&self) -> &RuntimePlan {
        &self.plan
    }

    pub(crate) fn revalidate(&self) -> Result<(), LoadError> {
        let drift = |owner: &str, text: &str| LoadError::input("input_drift", owner, text);
        if loader::inventory(&self.home).map_err(|e| drift("", &e))? != self.inventory {
            return Err(drift("", "candidate inventory changed"));
        }
        for (owner, pin) in &self.pins {
            pin.revalidate().map_err(|e| drift(owner, &e))?;
        }
        for (package, entries) in &self.trees {
            if loader::directory_entries(package).map_err(|e| drift("", &e))? != *entries {
                return Err(drift("", "package directory entries changed"));
            }
        }
        if !self.config_present
            && exists(&self.home.join("cm-runtime.toml")).map_err(|e| drift("", &e))?
        {
            return Err(drift("", "previously absent configuration now exists"));
        }
        let current = HostIdentity::read(Path::new("/proc/self/exe"))
            .map_err(|e| drift("", &e.to_string()))?;
        if current != self.plan.host {
            return Err(drift("", "current Host differs from the planned Host"));
        }
        Ok(())
    }

    pub(crate) fn commit(self) -> Result<CommittedPlan, LoadError> {
        self.revalidate()?;
        // Input linearization: only owned snapshots are consumed after this point.
        let mut modules = self.modules;
        let ordered = self
            .plan
            .initialization_order
            .iter()
            .map(|id| modules.remove(id).expect("resolved module exists"))
            .collect();
        Ok((self.plan, ordered, self.config))
    }
}

fn exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn reserved(id: &str) -> bool {
    id == "cm" || id == "core" || id.starts_with("cm.") || id.starts_with("core.")
}

fn failure(code: &str, id: &str, contribution: Option<&str>, message: &str) -> LoadError {
    LoadError::input(code, id, message).owner(id, contribution)
}

pub(crate) fn resource_error(mut error: LoadError, hooks: &[Contribution]) -> LoadError {
    let limiter = if let Some(id) = error.contribution.as_deref() {
        hooks
            .iter()
            .find(|hook| Some(hook.id.as_str()) == id.rsplit("::").next())
            .is_some_and(|hook| hook.kind == Kind::OutputLimit)
    } else {
        !hooks.is_empty() && hooks.iter().all(|hook| hook.kind == Kind::OutputLimit)
    };
    if limiter {
        error.resource = Some(cm_abi::v21::CAPABILITY.into());
    }
    error
}

fn stable_order(
    nodes: BTreeSet<String>,
    edges: &BTreeSet<(String, String)>,
    code: &str,
) -> Result<Vec<String>, LoadError> {
    let mut incoming: BTreeMap<String, usize> = nodes.iter().map(|id| (id.clone(), 0)).collect();
    for (_, to) in edges {
        *incoming.get_mut(to).expect("edge target was validated") += 1;
    }
    let mut ready: BTreeSet<String> = incoming
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::new();
    while let Some(id) = ready.pop_first() {
        for (_, to) in edges.iter().filter(|(from, _)| from == &id) {
            let count = incoming.get_mut(to).unwrap();
            *count -= 1;
            if *count == 0 {
                ready.insert(to.clone());
            }
        }
        order.push(id);
    }
    if order.len() != nodes.len() {
        let remaining: Vec<_> = nodes
            .difference(&order.iter().cloned().collect())
            .cloned()
            .collect();
        let owner = remaining[0].split("::").next().unwrap_or("");
        return Err(failure(
            code,
            owner,
            remaining.first().map(String::as_str),
            &format!("cycle among {remaining:?}"),
        ));
    }
    Ok(order)
}

fn phase(kind: &Kind) -> &'static str {
    match kind {
        Kind::Before => "before",
        Kind::Around | Kind::Replacement => "body",
        Kind::LegacyFilter => "legacy_filter",
        Kind::After => "after",
        Kind::OutputLimit => "output_limit",
        Kind::Lifecycle => "lifecycle",
        Kind::Tool => "tool",
        Kind::ContextSection => "context_section",
    }
}

fn resolve(
    selected: &BTreeMap<String, (Manifest, String)>,
    host: HostIdentity,
    config: ConfigIdentity,
    candidate_manifests: BTreeMap<String, String>,
) -> Result<RuntimePlan, LoadError> {
    let mut dependency_edges = BTreeSet::new();
    let mut hooks: BTreeMap<String, (&str, Contribution)> = BTreeMap::new();
    let mut mods = BTreeMap::new();
    let mut replacements = Vec::new();
    let mut payload_budget = 0_u64;
    let mut resource_budget = 0_u64;
    let mut resource_count = 0;
    let mut runtime_names = BTreeMap::new();
    for (id, (manifest, manifest_sha256)) in selected {
        loader::check_manifest(manifest).map_err(|e| failure("manifest_contract", id, None, &e))?;
        if let Some(binary) = &manifest.binary_manifest {
            binary
                .compatible(&host)
                .map_err(|e| failure("compatibility", id, None, &e))?;
        }
        if reserved(id) {
            return Err(failure("reserved_name", id, None, "reserved Mod namespace"));
        }
        if !manifest
            .required_capabilities
            .iter()
            .all(|cap| host.capabilities.contains(cap))
        {
            return Err(failure(
                "unknown_capability",
                id,
                None,
                "Host does not advertise capability",
            ));
        }
        let mut seen = BTreeSet::new();
        for dependency in &manifest.dependencies {
            if !loader::identifier(&dependency.id)
                || dependency.version.len() > 128
                || (manifest.format_version < 3
                    && (!loader::version(&dependency.version) || dependency.optional))
                || (manifest.format_version == 3
                    && semver::VersionReq::parse(&dependency.version).is_err())
            {
                return Err(failure(
                    "unsupported_version",
                    id,
                    None,
                    "dependencies.version: invalid version constraint",
                ));
            }
            if dependency.id == *id || !seen.insert(dependency.id.clone()) {
                return Err(failure(
                    "dependency",
                    id,
                    None,
                    "self or duplicate dependency",
                ));
            }
            let Some(other) = selected.get(&dependency.id) else {
                if dependency.optional {
                    continue;
                }
                return Err(failure(
                    "missing_dependency",
                    id,
                    None,
                    &format!("missing {}", dependency.id),
                ));
            };
            let matches = if manifest.format_version == 3 {
                let version = semver::Version::parse(&other.0.version).map_err(|_| {
                    failure(
                        "dependency_version",
                        id,
                        None,
                        "dependencies: selected version is not SemVer",
                    )
                })?;
                semver::VersionReq::parse(&dependency.version)
                    .expect("checked range")
                    .matches(&version)
            } else {
                other.0.version == dependency.version
            };
            if !matches {
                return Err(failure(
                    "dependency_version",
                    id,
                    None,
                    &format!("{} requires {}={}", id, dependency.id, dependency.version),
                ));
            }
            dependency_edges.insert((dependency.id.clone(), id.clone()));
        }
        seen.clear();
        for conflict in &manifest.conflicts {
            if !loader::identifier(conflict) || conflict == id || !seen.insert(conflict.clone()) {
                return Err(failure(
                    "conflict",
                    id,
                    None,
                    "invalid or duplicate conflict declaration",
                ));
            }
            if selected.contains_key(conflict) {
                return Err(failure(
                    "declared_conflict",
                    id,
                    None,
                    &format!("conflicting Mods: {id}, {conflict}"),
                ));
            }
        }
        payload_budget += manifest.payload_size;
        let mut paths = BTreeSet::from(["mod.toml".to_string(), manifest.payload.clone()]);
        loader::payload_path(Path::new("/package"), &manifest.payload)
            .map_err(|e| failure("payload_path", id, None, &e))?;
        if manifest.payload == "mod.toml" {
            return Err(failure(
                "payload_path",
                id,
                None,
                "payload overlaps manifest",
            ));
        }
        let mut resources = manifest.resources.clone();
        resources.sort_by(|a, b| a.path.cmp(&b.path));
        for resource in &resources {
            loader::payload_path(Path::new("/package"), &resource.path)
                .map_err(|e| failure("resource_path", id, None, &e))?;
            if !paths.insert(resource.path.clone()) || resource.size > loader::MAX_RESOURCE {
                return Err(failure(
                    "resource",
                    id,
                    None,
                    "duplicate/overlapping or oversized resource",
                ));
            }
            resource_count += 1;
            resource_budget = resource_budget
                .checked_add(resource.size)
                .ok_or_else(|| failure("budget", id, None, "resource size overflow"))?;
        }
        let mut contributions = manifest.hooks();
        contributions.sort_by(|a, b| a.id.cmp(&b.id));
        for contribution in &mut contributions {
            if manifest.abi_major == 2
                && (!loader::identifier(&contribution.id)
                    || reserved(&contribution.id)
                    || contribution.kind == Kind::LegacyFilter)
            {
                return Err(failure(
                    "reserved_name",
                    id,
                    Some(&contribution.id),
                    "invalid/reserved contribution",
                ));
            }
            let capability = if manifest.abi_major == 1 {
                cm_abi::CAPABILITY
            } else {
                v2::CAPABILITY
            };
            let limiter = contribution.kind == Kind::OutputLimit;
            let contract = if contribution.kind.runtime() {
                let capability = match contribution.kind {
                    Kind::Lifecycle => cm_abi::v22::LIFECYCLE,
                    Kind::Tool => cm_abi::v22::TOOL,
                    Kind::ContextSection => cm_abi::v22::CONTEXT_SECTION,
                    _ => unreachable!("runtime kind"),
                };
                manifest.format_version == 3 && manifest.abi_major == 2 && manifest.abi_minor == 2
                    && contribution.capability == capability
                    && manifest.required_capabilities.contains(&contribution.capability)
                    && crate::runtime::valid_name(id, &contribution.resource)
                    && contribution.priority == 0
                    && contribution.order_before.is_empty() && contribution.order_after.is_empty()
            } else if limiter {
                manifest.abi_major == 2
                    && manifest.abi_minor >= 1
                    && contribution.resource == cm_abi::v21::CAPABILITY
                    && contribution.capability == cm_abi::v21::CAPABILITY
                    && manifest
                        .required_capabilities
                        .contains(&contribution.capability)
                    && contribution.priority == 0
                    && contribution.order_before.is_empty()
                    && contribution.order_after.is_empty()
            } else {
                contribution.resource == cm_abi::CAPABILITY
                    && contribution.capability == capability
                    && manifest
                        .required_capabilities
                        .contains(&contribution.capability)
            };
            if !contract || !(-1_000_000..=1_000_000).contains(&contribution.priority) {
                return Err(failure(
                    "contribution_contract",
                    id,
                    Some(&contribution.id),
                    "unknown resource/capability or priority out of bounds",
                ));
            }
            if contribution.kind.runtime() {
                let name = (contribution.kind.abi(), contribution.resource.clone());
                if let Some(previous) = runtime_names.insert(name, format!("{id}::{}", contribution.id)) {
                    return Err(failure("runtime_name_collision", id, Some(&contribution.id),
                        &format!("runtime name {} claimed by {previous} and {id}::{}", contribution.resource, contribution.id)));
                }
                if runtime_names.len() > 128 {
                    return Err(failure("runtime_contribution_limit", id, Some(&contribution.id), "process runtime contribution limit is 128"));
                }
            }
            for references in [
                &mut contribution.order_before,
                &mut contribution.order_after,
            ] {
                references.sort();
                if references.windows(2).any(|pair| pair[0] == pair[1]) || references.len() > 128 {
                    return Err(failure(
                        "hook_reference",
                        id,
                        Some(&contribution.id),
                        "duplicate/too many order references",
                    ));
                }
            }
            let key = format!("{id}::{}", contribution.id);
            if contribution.kind == Kind::Replacement {
                replacements.push(key.clone());
            }
            if hooks.insert(key, (id, contribution.clone())).is_some() {
                return Err(failure(
                    "duplicate_contribution",
                    id,
                    Some(&contribution.id),
                    "duplicate contribution",
                ));
            }
        }
        let content_tree_sha256 = loader::hash(
            &serde_json::to_vec(&(manifest_sha256, &manifest.payload_sha256, &resources))
                .expect("content tree serializes"),
        );
        mods.insert(
            id.clone(),
            PlannedMod {
                version: manifest.version.clone(),
                manifest_sha256: manifest_sha256.clone(),
                payload_sha256: manifest.payload_sha256.clone(),
                payload_size: manifest.payload_size,
                abi: format!("{}.{}", manifest.abi_major, manifest.abi_minor),
                content_tree_sha256,
                package_format: "directory".into(),
                format_version: manifest.format_version,
                dependencies: manifest.dependencies.clone(),
                metadata: manifest
                    .binary_manifest
                    .as_ref()
                    .map(crate::manifest::BinaryManifest::summary),
                contributions,
                resources,
            },
        );
    }
    if hooks.len() > 128
        || resource_count > 64
        || payload_budget > 256 * 1024 * 1024
        || resource_budget > 64 * 1024 * 1024
    {
        return Err(failure(
            "budget",
            "",
            None,
            "runtime set exceeds contribution/resource/byte budget",
        ));
    }
    // Exclusive claims are rejected before priority or order can influence resolution.
    if replacements.len() > 1 {
        return Err(failure(
            "exclusive_conflict",
            replacements[0].split("::").next().unwrap(),
            Some(&replacements[0]),
            &format!(
                "exclusive {} claimed by {replacements:?}",
                cm_abi::CAPABILITY
            ),
        ));
    }
    let mut hook_edges = BTreeSet::new();
    for (key, (owner, contribution)) in &hooks {
        for (references, before) in [
            (&contribution.order_before, true),
            (&contribution.order_after, false),
        ] {
            for reference in references {
                let (_, target) = hooks.get(reference).ok_or_else(|| {
                    failure(
                        "missing_hook",
                        owner,
                        Some(key),
                        &format!("unknown contribution {reference}"),
                    )
                })?;
                if key == reference
                    || contribution.resource != target.resource
                    || phase(&contribution.kind) != phase(&target.kind)
                {
                    return Err(failure(
                        "unsupported_hook_order",
                        owner,
                        Some(key),
                        &format!("self, cross-resource or cross-phase reference {reference}"),
                    ));
                }
                // Replacement is terminal; an order edge cannot move it outside around wrappers.
                if (contribution.kind == Kind::Replacement && before)
                    || (target.kind == Kind::Replacement && !before)
                {
                    return Err(failure(
                        "unsupported_hook_order",
                        owner,
                        Some(key),
                        "replacement must remain terminal",
                    ));
                }
                hook_edges.insert(if before {
                    (key.clone(), reference.clone())
                } else {
                    (reference.clone(), key.clone())
                });
            }
        }
    }
    let initialization_order = stable_order(
        selected.keys().cloned().collect(),
        &dependency_edges,
        "dependency_cycle",
    )?;
    let mut phases = BTreeMap::new();
    for name in ["before", "body", "legacy_filter", "after", "output_limit", "lifecycle", "tool", "context_section"] {
        let nodes: BTreeSet<_> = hooks
            .iter()
            .filter(|(_, (_, hook))| phase(&hook.kind) == name)
            .map(|(key, _)| key.clone())
            .collect();
        let edges: BTreeSet<_> = hook_edges
            .iter()
            .filter(|(from, _)| nodes.contains(from))
            .cloned()
            .collect();
        let mut order = stable_order(nodes, &edges, "hook_cycle")?;
        if name == "body"
            && let Some(replacement) = replacements.first()
        {
            order.retain(|key| key != replacement);
            order.push(replacement.clone());
        }
        if !matches!(name, "output_limit" | "lifecycle" | "tool" | "context_section") || !order.is_empty() {
            phases.insert(name.into(), order);
        }
    }
    Ok(RuntimePlan {
        schema_version: 1,
        domain: DOMAIN.into(),
        host,
        config,
        candidate_manifests,
        candidate_contents: BTreeMap::new(),
        mods,
        dependency_edges: dependency_edges.into_iter().collect(),
        initialization_order,
        hook_edges: hook_edges.into_iter().collect(),
        phases,
        exclusive: replacements.pop(),
    })
}

pub fn prepare(home: &Path) -> Result<PreparedPlan, LoadError> {
    prepare_options(home, &crate::config::Options::default())
}

pub fn prepare_options(
    home: &Path,
    options: &crate::config::Options,
) -> Result<PreparedPlan, LoadError> {
    prepare_inputs(home, Path::new("/proc/self/exe"), options)
}

/// Probe-only counterfactual identity; commit still requires the current executable.
pub fn prepare_for_executable(home: &Path, executable: &Path) -> Result<PreparedPlan, LoadError> {
    prepare_inputs(home, executable, &crate::config::Options::default())
}

fn prepare_inputs(
    home: &Path,
    executable: &Path,
    options: &crate::config::Options,
) -> Result<PreparedPlan, LoadError> {
    let inventory = loader::inventory(home).map_err(|e| failure("inventory", "", None, &e))?;
    let mut candidates = BTreeMap::new();
    let mut pins = Vec::new();
    let mut trees = Vec::new();
    let mut snapshot_bytes = 0_usize;
    for directory in inventory.packages.keys() {
        let package = home.join("mods").join(directory);
        let candidate = loader::candidate(&package).map_err(|mut error| {
            if error.mod_id.is_none() {
                error.mod_id = Some(directory.clone());
            }
            error
        })?;
        let manifest = &candidate.manifest;
        snapshot_bytes += candidate.snapshot_size();
        if snapshot_bytes > 256 * 1024 * 1024 {
            return Err(failure(
                "budget",
                &manifest.id,
                None,
                "candidate snapshot byte limit",
            ));
        }
        if !loader::identifier(&manifest.id) {
            return Err(failure("manifest_id", &manifest.id, None, "invalid Mod ID"));
        }
        pins.extend(
            candidate
                .pins
                .iter()
                .cloned()
                .map(|pin| (manifest.id.clone(), pin)),
        );
        if let Some(tree) = &candidate.tree {
            trees.push((package, tree.clone()));
        }
        let id = manifest.id.clone();
        if candidates.insert(id.clone(), candidate).is_some() {
            return Err(failure("duplicate_mod", &id, None, "duplicate Mod ID"));
        }
    }
    let config_path = home.join("cm-runtime.toml");
    let config_present = exists(&config_path).map_err(|e| failure("selection", "", None, &e))?;
    let (config, selection, config_sha) = if config_present {
        let (bytes, pin) = loader::read_input(&config_path, loader::MAX_MANIFEST)
            .map_err(|e| failure("selection", "", None, &e))?;
        let selection = crate::config::Selection::parse(&bytes)
            .map_err(|e| failure("selection", "", None, &e))?;
        let sha = Some(pin.sha256.clone());
        pins.push((String::new(), pin));
        (bytes, selection, sha)
    } else {
        (
            Vec::new(),
            crate::config::absent(candidates.keys().cloned().collect()),
            None,
        )
    };
    let mut enabled = BTreeSet::new();
    for id in &selection.enabled {
        if !candidates.contains_key(id) || !enabled.insert(id.clone()) {
            return Err(failure(
                "selection",
                id,
                None,
                "unknown or duplicate selected Mod",
            ));
        }
    }
    let manifests: BTreeMap<_, _> = candidates
        .iter()
        .map(|(id, candidate)| (id.clone(), candidate.manifest.clone()))
        .collect();
    let (config_values, config_identities) = selection.resolve(options, &manifests, &config)?;
    let selected: BTreeMap<_, _> = candidates
        .iter()
        .filter(|(id, _)| enabled.contains(*id))
        .map(|(id, candidate)| {
            (
                id.clone(),
                (
                    candidate.manifest.clone(),
                    candidate.manifest_sha256.clone(),
                ),
            )
        })
        .collect();
    let candidate_manifests = candidates
        .iter()
        .map(|(id, candidate)| (id.clone(), candidate.manifest_sha256.clone()))
        .collect();
    let mut plan = resolve(
        &selected,
        HostIdentity::read(executable)?,
        ConfigIdentity {
            present: config_present,
            sha256: config_sha,
            mods: config_identities,
        },
        candidate_manifests,
    )
    .map_err(|error| {
        if let Some((manifest, _)) = error.mod_id.as_ref().and_then(|id| selected.get(id)) {
            resource_error(error, &manifest.hooks())
        } else {
            error
        }
    })?;
    plan.candidate_contents = candidates
        .iter()
        .map(|(id, candidate)| (id.clone(), candidate.content_sha256.clone()))
        .collect();
    for (id, module) in &mut plan.mods {
        if module.format_version == 3 {
            module.content_tree_sha256 = candidates[id].content_sha256.clone();
            module.package_format = "cm.content.v1".into();
        }
    }
    let mut modules = BTreeMap::new();
    for id in &plan.initialization_order {
        let candidate = candidates.remove(id).unwrap();
        let hooks = candidate.manifest.hooks();
        let (module, inputs) = candidate
            .prepare()
            .map_err(|e| resource_error(failure("package_input", id, None, &e), &hooks))?;
        pins.extend(inputs.into_iter().map(|pin| (id.clone(), pin)));
        modules.insert(id.clone(), module);
    }
    Ok(PreparedPlan {
        home: home.into(),
        inventory,
        pins,
        config_present,
        config: config_values,
        trees,
        plan,
        modules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_topology_is_independent_of_edge_insertion_and_detects_cycles() {
        let nodes = BTreeSet::from(["a".into(), "b".into(), "c".into()]);
        let mut edges = BTreeSet::from([("c".into(), "a".into())]);
        assert_eq!(
            stable_order(nodes.clone(), &edges, "cycle").unwrap(),
            ["b", "c", "a"]
        );
        edges.insert(("a".into(), "c".into()));
        assert!(stable_order(nodes, &edges, "cycle").is_err());
    }
}
