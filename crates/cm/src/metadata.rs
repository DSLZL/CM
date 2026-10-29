//! Metadata commands have no path to native registration or Core sessions.
use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use crate::LoadError;
use crate::config::Options;
use crate::{loader, mod_lock, runtime_plan};

pub enum Command {
    List,
    Plan,
    Doctor,
    Lock,
    CheckLock,
}

pub fn run(home: &Path, command: Command, options: &Options) -> Result<Value, LoadError> {
    let mut managed = crate::profile::snapshot(home)?;
    if matches!(command, Command::List) {
        let paths: Vec<_> = if let Some(snapshot) = &managed {
            snapshot
                .packages()
                .into_iter()
                .map(|(id, path, sha)| (id, path, Some(sha)))
                .collect()
        } else {
            loader::inventory(home)
                .map_err(|e| LoadError::input("inventory", "", &e))?
                .packages
                .keys()
                .map(|slot| (slot.clone(), home.join("mods").join(slot), None))
                .collect()
        };
        let mut mods = BTreeMap::new();
        let mut managed_pins = Vec::new();
        let mut managed_trees = Vec::new();
        let host = runtime_plan::HostIdentity::read(Path::new("/proc/self/exe"))?;
        for (slot, path, expected) in paths {
            let candidate = loader::candidate(&path).map_err(|mut error| {
                if error.mod_id.is_none() {
                    error.mod_id = Some(slot.clone());
                }
                error
            })?;
            let id = candidate.manifest.id.clone();
            let content = if let Some(expected) = expected {
                let full = loader::installation_snapshot(&path)?;
                managed_pins.extend(full.pins);
                if let Some(tree) = full.tree {
                    managed_trees.push((path.clone(), tree));
                }
                let actual = full.sha256;
                if actual != expected || id != slot {
                    return Err(LoadError::input(
                        "input_drift",
                        &id,
                        "managed object content/ID differs from its address",
                    ));
                }
                actual
            } else {
                candidate.content_sha256.clone()
            };
            loader::check_manifest(&candidate.manifest)
                .map_err(|e| LoadError::input("manifest_contract", &id, &e))?;
            let unsupported = candidate
                .manifest
                .binary_manifest
                .as_ref()
                .is_some_and(|m| m.compatible(&host).is_err())
                || candidate
                    .manifest
                    .required_capabilities
                    .iter()
                    .any(|cap| !host.capabilities.contains(cap));
            let declared = json!({"version": candidate.manifest.version, "format_version": candidate.manifest.format_version,
                "manifest_sha256": candidate.manifest_sha256, "content_sha256": content,
                "metadata": candidate.manifest.binary_manifest.as_ref().map(crate::manifest::BinaryManifest::summary),
                "qualification": {"declared":true,"verified":false,"unsupported":unsupported}});
            candidate
                .prepare()
                .map_err(|e| LoadError::input("package_input", &id, &e))?;
            if mods.insert(id.clone(), declared).is_some() {
                return Err(LoadError::input("duplicate_mod", &id, "duplicate Mod ID"));
            }
        }
        for pin in managed_pins {
            pin.revalidate()
                .map_err(|e| LoadError::input("input_drift", "", &e))?;
        }
        for (path, entries) in managed_trees {
            if loader::directory_entries(&path)
                .map_err(|e| LoadError::input("input_drift", "", &e))?
                != entries
            {
                return Err(LoadError::input(
                    "input_drift",
                    "",
                    "managed directory changed during list",
                ));
            }
        }
        if let Some(snapshot) = &managed {
            snapshot.revalidate()?;
        }
        return Ok(crate::diagnostics::metadata(
            json!({"schema_version":1,"command":"list","mods":mods,"already_native_executed":false}),
        ));
    }
    if managed.is_some() && matches!(command, Command::Lock) {
        crate::profile::Transaction::begin(home, crate::package::managed_identity()?)?
            .commit(options)?;
        managed = crate::profile::snapshot(home)?;
    }
    let prepared = runtime_plan::prepare_options(home, options)?;
    if !matches!(command, Command::Lock) {
        prepared.revalidate()?;
    }
    let lock_state = if let Some(snapshot) = &managed {
        if loader::hash(&mod_lock::canonical(prepared.plan())) != snapshot.generation.lock_sha256 {
            return Err(LoadError::input(
                "mod_lock",
                "",
                "managed generation lock is stale; refresh explicitly with cm lock",
            ));
        }
        if matches!(command, Command::Lock) {
            "written"
        } else {
            "current"
        }
    } else {
        match command {
            Command::Lock => {
                mod_lock::write(home, &prepared)?;
                "written"
            }
            Command::CheckLock => {
                mod_lock::check(home, prepared.plan())?;
                "current"
            }
            Command::Doctor if mod_lock::present(home)? => {
                mod_lock::check(home, prepared.plan())?;
                "current"
            }
            Command::Doctor => "absent",
            _ => "not_checked",
        }
    };
    Ok(crate::diagnostics::metadata(
        json!({"schema_version":1,"plan":prepared.plan(),"plan_sha256":prepared.plan().sha256(),
        "lock_sha256":loader::hash(&mod_lock::canonical(prepared.plan())),"lock":lock_state,
        "already_native_executed":false,"qualification":{"verified":false}}),
    ))
}
