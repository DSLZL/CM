//! Metadata commands have no path to native registration or Core sessions.
use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use crate::LoadError;
use crate::config::Options;
use crate::{loader, mod_lock, runtime_plan};

pub enum Command { List, Plan, Doctor, Lock, CheckLock }

pub fn run(home: &Path, command: Command, options: &Options) -> Result<Value, LoadError> {
    if matches!(command, Command::List) {
        let inventory = loader::inventory(home).map_err(|e| LoadError::input("inventory", "", &e))?;
        let mut mods = BTreeMap::new();
        let host = runtime_plan::HostIdentity::read(Path::new("/proc/self/exe"))?;
        for slot in inventory.packages.keys() {
            let candidate = loader::candidate(&home.join("mods").join(slot)).map_err(|mut error| {
                if error.mod_id.is_none() { error.mod_id = Some(slot.clone()); }
                error
            })?;
            let id = candidate.manifest.id.clone();
            loader::check_manifest(&candidate.manifest).map_err(|e| LoadError::input("manifest_contract", &id, &e))?;
            let unsupported = candidate.manifest.binary_manifest.as_ref().is_some_and(|m| m.compatible(&host).is_err())
                || candidate.manifest.required_capabilities.iter().any(|cap| !host.capabilities.contains(cap));
            let declared = json!({"version": candidate.manifest.version, "format_version": candidate.manifest.format_version,
                "manifest_sha256": candidate.manifest_sha256, "content_sha256": candidate.content_sha256,
                "metadata": candidate.manifest.binary_manifest.as_ref().map(crate::manifest::BinaryManifest::summary),
                "qualification": {"declared":true,"verified":false,"unsupported":unsupported}});
            candidate.prepare().map_err(|e| LoadError::input("package_input", &id, &e))?;
            if mods.insert(id.clone(), declared).is_some() { return Err(LoadError::input("duplicate_mod", &id, "duplicate Mod ID")); }
        }
        return Ok(json!({"schema_version":1,"command":"list","mods":mods,"already_native_executed":false}));
    }
    let prepared = runtime_plan::prepare_options(home, options)?;
    if !matches!(command, Command::Lock) { prepared.revalidate()?; }
    let lock_state = match command {
        Command::Lock => { mod_lock::write(home, &prepared)?; "written" }
        Command::CheckLock => { mod_lock::check(home, prepared.plan())?; "current" }
        Command::Doctor if mod_lock::present(home)? => { mod_lock::check(home, prepared.plan())?; "current" }
        Command::Doctor => "absent",
        _ => "not_checked",
    };
    Ok(json!({"schema_version":1,"plan":prepared.plan(),"plan_sha256":prepared.plan().sha256(),
        "lock_sha256":loader::hash(&mod_lock::canonical(prepared.plan())),"lock":lock_state,
        "already_native_executed":false,"qualification":{"verified":false}}))
}
