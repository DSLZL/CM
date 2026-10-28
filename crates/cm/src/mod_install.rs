//! Non-executing ingestion and selection changes, shared by drop-in and explicit CLI.
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::LoadError;
use crate::config::Options;
use crate::loader;
use crate::profile::{self, Directory, Transaction};

#[derive(Clone, Copy)]
pub enum Command<'a> {
    Install(&'a Path),
    Replace {
        id: &'a str,
        package: &'a Path,
        from: &'a str,
    },
    Enable(&'a str),
    Disable(&'a str),
    Remove(&'a str),
    Scan,
}

fn ingest(
    transaction: &mut Transaction,
    input: &Path,
    replacement: Option<(&str, &str)>,
) -> Result<(), LoadError> {
    let input = std::path::absolute(input).map_err(|e| profile::failure(&e.to_string()))?;
    let home = &transaction.root.path;
    let host_root = transaction
        .host
        .executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| profile::failure("missing Host root"))?;
    let official = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|p| p.join(".codex"));
    if home.starts_with(&input)
        || input.starts_with(home.join("store"))
        || input.starts_with(home.join("state"))
        || input.starts_with(host_root)
        || host_root.starts_with(&input)
        || official
            .as_ref()
            .is_some_and(|p| input.starts_with(p) || p.starts_with(&input))
    {
        return Err(profile::failure(
            "input overlaps protected Host/profile/storage/state",
        ));
    }
    let snapshot = loader::installation_snapshot(&input)?;
    let was_enabled = transaction.next.enabled.contains(&snapshot.id);
    if let Some((id, expected)) = replacement {
        if snapshot.id != id
            || !loader::digest(expected)
            || transaction.next.installed.get(id).map(String::as_str) != Some(expected)
        {
            return Err(LoadError::input(
                "input_drift",
                id,
                "replacement ID or expected old object differs",
            ));
        }
        if transaction
            .next
            .state
            .as_ref()
            .is_some_and(|view| view.contains_owner(id))
        {
            crate::state::exclusive(transaction)?;
        }
    }
    if let Some(old) = transaction.next.installed.get(&snapshot.id) {
        if old != &snapshot.sha256 && replacement.is_none() {
            return Err(LoadError::input(
                "installation_conflict",
                &snapshot.id,
                "same ID has different installed content",
            ));
        }
        if old == &snapshot.sha256 {
            transaction.next.consumed.insert(snapshot.sha256);
            return Ok(());
        }
    }
    if !transaction.next.installed.contains_key(&snapshot.id)
        && transaction.next.installed.len() >= 32
    {
        return Err(profile::failure("installed set exceeds 32 packages"));
    }
    let name = profile::temporary("object");
    let stage = transaction
        .objects
        .child(&name)
        .map_err(|e| profile::failure(&e))?;
    let result = (|| -> Result<(), LoadError> {
        for (relative, bytes) in &snapshot.files {
            loader::payload_path(&stage.path, relative).map_err(|e| profile::failure(&e))?;
            let path = Path::new(relative);
            let mut directory = Directory::open(&stage.path).map_err(|e| profile::failure(&e))?;
            if let Some(parent) = path.parent() {
                for part in parent.components() {
                    directory = directory
                        .child(
                            part.as_os_str()
                                .to_str()
                                .ok_or_else(|| profile::failure("non-UTF8 package path"))?,
                        )
                        .map_err(|e| profile::failure(&e))?;
                }
            }
            directory
                .create_file(
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| profile::failure("invalid package name"))?,
                    bytes,
                )
                .map_err(|e| profile::failure(&e))?;
            directory
                .file
                .sync_all()
                .map_err(|e| profile::failure(&e.to_string()))?;
        }
        stage.check().map_err(|e| profile::failure(&e))?;
        stage
            .file
            .sync_all()
            .map_err(|e| profile::failure(&e.to_string()))?;
        let staged = loader::installation_snapshot(&stage.path)?;
        if staged.sha256 != snapshot.sha256 || staged.id != snapshot.id {
            return Err(profile::failure(
                "staged package differs from owned snapshot",
            ));
        }
        if !transaction
            .objects
            .publish(&name, &snapshot.sha256)
            .map_err(|e| profile::failure(&e))?
        {
            let existing =
                loader::installation_snapshot(&transaction.objects.path.join(&snapshot.sha256))?;
            if existing.id != snapshot.id || existing.sha256 != snapshot.sha256 {
                return Err(profile::failure("CAS content/address mismatch"));
            }
            profile::discard(&transaction.objects, &name).map_err(|e| profile::failure(&e))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = profile::discard(&transaction.objects, &name);
    }
    result?;
    transaction
        .next
        .installed
        .insert(snapshot.id.clone(), snapshot.sha256.clone());
    if replacement.is_none() || was_enabled {
        transaction.next.enabled.insert(snapshot.id);
    }
    transaction.next.consumed.insert(snapshot.sha256);
    Ok(())
}

pub fn run(home: &Path, command: Command<'_>, options: &Options) -> Result<Value, LoadError> {
    let host = crate::package::managed_identity()?;
    let mut transaction = Transaction::begin(home, host)?;
    match command {
        Command::Install(input) => ingest(&mut transaction, input, None)?,
        Command::Replace { id, package, from } => {
            ingest(&mut transaction, package, Some((id, from)))?
        }
        Command::Enable(id) | Command::Disable(id) | Command::Remove(id) => {
            if !transaction.next.installed.contains_key(id) {
                return Err(LoadError::input(
                    "installation",
                    id,
                    "Mod ID is not installed",
                ));
            }
            match command {
                Command::Enable(_) => {
                    transaction.next.enabled.insert(id.into());
                }
                Command::Disable(_) => {
                    transaction.next.enabled.remove(id);
                }
                Command::Remove(_) => {
                    transaction.next.enabled.remove(id);
                    transaction.next.installed.remove(id);
                }
                _ => unreachable!(),
            }
        }
        Command::Scan => {
            let inbox = transaction.root.path.join("mods");
            let mut paths = Vec::new();
            for entry in std::fs::read_dir(&inbox).map_err(|e| profile::failure(&e.to_string()))? {
                let entry = entry.map_err(|e| profile::failure(&e.to_string()))?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| profile::failure("non-UTF8 inbox entry"))?;
                if name.ends_with(".part") || name.ends_with(".tmp") || name.ends_with(".partial") {
                    continue;
                }
                if paths.len() >= 32 {
                    return Err(profile::failure("inbox exceeds 32 complete entries"));
                }
                paths.push(entry.path());
            }
            paths.sort();
            // Check every complete input before touching the next set, including duplicate IDs.
            let mut seen = std::collections::BTreeSet::new();
            for input in paths {
                let candidate = loader::installation_snapshot(&input)?;
                if !seen.insert(candidate.id.clone()) {
                    return Err(LoadError::input(
                        "duplicate_mod",
                        &candidate.id,
                        "duplicate inbox Mod ID",
                    ));
                }
                if !transaction.next.consumed.contains(&candidate.sha256) {
                    ingest(&mut transaction, &input, None)?;
                }
            }
        }
    }
    transaction.commit(options)
}
