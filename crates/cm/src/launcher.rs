//! Launch the receipt-bound Host without a shell, PATH lookup or official profile.
use std::ffi::OsString;
#[cfg(not(windows))]
use std::os::unix::process::CommandExt;
use std::path::Path;

use crate::config::Options;
use crate::{LoadError, mod_install, profile};

#[cfg(windows)]
pub fn supervise_windows() -> Result<(), LoadError> {
    if let Some(path) = std::env::var_os("CM_WINDOWS_SNAPSHOT_ROOT") {
        profile::Directory::open(Path::new(&path)).map_err(|error| profile::failure(&error))?;
        return Ok(());
    }
    let root = profile::Directory::snapshots().map_err(|error| profile::failure(&error))?;
    let executable = crate::loader::current_executable()
        .map_err(|error| profile::failure(&error.to_string()))?;
    let mut command = std::process::Command::new(executable);
    command.args(std::env::args_os().skip(1));
    // shortcut: forced supervisor termination preserves its stage until owned crash recovery is qualified.
    let status = root
        .run_snapshot_child(&profile::temporary("snapshots"), &mut command)
        .map_err(|error| profile::failure(&error))?;
    drop(root);
    crate::exit_after_shutdown(status.code().unwrap_or(1))
}

pub fn launch(home: &Path, args: &[OsString], options: &Options) -> Result<(), LoadError> {
    profile::validate_environment(home)?;
    let value = mod_install::run(home, mod_install::Command::Scan, options)?;
    let generation = value["generation"]
        .as_str()
        .ok_or_else(|| profile::failure("missing committed generation"))?;
    let snapshot =
        profile::snapshot(home)?.ok_or_else(|| profile::failure("missing managed profile"))?;
    if snapshot.generation_id != generation {
        return Err(profile::failure(
            "active generation changed before launch; retry explicitly",
        ));
    }
    snapshot.revalidate()?;
    let mut command = std::process::Command::new(&snapshot.host.executable);
    if let Some(name) = &options.profile {
        command.arg("--cm-profile").arg(name);
    }
    for value in &options.overrides {
        command.arg("--cm-set").arg(value);
    }
    command
        .args(args)
        .env("CODEX_HOME", home)
        .env("CODEX_SQLITE_HOME", home)
        .env("CM_MANAGED_HOME", home)
        .env("CM_MANAGED_GENERATION", generation);
    #[cfg(not(windows))]
    {
        let error = command.exec();
        Err(profile::failure(&format!(
            "verified Host exec failed: {error}"
        )))
    }
    #[cfg(windows)]
    {
        let status = command
            .status()
            .map_err(|error| profile::failure(&format!("verified Host launch failed: {error}")))?;
        drop(command);
        drop(snapshot);
        crate::exit_after_shutdown(status.code().unwrap_or(1))
    }
}
