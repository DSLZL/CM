//! Launch the receipt-bound Host without a shell, PATH lookup or official profile.
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::Path;

use crate::config::Options;
use crate::{LoadError, mod_install, profile};

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
    let error = command.exec();
    Err(profile::failure(&format!(
        "verified Host exec failed: {error}"
    )))
}
