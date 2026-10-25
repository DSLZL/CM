//! Complete distribution preflight, before any native Mod entry.
use std::fs;
use std::io::Read;
use std::path::Component;
use std::path::Path;

use serde::Deserialize;

use crate::LoadError;
use crate::loader;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u32,
    files: Vec<Entry>,
    system_files: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    mode: String,
    sha256: String,
}

fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

pub fn preflight() -> Result<(), LoadError> {
    let result = (|| -> Result<(), String> {
        let executable = fs::canonicalize("/proc/self/exe").map_err(|error| error.to_string())?;
        let root = executable
            .parent()
            .and_then(Path::parent)
            .ok_or("missing package root")?;
        let mut bytes = Vec::new();
        fs::File::open(root.join("cm-runtime-files.json"))
            .map_err(|error| error.to_string())?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("package inventory exceeds limit".into());
        }
        let inventory: Inventory =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if inventory.schema_version != 1
            || inventory.files.len() > 4096
            || inventory.system_files.len() > 256
        {
            return Err("unsupported package inventory".into());
        }
        let mut paths = std::collections::BTreeSet::new();
        for entry in &inventory.files {
            if !relative(&entry.path) || !paths.insert(entry.path.as_str()) {
                return Err("invalid/duplicate package path".into());
            }
            let path = root.join(&entry.path);
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", entry.path))?;
            let hash = if entry.mode == "120000" && metadata.is_symlink() {
                let target = fs::read_link(&path).map_err(|error| error.to_string())?;
                if target.is_absolute()
                    || !fs::canonicalize(&path)
                        .map_err(|error| error.to_string())?
                        .starts_with(root)
                {
                    return Err("package link escapes root".into());
                }
                loader::hash(target.as_os_str().as_encoded_bytes())
            } else if ["100644", "100755"].contains(&entry.mode.as_str()) && metadata.is_file() {
                use std::os::unix::fs::PermissionsExt;
                if (metadata.permissions().mode() & 0o111 != 0) != (entry.mode == "100755") {
                    return Err(format!("package mode mismatch: {}", entry.path));
                }
                loader::executable_hash(&path)?
            } else {
                return Err(format!("unsupported package file: {}", entry.path));
            };
            if hash != entry.sha256 {
                return Err(format!("package digest mismatch: {}", entry.path));
            }
        }
        for required in [
            "bin/codex",
            "bin/codex-code-mode-host",
            "codex-resources/bwrap",
            "codex-path/rg",
            "cm-host.json",
            "dependency-inventory.json",
        ] {
            if !paths.contains(required) {
                return Err(format!("missing required component: {required}"));
            }
        }
        if !paths.iter().any(|path| path.starts_with("licenses/")) {
            return Err("missing licenses".into());
        }
        for name in &inventory.system_files {
            if !name.starts_with('/') || name.contains("..") || !Path::new(name).is_file() {
                return Err(format!("missing runtime dependency: {name}"));
            }
        }
        Ok(())
    })();
    result.map_err(|message| LoadError::new("package", false, &message))
}

#[cfg(test)]
mod tests {
    use super::relative;

    #[test]
    fn inventory_paths_cannot_escape_package() {
        assert!(relative("codex-resources/bwrap"));
        for value in ["", "/bin/codex", "../codex", "bin/../codex", "bin\\codex"] {
            assert!(!relative(value));
        }
    }
}
