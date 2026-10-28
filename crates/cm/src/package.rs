//! Complete distribution preflight, before any native Mod entry.
use std::fs;
use std::io::Read;
use std::path::Component;
use std::path::Path;

use serde::{Deserialize, Serialize};

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DevelopmentPackage {
    version: String,
    target: String,
    entrypoint: String,
}

fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn same_build_inode(executable: &Path, original: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    match (fs::metadata(executable), fs::metadata(original)) {
        (Ok(actual), Ok(built)) => {
            actual.is_file() && (actual.dev(), actual.ino()) == (built.dev(), built.ino())
        }
        _ => false,
    }
}

fn same_development_copy(executable: &Path, root: &Path, original: &Path) -> bool {
    if !original.is_file() {
        return false;
    }
    let Ok(file) = fs::File::open(root.join("codex-package.json")) else {
        return false;
    };
    let mut bytes = Vec::new();
    if file.take(4097).read_to_end(&mut bytes).is_err() || bytes.len() > 4096 {
        return false;
    }
    let Ok(package) = serde_json::from_slice::<DevelopmentPackage>(&bytes) else {
        return false;
    };
    if package.version != "0.0.0"
        || package.target != "x86_64-unknown-linux-gnu"
        || package.entrypoint != "bin/codex"
    {
        return false;
    }
    matches!(
        (
            loader::executable_hash(executable),
            loader::executable_hash(original)
        ),
        (Ok(actual), Ok(built)) if actual == built
    )
}

pub fn preflight() -> Result<(), LoadError> {
    validate(true)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedHost {
    pub executable: std::path::PathBuf,
    pub executable_sha256: String,
    pub inventory_sha256: String,
    pub target: String,
}

pub(crate) fn managed_identity() -> Result<ManagedHost, LoadError> {
    validate(false)?;
    let executable = fs::canonicalize("/proc/self/exe")
        .map_err(|e| LoadError::input("package", "", &e.to_string()))?;
    let inventory = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| LoadError::input("package", "", "missing package root"))?
        .join("cm-runtime-files.json");
    let (_, pin) = loader::read_input(&inventory, 4 * 1024 * 1024)
        .map_err(|e| LoadError::input("package", "", &e))?;
    Ok(ManagedHost {
        executable_sha256: loader::executable_hash(&executable)
            .map_err(|e| LoadError::input("package", "", &e))?,
        executable,
        inventory_sha256: pin.sha256,
        target: loader::TARGET.into(),
    })
}

fn validate(allow_development: bool) -> Result<(), LoadError> {
    let result = (|| -> Result<(), String> {
        let executable = fs::canonicalize("/proc/self/exe").map_err(|error| error.to_string())?;
        let root = executable
            .parent()
            .and_then(Path::parent)
            .ok_or("missing package root")?;
        // Upstream integration tests install copies of the 0.0.0 development CLI.
        if let Some(target) = option_env!("CARGO_TARGET_DIR").filter(|_| allow_development) {
            let original = Path::new(target).join("x86_64-unknown-linux-gnu/dev-small/codex");
            if same_build_inode(&executable, &original)
                || same_development_copy(&executable, root, &original)
            {
                return Ok(());
            }
        }
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
    use std::fs;

    use super::relative;
    use super::same_build_inode;
    use super::same_development_copy;

    #[test]
    fn copied_development_cli_requires_original_bytes_and_development_metadata() {
        let root = std::env::temp_dir().join(format!("cm-package-copy-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let original = root.join("original");
        let copied = root.join("copied");
        let manifest = root.join("codex-package.json");
        fs::write(&original, b"same Host bytes").unwrap();
        fs::copy(&original, &copied).unwrap();
        assert!(!same_development_copy(&copied, &root, &original));
        let mut package = serde_json::json!({
            "version": "0.0.0", "target": "x86_64-unknown-linux-gnu", "entrypoint": "bin/codex"
        });
        fs::write(&manifest, serde_json::to_vec(&package).unwrap()).unwrap();
        assert!(same_development_copy(&copied, &root, &original));
        package["version"] = "0.3.0-p04".into();
        fs::write(&manifest, serde_json::to_vec(&package).unwrap()).unwrap();
        assert!(!same_development_copy(&copied, &root, &original));
        package["version"] = "0.0.0".into();
        fs::write(&manifest, serde_json::to_vec(&package).unwrap()).unwrap();
        fs::write(&copied, b"changed CLI").unwrap();
        assert!(!same_development_copy(&copied, &root, &original));
        fs::copy(&original, &copied).unwrap();
        fs::remove_file(&original).unwrap();
        assert!(!same_development_copy(&copied, &root, &original));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unpackaged_exception_requires_original_inode() {
        let root = std::env::temp_dir().join(format!("cm-package-inode-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let original = root.join("original");
        let linked = root.join("linked");
        let copied = root.join("copied");
        fs::write(&original, b"same Host bytes").unwrap();
        fs::hard_link(&original, &linked).unwrap();
        fs::copy(&original, &copied).unwrap();
        assert!(same_build_inode(&original, &original));
        assert!(same_build_inode(&linked, &original));
        assert!(!same_build_inode(&copied, &original));
        assert!(!same_build_inode(&original, &root.join("missing")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_paths_cannot_escape_package() {
        assert!(relative("codex-resources/bwrap"));
        for value in ["", "/bin/codex", "../codex", "bin/../codex", "bin\\codex"] {
            assert!(!relative(value));
        }
    }
}
