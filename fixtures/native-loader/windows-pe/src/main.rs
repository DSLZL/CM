#[path = "../../../../crates/cm/src/profile/directory.rs"]
mod directory;
#[path = "../../../../crates/cm/src/loader/input.rs"]
mod input;
#[path = "../../../../crates/cm/src/loader/pe.rs"]
mod pe;
#[path = "../../../../crates/cm/src/loader/windows.rs"]
mod windows;

use input as loader;
use std::io::Read;
use std::path::Path;
use std::process::Command;

// Cargo sends build-script native link directives to the separate payload library.
#[link(name = "cm_windows_loader", kind = "static")]
unsafe extern "C" {}
#[link(name = "bcrypt")]
unsafe extern "C" {}

#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = 0xaa64;
#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = 0x8664;
#[cfg(not(all(
    target_os = "windows",
    any(target_arch = "aarch64", target_arch = "x86_64")
)))]
compile_error!("This fixture requires native 64-bit Windows");

fn private_controls(root: &Path, probe: &Path) -> Result<i32, Box<dyn std::error::Error>> {
    use std::ffi::OsStr;
    use std::fs;

    if !root.is_absolute() || !probe.is_absolute() {
        return Err("private controls require absolute owned paths".into());
    }
    let parent = input::open_directory(root)?;
    let control = |mode: &str| -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(probe)
            .args([OsStr::new(mode), root.as_os_str()])
            .output()?;
        if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
            return Err(format!("private native setup failed: {output:?}").into());
        }
        Ok(())
    };
    control("private-setup")?;
    println!("cm_private passed=descriptor-owner-mismatch");
    for (name, is_directory, expected, check) in [
        ("private-dir", true, true, "owner-directory"),
        ("private-file", false, true, "owner-file"),
        ("read-only-file", false, true, "owner-read-only"),
        ("everyone-file", false, false, "foreign-file-ace"),
        ("everyone-dir", true, false, "foreign-directory-ace"),
        ("null-dacl", false, false, "null-dacl"),
        ("empty-dacl", false, false, "empty-dacl"),
        ("unprotected-file", false, false, "unprotected-dacl"),
        ("denied-ace", false, false, "unsupported-ace"),
        ("inherited-ace", false, false, "inherited-ace"),
    ] {
        let result = if is_directory {
            directory::Directory::open(&root.join(name)).and_then(|value| value.check())
        } else {
            input::open_at(&parent, OsStr::new(name), false).and_then(|file| file.check_private())
        };
        assert_eq!(result.is_ok(), expected, "{name}: {result:?}");
        println!("cm_private passed={check}");
    }
    let private = directory::Directory::open(&root.join("private-dir"))?;
    let clone = private.file.try_clone()?;
    let identity = private.file.identity()?;
    assert_eq!(identity, clone.identity()?);
    control("private-change")?;
    assert_eq!(identity, private.file.identity()?);
    assert!(private.check().is_err());
    assert!(clone.check_private().is_err());
    assert!(directory::Directory::open(&private.path).is_err());
    println!("cm_private passed=held-dacl-drift");
    control("private-restore")?;
    private.check()?;
    clone.check_private()?;
    directory::Directory::open(&private.path)?.check()?;
    println!("cm_private passed=restored-dacl");

    let name = "created-文件";
    let bytes = "private\0内容".as_bytes();
    private.create_file(name, bytes)?;
    assert_eq!(fs::read(private.path.join(name))?, bytes);
    let file = input::open_at(&private.file, OsStr::new(name), false)?;
    file.check_private()?;
    let created_identity = file.identity()?;
    drop(file);
    println!("cm_private passed=created-private-file");

    private.create_file("created-empty", b"")?;
    assert!(fs::read(private.path.join("created-empty"))?.is_empty());
    input::open_at(&private.file, OsStr::new("created-empty"), false)?.check_private()?;
    println!("cm_private passed=created-empty-file");

    let chunked: Vec<u8> = (0..65_537).map(|i| (i % 251) as u8).collect();
    private.create_file("created-chunked", &chunked)?;
    assert_eq!(fs::read(private.path.join("created-chunked"))?, chunked);
    input::open_at(&private.file, OsStr::new("created-chunked"), false)?.check_private()?;
    println!("cm_private passed=created-chunked-file");

    assert!(private.create_file(name, b"replacement").is_err());
    fs::hard_link(private.path.join(name), private.path.join("created-link"))?;
    assert!(private.create_file(name, b"replacement").is_err());
    assert!(private.create_file("created-link", b"replacement").is_err());
    assert_eq!(fs::read(private.path.join(name))?, bytes);
    assert_eq!(fs::read(private.path.join("created-link"))?, bytes);
    fs::remove_file(private.path.join("created-link"))?;
    let file = input::open_at(&private.file, OsStr::new(name), false)?;
    assert_eq!(file.identity()?, created_identity);
    file.check_private()?;
    drop(file);
    println!("cm_private passed=existing-file-preserved");

    let collision = private.path.join("collision-dir");
    fs::create_dir(&collision)?;
    fs::write(collision.join("unchanged"), b"unchanged")?;
    assert!(
        private
            .create_file("collision-dir", b"replacement")
            .is_err()
    );
    let junction = private.path.join("collision-junction");
    let output = Command::new("cmd.exe")
        .args([
            OsStr::new("/D"),
            OsStr::new("/C"),
            OsStr::new("mklink"),
            OsStr::new("/J"),
            junction.as_os_str(),
            collision.as_os_str(),
        ])
        .output()?;
    assert!(output.status.success(), "junction setup: {output:?}");
    assert!(
        private
            .create_file("collision-junction", b"replacement")
            .is_err()
    );
    assert_eq!(fs::read(collision.join("unchanged"))?, b"unchanged");
    fs::remove_dir(&junction)?;
    println!("cm_private passed=file-directory-collision");

    let inventory = || -> Result<Vec<_>, std::io::Error> {
        let mut names = fs::read_dir(&private.path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    };
    let before = inventory()?;
    for name in [
        "",
        ".",
        "..",
        "../escaped",
        "..\\escaped",
        "stream:ads",
        "tail.",
        "tail ",
        "nul\0",
    ] {
        assert!(private.create_file(name, b"invalid").is_err(), "{name:?}");
    }
    assert_eq!(inventory()?, before);
    assert!(!root.join("escaped").exists());
    println!("cm_private passed=create-invalid-paths");

    control("private-change")?;
    assert!(private.create_file("denied-create", b"denied").is_err());
    assert_eq!(inventory()?, before);
    control("private-restore")?;
    private.check()?;
    println!("cm_private passed=unsafe-parent-no-write");

    let file = input::open_at(&private.file, OsStr::new(name), false)?;
    assert!(fs::write(private.path.join(name), b"replacement").is_err());
    assert!(fs::remove_file(private.path.join(name)).is_err());
    assert!(fs::rename(&private.path, root.join("private-moved")).is_err());
    assert_eq!(fs::read(private.path.join(name))?, bytes);
    file.check_private()?;
    drop(file);
    println!("cm_private passed=created-ancestor-pin");

    let lock_path = private.path.join(".cm-write.lock");
    assert!(private.writer_file(false).is_err());
    assert!(!lock_path.exists());
    let file = private.writer_file(true)?;
    file.check_private()?;
    let lock_identity = file.identity()?;
    drop(file);
    let file = private.writer_file(false)?;
    assert_eq!(file.identity()?, lock_identity);
    drop(file);
    assert!(fs::read(&lock_path)?.is_empty());
    println!("cm_private passed=lock-open-create");

    let probe_lock = |exclusive: bool, expected: i32| -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(std::env::current_exe()?)
            .args([
                OsStr::new("lock-probe"),
                private.path.as_os_str(),
                OsStr::new(if exclusive { "exclusive" } else { "shared" }),
            ])
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(expected),
            "lock probe: {output:?}"
        );
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        Ok(())
    };
    let file = private.writer_file(false)?;
    input::try_lock(&file, true)?;
    probe_lock(false, 32)?;
    probe_lock(true, 32)?;
    drop(private.writer_file(false)?);
    probe_lock(true, 32)?;
    println!("cm_private passed=lock-exclusive");

    let clone = file.try_clone()?;
    drop(file);
    probe_lock(true, 32)?;
    drop(clone);
    probe_lock(true, 0)?;
    println!("cm_private passed=lock-clone-lifetime");

    let first = private.writer_file(false)?;
    let second = private.writer_file(false)?;
    input::try_lock(&first, false)?;
    input::try_lock(&second, false)?;
    probe_lock(false, 0)?;
    probe_lock(true, 32)?;
    drop(first);
    probe_lock(true, 32)?;
    drop(second);
    probe_lock(true, 0)?;
    println!("cm_private passed=lock-shared");

    fs::remove_file(&lock_path)?;
    let lock_bytes = b"existing lock payload";
    private.create_file(".cm-write.lock", lock_bytes)?;
    let file = private.writer_file(false)?;
    let lock_identity = file.identity()?;
    drop(file);
    let file = private.writer_file(true)?;
    assert_eq!(file.identity()?, lock_identity);
    input::try_lock(&file, true)?;
    assert_eq!(file.metadata()?.len(), lock_bytes.len() as u64);
    drop(file);
    assert_eq!(fs::read(&lock_path)?, lock_bytes);
    println!("cm_private passed=lock-content-preserved");

    fs::remove_file(&lock_path)?;
    fs::hard_link(private.path.join(name), &lock_path)?;
    assert!(private.writer_file(false).is_err());
    assert!(private.writer_file(true).is_err());
    assert_eq!(fs::read(private.path.join(name))?, bytes);
    fs::remove_file(&lock_path)?;
    let output = Command::new("cmd.exe")
        .args([
            OsStr::new("/D"),
            OsStr::new("/C"),
            OsStr::new("mklink"),
            OsStr::new("/J"),
            lock_path.as_os_str(),
            collision.as_os_str(),
        ])
        .output()?;
    assert!(output.status.success(), "lock junction setup: {output:?}");
    assert!(private.writer_file(false).is_err());
    assert!(private.writer_file(true).is_err());
    assert_eq!(fs::read(collision.join("unchanged"))?, b"unchanged");
    fs::remove_dir(&lock_path)?;
    private.create_file(".cm-write.lock", lock_bytes)?;
    println!("cm_private passed=lock-unsafe-file");

    control("private-change")?;
    assert!(private.writer_file(false).is_err());
    assert!(private.writer_file(true).is_err());
    control("private-restore")?;
    private.check()?;
    assert_eq!(fs::read(&lock_path)?, lock_bytes);
    probe_lock(true, 0)?;
    println!("cm_private passed=lock-parent-drift");

    assert_eq!(private.file.sync_all().unwrap_err().raw_os_error(), Some(5));
    private.file.sync_private_directory()?;
    private.check()?;
    let regular = input::open_at(&private.file, OsStr::new(name), false)?;
    assert!(regular.sync_private_directory().is_err());
    drop(regular);
    assert_eq!(fs::read(private.path.join(name))?, bytes);
    println!("cm_private passed=directory-flush");

    let child = private.child("created-directory").map_err(|error| {
        let path = private.path.join("created-directory");
        let present = fs::symlink_metadata(path).is_ok();
        format!("new private directory failed: {error}; created={present}")
    })?;
    let child_path = child.path.clone();
    let child_identity = child.file.identity()?;
    assert_eq!(child_path, private.path.join("created-directory"));
    child.check()?;
    assert!(fs::read_dir(&child_path)?.next().is_none());
    child.create_file("unchanged", bytes)?;
    child.file.sync_private_directory()?;
    drop(child);
    println!("cm_private passed=created-private-directory");

    let child = private.child("created-directory")?;
    assert_eq!(child.file.identity()?, child_identity);
    assert_eq!(fs::read(child.path.join("unchanged"))?, bytes);
    child.check()?;
    drop(child);
    println!("cm_private passed=existing-private-directory");

    assert!(private.child(name).is_err());
    assert_eq!(fs::read(private.path.join(name))?, bytes);
    assert_eq!(
        input::open_at(&private.file, OsStr::new(name), false)?.identity()?,
        created_identity
    );
    let junction = private.path.join("directory-junction");
    let output = Command::new("cmd.exe")
        .args([
            OsStr::new("/D"),
            OsStr::new("/C"),
            OsStr::new("mklink"),
            OsStr::new("/J"),
            junction.as_os_str(),
            child_path.as_os_str(),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "directory junction setup: {output:?}"
    );
    assert!(private.child("directory-junction").is_err());
    assert_eq!(fs::read(child_path.join("unchanged"))?, bytes);
    fs::remove_dir(&junction)?;
    let target = root.join("missing-directory-target");
    fs::create_dir(&target)?;
    let output = Command::new("cmd.exe")
        .args([
            OsStr::new("/D"),
            OsStr::new("/C"),
            OsStr::new("mklink"),
            OsStr::new("/J"),
            junction.as_os_str(),
            target.as_os_str(),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "dangling junction setup: {output:?}"
    );
    fs::remove_dir(&target)?;
    assert!(private.child("directory-junction").is_err());
    assert!(!target.exists());
    assert!(fs::symlink_metadata(&junction).is_ok());
    fs::remove_dir(&junction)?;
    println!("cm_private passed=directory-collisions");

    let before = inventory()?;
    for name in [
        "",
        ".",
        "..",
        "../escaped",
        "..\\escaped",
        "stream:ads",
        "tail.",
        "tail ",
        "nul\0",
    ] {
        assert!(private.child(name).is_err(), "{name:?}");
    }
    assert_eq!(inventory()?, before);
    assert!(!root.join("escaped").exists());
    println!("cm_private passed=directory-invalid-paths");

    control("private-change")?;
    assert!(private.child("denied-directory").is_err());
    assert!(private.file.sync_private_directory().is_err());
    assert_eq!(inventory()?, before);
    control("private-restore")?;
    private.check()?;
    private.file.sync_private_directory()?;
    println!("cm_private passed=directory-parent-drift");

    let child = private.child("created-directory")?;
    let grandchild = child.child("retained-child")?;
    drop(child);
    let moved = private.path.join("moved-directory");
    assert!(fs::rename(&child_path, &moved).is_err());
    assert!(fs::remove_dir(&grandchild.path).is_err());
    grandchild.check()?;
    drop(grandchild);
    fs::rename(&child_path, &moved)?;
    fs::rename(&moved, &child_path)?;
    assert_eq!(fs::read(child_path.join("unchanged"))?, bytes);
    private.child("created-directory")?.check()?;
    println!("cm_private passed=directory-ancestor-pin");

    private.create_file("publish-临时", bytes)?;
    let file = input::open_at(&private.file, OsStr::new("publish-临时"), false)?;
    let published_identity = file.identity()?;
    drop(file);
    assert!(private.publish("publish-临时", "published-文件")?);
    assert!(!private.path.join("publish-临时").exists());
    assert_eq!(fs::read(private.path.join("published-文件"))?, bytes);
    let file = input::open_at(&private.file, OsStr::new("published-文件"), false)?;
    assert_eq!(file.identity()?, published_identity);
    file.check_private()?;
    drop(file);
    println!("cm_private passed=published-private-file");

    private.create_file("publish-collision", b"other")?;
    let file = input::open_at(&private.file, OsStr::new("publish-collision"), false)?;
    let collision_identity = file.identity()?;
    drop(file);
    assert!(!private.publish("publish-collision", "published-文件")?);
    assert!(!private.publish("publish-collision", "PUBLISH-COLLISION")?);
    assert!(!private.publish("publish-collision", "created-directory")?);
    assert_eq!(fs::read(private.path.join("published-文件"))?, bytes);
    assert_eq!(fs::read(private.path.join("publish-collision"))?, b"other");
    let file = input::open_at(&private.file, OsStr::new("publish-collision"), false)?;
    assert_eq!(file.identity()?, collision_identity);
    drop(file);
    let file = input::open_at(&private.file, OsStr::new("published-文件"), false)?;
    assert_eq!(file.identity()?, published_identity);
    drop(file);
    println!("cm_private passed=publish-collisions");

    let stage = private.child("publish-tree")?;
    let tree_identity = stage.file.identity()?;
    stage.child("nested")?.create_file("value", bytes)?;
    drop(stage);
    assert!(private.publish("publish-tree", "published-tree")?);
    assert!(!private.path.join("publish-tree").exists());
    let tree = directory::Directory::open(&private.path.join("published-tree"))?;
    assert_eq!(tree.file.identity()?, tree_identity);
    tree.check()?;
    assert_eq!(fs::read(tree.path.join("nested/value"))?, bytes);
    drop(tree);
    println!("cm_private passed=published-private-directory");

    private.create_file("publish-held", bytes)?;
    let file = input::open_at(&private.file, OsStr::new("publish-held"), false)?;
    let clone = file.try_clone()?;
    assert!(private.publish("publish-held", "published-held").is_err());
    drop(file);
    assert!(private.publish("publish-held", "published-held").is_err());
    drop(clone);
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(private.path.join("publish-held"))?;
    assert!(private.publish("publish-held", "published-held").is_err());
    drop(writer);
    assert!(private.publish("publish-held", "published-held")?);
    assert_eq!(fs::read(private.path.join("published-held"))?, bytes);
    private.create_file("publish-mapped", b"hello")?;
    with_writable_mapping(&private.path.join("publish-mapped"), || {
        assert!(
            private
                .publish("publish-mapped", "published-mapped")
                .is_err()
        );
    })?;
    assert!(private.publish("publish-mapped", "published-mapped")?);
    assert_eq!(fs::read(private.path.join("published-mapped"))?, b"hello");
    let stage = private.child("publish-held-tree")?;
    let descendant = stage.child("descendant")?;
    drop(stage);
    assert!(
        private
            .publish("publish-held-tree", "published-held-tree")
            .is_err()
    );
    descendant.check()?;
    drop(descendant);
    assert!(private.publish("publish-held-tree", "published-held-tree")?);
    println!("cm_private passed=publish-retained-pins");

    private.create_file("publish-hardlink", bytes)?;
    fs::hard_link(
        private.path.join("publish-hardlink"),
        private.path.join("publish-hardlink-alias"),
    )?;
    assert!(
        private
            .publish("publish-hardlink", "published-hardlink")
            .is_err()
    );
    fs::remove_file(private.path.join("publish-hardlink-alias"))?;
    assert_eq!(fs::read(private.path.join("publish-hardlink"))?, bytes);
    fs::write(private.path.join("publish-public"), b"unprotected")?;
    let file = input::open_at(&private.file, OsStr::new("publish-public"), false)?;
    assert!(file.check_private().is_err());
    drop(file);
    assert!(
        private
            .publish("publish-public", "published-public")
            .is_err()
    );
    let junction = private.path.join("publish-junction");
    let output = Command::new("cmd.exe")
        .args([
            OsStr::new("/D"),
            OsStr::new("/C"),
            OsStr::new("mklink"),
            OsStr::new("/J"),
            junction.as_os_str(),
            child_path.as_os_str(),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "publish junction setup: {output:?}"
    );
    assert!(
        private
            .publish("publish-junction", "published-junction")
            .is_err()
    );
    assert!(!private.publish("publish-collision", "publish-junction")?);
    assert_eq!(fs::read(child_path.join("unchanged"))?, bytes);
    fs::remove_dir(&junction)?;
    assert!(!private.path.join("published-hardlink").exists());
    assert!(!private.path.join("published-public").exists());
    assert!(!private.path.join("published-junction").exists());
    println!("cm_private passed=publish-unsafe-source");

    let before = inventory()?;
    for name in [
        "",
        ".",
        "..",
        "../escaped",
        "..\\escaped",
        "stream:ads",
        "tail.",
        "tail ",
        "nul\0",
    ] {
        assert!(
            private.publish("publish-collision", name).is_err(),
            "{name:?}"
        );
        assert!(
            private.publish(name, "publish-invalid").is_err(),
            "{name:?}"
        );
    }
    assert!(
        private
            .publish("publish-collision", &"x".repeat(256))
            .is_err()
    );
    assert!(
        private
            .publish(&"x".repeat(256), "publish-invalid")
            .is_err()
    );
    assert!(
        private
            .publish("publish-missing", "publish-invalid")
            .is_err()
    );
    assert_eq!(inventory()?, before);
    assert!(!root.join("escaped").exists());
    println!("cm_private passed=publish-invalid-paths");

    control("private-change")?;
    assert!(
        private
            .publish("publish-collision", "publish-denied")
            .is_err()
    );
    assert_eq!(inventory()?, before);
    control("private-restore")?;
    private.check()?;
    assert!(private.publish("publish-collision", "publish-restored")?);
    assert_eq!(fs::read(private.path.join("publish-restored"))?, b"other");
    println!("cm_private passed=publish-parent-drift");

    let stage = private.staging("discard-tree")?;
    let stage_identity = input::identity(&stage.file)?;
    stage.child("nested")?.create_file("value", bytes)?;
    assert!(private.staging("discard-tree").is_err());
    assert_eq!(fs::read(stage.path.join("nested/value"))?, bytes);
    assert_eq!(input::identity(&private.child("discard-tree")?.file)?, stage_identity);
    drop(stage);
    println!("cm_private passed=staging-create-only");

    let entry_identity = |name: &str, directory| {
        input::open_at(&private.file, OsStr::new(name), directory)
            .and_then(|file| input::identity(&file))
    };
    private.create_file("remove-文件", bytes)?;
    let expected = entry_identity("remove-文件", false)?;
    for byte in 0..8 {
        let mut changed = expected;
        changed.0 ^= 1u64 << (byte * 8);
        assert!(private.remove(OsStr::new("remove-文件"), changed, false).is_err());
    }
    for byte in 0..16 {
        let mut changed = expected;
        changed.1[byte] ^= 1;
        assert!(private.remove(OsStr::new("remove-文件"), changed, false).is_err());
    }
    assert_eq!(entry_identity("remove-文件", false)?, expected);
    assert_eq!(fs::read(private.path.join("remove-文件"))?, bytes);
    private.remove(OsStr::new("remove-文件"), expected, false)?;
    assert!(!private.path.join("remove-文件").exists());
    println!("cm_private passed=remove-full-identity");

    private.create_file("remove-file", bytes)?;
    let expected = entry_identity("remove-file", false)?;
    assert!(private.remove(OsStr::new("remove-file"), expected, true).is_err());
    private.remove(OsStr::new("remove-file"), expected, false)?;
    let empty = private.staging("remove-empty")?;
    let expected = input::identity(&empty.file)?;
    drop(empty);
    assert!(private.remove(OsStr::new("remove-empty"), expected, false).is_err());
    private.remove(OsStr::new("remove-empty"), expected, true)?;
    assert!(!private.path.join("remove-empty").exists());
    assert!(private.remove(OsStr::new("discard-tree"), stage_identity, true).is_err());
    assert_eq!(fs::read(private.path.join("discard-tree/nested/value"))?, bytes);
    println!("cm_private passed=remove-entry-kinds");

    private.create_file("remove-held", bytes)?;
    let file = input::open_at(&private.file, OsStr::new("remove-held"), false)?;
    let expected = input::identity(&file)?;
    let clone = file.try_clone()?;
    assert!(private.remove(OsStr::new("remove-held"), expected, false).is_err());
    drop(file);
    assert!(private.remove(OsStr::new("remove-held"), expected, false).is_err());
    drop(clone);
    let writer = fs::OpenOptions::new().write(true).open(private.path.join("remove-held"))?;
    assert!(private.remove(OsStr::new("remove-held"), expected, false).is_err());
    drop(writer);
    private.remove(OsStr::new("remove-held"), expected, false)?;
    private.create_file("remove-mapped", b"hello")?;
    let expected = entry_identity("remove-mapped", false)?;
    with_writable_mapping(&private.path.join("remove-mapped"), || {
        assert!(private.remove(OsStr::new("remove-mapped"), expected, false).is_err());
    })?;
    private.remove(OsStr::new("remove-mapped"), expected, false)?;
    let descendant = directory::Directory::open(&private.path.join("discard-tree/nested"))?;
    assert!(private.remove(OsStr::new("discard-tree"), stage_identity, true).is_err());
    descendant.check()?;
    drop(descendant);
    println!("cm_private passed=remove-retained-pins");

    private.create_file("remove-hardlink", bytes)?;
    let expected = entry_identity("remove-hardlink", false)?;
    fs::hard_link(private.path.join("remove-hardlink"), private.path.join("remove-alias"))?;
    assert!(private.remove(OsStr::new("remove-hardlink"), expected, false).is_err());
    assert_eq!(fs::read(private.path.join("remove-alias"))?, bytes);
    fs::remove_file(private.path.join("remove-alias"))?;
    private.remove(OsStr::new("remove-hardlink"), expected, false)?;
    let expected = entry_identity("publish-public", false)?;
    assert!(private.remove(OsStr::new("publish-public"), expected, false).is_err());
    assert_eq!(fs::read(private.path.join("publish-public"))?, b"unprotected");
    let junction = private.path.join("discard-tree/junction");
    let output = Command::new("cmd.exe")
        .args([OsStr::new("/D"), OsStr::new("/C"), OsStr::new("mklink"),
            OsStr::new("/J"), junction.as_os_str(), collision.as_os_str()])
        .output()?;
    assert!(output.status.success(), "discard junction setup: {output:?}");
    assert!(directory::discard(&private, "discard-tree", stage_identity).is_err());
    assert!(fs::symlink_metadata(&junction).is_ok());
    assert_eq!(fs::read(collision.join("unchanged"))?, b"unchanged");
    fs::remove_dir(&junction)?;
    directory::discard(&private, "discard-tree", stage_identity)?;
    assert!(!private.path.join("discard-tree").exists());
    assert_eq!(fs::read(collision.join("unchanged"))?, b"unchanged");
    println!("cm_private passed=discard-private-tree");

    let stage = private.staging("discard-original")?;
    stage.create_file("value", bytes)?;
    let original = input::identity(&stage.file)?;
    drop(stage);
    fs::rename(private.path.join("discard-original"), private.path.join("discard-saved"))?;
    let replacement = private.staging("discard-original")?;
    replacement.create_file("value", bytes)?;
    let replaced = input::identity(&replacement.file)?;
    assert_ne!(original, replaced);
    drop(replacement);
    assert!(directory::discard(&private, "discard-original", original).is_err());
    assert_eq!(fs::read(private.path.join("discard-original/value"))?, bytes);
    assert_eq!(fs::read(private.path.join("discard-saved/value"))?, bytes);
    directory::discard(&private, "discard-original", replaced)?;
    directory::discard(&private, "discard-saved", original)?;
    println!("cm_private passed=discard-replacement-preserved");

    private.create_file("remove-parent-drift", bytes)?;
    let expected = entry_identity("remove-parent-drift", false)?;
    let before = inventory()?;
    for name in ["", ".", "..", "../escaped", "..\\escaped", "stream:ads", "tail.", "tail ", "nul\0"] {
        assert!(private.remove(OsStr::new(name), expected, false).is_err(), "{name:?}");
    }
    assert!(private.remove(OsStr::new(&"x".repeat(256)), expected, false).is_err());
    assert!(private.remove(OsStr::new("remove-missing"), expected, false).is_err());
    assert_eq!(inventory()?, before);
    control("private-change")?;
    assert!(private.remove(OsStr::new("remove-parent-drift"), expected, false).is_err());
    assert_eq!(inventory()?, before);
    control("private-restore")?;
    private.remove(OsStr::new("remove-parent-drift"), expected, false)?;
    println!("cm_private passed=remove-invalid-parent");
    Ok(0)
}

fn with_writable_mapping(
    path: &Path,
    check: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe extern "system" {
        fn CreateFileMappingW(
            file: *mut std::ffi::c_void,
            security: *const std::ffi::c_void,
            protection: u32,
            high: u32,
            low: u32,
            name: *const u16,
        ) -> *mut std::ffi::c_void;
        fn MapViewOfFile(
            mapping: *mut std::ffi::c_void,
            access: u32,
            high: u32,
            low: u32,
            size: usize,
        ) -> *mut std::ffi::c_void;
        fn UnmapViewOfFile(view: *const std::ffi::c_void) -> i32;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    }
    use std::os::windows::io::AsRawHandle;
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    let mapping = unsafe {
        CreateFileMappingW(
            writer.as_raw_handle(),
            std::ptr::null(),
            4,
            0,
            0,
            std::ptr::null(),
        )
    };
    assert!(!mapping.is_null());
    let view = unsafe { MapViewOfFile(mapping, 2, 0, 0, 5) };
    assert!(!view.is_null());
    drop(writer);
    unsafe { std::ptr::copy_nonoverlapping(b"hello".as_ptr(), view.cast::<u8>(), 5) };
    check();
    assert_ne!(unsafe { UnmapViewOfFile(view) }, 0);
    assert_ne!(unsafe { CloseHandle(mapping) }, 0);
    Ok(())
}

fn input_controls(root: &Path) -> Result<i32, Box<dyn std::error::Error>> {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt;

    fn passed(name: &str) {
        println!("cm_input passed={name}");
    }
    let path = root.join("value");
    fs::write(&path, b"hello")?;
    let (bytes, pin) = input::read_input(&path, 5)?;
    assert_eq!(bytes, b"hello");
    assert_eq!(pin.size, 5);
    assert_eq!(
        pin.sha256,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    passed("bounded-read");
    let empty = root.join("empty");
    fs::write(&empty, b"")?;
    let (bytes, empty_pin) = input::read_input(&empty, 0)?;
    assert!(bytes.is_empty());
    assert_eq!(empty_pin.size, 0);
    assert_eq!(
        empty_pin.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    empty_pin.revalidate()?;
    passed("empty-read");
    assert!(input::read_input(&path, 4).is_err());
    assert!(input::read_input(&path, u64::MAX).is_err());
    assert!(input::read_input(root, 32).is_err());
    passed("read-bounds");
    pin.revalidate()?;
    pin.clone().revalidate()?;
    passed("unchanged-pin");
    fs::write(&path, b"other")?;
    assert!(pin.revalidate().is_err());
    passed("changed-bytes");
    fs::write(&path, b"hello")?;
    let (_, pin) = input::read_input(&path, 5)?;
    let parent = input::open_directory(root)?;
    assert_eq!(parent.path(), root);
    let file = input::open_at(&parent, OsStr::new("value"), false)?;
    let old_identity = input::identity(&file)?;
    assert_eq!(std::mem::size_of_val(&old_identity), 24);
    drop(file);
    drop(parent);
    fs::rename(&path, root.join("old"))?;
    fs::write(&path, b"hello")?;
    assert!(pin.revalidate().is_err());
    let parent = input::open_directory(root)?;
    let file = input::open_at(&parent, OsStr::new("value"), false)?;
    assert_ne!(old_identity, input::identity(&file)?);
    drop(file);
    passed("same-bytes-replacement");
    for name in [
        ".",
        "..",
        "value:stream",
        "old/value",
        "old\\value",
        "value.",
        "value ",
    ] {
        assert!(input::open_at(&parent, OsStr::new(name), false).is_err());
    }
    assert!(input::open_directory(Path::new("relative")).is_err());
    assert!(input::open_directory(&root.join("..")).is_err());
    passed("invalid-paths");
    let writer = fs::OpenOptions::new().write(true).open(&path)?;
    assert!(input::open_at(&parent, OsStr::new("value"), false).is_err());
    drop(writer);
    passed("preheld-writer");
    with_writable_mapping(&path, || {
        assert!(input::open_at(&parent, OsStr::new("value"), false).is_err());
    })?;
    input::read_input(&path, 5)?;
    passed("preheld-mapping");
    let file = input::open_at(&parent, OsStr::new("value"), false)?;
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());
    assert!(fs::rename(&path, root.join("moved")).is_err());
    drop(file);
    passed("retained-file");
    let mut directory_writer = fs::OpenOptions::new();
    directory_writer.write(true).custom_flags(0x02000000);
    let writer = directory_writer.open(root);
    let writer = writer.expect("retained parent permits namespace writes");
    drop(writer);
    assert!(fs::rename(root, root.with_extension("moved")).is_err());
    let branch = root.join("parent");
    fs::create_dir(&branch).expect("retained-ancestors create directory");
    fs::write(branch.join("child"), b"child").expect("retained-ancestors write child");
    let directory = input::open_directory(&branch).expect("retained-ancestors open directory");
    let child = input::open_at(&directory, OsStr::new("child"), false)
        .expect("retained-ancestors open child");
    let mut cloned = child.try_clone().expect("retained-ancestors clone child");
    assert_eq!(child.path(), branch.join("child"));
    drop(directory);
    drop(child);
    assert!(fs::rename(&branch, root.join("renamed")).is_err());
    let mut bytes = Vec::new();
    cloned
        .read_to_end(&mut bytes)
        .expect("retained-ancestors read clone");
    assert_eq!(bytes, b"child");
    drop(cloned);
    fs::rename(&branch, root.join("renamed")).expect("retained-ancestors rename after final drop");
    fs::rename(root.join("renamed"), &branch).expect("retained-ancestors restore directory");
    passed("retained-ancestors");
    fs::hard_link(&path, root.join("hardlink"))?;
    assert!(input::read_input(&path, 5).is_err());
    assert!(input::read_input(&root.join("hardlink"), 5).is_err());
    fs::remove_file(root.join("hardlink"))?;
    passed("hardlinks");
    let junction = root.join("junction");
    assert!(
        Command::new("cmd.exe")
            .args([
                OsStr::new("/D"),
                OsStr::new("/C"),
                OsStr::new("mklink"),
                OsStr::new("/J"),
                junction.as_os_str(),
                branch.as_os_str()
            ])
            .status()?
            .success()
    );
    assert!(input::open_at(&parent, OsStr::new("junction"), true).is_err());
    assert!(input::open_directory(&junction).is_err());
    assert!(input::read_input(&junction.join("child"), 5).is_err());
    fs::remove_dir(&junction)?;
    passed("reparse-points");
    drop(parent);
    assert_eq!(fs::read(&path)?, b"hello");
    passed("post-close-usable");
    Ok(0)
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 3 && args[0] == "lock-probe" {
        let exclusive = match args[2].to_str() {
            Some("exclusive") => true,
            Some("shared") => false,
            _ => return Err("invalid lock probe mode".into()),
        };
        let directory = directory::Directory::open(Path::new(&args[1]))?;
        let file = directory.writer_file(false)?;
        return match input::try_lock(&file, exclusive) {
            Ok(()) => Ok(0),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(32),
            Err(error) => Err(error.into()),
        };
    }
    if args.len() == 2 && args[0] == "input" {
        return input_controls(Path::new(&args[1]));
    }
    if args.len() == 3 && args[0] == "private" {
        return private_controls(Path::new(&args[1]), Path::new(&args[2]));
    }
    if args.len() != 3 && args.len() != 7 {
        return Err("expected validate DLL ENTRY, or load DLL ENTRY PROBE HASH MODE POISON".into());
    }
    let mode = args[0].to_str().ok_or("invalid mode")?;
    if !matches!(mode, "validate" | "load") || (mode == "validate") != (args.len() == 3) {
        return Err("invalid closed fixture mode".into());
    }
    let path = Path::new(&args[1]);
    if !path.is_absolute() {
        return Err("expected absolute DLL path".into());
    }
    let entry = args[2].to_str().ok_or("invalid entry")?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let audit = match pe::check(&bytes, MACHINE, entry) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cm_pe_rejected: {error}");
            return Ok(3);
        }
    };
    println!(
        "cm_pe dependencies={} imports={} ordinals={} entry={}",
        audit.dependencies.join(","),
        audit.imports,
        audit.ordinal_imports,
        audit.entry_rva
    );
    if mode == "validate" {
        return Ok(0);
    }
    let snapshot = if args[5] == "guarded" {
        let snapshot = windows::Snapshot::open(path, args[4].to_str().ok_or("invalid hash")?)?;
        assert!(
            snapshot.read()? == bytes,
            "retained snapshot differs from parsed bytes"
        );
        Some(snapshot)
    } else if args[5] == "snapshot" {
        for (name, extension) in [
            (c"cm-mod-v1", "dll"),
            (c"cm-distribution-verifier", "exe"),
            (c"cm-distribution-bundle", "jsonl"),
            (c"cm-distribution-root", "bin"),
        ] {
            let private = windows::Snapshot::create(&bytes, name)?;
            let private_path = private.path().to_path_buf();
            assert_eq!(private_path.extension().unwrap(), extension);
            assert_eq!(private.read()?, bytes);
            assert!(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&private_path)
                    .is_err()
            );
            assert!(std::fs::remove_file(&private_path).is_err());
            drop(private);
            assert!(!private_path.exists());
            assert!(!private_path.parent().unwrap().exists());
        }
        Some(windows::Snapshot::create(&bytes, c"cm-mod-v1")?)
    } else {
        None
    };
    if let Some(snapshot) = snapshot {
        let library = snapshot.load(&audit.dependencies)?;
        let entry = std::ffi::CString::new(entry)?;
        let function = unsafe {
            library.get::<unsafe extern "system" fn() -> i32>(entry.as_bytes_with_nul())?
        };
        let value = unsafe { function() };
        println!(
            "{{\"status\":\"loaded\",\"entry_value\":{value},\"dependencies\":{},\"guarded\":true,\"payload_executed\":true}}",
            audit.dependencies.len()
        );
        return Ok(if value == 41 { 0 } else { 2 });
    }
    let probe = Path::new(&args[3]);
    if !probe.is_absolute() {
        return Err("expected absolute native control executable".into());
    }
    let status = Command::new(probe)
        .args([
            args[5].as_os_str(),
            args[1].as_os_str(),
            args[4].as_os_str(),
            args[2].as_os_str(),
            std::ffi::OsStr::new(&audit.dependencies.join(",")),
            args[6].as_os_str(),
        ])
        .status()?;
    Ok(status
        .code()
        .ok_or("native control terminated abnormally")?)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("cm_pe_error: {error}");
            std::process::exit(4);
        }
    }
}
