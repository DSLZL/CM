#[path = "../../../../crates/cm/src/loader/input.rs"]
mod input;
#[path = "../../../../crates/cm/src/loader/pe.rs"]
mod pe;
#[path = "../../../../crates/cm/src/loader/windows.rs"]
mod windows;

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
    let writer = fs::OpenOptions::new().read(true).write(true).open(&path)?;
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
    assert!(input::open_at(&parent, OsStr::new("value"), false).is_err());
    assert_ne!(unsafe { UnmapViewOfFile(view) }, 0);
    assert_ne!(unsafe { CloseHandle(mapping) }, 0);
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
    if args.len() == 2 && args[0] == "input" {
        return input_controls(Path::new(&args[1]));
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
