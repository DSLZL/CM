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

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
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
