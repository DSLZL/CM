#[path = "../../../../crates/cm/src/loader/pe.rs"]
mod pe;

use std::io::Read;
use std::path::Path;
use std::process::Command;

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
