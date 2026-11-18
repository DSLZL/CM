use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::{ffi::OsStrExt, io::FromRawHandle, process::ExitStatusExt};
use std::process::{Command, ExitStatus};
use std::ptr::NonNull;

unsafe extern "C" {
    fn cm_windows_verifier_spawn(
        program: *const u16,
        command: *mut u16,
        environment: *const u16,
        output: *mut *mut c_void,
        diagnostics: *mut *mut c_void,
    ) -> *mut c_void;
    fn cm_windows_verifier_poll(process: *const c_void, code: *mut u32) -> i32;
    fn cm_windows_verifier_stop(process: *mut c_void);
    fn cm_windows_verifier_free(process: *mut c_void);
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) || value.len() > 32766 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid verifier argument",
        ));
    }
    Ok(value)
}

fn quote(value: &[u16], result: &mut Vec<u16>) {
    result.push(34);
    let mut slashes = 0;
    for &unit in value {
        if unit == 92 {
            slashes += 1;
            continue;
        }
        result.extend(std::iter::repeat_n(
            92,
            if unit == 34 { 2 * slashes + 1 } else { slashes },
        ));
        result.push(unit);
        slashes = 0;
    }
    result.extend(std::iter::repeat_n(92, 2 * slashes));
    result.push(34);
}

pub(super) struct Child {
    process: NonNull<c_void>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}

pub(super) fn spawn(command: &Command) -> io::Result<Child> {
    if !std::path::Path::new(command.get_program()).is_absolute()
        || command.get_current_dir().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "verifier requires an absolute program",
        ));
    }
    let mut program = wide(command.get_program())?;
    program.push(0);
    let mut arguments = Vec::new();
    quote(&program[..program.len() - 1], &mut arguments);
    for argument in command.get_args() {
        arguments.push(32);
        quote(&wide(argument)?, &mut arguments);
    }
    if arguments.len() > 32766 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "verifier command exceeds bounds",
        ));
    }
    arguments.push(0);
    unsafe extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut root = [0; 4096];
    let length = unsafe { GetWindowsDirectoryW(root.as_mut_ptr(), root.len() as u32) } as usize;
    if length == 0 || length >= root.len() {
        return Err(io::Error::last_os_error());
    }
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("SYSTEMROOT".to_owned(), root[..length].to_vec());
    for (key, value) in command.get_envs() {
        let Some(value) = value else { continue };
        let key = key
            .to_str()
            .filter(|key| {
                !key.is_empty()
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid verifier environment")
            })?;
        if key.eq_ignore_ascii_case("SYSTEMROOT") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "verifier SystemRoot is fixed",
            ));
        }
        entries.insert(key.to_ascii_uppercase(), wide(value)?);
    }
    let mut environment = Vec::new();
    for (key, value) in entries {
        environment.extend(key.encode_utf16());
        environment.push(61);
        environment.extend(value);
        environment.push(0);
    }
    environment.push(0);
    if environment.len() > 32767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "verifier environment exceeds bounds",
        ));
    }
    let mut stdout = std::ptr::null_mut();
    let mut stderr = std::ptr::null_mut();
    let process = NonNull::new(unsafe {
        cm_windows_verifier_spawn(
            program.as_ptr(),
            arguments.as_mut_ptr(),
            environment.as_ptr(),
            &mut stdout,
            &mut stderr,
        )
    })
    .ok_or_else(io::Error::last_os_error)?;
    Ok(Child {
        process,
        stdout: Some(unsafe { File::from_raw_handle(stdout) }),
        stderr: Some(unsafe { File::from_raw_handle(stderr) }),
    })
}

impl Child {
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let mut code = 0;
        match unsafe { cm_windows_verifier_poll(self.process.as_ptr(), &mut code) } {
            0 => Ok(None),
            1 => Ok(Some(ExitStatus::from_raw(code))),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn stop(&mut self) {
        unsafe { cm_windows_verifier_stop(self.process.as_ptr()) };
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        unsafe { cm_windows_verifier_free(self.process.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, Instant};

    const CHILD: &str = "provenance::windows::tests::controlled_child";
    const QUOTED: &str = "space Unicode 中文 quote\" slash\\\\end\\";

    fn command(mode: &str) -> Command {
        let mut command = Command::new(crate::loader::current_executable().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                CHILD,
                "--nocapture",
                "--skip",
                QUOTED,
            ])
            .env_clear()
            .env("CM_VERIFIER_TEST_MODE", mode)
            .env("CM_VERIFIER_QUOTED", QUOTED);
        command
    }

    #[test]
    #[ignore = "controlled verifier child"]
    fn controlled_child() {
        let mode = std::env::var("CM_VERIFIER_TEST_MODE").unwrap();
        assert_eq!(std::env::var("CM_VERIFIER_QUOTED").unwrap(), QUOTED);
        assert_eq!(std::env::args().last().unwrap(), QUOTED);
        match mode.as_str() {
            "ok" => std::io::stdout().write_all(b"verified bytes").unwrap(),
            "fail" => std::process::exit(3),
            "large" => {
                let _ = std::io::stdout().write_all(&vec![0; super::super::LIMIT as usize + 1]);
            }
            "sleep" => std::thread::sleep(Duration::from_secs(60)),
            "descendant" => {
                let mut descendant = Command::new(std::env::current_exe().unwrap());
                descendant
                    .args([
                        "--ignored",
                        "--exact",
                        CHILD,
                        "--nocapture",
                        "--skip",
                        QUOTED,
                    ])
                    .env("CM_VERIFIER_TEST_MODE", "sleep");
                let child = descendant.spawn().unwrap();
                writeln!(std::io::stdout(), "\ndescendant={}", child.id()).unwrap();
                std::process::exit(0);
            }
            _ => panic!("unknown controlled mode"),
        }
    }

    #[test]
    fn verifier_native_job_preserves_arguments_and_bounds_process_tree() {
        let output =
            super::super::collect_verifier(spawn(&command("ok")).unwrap(), Duration::from_secs(10))
                .unwrap();
        assert!(output.windows(14).any(|part| part == b"verified bytes"));
        for mode in ["fail", "sleep", "large"] {
            let start = Instant::now();
            assert!(
                super::super::collect_verifier(
                    spawn(&command(mode)).unwrap(),
                    Duration::from_secs(2)
                )
                .is_err()
            );
            assert!(start.elapsed() < Duration::from_secs(10));
        }
        let output = super::super::collect_verifier(
            spawn(&command("descendant")).unwrap(),
            Duration::from_secs(10),
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        let id: u32 = output
            .lines()
            .find_map(|line| line.strip_prefix("descendant="))
            .unwrap()
            .parse()
            .unwrap();
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, id: u32) -> *mut c_void;
            fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        let process = unsafe { OpenProcess(0x0010_1000, 0, id) };
        if process.is_null() {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(87));
        } else {
            let status = unsafe { WaitForSingleObject(process, 2000) };
            unsafe { CloseHandle(process) };
            assert_eq!(status, 0, "verifier descendant survived its parent");
        }
        let mut invalid = command("ok");
        invalid.env("SYSTEMROOT", "untrusted");
        assert!(spawn(&invalid).is_err());
        assert!(spawn(&Command::new("relative.exe")).is_err());
    }

    #[test]
    fn bundle_snapshot_keeps_jsonl_suffix_and_cleans_up() {
        let bytes = b"sealed bundle bytes";
        let bundle =
            crate::loader::sealed_named_snapshot(bytes, c"cm-distribution-bundle").unwrap();
        let path = crate::loader::snapshot_path(&bundle);
        assert_eq!(path.extension().unwrap(), "jsonl");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        drop(bundle);
        assert!(!path.exists());
    }
}
