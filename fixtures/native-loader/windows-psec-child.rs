#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
compile_error!("This fixture requires native Windows ARM64");

use flatbuffers::FlatBufferBuilder;
use learning_mode_windows::{
    SecurityEnvironmentApi, SecurityEnvironmentStartupInfo, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};
use process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, EndpointPolicyT, FilterAction, NetworkPolicyT,
    ProcessSecurityEnvironmentT, SchemaVersionT,
};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::process::{self, Command};
use windows_core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

// The pinned SDK's TraceLogging dependency needs the ETW import library.
#[link(name = "advapi32")]
unsafe extern "system" {}

fn text(path: &Path) -> String {
    assert!(path.is_absolute());
    let value = path.to_str().expect("UTF-8 hosted path");
    assert!(!value.contains(['"', '\0']));
    value.to_owned()
}

fn child(root: &Path, role: &str) -> ! {
    let work = root.join("work");
    let protected = root.join("protected/canary");
    assert_eq!(fs::read(work.join("input")).unwrap(), b"psec-positive");
    fs::write(work.join(format!("{role}.positive")), b"psec-positive").unwrap();
    let read_error = fs::read(&protected).unwrap_err().raw_os_error().unwrap();
    let write_error = OpenOptions::new()
        .write(true)
        .open(&protected)
        .unwrap_err()
        .raw_os_error()
        .unwrap();
    assert_eq!(read_error, 5, "protected read was not denied");
    assert_eq!(write_error, 5, "protected write-open was not denied");
    assert!(std::env::var_os("CM_SOURCE_DIR").is_none());
    assert!(std::env::var_os("GITHUB_WORKSPACE").is_none());
    let mut record = json!({
        "role": role, "pid": process::id(), "read_error": read_error,
        "write_error": write_error, "positive": true, "environment_clean": true,
    });
    if role == "child" {
        let mut descendant = Command::new(std::env::current_exe().unwrap())
            .arg("--descendant")
            .arg(root)
            .current_dir(&work)
            .spawn()
            .expect("spawn real descendant without a fresh PSEC attribute");
        record["descendant_pid"] = json!(descendant.id());
        assert_eq!(descendant.wait().unwrap().code(), Some(38));
    }
    fs::write(
        work.join(format!("{role}.json")),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    process::exit(if role == "child" { 37 } else { 38 });
}

fn broker(root: &Path) {
    let exe = std::env::current_exe().unwrap();
    let system = std::env::var("SystemRoot").unwrap();
    assert!(std::env::var_os("CM_SOURCE_DIR").is_some());
    assert!(std::env::var_os("GITHUB_WORKSPACE").is_some());
    let work = root.join("work");
    let protected = root.join("protected");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir(&protected).unwrap();
    fs::write(work.join("input"), b"psec-positive").unwrap();
    let canary = protected.join("canary");
    fs::write(&canary, b"psec-denied").unwrap();
    assert_eq!(fs::read(&canary).unwrap(), b"psec-denied");
    drop(OpenOptions::new().write(true).open(&canary).unwrap());

    let mut spec = ProcessSecurityEnvironmentT::default();
    spec.version = SchemaVersionT { major: 1, minor: 0 };
    spec.fs_read_write = Some(vec![text(&work)]);
    spec.fs_read_only = Some(vec![system.clone(), text(exe.parent().unwrap())]);
    spec.fs_deny = Some(vec![text(&protected)]);
    let mut egress = EndpointPolicyT::default();
    egress.default_action = FilterAction::deny;
    let mut network = NetworkPolicyT::default();
    network.egress = Some(Box::new(egress));
    spec.network_policy = Some(Box::new(network));
    let mut builder = FlatBufferBuilder::with_capacity(1024);
    let packed = spec.pack(&mut builder);
    finish_process_security_environment_buffer(&mut builder, packed);
    assert_eq!(&builder.finished_data()[4..8], b"PSEC");
    let api = SecurityEnvironmentApi::load().expect("load fixed PSEC API");
    assert!(api.supports_deny_paths().unwrap());
    let environment = api
        .create(builder.finished_data(), PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("create real PSEC with file policy and no capabilities");
    let startup = SecurityEnvironmentStartupInfo::new(
        STARTUPINFOW::default(),
        environment.raw(),
        &[],
    )
    .expect("attach PSEC with zero inherited handles");

    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.unwrap();
    let job_owner = unsafe { OwnedHandle::from_raw_handle(job.0) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    }
    .expect("set kill-on-close before creating a child");
    let exe_wide: Vec<u16> = text(&exe).encode_utf16().chain([0]).collect();
    let mut command: Vec<u16> = format!("\"{}\" --child \"{}\"", text(&exe), text(root))
        .encode_utf16()
        .chain([0])
        .collect();
    let cwd: Vec<u16> = text(&work).encode_utf16().chain([0]).collect();
    let environment_block: Vec<u16> = format!(
        "SystemRoot={system}\0TEMP={}\0TMP={}\0WINDIR={system}\0\0",
        text(&work),
        text(&work)
    )
    .encode_utf16()
    .collect();
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(exe_wide.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            Some(environment_block.as_ptr().cast()),
            PCWSTR(cwd.as_ptr()),
            &startup.startup_info().StartupInfo,
            &mut pi,
        )
    }
    .expect("single-attempt CreateProcessW with PSEC; no legacy fallback");
    let process_owner = unsafe { OwnedHandle::from_raw_handle(pi.hProcess.0) };
    let thread_owner = unsafe { OwnedHandle::from_raw_handle(pi.hThread.0) };
    if let Err(error) = unsafe { AssignProcessToJobObject(job, pi.hProcess) } {
        unsafe { TerminateProcess(pi.hProcess, 97) }.expect("terminate unassigned suspended child");
        assert_eq!(unsafe { WaitForSingleObject(pi.hProcess, 5000) }, WAIT_OBJECT_0);
        panic!("assign PSEC child to job: {error}");
    }
    assert_eq!(unsafe { ResumeThread(pi.hThread) }, 1);
    assert_eq!(
        unsafe { WaitForSingleObject(pi.hProcess, 15000) },
        WAIT_OBJECT_0,
        "bounded child/descendant deadline"
    );
    let mut exit = 0;
    unsafe { GetExitCodeProcess(pi.hProcess, &mut exit) }.unwrap();
    if exit != 37 {
        for role in ["child", "descendant"] {
            if let Ok(detail) = fs::read_to_string(work.join(format!("{role}.failure.log"))) {
                eprintln!("{role} failure: {}", detail.chars().take(4096).collect::<String>());
            }
        }
    }
    assert_eq!(exit, 37, "real PSEC child did not finish file controls");
    drop(thread_owner);
    drop(process_owner);
    drop(job_owner);
    drop(startup);
    environment.close();

    let child: Value = serde_json::from_slice(&fs::read(work.join("child.json")).unwrap()).unwrap();
    let descendant: Value =
        serde_json::from_slice(&fs::read(work.join("descendant.json")).unwrap()).unwrap();
    assert_eq!(child["pid"], pi.dwProcessId);
    assert_eq!(child["descendant_pid"], descendant["pid"]);
    let descendant_pid = descendant["pid"].as_u64().unwrap();
    assert!(descendant_pid > 0 && descendant_pid <= u32::MAX as u64);
    assert_ne!(descendant_pid, pi.dwProcessId as u64);
    assert_ne!(descendant_pid, process::id() as u64);
    for (role, record) in [("child", &child), ("descendant", &descendant)] {
        assert_eq!(record["role"], role);
        assert_eq!(record["read_error"], 5);
        assert_eq!(record["write_error"], 5);
        assert_eq!(record["positive"], true);
        assert_eq!(record["environment_clean"], true);
        assert_eq!(
            fs::read(work.join(format!("{role}.positive"))).unwrap(),
            b"psec-positive"
        );
    }
    assert_eq!(fs::read(&canary).unwrap(), b"psec-denied");
    drop(OpenOptions::new().write(true).open(&canary).unwrap());
    println!(
        "{}",
        json!({
            "gate": "native-psec-process-file-control", "policy": "psec-only",
            "broker_pid": process::id(), "child_pid": pi.dwProcessId,
            "descendant_pid": descendant_pid, "child_exit_code": exit,
            "descendant_exit_code": 38, "file_positive_count": 2,
            "child_read_error": 5, "child_write_open_error": 5,
            "descendant_read_error": 5, "descendant_write_open_error": 5,
            "protected_bytes_preserved": true, "ordinary_file_baselines": 2,
            "environment_allowlist_count": 4, "environment_canaries_absent": true,
            "inherited_handle_count": 0, "suspended_job_assignment_checked": true,
            "legacy_fallback": false, "network": "not_run", "full_isolation": "not_run",
        })
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() == 3);
    let root = Path::new(&args[2]);
    if matches!(args[1].as_str(), "--child" | "--descendant") {
        let role = args[1].trim_start_matches("--");
        let failure = root.join("work").join(format!("{role}.failure.log"));
        std::panic::set_hook(Box::new(move |info| {
            let detail: String = info.to_string().chars().take(4096).collect();
            let _ = fs::write(&failure, detail);
        }));
    }
    match args[1].as_str() {
        "--broker" => broker(root),
        "--child" => child(root, "child"),
        "--descendant" => child(root, "descendant"),
        _ => panic!("unknown fixed PSEC fixture role"),
    }
}
