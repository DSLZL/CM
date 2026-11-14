#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
compile_error!("This fixture requires native Windows ARM64");

use flatbuffers::FlatBufferBuilder;
use learning_mode_windows::{
    SecurityEnvironmentApi, SecurityEnvironmentStartupInfo, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};
use process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, EndpointPolicyT, FilterAction, NetworkPolicyT,
    ProcessSecurityEnvironmentT, ProxyInfoT, SchemaVersionT,
};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::process::{self, Command};
use std::time::Duration;
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

fn network_error(error: Option<std::io::Error>) -> Value {
    match error {
        Some(error) if error.raw_os_error().is_none() && error.kind() == std::io::ErrorKind::TimedOut => json!("timed_out"),
        Some(error) => json!(error.raw_os_error().unwrap_or(0)),
        None => json!(0),
    }
}

fn network_controls(work: &Path, role: &str) -> Value {
    let bytes = fs::read(work.join("network.json")).unwrap();
    assert!(bytes.len() <= 4096);
    let config: Value = serde_json::from_slice(&bytes).unwrap();
    let audit = Path::new(config["audit_dir"].as_str().unwrap()).join("network-audit-canary.txt");
    let audit_read_error = fs::read(&audit).unwrap_err().raw_os_error().unwrap();
    let audit_write_open_error = OpenOptions::new().write(true).open(&audit)
        .unwrap_err().raw_os_error().unwrap();
    assert_eq!(audit_read_error, 5);
    assert_eq!(audit_write_open_error, 5);
    let host: Ipv4Addr = config["host"].as_str().unwrap().parse().unwrap();
    assert!(!host.is_loopback() && !host.is_unspecified() && !host.is_link_local());
    let port = |name: &str| u16::try_from(config[name].as_u64().unwrap()).unwrap();
    let provider: SocketAddr = (Ipv4Addr::LOCALHOST, port("provider_port")).into();
    let outside: SocketAddr = (host, port("outside_port")).into();
    let other_port: SocketAddr = (Ipv4Addr::LOCALHOST, port("outside_port")).into();
    let other_address: SocketAddr = (Ipv4Addr::new(127, 0, 0, 2), port("provider_port")).into();
    let timeout = Duration::from_millis(400);
    let denied = |error: &Value| matches!(error.as_i64(), Some(10013 | 10060)) || error.as_str() == Some("timed_out");
    let mut trace = fs::File::create(work.join(format!("{role}.network.log"))).unwrap();
    let mut stream = TcpStream::connect_timeout(&provider, Duration::from_secs(1))
        .expect("exact loopback provider must be reachable");
    stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
    write!(stream, "GET /{role}/{}/provider HTTP/1.0\r\n\r\n", process::id()).unwrap();
    let mut response = Vec::new();
    stream.take(1025).read_to_end(&mut response).unwrap();
    assert_eq!(response, b"HTTP/1.0 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\ncm-provider-ok");
    writeln!(trace, "provider=passed pid={}", process::id()).unwrap();
    let mut tcp_errors = Vec::new();
    for endpoint in [outside, other_port, other_address] {
        let error = network_error(TcpStream::connect_timeout(&endpoint, timeout).err());
        writeln!(trace, "tcp {endpoint} error={error}").unwrap();
        assert!(denied(&error), "forbidden TCP endpoint {endpoint}: {error}");
        tcp_errors.push(error);
    }
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    udp.set_read_timeout(Some(timeout)).unwrap();
    let mut udp_errors = Vec::new();
    for (index, endpoint) in [outside, other_port, provider].into_iter().enumerate() {
        let message = format!("{role}/{}/udp{index}", process::id());
        let error = match udp.send_to(message.as_bytes(), endpoint) {
            Ok(length) => {
                assert_eq!(length, message.len());
                network_error(udp.recv_from(&mut [0u8; 1024]).err())
            }
            Err(error) => network_error(Some(error)),
        };
        writeln!(trace, "udp {endpoint} error={error}").unwrap();
        assert!(denied(&error), "forbidden UDP endpoint {endpoint}: {error}");
        udp_errors.push(error);
    }
    json!({"provider": true, "tcp_errors": tcp_errors, "udp_errors": udp_errors,
        "audit_read_error": audit_read_error, "audit_write_open_error": audit_write_open_error})
}

fn child(root: &Path, role: &str, network_probe: bool) -> ! {
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
    assert!(!std::env::var_os("LOCALAPPDATA").unwrap().is_empty());
    let mut record = json!({
        "role": role, "pid": process::id(), "read_error": read_error,
        "write_error": write_error, "positive": true, "environment_clean": true,
    });
    if network_probe {
        record["network"] = network_controls(&work, role);
    }
    if role == "child" {
        let mut descendant = Command::new(std::env::current_exe().unwrap())
            .arg(if network_probe { "--network-descendant" } else { "--descendant" })
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

fn broker(root: &Path, network_probe: bool) {
    let exe = std::env::current_exe().unwrap();
    let system = std::env::var("SystemRoot").unwrap();
    assert!(std::env::var_os("CM_SOURCE_DIR").is_some());
    assert!(std::env::var_os("GITHUB_WORKSPACE").is_some());
    let work = root.join("work");
    let protected = root.join("protected");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir(&protected).unwrap();
    fs::write(work.join("input"), b"psec-positive").unwrap();
    let network_config: Option<Value> = network_probe.then(|| {
        let bytes = fs::read(root.join("network.json")).unwrap();
        assert!(bytes.len() <= 4096);
        fs::write(work.join("network.json"), &bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    });
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
    if let Some(config) = &network_config {
        let port = u16::try_from(config["provider_port"].as_u64().unwrap()).unwrap();
        assert_ne!(port, 0);
        let mut proxy = ProxyInfoT::default();
        proxy.url = Some(format!("http://127.0.0.1:{port}"));
        network.proxy = Some(Box::new(proxy));
        network.allowed_appcontainer_peer = Some("MXC-Loopback".to_owned());
        spec.capabilities = Some("privateNetworkClientServer,networkLoopback".to_owned());
        spec.fs_deny.as_mut().unwrap().push(text(Path::new(config["audit_dir"].as_str().unwrap())));
    } else {
        network.egress = Some(Box::new(egress));
    }
    spec.network_policy = Some(Box::new(network));
    let mut builder = FlatBufferBuilder::with_capacity(1024);
    let packed = spec.pack(&mut builder);
    finish_process_security_environment_buffer(&mut builder, packed);
    assert_eq!(&builder.finished_data()[4..8], b"PSEC");
    let api = SecurityEnvironmentApi::load().expect("load fixed PSEC API");
    assert!(api.supports_deny_paths().unwrap());
    let environment = api
        .create(builder.finished_data(), PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("create real PSEC with fixed file and network policy");
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
    let child_mode = if network_probe { "--network-child" } else { "--child" };
    let mut command: Vec<u16> = format!("\"{}\" {child_mode} \"{}\"", text(&exe), text(root))
        .encode_utf16()
        .chain([0])
        .collect();
    let cwd: Vec<u16> = text(&work).encode_utf16().chain([0]).collect();
    let environment_block: Vec<u16> = format!(
        "LOCALAPPDATA={}\0SystemRoot={system}\0TEMP={}\0TMP={}\0WINDIR={system}\0\0",
        text(&work),
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
            for kind in ["failure", "network"] {
                if let Ok(detail) = fs::read_to_string(work.join(format!("{role}.{kind}.log"))) {
                    eprintln!("{role} {kind}: {}", detail.chars().take(4096).collect::<String>());
                }
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
    let mut result = json!({
            "gate": "native-psec-process-file-control", "policy": "psec-only",
            "broker_pid": process::id(), "child_pid": pi.dwProcessId,
            "descendant_pid": descendant_pid, "child_exit_code": exit,
            "descendant_exit_code": 38, "file_positive_count": 2,
            "child_read_error": 5, "child_write_open_error": 5,
            "descendant_read_error": 5, "descendant_write_open_error": 5,
            "protected_bytes_preserved": true, "ordinary_file_baselines": 2,
            "environment_allowlist_count": 5, "environment_canaries_absent": true,
            "inherited_handle_count": 0, "suspended_job_assignment_checked": true,
            "legacy_fallback": false, "network": "not_run", "full_isolation": "not_run",
        });
    if network_probe {
        result["gate"] = json!("native-psec-provider-network-control");
        result["network"] = json!("passed_provider_and_canary_controls");
        result["network_controls"] = json!({"child": child["network"], "descendant": descendant["network"]});
    }
    println!("{result}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() == 3);
    let root = Path::new(&args[2]);
    if matches!(args[1].as_str(), "--child" | "--descendant" | "--network-child" | "--network-descendant") {
        let role = if args[1].ends_with("descendant") { "descendant" } else { "child" };
        let failure = root.join("work").join(format!("{role}.failure.log"));
        std::panic::set_hook(Box::new(move |info| {
            let detail: String = info.to_string().chars().take(4096).collect();
            let _ = fs::write(&failure, detail);
        }));
    }
    match args[1].as_str() {
        "--broker" => broker(root, false),
        "--network" => broker(root, true),
        "--child" => child(root, "child", false),
        "--descendant" => child(root, "descendant", false),
        "--network-child" => child(root, "child", true),
        "--network-descendant" => child(root, "descendant", true),
        _ => panic!("unknown fixed PSEC fixture role"),
    }
}
