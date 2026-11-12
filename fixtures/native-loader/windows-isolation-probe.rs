use appcontainer_common::base_container_runner::BaseContainerRunner;
use learning_mode_windows::SecurityEnvironmentApi;

// The pinned SDK's TraceLogging dependency needs the ETW import library.
#[link(name = "advapi32")]
unsafe extern "system" {}

fn main() {
    let usable = BaseContainerRunner::is_process_security_environment_usable();
    let deny_paths = SecurityEnvironmentApi::load()
        .and_then(|api| api.supports_deny_paths())
        .unwrap_or(false);
    println!(
        "{}",
        serde_json::json!({
            "gate": "native-psec-availability",
            "usable": usable,
            "deny_paths": deny_paths,
            "full_isolation": "not_run",
        })
    );
    if !usable || !deny_paths {
        std::process::exit(2);
    }
}
