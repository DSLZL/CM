//! Actions-only ABI/lifetime harness; business acceptance uses packaged CLI exec.
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use cm_runtime::tool_policy::Context;
use cm_runtime::tool_policy::evaluate;

fn policy(cancelled: &AtomicBool) -> Result<(), String> {
    let original = std::env::var("CM_PROBE_ORIGINAL").as_deref() != Ok("false");
    let tool = std::env::var("CM_PROBE_TOOL").unwrap_or_else(|_| "exec_command".into());
    let decision = evaluate(
        Context {
            namespace: "functions",
            tool: &tool,
            call_id: "probe-call",
            thread_id: "probe-thread",
            turn_id: "probe-turn",
        },
        original,
        || cancelled.load(Ordering::Acquire),
    )
    .map_err(|e| format!("{e:?}"))?;
    println!("{{\"parallel\":{}}}", decision.supports_parallel);
    drop(decision);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = PathBuf::from(std::env::args_os().nth(1).ok_or("missing profile")?);
    let guard = cm_runtime::initialize(&home, true)?;
    let action = std::env::var("CM_PROBE_ACTION").unwrap_or_else(|_| "load".into());
    match action.as_str() {
        "load" => {}
        "policy" => policy(&AtomicBool::new(false))?,
        "cancel-before" => {
            let error = policy(&AtomicBool::new(true)).unwrap_err();
            if error != "Cancelled" {
                return Err(error.into());
            }
        }
        "drain" | "cancel-after" => {
            let cancelled = Arc::new(AtomicBool::new(false));
            let worker_cancelled = Arc::clone(&cancelled);
            let worker = std::thread::spawn(move || policy(&worker_cancelled));
            let mut command = String::new();
            std::io::stdin().lock().read_line(&mut command)?;
            if command.trim() != "continue" {
                return Err("missing explicit barrier command".into());
            }
            if action == "cancel-after" {
                cancelled.store(true, Ordering::Release);
                println!("cancel-recorded");
                std::io::Write::flush(&mut std::io::stdout())?;
                let result = worker.join().map_err(|_| "probe thread panicked")?;
                if result != Err("Cancelled".into()) {
                    return Err("after-callback cancellation was lost".into());
                }
                guard.finish()?;
            } else {
                guard.finish()?;
                worker.join().map_err(|_| "probe thread panicked")??;
            }
            return Ok(());
        }
        _ => return Err("unknown probe action".into()),
    }
    guard.finish()?;
    Ok(())
}
