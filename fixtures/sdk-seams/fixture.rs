//! Independent author fixture: only cm-sdk/cm-abi, with explicit test barriers.
use cm_sdk::{Host, Init, Mod, NextPoll, Request, v22, v23};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use v22::Handle;

pub struct Fixture { host: Host, pending: BTreeMap<Handle, Arc<Pending>> }
struct Pending { cancelled: Mutex<bool>, changed: Condvar }
fn token(value: Handle) -> String { format!("{:x}:{:x}:{:x}", value.epoch, value.slot, value.generation) }
fn hex(value: &[u8]) -> String { value.iter().map(|byte| format!("{byte:02x}")).collect() }
pub fn record(event: &str, request: Handle, detail: &str) {
    if let Some(path) = std::env::var_os("CM_SEAMS_EVENTS") {
        let line = format!("{{\"owner\":{:?},\"version\":{},\"event\":{event:?},\"request\":{:?}{detail}}}\n",
            super::OWNER, if cfg!(feature = "version2") { 2 } else { 1 }, token(request));
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path).expect("fixture log");
        file.write_all(line.as_bytes()).expect("one atomic fixture record");
    }
}
pub fn create(init: Init) -> Result<Fixture, String> {
    record("init", Handle::NONE, "");
    Ok(Fixture { host: init.host, pending: BTreeMap::new() })
}
pub extern "C" fn constructor() { record("constructor", Handle::NONE, ""); }
fn sequence(input: &[u8]) -> Result<u64, String> {
    let input = std::str::from_utf8(input).map_err(|_| "input UTF-8")?;
    let value = input.split_once("\"sequence\":").ok_or("sequence missing")?.1.trim_start();
    let end = value.find(|character: char| !character.is_ascii_digit()).unwrap_or(value.len());
    value[..end].parse().map_err(|_| "invalid sequence".into())
}
fn cancelled(pending: &Pending) -> bool { *pending.cancelled.lock().expect("cancel lock") }
fn barrier(pending: &Pending, owner: &str) {
    let Some(directory) = std::env::var_os("CM_SEAMS_BARRIER") else { return; };
    let path = std::path::PathBuf::from(directory).join(owner);
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut guard = pending.cancelled.lock().expect("barrier lock");
    while !*guard && !path.exists() && Instant::now() < deadline {
        guard = pending.changed.wait_timeout(guard, Duration::from_millis(10)).expect("barrier wait").0;
    }
    assert!(*guard || path.exists(), "fixture barrier timed out");
}
fn finish(host: Host, request: Handle, status: u32, output: &[u8]) {
    record("complete", request, &format!(",\"status\":{status}"));
    let _ = host.complete(request, status, output, true);
}
impl Mod for Fixture {
    fn dispatch(&mut self, request: Request) -> Result<(), String> {
        record("dispatch", request.handle, &format!(",\"kind\":{},\"route\":{},\"thread\":{:?},\"turn\":{:?},\"call\":{:?},\"input_hex\":{:?}",
            request.event, request.route, request.thread_id, request.turn_id, request.call_id, hex(&request.input)));
        let selected_kind = std::env::var("CM_SEAMS_MODE_KIND").ok().and_then(|value| value.parse::<u32>().ok());
        let selected_owner = std::env::var("CM_SEAMS_MODE_OWNER").ok();
        let mode = if selected_kind.is_none_or(|kind| kind == request.event)
            && selected_owner.as_deref().is_none_or(|owner| owner == super::OWNER) {
            std::env::var("CM_SEAMS_MODE").unwrap_or_default()
        } else { String::new() };
        let pending = Arc::new(Pending { cancelled: Mutex::new(false), changed: Condvar::new() });
        self.pending.insert(request.handle, Arc::clone(&pending));
        if request.event == v23::TOOL_AROUND && matches!(mode.as_str(), "zero" | "replacement") {
            finish(self.host, request.handle, v22::SUCCEEDED, br#"{"version":1,"action":"text","text":"fixture short circuit","success":true}"#);
            return Ok(());
        }
        let mut task = None;
        if request.event == v23::TOOL_AROUND && mode != "cancel-before" {
            task = Some(self.host.next_start(request.handle).map_err(|error| format!("next start: {error:?}"))?);
            record("next-start", request.handle, &format!(",\"task\":{:?}", token(task.expect("task"))));
            if mode == "next-twice" {
                let error = self.host.next_start(request.handle).expect_err("repeat next rejected");
                record("repeat-next", request.handle, &format!(",\"code\":{}", error.code));
                assert_eq!(error.code, v22::ALREADY_COMPLETED);
            }
        }
        let host = self.host;
        std::thread::spawn(move || {
            if mode == "noncooperative" {
                record("waiting", request.handle, "");
                loop { std::thread::park(); }
            }
            if std::env::var_os("CM_SEAMS_BARRIER").is_some()
                && std::env::var("CM_SEAMS_BARRIER_KIND").ok().and_then(|value| value.parse::<u32>().ok()).is_none_or(|kind| kind == request.event) {
                record("waiting", request.handle, &format!(",\"kind\":{}", request.event));
                barrier(&pending, super::OWNER);
            }
            if request.event == v23::TOOL_AROUND && mode == "cancel-before" && !cancelled(&pending) {
                task = host.next_start(request.handle).ok();
            }
            if let Some(task) = task {
                let deadline = Instant::now() + Duration::from_secs(35);
                loop {
                    if cancelled(&pending) { let _ = host.next_cancel(request.handle, task); break; }
                    match host.next_poll(request.handle, task) {
                        Ok(NextPoll::Pending) if Instant::now() < deadline => {
                            let guard = pending.cancelled.lock().expect("poll lock");
                            let _ = pending.changed.wait_timeout(guard, Duration::from_millis(2)).expect("poll wait");
                        }
                        Ok(NextPoll::Ready { status, result }) => {
                            record("next-ready", request.handle, &format!(",\"status\":{status},\"result_hex\":{:?}", hex(&result)));
                            break;
                        }
                        value => { record("next-stopped", request.handle, &format!(",\"error\":{:?}", format!("{value:?}"))); break; }
                    }
                }
                let _ = host.next_release(request.handle, task);
            }
            let status = if cancelled(&pending) && mode != "late-complete" { v22::CANCELLED } else if mode == "mod-error" { v22::FAILED } else { v22::SUCCEEDED };
            let output = match request.event {
                v23::TOOL_AROUND => br#"{"version":1,"action":"keep"}"#.to_vec(),
                v23::STREAM_EVENT => {
                    let sequence = sequence(&request.input).expect("stream DTO");
                    format!("{{\"version\":1,\"ack\":{}}}", sequence + u64::from(mode == "bad-ack")).into_bytes()
                }
                v23::CLI_CALL => format!("{{\"version\":1,\"text\":\"{} author-v{} bytes={}\"}}",
                    super::OWNER, if cfg!(feature = "version2") { 2 } else { 1 }, request.input.len()).into_bytes(),
                v23::TUI_CALL => format!("{{\"version\":1,\"notice\":\"{} UI notice-v{}\"}}",
                    super::OWNER, if cfg!(feature = "version2") { 2 } else { 1 }).into_bytes(),
                _ => b"{}".to_vec(),
            };
            if mode == "duplicate-complete" {
                host.complete(request.handle, status, &output, false).expect("first nonquiescent completion");
            }
            finish(host, request.handle, status, &output);
        });
        Ok(())
    }
    fn cancel(&mut self, request: Handle) -> Result<(), String> {
        record("cancel", request, "");
        if let Some(pending) = self.pending.get(&request) {
            *pending.cancelled.lock().map_err(|_| "cancel lock")? = true;
            pending.changed.notify_all();
        }
        Ok(())
    }
    fn request_release(&mut self, request: Handle) -> Result<(), String> {
        record("request-release", request, "");
        self.pending.remove(&request);
        Ok(())
    }
}
impl Drop for Fixture { fn drop(&mut self) { record("userdata-release", Handle::NONE, ""); } }
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_stream_sequence_parser() {
        assert_eq!(sequence(br#"{"sequence":42,"event":{}}"#).unwrap(), 42);
        for value in [br#"{"sequence":-1}"#.as_slice(), b"{}", br#"{"sequence":18446744073709551616}"#] { assert!(sequence(value).is_err()); }
    }
}
