//! Shared implementation of the two independent native acceptance Mods.
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use cm_sdk::{Host, Init, Mod, Request, v22};
use v22::Handle;

pub struct Fixture {
    host: Host,
    owner: &'static str,
    mode: String,
    pending: BTreeMap<Handle, Arc<Pending>>,
    previous: Option<(Handle, Handle, Handle)>,
}
struct Pending {
    cancelled: AtomicBool,
    changed: Condvar,
    lock: Mutex<()>,
}
struct DispatchReturn {
    owner: &'static str,
    request: Handle,
}
impl Drop for DispatchReturn {
    fn drop(&mut self) {
        record(
            self.owner,
            "dispatch-return",
            &format!(",\"request\":{:?}", handle(self.request)),
        );
    }
}

fn handle(handle: Handle) -> String {
    format!(
        "{:x}:{:x}:{:x}",
        handle.epoch, handle.slot, handle.generation
    )
}

fn parse_handle(text: &str) -> Option<Handle> {
    let values = text
        .split(':')
        .map(|part| u64::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if values.len() != 3 {
        return None;
    }
    Some(Handle {
        epoch: values[0],
        slot: values[1].try_into().ok()?,
        generation: values[2].try_into().ok()?,
    })
}

pub fn record(owner: &str, event: &str, fields: &str) {
    if let Ok(path) = std::env::var("CM_RUNTIME_EVENTS") {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("fixture event file");
        // Format first so concurrent Mod callbacks append each record in one write.
        let line = format!("{{\"owner\":{owner:?},\"event\":{event:?}{fields}}}\n");
        file.write_all(line.as_bytes())
            .expect("fixture event write");
    }
}

fn code(result: Result<(), cm_sdk::Error>) -> u32 {
    result.err().map_or(0, |error| error.code)
}

impl Fixture {
    pub fn new(owner: &'static str, init: Init) -> Result<Self, String> {
        record(
            owner,
            "init",
            &format!(
                ",\"config_bytes\":{},\"resources\":{}",
                init.config.len(),
                init.resources.len()
            ),
        );
        Ok(Self {
            host: init.host,
            owner,
            mode: std::env::var("CM_RUNTIME_MODE").unwrap_or_default(),
            pending: BTreeMap::new(),
            previous: None,
        })
    }

    fn count(&self, request: Handle, scope: Handle) -> Result<u64, String> {
        if scope == Handle::NONE {
            return Ok(0);
        }
        let previous = match self.host.state(request, scope, "calls") {
            Ok(value) => String::from_utf8(value)
                .map_err(|error| error.to_string())?
                .parse::<u64>()
                .map_err(|error| error.to_string())?,
            Err(error) if error.code == v22::NOT_FOUND => 0,
            Err(error) => return Err(format!("state_get: {error:?}")),
        };
        self.host
            .set_state(
                request,
                scope,
                "calls",
                (previous + 1).to_string().as_bytes(),
            )
            .map_err(|error| format!("state_set: {error:?}"))?;
        Ok(previous)
    }

    fn probes(&mut self, request: &Request) {
        let invalid_type =
            code(
                self.host
                    .complete(request.mod_scope, v22::SUCCEEDED, b"{}", false),
            );
        let wrong_scope =
            code(
                self.host
                    .set_state(request.handle, request.handle, "calls", b"bad"),
            );
        let oversized = code(self.host.set_state(
            request.handle,
            request.thread_scope,
            "oversized",
            &vec![0; v22::MAX_INPUT + 1],
        ));
        record(
            self.owner,
            "handle-probes",
            &format!(
                ",\"request\":{:?},\"invalid_type\":{invalid_type},\"wrong_scope\":{wrong_scope},\"oversized\":{oversized}",
                handle(request.handle)
            ),
        );
        assert_ne!(invalid_type, 0);
        assert_ne!(wrong_scope, 0);
        assert_ne!(oversized, 0);
        if let Ok(old) = std::env::var("CM_RUNTIME_OLD_HANDLE") {
            let old = parse_handle(&old).expect("previous process handle");
            let old_epoch = code(self.host.complete(old, v22::SUCCEEDED, b"{}", false));
            assert_eq!(old_epoch, v22::STALE);
            record(
                self.owner,
                "old-process-handle",
                &format!(",\"code\":{old_epoch}"),
            );
        }
        if let Ok(path) = std::env::var("CM_RUNTIME_EVENTS")
            && let Ok(events) = std::fs::read_to_string(path)
        {
            for line in events
                .lines()
                .filter(|line| !line.contains(&format!("\"owner\":{:?}", self.owner)))
            {
                if let Some(value) = line.split("\"thread_scope\":\"").nth(1)
                    && let Some(foreign) = value.split('"').next().and_then(parse_handle)
                {
                    let code =
                        code(
                            self.host
                                .set_state(request.handle, foreign, "calls", b"foreign"),
                        );
                    assert_eq!(code, v22::WRONG_OWNER);
                    record(
                        self.owner,
                        "cross-owner-handle",
                        &format!(",\"code\":{code}"),
                    );
                    break;
                }
            }
        }
        if let Some((old_request, old_thread, old_turn)) = self.previous {
            let stale_request = code(
                self.host
                    .complete(old_request, v22::SUCCEEDED, b"{}", false),
            );
            let old_thread_code = if old_thread == request.thread_scope {
                0
            } else {
                code(
                    self.host
                        .set_state(request.handle, old_thread, "calls", b"wrong-thread"),
                )
            };
            let old_turn_code = if old_turn == request.turn_scope || old_turn == Handle::NONE {
                0
            } else {
                code(
                    self.host
                        .set_state(request.handle, old_turn, "calls", b"wrong-turn"),
                )
            };
            record(
                self.owner,
                "previous-handles",
                &format!(
                    ",\"stale_request\":{stale_request},\"old_thread\":{old_thread_code},\"old_turn\":{old_turn_code}"
                ),
            );
            assert_ne!(stale_request, 0);
            if old_thread != request.thread_scope {
                assert_ne!(old_thread_code, 0);
            }
            if old_turn != request.turn_scope && old_turn != Handle::NONE {
                assert_ne!(old_turn_code, 0);
            }
        }
        self.previous = Some((request.handle, request.thread_scope, request.turn_scope));
    }

    fn bounds(&self, request: &Request) {
        assert_eq!(
            code(self.host.complete(request.handle, 999, b"{}", false)),
            v22::INVALID
        );
        assert_eq!(
            code(self.host.complete(
                request.handle,
                v22::SUCCEEDED,
                &vec![0; v22::MAX_RESULT + 1],
                false
            )),
            v22::INVALID
        );
        assert_eq!(
            code(
                self.host
                    .set_state(request.handle, request.turn_scope, &"k".repeat(129), b"x")
            ),
            v22::INVALID
        );
        let value = vec![0; v22::MAX_INPUT];
        for index in 0..15 {
            self.host
                .set_state(
                    request.handle,
                    request.turn_scope,
                    &format!("limit{index}"),
                    &value,
                )
                .expect("state below total limit");
        }
        assert_eq!(
            code(
                self.host
                    .set_state(request.handle, request.turn_scope, "limit15", &value)
            ),
            v22::LIMIT
        );
        self.host
            .set_state(request.handle, request.turn_scope, "limit0", b"x")
            .expect("replacement releases quota");
        self.host
            .set_state(request.handle, request.turn_scope, "limit15", &value)
            .expect("quota recovers");
        record(
            self.owner,
            "bounds",
            ",\"invalid_status\":true,\"result_limit\":true,\"key_limit\":true,\"state_total_limit\":true,\"quota_recovered\":true",
        );
    }
}

impl Mod for Fixture {
    fn dispatch(&mut self, request: Request) -> Result<(), String> {
        let _returned = DispatchReturn {
            owner: self.owner,
            request: request.handle,
        };
        let mod_calls = self.count(request.handle, request.mod_scope)?;
        let thread_calls = self.count(request.handle, request.thread_scope)?;
        let turn_calls = self.count(request.handle, request.turn_scope)?;
        record(
            self.owner,
            "dispatch",
            &format!(
                ",\"kind\":{},\"route\":{},\"request\":{:?},\"mod_scope\":{:?},\"thread_scope\":{:?},\"turn_scope\":{:?},\"thread\":{:?},\"turn\":{:?},\"call\":{:?},\"mod_before\":{mod_calls},\"thread_before\":{thread_calls},\"turn_before\":{turn_calls}",
                request.event,
                request.route,
                handle(request.handle),
                handle(request.mod_scope),
                handle(request.thread_scope),
                handle(request.turn_scope),
                request.thread_id,
                request.turn_id,
                request.call_id
            ),
        );
        if self.mode == "handles" {
            self.probes(&request);
        }
        if self.mode == "bounds" && request.event == v22::TOOL_CALL {
            self.bounds(&request);
        }
        if self.mode == "lifecycle-error" && request.event == v22::THREAD_START {
            self.host
                .complete(
                    request.handle,
                    v22::FAILED,
                    b"controlled lifecycle failure",
                    true,
                )
                .map_err(|error| format!("{error:?}"))?;
            return Ok(());
        }
        if self.mode == "context-error" && request.event == v22::SECTION {
            self.host
                .complete(
                    request.handle,
                    v22::FAILED,
                    b"controlled context failure",
                    true,
                )
                .map_err(|error| format!("{error:?}"))?;
            return Ok(());
        }
        if self.mode == "tool-error" && request.event == v22::TOOL_CALL {
            self.host
                .complete(
                    request.handle,
                    v22::FAILED,
                    b"controlled tool failure",
                    true,
                )
                .map_err(|error| format!("{error:?}"))?;
            return Ok(());
        }
        if (self.mode == "turn-error" && request.event == v22::TURN_START)
            || (self.mode == "stop-error" && request.event == v22::THREAD_STOP)
        {
            self.host
                .complete(
                    request.handle,
                    v22::FAILED,
                    b"controlled cleanup or turn failure",
                    true,
                )
                .map_err(|error| format!("{error:?}"))?;
            return Ok(());
        }
        if ["callback-error", "panic"].contains(&self.mode.as_str())
            && request.event == v22::TOOL_CALL
        {
            self.host
                .complete(request.handle, v22::CANCELLED, b"", true)
                .map_err(|error| format!("{error:?}"))?;
            if self.mode == "panic" {
                panic!("controlled Mod panic");
            }
            return Err("controlled native callback error".into());
        }
        let output = if request.event == v22::SECTION {
            format!(
                "CM_SECTION_{} thread={} turn={}",
                self.owner, request.thread_id, request.turn_id
            )
            .into_bytes()
        } else if request.event == v22::TOOL_CALL {
            format!("{{\"owner\":{:?},\"arguments\":{},\"mod_before\":{mod_calls},\"thread_before\":{thread_calls},\"turn_before\":{turn_calls}}}",
                self.owner, String::from_utf8_lossy(&request.input)).into_bytes()
        } else {
            b"{}".to_vec()
        };
        if request.event == v22::TOOL_CALL
            && ["async", "cancel", "noncooperative", "late", "timeout"]
                .contains(&self.mode.as_str())
        {
            let pending = Arc::new(Pending {
                cancelled: AtomicBool::new(false),
                changed: Condvar::new(),
                lock: Mutex::new(()),
            });
            self.pending.insert(request.handle, pending.clone());
            let host = self.host;
            let owner = self.owner;
            let mode = self.mode.clone();
            let barrier =
                std::env::var("CM_RUNTIME_BARRIER").map_err(|_| "missing fixture barrier")?;
            std::thread::spawn(move || {
                record(
                    owner,
                    "worker-entered",
                    &format!(",\"request\":{:?}", handle(request.handle)),
                );
                let started = Instant::now();
                let mut guard = pending.lock.lock().expect("fixture barrier lock");
                while !pending.cancelled.load(Ordering::Acquire)
                    && !std::path::Path::new(&barrier).exists()
                {
                    assert!(
                        started.elapsed() < Duration::from_secs(45),
                        "fixture barrier timeout"
                    );
                    guard = pending
                        .changed
                        .wait_timeout(guard, Duration::from_millis(5))
                        .expect("fixture barrier wait")
                        .0;
                }
                drop(guard);
                let cancelled = pending.cancelled.load(Ordering::Acquire);
                if mode == "noncooperative" {
                    record(
                        owner,
                        "noncooperative",
                        &format!(",\"request\":{:?}", handle(request.handle)),
                    );
                    return;
                }
                let status = if cancelled && mode != "late" {
                    v22::CANCELLED
                } else {
                    v22::SUCCEEDED
                };
                let result = code(host.complete(request.handle, status, &output, true));
                record(
                    owner,
                    "worker-complete",
                    &format!(
                        ",\"request\":{:?},\"code\":{result},\"cancelled\":{cancelled}",
                        handle(request.handle)
                    ),
                );
                if cancelled {
                    assert_eq!(result, v22::REQUEST_CANCELLED);
                } else {
                    assert_eq!(result, 0);
                }
            });
        } else {
            self.host
                .complete(request.handle, v22::SUCCEEDED, &output, false)
                .map_err(|error| format!("{error:?}"))?;
            let duplicate = code(
                self.host
                    .complete(request.handle, v22::SUCCEEDED, &output, true),
            );
            assert_eq!(duplicate, v22::ALREADY_COMPLETED);
            record(
                self.owner,
                "duplicate-complete",
                &format!(
                    ",\"request\":{:?},\"code\":{duplicate}",
                    handle(request.handle)
                ),
            );
        }
        Ok(())
    }

    fn cancel(&mut self, request: Handle) -> Result<(), String> {
        record(
            self.owner,
            "cancel",
            &format!(",\"request\":{:?}", handle(request)),
        );
        if let Some(pending) = self.pending.get(&request) {
            pending.cancelled.store(true, Ordering::Release);
            pending.changed.notify_all();
        }
        record(
            self.owner,
            "cancel-return",
            &format!(",\"request\":{:?}", handle(request)),
        );
        Ok(())
    }

    fn request_release(&mut self, request: Handle) -> Result<(), String> {
        self.pending.remove(&request);
        record(
            self.owner,
            "request-release",
            &format!(",\"request\":{:?}", handle(request)),
        );
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(
            self.pending.is_empty(),
            "userdata freed while a native request is still active"
        );
        record(self.owner, "userdata-release", "");
        if self.mode == "release-error" && self.owner == "lifecycle-audit" {
            panic!("controlled userdata release panic");
        }
    }
}
