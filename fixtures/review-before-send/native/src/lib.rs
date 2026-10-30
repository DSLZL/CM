use cm_sdk::{Host, Init, Mod, Request, abi::Bytes, v22};
use std::collections::BTreeSet;
use std::io::Write;

const DECISION: &[u8] = br#"{"schema_version":1,"require_review":true}"#;

struct Fixture {
    host: Host,
    pending: BTreeSet<v22::Handle>,
}

fn record(event: &str, code: u32) {
    let path = std::env::var_os("CM_REVIEW_FAULT_LOG").expect("fault log");
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path).expect("open log");
    writeln!(file, "{{\"event\":\"{event}\",\"code\":{code}}}").expect("record");
}

fn create(init: Init) -> Result<Fixture, String> {
    Ok(Fixture { host: init.host, pending: BTreeSet::new() })
}

impl Mod for Fixture {
    fn dispatch(&mut self, request: Request) -> Result<(), String> {
        assert_eq!(request.event, v22::SUBMIT_REVIEW);
        assert_eq!(request.thread_scope, v22::Handle::NONE);
        assert_eq!(request.turn_scope, v22::Handle::NONE);
        assert!(request.thread_id.is_empty() && request.turn_id.is_empty() && request.call_id.is_empty());
        self.host.set_state(request.handle, request.mod_scope, "review-probe", b"mod-only")
            .map_err(|error| error.message)?;
        assert_eq!(self.host.state(request.handle, request.mod_scope, "review-probe").map_err(|e| e.message)?, b"mod-only");
        assert!(self.host.state(request.handle, request.thread_scope, "review-probe").is_err());
        assert!(self.host.state(request.handle, request.turn_scope, "review-probe").is_err());
        record("ui-only-scopes", 0);
        let mode = std::env::var("CM_REVIEW_FAULT").expect("fixed fixture mode");
        match mode.as_str() {
            "error" => return Err("controlled dispatch error".into()),
            "panic" => panic!("controlled SDK boundary panic"),
            "cancel" | "deadline" => {
                self.pending.insert(request.handle);
                return Ok(());
            }
            "late" => {
                let host = self.host;
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(32));
                    let code = host.complete(request.handle, v22::SUCCEEDED, DECISION, true)
                        .map_or_else(|error| error.code, |()| 0);
                    record("late-completion", code);
                });
                return Ok(());
            }
            _ => {}
        }
        let result: &[u8] = match mode.as_str() {
            "false" => br#"{"schema_version":1,"require_review":false}"#,
            "extra" => br#"{"schema_version":1,"require_review":true,"authorized":true}"#,
            "malformed" => b"{",
            "duplicate" | "stale" | "complete-error" => DECISION,
            _ => return Err("unknown fault fixture mode".into()),
        };
        if mode == "stale" {
            let stale = v22::Handle { epoch: request.handle.epoch ^ 1, ..request.handle };
            let error = self.host.complete(stale, v22::SUCCEEDED, result, true).expect_err("stale request rejected");
            record("stale-completion", error.code);
        }
        self.host.complete(request.handle, v22::SUCCEEDED, result, true).map_err(|error| error.message)?;
        if mode == "complete-error" {
            return Err("controlled error after synchronous completion".into());
        }
        if mode == "duplicate" {
            let error = self.host.complete(request.handle, v22::SUCCEEDED, result, true).expect_err("one completion");
            assert_eq!(error.code, v22::ALREADY_COMPLETED);
            record("duplicate-completion", error.code);
        }
        Ok(())
    }

    fn cancel(&mut self, request: v22::Handle) -> Result<(), String> {
        if self.pending.remove(&request) {
            let error = self.host.complete(request, v22::CANCELLED, b"", true).expect_err("cancelled");
            assert_eq!(error.code, v22::REQUEST_CANCELLED);
        }
        record("cancel", 0);
        Ok(())
    }

    fn request_release(&mut self, _request: v22::Handle) -> Result<(), String> {
        record("request-release", 0);
        Ok(())
    }
}

const CONTRIBUTIONS: &[v22::RuntimeContribution] = &[v22::RuntimeContribution {
    header: v22::header::<v22::RuntimeContribution>(), id: Bytes::from_static("draft-review"),
    capability: Bytes::from_static(v22::SUBMIT_REVIEW_CAPABILITY),
    resource: Bytes::from_static(v22::SUBMIT_REVIEW_CAPABILITY),
    kind: v22::KIND_SUBMIT_REVIEW, reserved: 0, route: 1,
}];

cm_sdk::export_mod!(Fixture, "org.example.review-before-send", create, crate::CONTRIBUTIONS);
