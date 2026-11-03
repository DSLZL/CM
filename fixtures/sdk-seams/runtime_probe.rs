// Included only in an isolated Core probe's cm-runtime dependency.
use super::*;
use std::sync::atomic::AtomicUsize;

async fn until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "protocol barrier not reached");
        tokio::task::yield_now().await;
    }
}

fn poll_code(instance: Handle, parent: Handle, task: Handle, capacity: usize) -> (u32, v23::NextOutput, Vec<u8>) {
    let mut bytes = vec![0x5a; capacity + 2];
    let mut output = v23::NextOutput {
        header: v23::header::<v23::NextOutput>(), status: v23::PENDING, reserved: 0,
        result: v22::Buffer { data: bytes[1..].as_mut_ptr(), capacity: capacity as u64, len: 0 },
    };
    let pointer = output.result.data;
    let mut storage = [0_u8; cm_abi::ERROR_CAPACITY];
    let mut error = ErrorBuffer { data: storage.as_mut_ptr(), capacity: storage.len() as u64, len: 0 };
    let code = unsafe { (continuation_services().poll.expect("poll"))(instance, parent, task, &mut output, &mut error) };
    assert_eq!(pointer, output.result.data);
    assert_eq!(output.result.capacity, capacity as u64);
    assert_eq!((bytes[0], bytes[capacity + 1]), (0x5a, 0x5a));
    (code, output, bytes)
}

pub async fn run() {
    let case = std::env::var("CM_SEAMS_PROBE_CASE").expect("case");
    let home = std::path::PathBuf::from(std::env::var_os("CM_SEAMS_PROFILE").expect("profile"));
    let guard = crate::initialize(&home, true).expect("actual native Mod registration");
    let graph = crate::commands::configured_graph().expect("graph");
    if case.starts_with("tui-") {
        let owner = crate::commands::UiOwner::new().expect("UI owner");
        let work = owner.begin(&graph, "sdk-a__notice", None).expect("actual UI request");
        if case == "tui-cancel" {
            drop(owner);
            let mut completion = work.run().await;
            let replacement = crate::commands::UiOwner::new().expect("replacement");
            assert!(replacement.apply(&mut completion).is_err());
            drop(replacement);
        } else {
            let mut completion = work.run().await;
            if case == "tui-wrong-thread" {
                std::thread::scope(|scope| {
                    scope.spawn(|| assert!(owner.apply(&mut completion).is_err())).join().expect("wrong-thread probe");
                });
            } else if case == "tui-stale-owner" {
                let replacement = crate::commands::UiOwner::new().expect("replacement");
                assert!(replacement.apply(&mut completion).is_err());
                drop(replacement);
            }
            assert!(owner.apply(&mut completion).expect("current owner notice").contains("sdk-a UI notice"));
            assert!(owner.apply(&mut completion).is_err(), "duplicate apply");
            drop(owner);
        }
        guard.finish().expect("UI cleanup");
    } else {
        let registry = Registry::new().expect("registry");
        let thread = registry.thread("cm-g06-private-thread").expect("thread");
        let turn = thread.turn("cm-g06-private-turn").expect("turn");
        let contribution = ordered_contributions(Kind::ToolAround).expect("contributions").into_iter()
            .find(|item| item.owner == "sdk-a").expect("sdk-a");
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(tokio::sync::Notify::new());
        let cancelled = Arc::new(AtomicBool::new(false));
        let work_calls = Arc::clone(&calls);
        let work_started = Arc::clone(&started);
        let work_released = Arc::clone(&released);
        let cancel_released = Arc::clone(&released);
        let cancel_flag = Arc::clone(&cancelled);
        let next = Continuation::new(tokio::runtime::Handle::current(), move || async move {
            work_calls.fetch_add(1, Ordering::AcqRel);
            work_started.notify_one();
            work_released.notified().await;
            Ok(b"saved original preview".to_vec())
        }, move || { cancel_flag.store(true, Ordering::Release); cancel_released.notify_one(); });
        let request = dispatch_with_next(&turn, &contribution, br#"{"version":1,"target":"exec_command","arguments":{}}"#, "cm-g06-private-call", Arc::clone(&next)).expect("native dispatch");
        let parent = Arc::clone(&request.request);
        let mut request = Some(request);
        until(|| parent.state.lock().is_ok_and(|state| state.started_returned)).await;
        if case == "cancel-before" || case == "cancel-queued" {
            parent.cancel(false);
            assert!(request.take().expect("request").await.is_err());
            assert_eq!(calls.load(Ordering::Acquire), 0, "cancelled queued work ran");
        } else {
            until(|| calls.load(Ordering::Acquire) == 1).await;
            let task = {
                let hub = hub().expect("hub");
                let tables = hub.tables.lock().expect("table");
                let (slot, value) = tables.slots.iter().enumerate().find(|(_, slot)| {
                    matches!(&slot.value, Some(Object::Next { request, .. }) if *request == parent.handle())
                }).expect("task published");
                Handle { epoch: hub.epoch, slot: slot as u32, generation: value.generation }
            };
            let instance = parent.module.instance;
            if case == "tool-foreign-owner" {
                let foreign = hub().expect("hub").tables.lock().expect("table").modules.values()
                    .find(|module| module.instance != instance).expect("second actual owner").instance;
                assert_eq!(poll_code(foreign, parent.handle(), task, 64).0, v22::WRONG_OWNER);
                assert!(!parent.state.lock().expect("parent").cancelled);
                assert_eq!(poll_code(instance, parent.handle(), task, 64).0, 0);
            } else if case == "tool-stale-token" {
                let mut stale = task;
                stale.generation = stale.generation.checked_add(1).expect("generation");
                assert_eq!(poll_code(instance, parent.handle(), stale, 64).0, v22::STALE);
            } else if case == "release-pending" {
                let mut error = ErrorBuffer { data: std::ptr::null_mut(), capacity: 0, len: 0 };
                assert_eq!(unsafe { (continuation_services().release.expect("release"))(instance, parent.handle(), task, &mut error) }, 0);
                assert_eq!(poll_code(instance, parent.handle(), task, 64).0, v22::STALE);
                assert!(cancelled.load(Ordering::Acquire));
            } else if matches!(case.as_str(), "cancel-running" | "late-complete" | "exit-race") {
                parent.cancel(false);
                assert!(cancelled.load(Ordering::Acquire));
            } else if case == "drop-parent" {
                drop(request.take());
                assert!(cancelled.load(Ordering::Acquire));
            } else if case == "poll-bound" {
                released.notify_one();
                until(|| next.completed()).await;
                assert_eq!(poll_code(instance, parent.handle(), task, 1).0, v22::LIMIT);
                let (code, output, bytes) = poll_code(instance, parent.handle(), task, 64);
                assert_eq!(code, 0);
                assert_eq!(&bytes[1..1 + output.result.len as usize], b"saved original preview");
            }
            released.notify_one();
            until(|| next.completed()).await;
            if let Some(directory) = std::env::var_os("CM_SEAMS_BARRIER") {
                std::fs::write(std::path::PathBuf::from(directory).join("sdk-a"), b"release").expect("fixture release");
            }
            if let Some(request) = request {
                let result = request.await;
                if matches!(case.as_str(), "cancel-running" | "late-complete" | "exit-race") { assert!(result.is_err()); }
                else { assert!(result.is_ok(), "{result:?}"); }
            }
            if case == "cancel-after-complete" {
                parent.cancel(false);
                assert!(!parent.state.lock().expect("parent").cancelled);
            }
            assert_eq!(calls.load(Ordering::Acquire), 1, "saved work consumed twice");
        }
        until(|| {
            let hub = hub().expect("hub");
            hub.tables.lock().expect("table").get(hub.epoch, parent.handle()).is_err()
        }).await;
        turn.close().expect("turn cleanup");
        thread.close().expect("thread cleanup");
        drop(registry);
        guard.finish().expect("native cleanup");
    }
    std::fs::write(std::env::var_os("CM_SEAMS_PROBE_REPORT").expect("report"),
        json!({"status":"pass","case":case,"boundary":"private instrumented executable; real registered native Mod, not production H"}).to_string()).expect("report write");
}
