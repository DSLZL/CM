// Included only in a private cm-host-adapter copy.
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

struct ProbeDrop(Arc<AtomicBool>);
impl Drop for ProbeDrop {
    fn drop(&mut self) {
        self.0.store(true, AtomicOrdering::Release);
    }
}

pub async fn sdk_stream_probe(home: &std::path::Path, case: &str) {
    let guard = cm_runtime::initialize(home, true).expect("native registration");
    let registry = Registry::new().expect("registry");
    let thread = registry
        .thread("sdk-stream-private-thread")
        .expect("thread");
    let scope = thread.turn("sdk-stream-private-turn").expect("turn");
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let count = Arc::clone(&polls);
    let sentinel = ProbeDrop(Arc::clone(&dropped));
    let upstream: ModelResponseStream = Box::pin(futures::stream::poll_fn(move |_| {
        let _retain = &sentinel;
        let event = match count.fetch_add(1, AtomicOrdering::AcqRel) {
            0 => Some(Ok(ResponseEvent::Created {
                response_id: Some("private-response".into()),
            })),
            1 => Some(Ok(ResponseEvent::ToolCallInputDelta {
                item_id: "private-tool-item".into(),
                call_id: Some("private-tool-call".into()),
                delta: "unchanged-input".into(),
            })),
            2 => Some(Ok(ResponseEvent::OutputTextDelta("unchanged".into()))),
            3 => Some(Ok(ResponseEvent::Completed {
                response_id: "private-response".into(),
                token_usage: None,
                usage_metadata: None,
                end_turn: None,
            })),
            _ => None,
        };
        std::task::Poll::Ready(event)
    }));
    let observer = Observer {
        scope: Ok(scope.clone()),
        contributions: runtime::ordered_contributions(Kind::ResponseStream)
            .expect("ordered streams"),
        request: "private-logical-request".into(),
        attempt: 1,
    };
    let observer_count = observer.contributions.len();
    let mut stream = Box::new(observer).intercept(upstream);
    let mut first = Box::pin(stream.next());
    assert!(futures::poll!(&mut first).is_pending());
    let deadline = Instant::now() + Duration::from_secs(10);
    let events = std::path::PathBuf::from(std::env::var_os("CM_SEAMS_EVENTS").expect("events"));
    while !std::fs::read_to_string(&events)
        .unwrap_or_default()
        .contains("\"event\":\"waiting\"")
    {
        assert!(Instant::now() < deadline, "native stream barrier");
        tokio::task::yield_now().await;
    }
    assert_eq!(
        polls.load(AtomicOrdering::Acquire),
        1,
        "prefetched while one ACK is pending"
    );
    let terminal =
        case.ends_with("drop") || case.ends_with("late-ack") || case.ends_with("turn-cancel");
    if terminal {
        if case.ends_with("turn-cancel") {
            scope.begin_close().expect("begin close");
        }
        drop(first);
        drop(stream);
        assert!(
            dropped.load(AtomicOrdering::Acquire),
            "upstream retained after drop"
        );
    } else {
        let barrier =
            std::path::PathBuf::from(std::env::var_os("CM_SEAMS_BARRIER").expect("barrier"));
        for owner in ["sdk-a", "sdk-b"] {
            std::fs::write(barrier.join(owner), b"release").expect("release");
        }
        assert!(matches!(
            first.await,
            Some(Ok(ResponseEvent::Created { .. }))
        ));
        if case.ends_with("slow-consumer") {
            for _ in 0..1000 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                polls.load(AtomicOrdering::Acquire),
                1,
                "upstream advanced without consumer demand"
            );
        }
        assert!(
            matches!(stream.next().await, Some(Ok(ResponseEvent::ToolCallInputDelta { delta, .. })) if delta == "unchanged-input")
        );
        assert!(
            matches!(stream.next().await, Some(Ok(ResponseEvent::OutputTextDelta(text))) if text == "unchanged")
        );
        assert!(matches!(
            stream.next().await,
            Some(Ok(ResponseEvent::Completed { .. }))
        ));
        assert!(
            dropped.load(AtomicOrdering::Acquire),
            "Completed retained upstream until another poll"
        );
        let dispatches = std::fs::read_to_string(&events)
            .expect("stream events")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("stream event"))
            .filter(|row| row["event"] == "dispatch" && row["kind"] == v23::STREAM_EVENT)
            .count();
        assert_eq!(
            dispatches,
            5 * observer_count,
            "missing terminal stream ACK"
        );
        assert!(stream.next().await.is_none());
        drop(stream);
        assert!(dropped.load(AtomicOrdering::Acquire));
        let observer = Observer {
            scope: Ok(scope.clone()),
            contributions: runtime::ordered_contributions(Kind::ResponseStream)
                .expect("ordered streams"),
            request: "private-transport-retry".into(),
            attempt: 1,
        };
        let upstream = Box::pin(futures::stream::iter([Err(ModelResponseError::Stream(
            "transport interrupted".into(),
        ))]));
        let mut retry = Box::new(observer).intercept(upstream);
        assert!(matches!(retry.next().await, Some(Err(_))));
        assert!(retry.next().await.is_none());
        scope
            .check()
            .expect("transport error poisoned native scope");
    }
    scope.close().expect("cooperative ACK drain");
    thread.close().expect("thread drain");
    drop(scope);
    drop(thread);
    drop(registry);
    guard.finish().expect("native cleanup");
    std::fs::write(std::env::var_os("CM_SEAMS_PROBE_REPORT").expect("report"),
        json!({"status":"pass","case":case,"upstream_polls":polls.load(AtomicOrdering::Acquire),
            "in_flight_limit":1,"upstream_dropped":dropped.load(AtomicOrdering::Acquire),
            "boundary":"private instrumented stream executable; production bridge and real native Mod"}).to_string()).expect("report");
}
