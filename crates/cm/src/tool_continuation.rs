//! Host-owned, once-consumed child work; no Rust task or output crosses the ABI.
use super::*;
use std::sync::Weak;

type Work = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<Vec<u8>, LoadError>> + Send>> + Send>;

struct State {
    work: Option<Work>,
    consumed: bool,
    cancelled: bool,
    released: bool,
    result: Option<Result<Vec<u8>, LoadError>>,
}

pub struct Continuation {
    runtime: tokio::runtime::Handle,
    cancel_work: Box<dyn Fn() + Send + Sync>,
    state: Mutex<State>,
    request: OnceLock<Weak<RequestData>>,
    task: OnceLock<Handle>,
    returned: tokio::sync::Notify,
}

impl Continuation {
    /// Uses the actual caller's runtime and cancellation token, never a new executor.
    pub fn new<F, Fut>(runtime: tokio::runtime::Handle, work: F, cancel: impl Fn() + Send + Sync + 'static) -> Arc<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<u8>, LoadError>> + Send + 'static,
    {
        Arc::new(Self {
            runtime, cancel_work: Box::new(cancel),
            state: Mutex::new(State { work: Some(Box::new(move || Box::pin(work()))), consumed: false, cancelled: false, released: false, result: None }),
            request: OnceLock::new(), task: OnceLock::new(), returned: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn bind(self: &Arc<Self>, request: &Arc<RequestData>) -> Result<(), LoadError> {
        self.request.set(Arc::downgrade(request)).map_err(|_| failure("continuation already bound"))
    }

    pub(super) fn dispatch_returned(&self) { self.returned.notify_one(); }

    pub(super) fn quiet(&self) -> bool {
        self.state.lock().is_ok_and(|state| !state.consumed || state.result.is_some())
    }

    pub fn completed(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.result.is_some())
    }

    pub(super) fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() { state.cancelled = true; }
        (self.cancel_work)();
    }

    fn finish(&self, result: Result<Vec<u8>, LoadError>) {
        if let Ok(mut state) = self.state.lock() { state.result = Some(result); }
        if let Some(request) = self.request.get().and_then(Weak::upgrade) {
            request.wake();
            request.progress();
        }
    }

    pub(super) fn remove(&self, tables: &mut Tables, epoch: u64) {
        if let Some(task) = self.task.get() { let _ = tables.remove(epoch, *task); }
    }

    fn start(self: &Arc<Self>, request: &Arc<RequestData>) -> Result<Handle, u32> {
        let parent = request.state.lock().map_err(|_| v22::INVALID)?;
        if parent.terminal { return Err(if parent.cancelled { v22::REQUEST_CANCELLED } else { v22::ALREADY_COMPLETED }); }
        {
            let mut state = self.state.lock().map_err(|_| v22::INVALID)?;
            if state.consumed {
                drop(state);
                drop(parent);
                request.latch(request.error("continuation consumed more than once"));
                return Err(v22::ALREADY_COMPLETED);
            }
            if state.cancelled { return Err(v22::REQUEST_CANCELLED); }
            state.consumed = true;
        }
        drop(parent);
        let allocate = (|| {
            let hub = hub().map_err(|_| v22::INVALID)?;
            let result = hub.tables.lock().map_err(|_| v22::INVALID)?.insert(hub.epoch, Object::Next {
                request: request.handle(), instance: request.module.instance, continuation: Arc::clone(self),
            }).map_err(|_| v22::LIMIT);
            result
        })();
        let task = match allocate {
            Ok(task) => task,
            Err(code) => {
                let error = request.error("continuation task allocation failed");
                self.finish(Err(error.clone()));
                request.latch(error);
                return Err(code);
            }
        };
        self.task.set(task).map_err(|_| v22::INVALID)?;
        let next = Arc::clone(self);
        let request = Arc::clone(request);
        let executor = self.runtime.clone();
        self.runtime.spawn(async move {
            loop {
                let notified = next.returned.notified();
                let returned = request.state.lock().is_ok_and(|state| state.started_returned);
                if returned { break; }
                notified.await;
            }
            let work = match next.state.lock() {
                Ok(mut state) if !state.cancelled => state.work.take(),
                _ => None,
            };
            let result = match work {
                Some(work) => match executor.spawn(async move { work().await }).await {
                    Ok(result) => result,
                    Err(error) => Err(request.error(&format!("continuation task failed: {error}"))),
                },
                None => Err(request.error("continuation cancelled before start")),
            };
            let mut result = result.and_then(|bytes| if bytes.len() <= v22::MAX_RESULT { Ok(bytes) } else { Err(request.error("continuation preview limit")) });
            if let Err(error) = &mut result {
                let mut end = error.message.len().min(v22::MAX_RESULT);
                while !error.message.is_char_boundary(end) { end -= 1; }
                error.message.truncate(end);
            }
            event("runtime-next-finished", json!({"request": handle_json(request.handle()), "task": handle_json(task), "ok": result.is_ok()}));
            next.finish(result);
        });
        event("runtime-next-consumed", json!({"request": handle_json(request.handle()), "task": handle_json(task)}));
        Ok(task)
    }
}

pub(crate) fn services() -> v23::ContinuationApi {
    v23::ContinuationApi { header: v23::header::<v23::ContinuationApi>(), start: Some(start), poll: Some(poll), cancel: Some(cancel), release: Some(release), reserved: 0 }
}

fn task(instance: Handle, parent: Handle, handle: Handle) -> Result<(Arc<RequestData>, Arc<Continuation>), u32> {
    let request = request(instance, parent)?;
    let hub = hub().map_err(|_| v22::INVALID)?;
    let tables = hub.tables.lock().map_err(|_| v22::INVALID)?;
    match tables.get(hub.epoch, handle)? {
        Object::Next { request: owner, instance: module, continuation } if *owner == parent && *module == instance => Ok((request, Arc::clone(continuation))),
        Object::Next { .. } => Err(v22::WRONG_OWNER),
        _ => Err(v22::INVALID),
    }
}

unsafe extern "C" fn start(instance: Handle, parent: Handle, output: *mut Handle, error: *mut ErrorBuffer) -> u32 {
    service(error, || {
        if output.is_null() || !(output as usize).is_multiple_of(align_of::<Handle>()) { return Err(v22::INVALID); }
        let request = request(instance, parent)?;
        let next = request.continuation.as_ref().ok_or(v22::INVALID)?;
        let task = next.start(&request)?;
        unsafe { output.write(task) };
        Ok(())
    })
}

unsafe extern "C" fn poll(instance: Handle, parent: Handle, handle: Handle, output: *mut v23::NextOutput, error: *mut ErrorBuffer) -> u32 {
    service(error, || {
        if output.is_null() || !(output as usize).is_multiple_of(align_of::<v23::NextOutput>())
            || unsafe { output.cast::<u32>().read() } < size_of::<Header>() as u32 { return Err(v22::INVALID); }
        let header = unsafe { output.cast::<Header>().read() };
        if header.major != 2 || header.minor != 3 || header.struct_size != size_of::<v23::NextOutput>() as u32 { return Err(v22::INVALID); }
        let buffer = unsafe { &mut *output };
        if buffer.reserved != 0 || buffer.result.capacity > v22::MAX_RESULT as u64
            || buffer.result.len != 0 || (buffer.result.capacity != 0 && buffer.result.data.is_null()) { return Err(v22::INVALID); }
        let (request, next) = task(instance, parent, handle)?;
        let parent_state = request.state.lock().map_err(|_| v22::INVALID)?;
        if parent_state.terminal { return Err(if parent_state.cancelled { v22::REQUEST_CANCELLED } else { v22::ALREADY_COMPLETED }); }
        drop(parent_state);
        let state = next.state.lock().map_err(|_| v22::INVALID)?;
        if state.released { return Err(v22::STALE); }
        let (status, result) = match &state.result {
            None => (v23::PENDING, &[][..]),
            Some(Ok(bytes)) => (v22::SUCCEEDED, bytes.as_slice()),
            Some(Err(error)) => (if state.cancelled { v22::CANCELLED } else { v22::FAILED }, error.message.as_bytes()),
        };
        if result.len() > buffer.result.capacity as usize { return Err(v22::LIMIT); }
        if !result.is_empty() { unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), buffer.result.data, result.len()) }; }
        buffer.result.len = result.len() as u64;
        buffer.status = status;
        Ok(())
    })
}

unsafe extern "C" fn cancel(instance: Handle, parent: Handle, handle: Handle, error: *mut ErrorBuffer) -> u32 {
    service(error, || {
        let (request, next) = task(instance, parent, handle)?;
        let state = request.state.lock().map_err(|_| v22::INVALID)?;
        if state.terminal { return Err(if state.cancelled { v22::REQUEST_CANCELLED } else { v22::ALREADY_COMPLETED }); }
        drop(state);
        if next.state.lock().map_err(|_| v22::INVALID)?.released { return Err(v22::STALE); }
        next.cancel();
        Ok(())
    })
}

unsafe extern "C" fn release(instance: Handle, parent: Handle, handle: Handle, error: *mut ErrorBuffer) -> u32 {
    service(error, || {
        let (request, next) = task(instance, parent, handle)?;
        let parent_state = request.state.lock().map_err(|_| v22::INVALID)?;
        if parent_state.terminal { return Err(if parent_state.cancelled { v22::REQUEST_CANCELLED } else { v22::ALREADY_COMPLETED }); }
        drop(parent_state);
        let mut state = next.state.lock().map_err(|_| v22::INVALID)?;
        if state.released { return Err(v22::STALE); }
        state.released = true;
        let running = state.result.is_none();
        drop(state);
        if running { next.cancel(); }
        Ok(())
    })
}
