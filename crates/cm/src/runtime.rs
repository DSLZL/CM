//! Host-owned ABI 2.2 scopes, request delivery and native cleanup.
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::future::Future;
use std::io::Read;
use std::mem::{align_of, size_of};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use cm_abi::{Bytes, ErrorBuffer, Header, v22};
use serde_json::json;
pub use v22::Handle;

use crate::{LoadError, NativeCall, event};
use crate::loader::native;

const DEADLINE: Duration = Duration::from_secs(30);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(5);
static HUB: OnceLock<Result<Hub, LoadError>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Lifecycle, Tool, ContextSection }

#[derive(Clone, Debug)]
pub struct Contribution {
    pub owner: String,
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub(crate) route: u64,
    pub(crate) instance: Handle,
}

pub fn valid_name(owner: &str, name: &str) -> bool {
    name.len() <= 64 && name.strip_prefix(&format!("{owner}__")).is_some_and(|suffix| !suffix.is_empty())
        && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

pub fn registration_error(owner: &str, contribution: &str, message: &str) -> LoadError {
    let mut error = LoadError::native("runtime_registration", message).owner(owner, Some(contribution));
    error.resource = Some("runtime".into());
    error
}

/// Called by the actual Host registry before its skip/assert collision path.
pub fn guard_name(kind: Kind, name: &str, occupied: bool) -> Result<(), LoadError> {
    if !occupied { return Ok(()); }
    let owner = contributions()?.into_iter().find(|item| item.kind == kind && item.name == name);
    if let Some(owner) = owner {
        let mut error = registration_error(&owner.owner, &owner.id,
            &format!("name collision: CM {}::{} ({name}) versus existing Host builtin/external contribution", owner.owner, owner.id));
        error.resource = Some(name.into());
        fail_registration(error.clone());
        return Err(error);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScopeKind { Instance, Mod, Thread, Turn }

struct ScopeData {
    owner: Handle,
    parent: Handle,
    kind: ScopeKind,
    open: bool,
    values: BTreeMap<String, Vec<u8>>,
    bytes: usize,
}

enum Object { Scope(ScopeData), Request(Arc<RequestData>) }
struct Slot { generation: u32, value: Option<Object> }

struct Tables {
    slots: Vec<Slot>,
    modules: BTreeMap<Handle, Arc<Module>>,
    contributions: Vec<Contribution>,
    stopping: bool,
    scopes: usize,
    requests: usize,
    levels: BTreeMap<String, Level>,
    failed: Option<LoadError>,
    shutdown_error: Option<LoadError>,
}

enum Level { Scope(std::sync::Weak<ScopeInner>), Failed(LoadError) }

struct Hub { epoch: u64, tables: Mutex<Tables>, changed: Condvar }

fn hub() -> Result<&'static Hub, LoadError> {
    HUB.get_or_init(|| {
        let mut bytes = [0_u8; 8];
        std::fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|error| LoadError::native("runtime_epoch", &error.to_string()))?;
        let epoch = u64::from_ne_bytes(bytes);
        if epoch == 0 { return Err(LoadError::native("runtime_epoch", "zero random epoch")); }
        Ok(Hub {
            epoch,
            tables: Mutex::new(Tables { slots: Vec::new(), modules: BTreeMap::new(),
                contributions: Vec::new(), stopping: false, scopes: 0, requests: 0, levels: BTreeMap::new(), failed: None, shutdown_error: None }),
            changed: Condvar::new(),
        })
    }).as_ref().map_err(Clone::clone)
}

fn failure(message: &str) -> LoadError { LoadError::native("runtime", message) }
fn lock_error() -> LoadError { failure("poisoned runtime metadata") }

impl Tables {
    fn insert(&mut self, epoch: u64, object: Object) -> Result<Handle, LoadError> {
        if let Some((index, slot)) = self.slots.iter_mut().enumerate()
            .find(|(_, slot)| slot.value.is_none() && slot.generation < u32::MAX)
        {
            slot.generation += 1;
            slot.value = Some(object);
            return Ok(Handle { epoch, slot: index as u32, generation: slot.generation });
        }
        let index = u32::try_from(self.slots.len()).map_err(|_| failure("handle slots exhausted"))?;
        self.slots.push(Slot { generation: 1, value: Some(object) });
        Ok(Handle { epoch, slot: index, generation: 1 })
    }

    fn get(&self, epoch: u64, handle: Handle) -> Result<&Object, u32> {
        if handle.epoch != epoch { return Err(v22::STALE); }
        let slot = self.slots.get(handle.slot as usize).ok_or(v22::STALE)?;
        if slot.generation != handle.generation { return Err(v22::STALE); }
        slot.value.as_ref().ok_or(v22::STALE)
    }

    fn scope(&self, epoch: u64, handle: Handle) -> Result<&ScopeData, u32> {
        match self.get(epoch, handle)? { Object::Scope(scope) => Ok(scope), _ => Err(v22::INVALID) }
    }

    fn remove(&mut self, epoch: u64, handle: Handle) -> Result<(), u32> {
        self.get(epoch, handle)?;
        self.slots[handle.slot as usize].value = None;
        Ok(())
    }

    fn requests(&self) -> Vec<Arc<RequestData>> {
        self.slots.iter().filter_map(|slot| match &slot.value {
            Some(Object::Request(request)) => Some(Arc::clone(request)), _ => None,
        }).collect()
    }

    fn allocate_scopes(&mut self, epoch: u64, kind: ScopeKind,
        parents: &[(Handle, Handle)]) -> Result<BTreeMap<Handle, Handle>, LoadError>
    {
        if self.stopping || self.scopes + parents.len() > v22::MAX_SCOPES {
            return Err(failure("scope limit/stopping"));
        }
        let parent_kind = match kind { ScopeKind::Mod => ScopeKind::Instance,
            ScopeKind::Thread => ScopeKind::Mod, ScopeKind::Turn => ScopeKind::Thread,
            ScopeKind::Instance => return Err(failure("invalid scope allocation")) };
        for (owner, parent) in parents {
            let scope = self.scope(epoch, *parent).map_err(|_| failure("stale parent scope"))?;
            if !scope.open || scope.owner != *owner || scope.kind != parent_kind {
                return Err(failure("parent scope closing/type/owner mismatch"));
            }
        }
        let mut members = BTreeMap::new();
        for (owner, parent) in parents {
            let handle = match self.insert(epoch, Object::Scope(ScopeData { owner: *owner,
                parent: *parent, kind, open: true, values: BTreeMap::new(), bytes: 0 })) {
                Ok(handle) => handle,
                Err(error) => {
                    for handle in members.values() { let _ = self.remove(epoch, *handle); }
                    return Err(error);
                }
            };
            members.insert(*owner, handle);
        }
        self.scopes += members.len();
        Ok(members)
    }
}

pub(crate) fn new_instance(owner: &str) -> Result<Handle, LoadError> {
    let hub = hub()?;
    let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
    if tables.stopping || tables.scopes >= v22::MAX_SCOPES { return Err(failure("scope limit/stopping")); }
    let handle = tables.insert(hub.epoch, Object::Scope(ScopeData {
        owner: Handle::NONE, parent: Handle::NONE, kind: ScopeKind::Instance,
        open: true, values: BTreeMap::new(), bytes: 0,
    }))?;
    if let Some(Object::Scope(scope)) = tables.slots[handle.slot as usize].value.as_mut() { scope.owner = handle; }
    tables.scopes += 1;
    event("runtime-instance", json!({"mod": owner, "instance": handle_json(handle)}));
    Ok(handle)
}

fn handle_json(handle: Handle) -> serde_json::Value {
    json!({"epoch": handle.epoch, "slot": handle.slot, "generation": handle.generation})
}

pub(crate) fn services(instance: Handle) -> v22::HostRuntimeApi {
    v22::HostRuntimeApi { header: v22::header::<v22::HostRuntimeApi>(), instance,
        complete: Some(complete), state_get: Some(state_get), state_set: Some(state_set), reserved: 0 }
}

enum Job { Dispatch(Arc<RequestData>, OwnedInput), Cancel(Arc<RequestData>), Release(Arc<RequestData>) }

struct Module {
    owner: String,
    instance: Handle,
    sender: mpsc::Sender<Job>,
}

pub(crate) fn install(instance: Handle, owner: &str, userdata: *mut c_void,
    api: v22::ModRuntimeApi, contributions: Vec<Contribution>, gate: Arc<Mutex<()>>) -> Result<(), LoadError>
{
    let hub = hub()?;
    let (sender, receiver) = mpsc::channel();
    let module = Arc::new(Module { owner: owner.into(), instance, sender });
    // Userdata stays owned by its Mod; the worker only borrows it until runtime drain.
    let userdata = userdata as usize;
    std::thread::Builder::new().name(format!("cm-{owner}")).spawn(move || {
        while let Ok(job) = receiver.recv() {
            let result = gate.lock().map_err(|_| failure("poisoned Mod call gate")).and_then(|_gate| match &job {
                Job::Dispatch(request, input) => {
                    let dto = v22::Request {
                        header: v22::header::<v22::Request>(), handle: request.handle(),
                        mod_scope: request.mod_scope, thread_scope: request.thread, turn_scope: request.turn,
                        route: request.contribution.route, event: input.event, reserved: 0,
                        input: bytes(&input.input), thread_id: Bytes::borrowed(&input.thread_id),
                        turn_id: Bytes::borrowed(&input.turn_id), call_id: Bytes::borrowed(&input.call_id),
                    };
                    ordinary("runtime_dispatch", || native::invoke("runtime_dispatch", |error| unsafe {
                        (api.dispatch.expect("validated dispatch"))(userdata as *mut c_void, &dto, error)
                    }))
                }
                Job::Cancel(request) => ordinary("runtime_cancel", || native::invoke("runtime_cancel", |error| unsafe {
                    (api.cancel.expect("validated cancel"))(userdata as *mut c_void, request.handle(), error)
                })),
                Job::Release(request) => ordinary("request_release", || native::invoke("request_release", |error| unsafe {
                    (api.request_release.expect("validated request_release"))(userdata as *mut c_void, request.handle(), error)
                })),
            });
            let request = match &job { Job::Dispatch(request, _) | Job::Cancel(request) | Job::Release(request) => request };
            let result = result.map_err(|error| request.contextual(error));
            if let Err(error) = &result { request.latch(error.clone()); }
            match job {
                Job::Dispatch(request, _) => {
                    if let Ok(mut state) = request.state.lock() {
                        state.started_returned = true;
                        if let Err(error) = result { state.deliver(Err(error)); }
                    }
                    request.wake();
                    request.progress();
                }
                Job::Cancel(request) => {
                    if let Ok(mut state) = request.state.lock() { state.cancel_returned = true; }
                    request.progress();
                }
                Job::Release(request) => {
                    // Release is never retried, even when the owner reports failure.
                    event("runtime-request-released", json!({"mod": request.module.owner, "request": handle_json(request.handle()), "ok": result.is_ok()}));
                    if let Ok(mut tables) = hub.tables.lock()
                        && tables.remove(hub.epoch, request.handle()).is_ok()
                    { tables.requests -= 1; }
                    hub.changed.notify_all();
                }
            }
        }
    }).map_err(|error| failure(&error.to_string()))?;
    let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
    tables.modules.insert(instance, module);
    tables.contributions.extend(contributions);
    Ok(())
}

fn ordinary(stage: &str, f: impl FnOnce() -> Result<(), LoadError>) -> Result<(), LoadError> {
    let _guard = NativeCall::enter().map_err(|error| LoadError::native(stage, &error))?;
    f()
}

pub fn contributions() -> Result<Vec<Contribution>, LoadError> {
    let Some(hub) = HUB.get() else { return Ok(Vec::new()); };
    let hub = hub.as_ref().map_err(Clone::clone)?;
    let mut contributions = hub.tables.lock().map_err(|_| lock_error())?.contributions.clone();
    contributions.sort_by(|a, b| (&a.owner, &a.id).cmp(&(&b.owner, &b.id)));
    Ok(contributions)
}

pub fn fail_registration(error: LoadError) {
    event("runtime-registration-failed", json!(error));
    if let Ok(hub) = hub() && let Ok(mut tables) = hub.tables.lock() {
        tables.failed.get_or_insert(error);
    }
}

pub fn bind_level(level: &str, scope: &Result<Scope, LoadError>) -> Result<(), LoadError> {
    let hub = hub()?;
    let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
    tables.levels.retain(|_, value| !matches!(value, Level::Scope(scope) if scope.strong_count() == 0));
    if !tables.levels.contains_key(level) && tables.levels.len() >= v22::MAX_SCOPES {
        let error = failure("extension level limit");
        tables.failed.get_or_insert(error.clone());
        return Err(error);
    }
    tables.levels.insert(level.into(), match scope {
        Ok(scope) => Level::Scope(Arc::downgrade(&scope.0)), Err(error) => Level::Failed(error.clone()),
    });
    Ok(())
}

/// Low-level Core error gate; Core never depends on the adapter's Rust types.
pub fn check_level(level: &str) -> Result<(), LoadError> {
    let Some(hub) = HUB.get() else { return Ok(()); };
    let hub = hub.as_ref().map_err(Clone::clone)?;
    let scope = {
        let tables = hub.tables.lock().map_err(|_| lock_error())?;
        if let Some(error) = &tables.failed { return Err(error.clone()); }
        match tables.levels.get(level) {
            Some(Level::Scope(scope)) => scope.upgrade().map(Scope),
            Some(Level::Failed(error)) => return Err(error.clone()), None => None,
        }
    };
    scope.map_or(Ok(()), |scope| scope.check())
}

pub fn forget_level(level: &str) {
    if let Some(Ok(hub)) = HUB.get() && let Ok(mut tables) = hub.tables.lock() { tables.levels.remove(level); }
}

#[derive(Clone)]
pub struct Registry(Arc<RegistryInner>);
struct RegistryInner { members: BTreeMap<Handle, Handle> }

impl Registry {
    pub fn new() -> Result<Self, LoadError> {
        let hub = hub()?;
        let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
        let parents: Vec<_> = tables.modules.keys().map(|instance| (*instance, *instance)).collect();
        let members = tables.allocate_scopes(hub.epoch, ScopeKind::Mod, &parents)?;
        Ok(Self(Arc::new(RegistryInner { members })))
    }

    pub fn thread(&self, thread_id: &str) -> Result<Scope, LoadError> {
        Scope::create(self.clone(), None, thread_id, "")
    }
}

impl Drop for RegistryInner {
    fn drop(&mut self) {
        if let Some(Ok(hub)) = HUB.get() && let Ok(mut tables) = hub.tables.lock() {
            for handle in self.members.values() {
                if tables.remove(hub.epoch, *handle).is_ok() { tables.scopes -= 1; }
            }
        }
    }
}

#[derive(Clone)]
pub struct Scope(Arc<ScopeInner>);

struct ScopeInner {
    registry: Registry,
    members: BTreeMap<Handle, Handle>,
    parent: Option<Scope>,
    thread_id: String,
    turn_id: String,
    errors: Mutex<Vec<LoadError>>,
}

impl Scope {
    pub fn turn(&self, turn_id: &str) -> Result<Self, LoadError> { Self::create(self.0.registry.clone(), Some(self.clone()), &self.0.thread_id, turn_id) }

    fn create(registry: Registry, parent: Option<Scope>, thread_id: &str, turn_id: &str) -> Result<Self, LoadError> {
        if thread_id.is_empty() || thread_id.len() > 128 || turn_id.len() > 128
            || parent.as_ref().is_some_and(|parent| parent.0.parent.is_some() || turn_id.is_empty())
        { return Err(failure("invalid scope identity/type")); }
        let hub = hub()?;
        let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
        let parents = tables.modules.keys().map(|instance| {
            let ancestor = match &parent {
                Some(parent) => *parent.0.members.get(instance).ok_or_else(|| failure("parent Mod scope missing"))?,
                None => *registry.0.members.get(instance).ok_or_else(|| failure("registry Mod scope missing"))?,
            };
            Ok((*instance, ancestor))
        }).collect::<Result<Vec<_>, LoadError>>()?;
        let members = tables.allocate_scopes(hub.epoch,
            if parent.is_some() { ScopeKind::Turn } else { ScopeKind::Thread }, &parents)?;
        event("runtime-scope-open", json!({"thread": thread_id, "turn": turn_id,
            "members": members.values().copied().map(handle_json).collect::<Vec<_>>()}));
        Ok(Self(Arc::new(ScopeInner { registry, members, parent, thread_id: thread_id.into(), turn_id: turn_id.into(), errors: Mutex::new(Vec::new()) })))
    }

    pub fn check(&self) -> Result<(), LoadError> {
        if let Some(parent) = &self.0.parent { parent.check()?; }
        self.0.errors.lock().map_err(|_| lock_error())?.first().cloned().map_or(Ok(()), Err)
    }

    pub fn fail(&self, error: LoadError) {
        event("runtime-scope-failed", json!({"thread": self.0.thread_id, "turn": self.0.turn_id, "error": error}));
        if let Ok(mut errors) = self.0.errors.lock() { errors.push(error.clone()); }
        if let Some(Ok(hub)) = HUB.get() && let Ok(mut tables) = hub.tables.lock() {
            tables.shutdown_error.get_or_insert(error);
        }
    }

    pub fn begin_close(&self) -> Result<(), LoadError> {
        let hub = hub()?;
        let requests = {
            let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
            for handle in self.0.members.values() {
                if let Ok(Object::Scope(_)) = tables.get(hub.epoch, *handle)
                    && let Some(Object::Scope(scope)) = tables.slots[handle.slot as usize].value.as_mut()
                { scope.open = false; }
            }
            tables.requests().into_iter().filter(|request| self.contains(request)).collect::<Vec<_>>()
        };
        for request in requests { request.cancel(false); }
        Ok(())
    }

    fn contains(&self, request: &RequestData) -> bool {
        self.0.members.values().any(|handle| *handle == request.thread || *handle == request.turn)
    }

    pub fn close(&self) -> Result<(), LoadError> {
        self.begin_close()?;
        let hub = hub()?;
        let deadline = Instant::now() + CLEANUP_DEADLINE;
        let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
        while tables.requests().iter().any(|request| self.contains(request)) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let error = failure("native cleanup deadline; request, state and library pinned until process exit");
                drop(tables);
                self.fail(error.clone());
                return Err(error);
            }
            tables = hub.changed.wait_timeout(tables, remaining).map_err(|_| lock_error())?.0;
        }
        for handle in self.0.members.values() {
            if tables.remove(hub.epoch, *handle).is_ok() { tables.scopes -= 1; }
        }
        event("runtime-scope-closed", json!({"thread": self.0.thread_id, "turn": self.0.turn_id}));
        drop(tables);
        self.check()
    }
}

impl Drop for ScopeInner {
    fn drop(&mut self) {
        // In-flight requests retain their Scope, so this path cannot free active state.
        if let Some(Ok(hub)) = HUB.get() && let Ok(mut tables) = hub.tables.lock() {
            for handle in self.members.values() {
                if tables.remove(hub.epoch, *handle).is_ok() { tables.scopes -= 1; }
            }
        }
    }
}

struct OwnedInput { event: u32, input: Vec<u8>, thread_id: String, turn_id: String, call_id: String }

struct RequestState {
    result: Option<Result<Vec<u8>, LoadError>>,
    terminal: bool,
    cancelled: bool,
    quiet: bool,
    started_returned: bool,
    cancel_queued: bool,
    cancel_returned: bool,
    release_queued: bool,
    waker: Option<Waker>,
}

impl RequestState {
    fn deliver(&mut self, result: Result<Vec<u8>, LoadError>) -> bool {
        if self.terminal { return false; }
        self.terminal = true;
        self.result = Some(result);
        true
    }

    fn releasable(&self) -> bool {
        self.terminal && self.quiet && self.started_returned
            && (!self.cancel_queued || self.cancel_returned) && !self.release_queued
    }
}

struct RequestData {
    handle: OnceLock<Handle>,
    module: Arc<Module>,
    contribution: Contribution,
    scope: Scope,
    mod_scope: Handle,
    thread: Handle,
    turn: Handle,
    cleanup: bool,
    state: Mutex<RequestState>,
    changed: Condvar,
}

impl RequestData {
    fn handle(&self) -> Handle { *self.handle.get().expect("assigned before publication") }
    fn latch(&self, error: LoadError) { self.scope.fail(error); }
    fn wake(&self) {
        let waker = self.state.lock().ok().and_then(|mut state| state.waker.take());
        if let Some(waker) = waker { waker.wake(); }
        self.changed.notify_all();
    }
    fn cancel(self: &Arc<Self>, timeout: bool) {
        let queued = if let Ok(mut state) = self.state.lock() {
            if state.terminal { false } else {
                state.cancelled = true;
                let error = self.error(if timeout { "request timeout" } else { "request cancelled" });
                state.deliver(Err(error));
                state.cancel_queued = true;
                true
            }
        } else { false };
        if queued {
            if timeout { self.latch(self.error("request timeout")); }
            event("runtime-request-cancel", json!({"mod": self.module.owner, "request": handle_json(self.handle()), "timeout": timeout}));
            if self.module.sender.send(Job::Cancel(Arc::clone(self))).is_err() { self.latch(self.error("native worker unavailable; pinned")); }
            self.wake();
        }
    }
    fn progress(self: &Arc<Self>) {
        let release = if let Ok(mut state) = self.state.lock() {
            if state.releasable()
            { state.release_queued = true; true } else { false }
        } else { false };
        if release && self.module.sender.send(Job::Release(Arc::clone(self))).is_err() { self.latch(self.error("release worker unavailable; pinned")); }
    }
    fn error(&self, message: &str) -> LoadError {
        self.contextual(failure(message))
    }
    fn contextual(&self, error: LoadError) -> LoadError {
        let mut error = error.owner(&self.module.owner, Some(&self.contribution.id));
        error.message = format!("{}; request={:?}; thread={}; turn={}", error.message,
            self.handle(), self.scope.0.thread_id, self.scope.0.turn_id);
        error.resource = Some(self.contribution.name.clone());
        error
    }
}

pub struct RequestFuture { request: Arc<RequestData> }

impl Future for RequestFuture {
    type Output = Result<Vec<u8>, LoadError>;
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = match self.request.state.lock() { Ok(state) => state, Err(_) => return Poll::Ready(Err(lock_error())) };
        if let Some(result) = state.result.take() { Poll::Ready(result) }
        else { state.waker = Some(context.waker().clone()); Poll::Pending }
    }
}

impl Drop for RequestFuture {
    fn drop(&mut self) { self.request.cancel(false); }
}

pub fn dispatch(scope: &Scope, contribution: &Contribution, event_kind: u32,
    input: &[u8], call_id: &str) -> Result<RequestFuture, LoadError>
{
    let cleanup = [v22::THREAD_STOP, v22::TURN_STOP, v22::TURN_ABORT, v22::TURN_ERROR].contains(&event_kind);
    if !cleanup { scope.check()?; }
    if input.len() > v22::MAX_INPUT || call_id.len() > 512 { return Err(failure("request input limit")); }
    let expected = match contribution.kind { Kind::Lifecycle => (v22::THREAD_START..=v22::TURN_ERROR).contains(&event_kind),
        Kind::Tool => event_kind == v22::TOOL_CALL, Kind::ContextSection => event_kind == v22::SECTION };
    if !expected || ((event_kind >= v22::TURN_START) != scope.0.parent.is_some()) {
        return Err(failure("event/contribution/scope kind mismatch"));
    }
    let hub = hub()?;
    let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
    let module = tables.modules.get(&contribution.instance).cloned().ok_or_else(|| failure("unknown Mod instance"))?;
    let turn = if scope.0.parent.is_some() { *scope.0.members.get(&module.instance).ok_or_else(|| failure("turn scope missing"))? } else { Handle::NONE };
    let thread_scope = scope.0.parent.as_ref().unwrap_or(scope);
    let thread = *thread_scope.0.members.get(&module.instance).ok_or_else(|| failure("thread scope missing"))?;
    if tables.stopping || (!cleanup && (!tables.scope(hub.epoch, thread).map_err(|_| failure("stale thread"))?.open
        || (turn != Handle::NONE && !tables.scope(hub.epoch, turn).map_err(|_| failure("stale turn"))?.open)))
    { return Err(failure("scope closing/stopping")); }
    if !tables.contributions.iter().any(|declared| declared.instance == contribution.instance && declared.id == contribution.id
        && declared.name == contribution.name && declared.kind == contribution.kind && declared.route == contribution.route)
    { return Err(failure("undeclared runtime contribution")); }
    if tables.requests >= v22::MAX_REQUESTS || tables.requests().iter().filter(|request| request.module.instance == module.instance).count() >= v22::MAX_MOD_REQUESTS {
        return Err(failure("in-flight request limit").owner(&module.owner, Some(&contribution.id)));
    }
    let mod_scope = *scope.0.registry.0.members.get(&module.instance).ok_or_else(|| failure("Mod scope missing"))?;
    let request = Arc::new(RequestData { handle: OnceLock::new(), module, contribution: contribution.clone(), mod_scope,
        scope: scope.clone(), thread, turn, cleanup,
        state: Mutex::new(RequestState { result: None, terminal: false, cancelled: false, quiet: false,
            started_returned: false, cancel_queued: false, cancel_returned: false, release_queued: false, waker: None }),
        changed: Condvar::new(),
    });
    let handle = tables.insert(hub.epoch, Object::Request(Arc::clone(&request)))?;
    request.handle.set(handle).map_err(|_| failure("duplicate request assignment"))?;
    tables.requests += 1;
    drop(tables);
    event("runtime-request", json!({"mod": contribution.owner, "contribution": contribution.id, "resource": contribution.name,
        "event_kind": event_kind, "request": handle_json(handle), "thread": scope.0.thread_id, "turn": scope.0.turn_id}));
    let job = Job::Dispatch(Arc::clone(&request), OwnedInput { event: event_kind, input: input.to_vec(),
        thread_id: scope.0.thread_id.clone(), turn_id: scope.0.turn_id.clone(), call_id: call_id.into() });
    if request.module.sender.send(job).is_err() { request.latch(request.error("native worker unavailable")); request.cancel(true); }
    let timer_request = Arc::clone(&request);
    std::thread::Builder::new().name("cm-deadline".into()).spawn(move || {
        if let Ok(state) = timer_request.state.lock()
            && let Ok((state, timeout)) = timer_request.changed.wait_timeout_while(state, DEADLINE, |state| !state.terminal)
        {
            let expired = timeout.timed_out() && !state.terminal;
            drop(state);
            if expired { timer_request.cancel(true); }
        }
    }).map_err(|error| { request.cancel(true); failure(&error.to_string()) })?;
    Ok(RequestFuture { request })
}

fn request(instance: Handle, handle: Handle) -> Result<Arc<RequestData>, u32> {
    let hub = hub().map_err(|_| v22::INVALID)?;
    let tables = hub.tables.lock().map_err(|_| v22::INVALID)?;
    match tables.get(hub.epoch, handle)? {
        Object::Request(request) if request.module.instance == instance => Ok(Arc::clone(request)),
        Object::Request(_) => Err(v22::WRONG_OWNER), _ => Err(v22::INVALID),
    }
}

unsafe fn view(value: Bytes, limit: usize) -> Result<Vec<u8>, u32> {
    if value.len > limit as u64 || (value.len != 0 && value.data.is_null()) { return Err(v22::INVALID); }
    Ok(if value.len == 0 { Vec::new() } else { unsafe { std::slice::from_raw_parts(value.data, value.len as usize) }.to_vec() })
}
fn bytes(value: &[u8]) -> Bytes { Bytes { data: value.as_ptr(), len: value.len() as u64 } }

fn service(error: *mut ErrorBuffer, f: impl FnOnce() -> Result<(), u32>) -> u32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => cm_abi::OK,
        result => {
            let code = match result { Ok(Err(code)) => code, _ => v22::INVALID };
            let message = format!("CM runtime service rejected: code={code}");
            if !error.is_null() {
                let error = unsafe { &mut *error };
                if error.capacity <= cm_abi::ERROR_CAPACITY as u64 && !error.data.is_null() {
                    let len = message.len().min(error.capacity as usize);
                    unsafe { std::ptr::copy_nonoverlapping(message.as_ptr(), error.data, len) };
                    error.len = len as u64;
                }
            }
            code
        }
    }
}

unsafe extern "C" fn complete(instance: Handle, completion: *const v22::Completion, error: *mut ErrorBuffer) -> u32 {
    service(error, || {
        if completion.is_null() || !(completion as usize).is_multiple_of(align_of::<v22::Completion>()) { return Err(v22::INVALID); }
        if unsafe { completion.cast::<u32>().read() } < size_of::<Header>() as u32 { return Err(v22::INVALID); }
        if !valid_header::<v22::Completion>(unsafe { completion.cast::<Header>().read() }) { return Err(v22::INVALID); }
        let value = unsafe { completion.read() };
        if !valid_header::<v22::Completion>(value.header) || value.flags & !v22::QUIESCENT != 0
            || ![v22::SUCCEEDED, v22::FAILED, v22::CANCELLED].contains(&value.status)
        { return Err(v22::INVALID); }
        let result = unsafe { view(value.result, v22::MAX_RESULT)? };
        let request = request(instance, value.request)?;
        let mut state = request.state.lock().map_err(|_| v22::INVALID)?;
        let code = if state.terminal {
            if state.cancelled { v22::REQUEST_CANCELLED } else { v22::ALREADY_COMPLETED }
        } else {
            let result = match value.status {
                v22::SUCCEEDED => Ok(result),
                v22::FAILED => {
                    let message = String::from_utf8(result).map_err(|_| v22::INVALID)?;
                    let mut error = request.error(&message);
                    error.code = "mod_error".into();
                    Err(error)
                }
                _ => { state.cancelled = true; Err(request.error("Mod cancelled request")) }
            };
            state.deliver(result);
            cm_abi::OK
        };
        if value.flags & v22::QUIESCENT != 0 { state.quiet = true; }
        drop(state);
        event("runtime-complete", json!({"mod": request.module.owner, "request": handle_json(value.request),
            "status": value.status, "quiescent": value.flags & v22::QUIESCENT != 0, "code": code}));
        request.wake();
        request.progress();
        if code == cm_abi::OK { Ok(()) } else { Err(code) }
    })
}

pub(crate) fn valid_header<T>(header: Header) -> bool {
    header.struct_size == size_of::<T>() as u32 && header.major == 2 && header.minor == 2
}

fn state_access(instance: Handle, request_handle: Handle, scope_handle: Handle, key: Bytes,
    f: impl FnOnce(&mut ScopeData, &str) -> Result<(), u32>) -> Result<(), u32>
{
    let key = String::from_utf8(unsafe { view(key, 128)? }).map_err(|_| v22::INVALID)?;
    if !crate::loader::identifier(&key) { return Err(v22::INVALID); }
    let request = request(instance, request_handle)?;
    let state = request.state.lock().map_err(|_| v22::INVALID)?;
    if state.terminal || state.quiet { return Err(if state.cancelled { v22::REQUEST_CANCELLED } else { v22::ALREADY_COMPLETED }); }
    if ![request.mod_scope, request.thread, request.turn].contains(&scope_handle) || scope_handle == Handle::NONE { return Err(v22::WRONG_OWNER); }
    let hub = hub().map_err(|_| v22::INVALID)?;
    let mut tables = hub.tables.lock().map_err(|_| v22::INVALID)?;
    let scope = tables.scope(hub.epoch, scope_handle)?;
    if !request.cleanup && (!tables.scope(hub.epoch, request.thread)?.open
        || (request.turn != Handle::NONE && !tables.scope(hub.epoch, request.turn)?.open)) { return Err(v22::STALE); }
    if scope.owner != instance { return Err(v22::WRONG_OWNER); }
    let valid_parent = match scope.kind { ScopeKind::Instance => false, ScopeKind::Mod => scope.parent == instance,
        ScopeKind::Thread => scope.parent == request.mod_scope, ScopeKind::Turn => scope.parent == request.thread };
    if !valid_parent || (!scope.open && !request.cleanup) { return Err(v22::STALE); }
    let Some(Object::Scope(scope)) = tables.slots[scope_handle.slot as usize].value.as_mut() else { return Err(v22::INVALID); };
    f(scope, &key)
}

unsafe extern "C" fn state_get(instance: Handle, request: Handle, scope: Handle, key: Bytes,
    output: *mut v22::Buffer, error: *mut ErrorBuffer) -> u32
{
    service(error, || {
        if output.is_null() || !(output as usize).is_multiple_of(align_of::<v22::Buffer>()) { return Err(v22::INVALID); }
        let output = unsafe { &mut *output };
        if output.capacity > v22::MAX_INPUT as u64 || (output.capacity != 0 && output.data.is_null()) { return Err(v22::INVALID); }
        state_access(instance, request, scope, key, |scope, key| {
            let value = scope.values.get(key).ok_or(v22::NOT_FOUND)?;
            if value.len() > output.capacity as usize { return Err(v22::LIMIT); }
            if !value.is_empty() { unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), output.data, value.len()) }; }
            output.len = value.len() as u64;
            Ok(())
        })
    })
}

unsafe extern "C" fn state_set(instance: Handle, request: Handle, scope: Handle, key: Bytes,
    value: Bytes, error: *mut ErrorBuffer) -> u32
{
    service(error, || {
        let value = unsafe { view(value, v22::MAX_INPUT)? };
        state_access(instance, request, scope, key, |scope, key| {
            let old = scope.values.get(key).map_or(0, |value| value.len() + key.len());
            let bytes = scope.bytes - old + key.len() + value.len();
            if bytes > v22::MAX_STATE { return Err(v22::LIMIT); }
            scope.values.insert(key.into(), value);
            scope.bytes = bytes;
            Ok(())
        })
    })
}

pub(crate) fn can_release(instance: Handle) -> Result<(), LoadError> {
    let hub = hub()?;
    let tables = hub.tables.lock().map_err(|_| lock_error())?;
    if tables.requests().iter().any(|request| request.module.instance == instance) {
        return Err(failure("Mod still owns active native requests; userdata/library pinned"));
    }
    Ok(())
}

pub(crate) fn shutdown() -> Result<(), LoadError> {
    let Some(hub) = HUB.get() else { return Ok(()); };
    let hub = hub.as_ref().map_err(Clone::clone)?;
    let requests = {
        let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
        tables.stopping = true;
        tables.requests()
    };
    for request in requests { request.cancel(false); }
    let deadline = Instant::now() + CLEANUP_DEADLINE;
    let mut tables = hub.tables.lock().map_err(|_| lock_error())?;
    while tables.requests != 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(failure("shutdown cleanup deadline; active native data remains pinned")); }
        tables = hub.changed.wait_timeout(tables, remaining).map_err(|_| lock_error())?.0;
    }
    tables.failed.clone().or_else(|| tables.shutdown_error.clone()).map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handles_check_epoch_type_generation_and_never_wrap() {
        let mut tables = Tables { slots: Vec::new(), modules: BTreeMap::new(), contributions: Vec::new(), stopping: false, scopes: 0, requests: 0, levels: BTreeMap::new(), failed: None, shutdown_error: None };
        let object = || Object::Scope(ScopeData { owner: Handle::NONE, parent: Handle::NONE, kind: ScopeKind::Mod, open: true, values: BTreeMap::new(), bytes: 0 });
        let old = tables.insert(7, object()).unwrap();
        assert!(tables.get(8, old).is_err());
        tables.remove(7, old).unwrap();
        let new = tables.insert(7, object()).unwrap();
        assert_eq!(old.slot, new.slot);
        assert_ne!(old.generation, new.generation);
        assert!(tables.get(7, old).is_err());
        tables.slots[0].generation = u32::MAX;
        tables.slots[0].value = None;
        assert_ne!(tables.insert(7, object()).unwrap().slot, 0);
    }

    #[test]
    fn delivery_has_exactly_one_winner_and_quiescence_is_separate() {
        let mut state = RequestState { result: None, terminal: false, cancelled: false, quiet: false,
            started_returned: false, cancel_queued: false, cancel_returned: false, release_queued: false, waker: None };
        assert!(state.deliver(Ok(b"winner".to_vec())));
        assert!(!state.deliver(Err(failure("late cancel"))));
        assert_eq!(state.result.unwrap().unwrap(), b"winner");
        assert!(!state.quiet);
    }

    #[test]
    fn cancellation_and_completion_race_without_early_release() {
        let state = Arc::new(Mutex::new(RequestState { result: None, terminal: false, cancelled: false,
            quiet: false, started_returned: false, cancel_queued: true, cancel_returned: false,
            release_queued: false, waker: None }));
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let workers = [true, false].map(|complete| {
            let state = state.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                state.lock().unwrap().deliver(if complete { Ok(b"done".to_vec()) } else { Err(failure("cancelled")) })
            })
        });
        barrier.wait();
        assert_eq!(workers.into_iter().map(|worker| worker.join().unwrap()).filter(|won| *won).count(), 1);
        let mut state = state.lock().unwrap();
        assert!(!state.releasable());
        state.quiet = true;
        assert!(!state.releasable());
        state.started_returned = true;
        assert!(!state.releasable());
        state.cancel_returned = true;
        assert!(state.releasable());
        state.release_queued = true;
        assert!(!state.releasable());
    }

    #[test]
    fn scope_creation_validates_every_parent_before_allocation() {
        let mut tables = Tables { slots: Vec::new(), modules: BTreeMap::new(), contributions: Vec::new(),
            stopping: false, scopes: 0, requests: 0, levels: BTreeMap::new(), failed: None, shutdown_error: None };
        let owner = Handle { epoch: 7, slot: 100, generation: 1 };
        let parent = tables.insert(7, Object::Scope(ScopeData { owner, parent: owner,
            kind: ScopeKind::Mod, open: true, values: BTreeMap::new(), bytes: 0 })).unwrap();
        let before = tables.slots.len();
        assert!(tables.allocate_scopes(7, ScopeKind::Thread, &[(owner, parent), (owner, Handle::NONE)]).is_err());
        assert_eq!(tables.slots.len(), before);
        assert_eq!(tables.scopes, 0);
        let other_owner = Handle { slot: 101, ..owner };
        assert!(tables.allocate_scopes(7, ScopeKind::Thread, &[(other_owner, parent)]).is_err());
        assert!(tables.allocate_scopes(7, ScopeKind::Turn, &[(owner, parent)]).is_err());
        tables.scopes = v22::MAX_SCOPES;
        assert!(tables.allocate_scopes(7, ScopeKind::Thread, &[(owner, parent)]).is_err());
    }

    #[test]
    fn ordinary_native_reentry_is_rejected_without_clearing_outer_guard() {
        let outer = NativeCall::enter().unwrap();
        assert!(NativeCall::enter().is_err());
        assert!(NativeCall::enter().is_err());
        drop(outer);
        assert!(NativeCall::enter().is_ok());
    }
}
