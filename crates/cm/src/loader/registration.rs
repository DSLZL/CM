//! Private staging: no registration becomes visible until every init succeeds.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::align_of;
use std::mem::size_of;
use std::ptr;

use cm_abi::Bytes;
use cm_abi::Header;
use cm_abi::PolicyInput;
use cm_abi::v2;
use cm_abi::v21;
use serde_json::json;

use super::Kind;
use super::Preflighted;
use super::native;
use super::native::NativeMod;
use crate::LoadError;
use crate::event;
use crate::runtime_plan::RuntimePlan;

enum Module {
    Legacy(NativeMod),
    Composition(CompositionMod),
}

pub(crate) struct Binding {
    pub owner: String,
    pub local_id: String,
    pub kind: Kind,
    module: usize,
    callback: usize,
}

pub(crate) struct RegistrationSet {
    pub plan: RuntimePlan,
    pub digest: String,
    modules: Vec<(String, Module)>,
    pub bindings: BTreeMap<String, Binding>,
}

impl RegistrationSet {
    pub(crate) fn load(
        plan: RuntimePlan,
        modules: Vec<Preflighted>,
        mut config: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, LoadError> {
        let digest = plan.sha256();
        let mut staged = Self {
            plan,
            digest,
            modules: Vec::new(),
            bindings: BTreeMap::new(),
        };
        for prepared in modules {
            let owner = prepared.manifest.id.clone();
            let config = Box::leak(config.remove(&owner).unwrap_or_default().into_boxed_slice());
            let hooks = prepared.manifest.hooks();
            event(
                "init-start",
                json!({"mod": owner, "plan_sha256": staged.digest}),
            );
            let loaded = if prepared.manifest.abi_major == 1 {
                NativeMod::load(prepared).map(Module::Legacy)
            } else {
                CompositionMod::load(prepared, config, &staged.plan.host.build_id)
                    .map(Module::Composition)
            };
            let module = match loaded {
                Ok(module) => module,
                Err(error) => {
                    let error =
                        crate::runtime_plan::resource_error(error.owner(&owner, None), &hooks);
                    if let Err(cleanup) = staged.release() {
                        event("release-failed", json!(cleanup));
                    }
                    return Err(error);
                }
            };
            for (callback, hook) in hooks.into_iter().enumerate() {
                staged.bindings.insert(
                    format!("{owner}::{}", hook.id),
                    Binding {
                        owner: owner.clone(),
                        local_id: hook.id,
                        kind: hook.kind,
                        module: staged.modules.len(),
                        callback,
                    },
                );
            }
            staged.modules.push((owner.clone(), module));
            if crate::tool_policy::NEXT_VIOLATION.load(std::sync::atomic::Ordering::Acquire) {
                let error = crate::runtime_plan::resource_error(
                    LoadError::native("init", "Next used outside a dispatch").owner(&owner, None),
                    &staged.plan.mods[&owner].contributions,
                );
                if let Err(cleanup) = staged.release() {
                    event("release-failed", json!(cleanup));
                }
                return Err(error);
            }
            event(
                "init-complete",
                json!({"mod": owner, "plan_sha256": staged.digest}),
            );
        }
        event(
            "registration-commit",
            json!({
                "mod_count": staged.modules.len(), "plan_sha256": staged.digest,
                "initialization_order": staged.plan.initialization_order,
            }),
        );
        Ok(staged)
    }

    pub(crate) fn len(&self) -> usize {
        self.modules.len()
    }

    pub(crate) fn legacy(&self, key: &str, input: &PolicyInput) -> Result<u32, LoadError> {
        let binding = &self.bindings[key];
        match &self.modules[binding.module].1 {
            Module::Legacy(module) => module
                .policy(input)
                .map_err(|e| e.owner(&binding.owner, Some(&binding.local_id))),
            _ => Err(LoadError::native(
                "policy",
                "internal legacy binding mismatch",
            )),
        }
    }

    pub(crate) fn hook(&self, key: &str, input: &v2::Input) -> Result<(u32, bool), LoadError> {
        let binding = &self.bindings[key];
        match &self.modules[binding.module].1 {
            Module::Composition(module) => module
                .hook(binding.callback, input)
                .map_err(|e| e.owner(&binding.owner, Some(&binding.local_id))),
            _ => Err(LoadError::native(
                "policy",
                "internal composition binding mismatch",
            )),
        }
    }

    pub(crate) fn limit(
        &self,
        key: &str,
        input: &v21::Input,
    ) -> Result<(v21::Output, bool), LoadError> {
        let binding = &self.bindings[key];
        let result = match &self.modules[binding.module].1 {
            Module::Composition(module) => module.limit(binding.callback, input),
            _ => Err(LoadError::native(
                "output_limit",
                "internal limiter binding mismatch",
            )),
        };
        result.map_err(|error| {
            let mut error = error.owner(&binding.owner, Some(&binding.local_id));
            error.resource = Some(v21::CAPABILITY.into());
            error
        })
    }

    pub(crate) fn release(&mut self) -> Result<(), LoadError> {
        let mut first = None;
        for (owner, module) in self.modules.iter_mut().rev() {
            event("release-start", json!({"mod": owner}));
            let result = match module {
                Module::Legacy(module) => module.release(),
                Module::Composition(module) => module.release(),
            };
            if let Err(error) = result {
                let error = crate::runtime_plan::resource_error(
                    error.owner(owner, None),
                    &self.plan.mods[owner.as_str()].contributions,
                );
                event("release-failed", json!(error));
                if first.is_none() {
                    first = Some(error);
                }
            }
            event("release-complete", json!({"mod": owner}));
        }
        first.map_or(Ok(()), Err)
    }
}

#[derive(Clone, Copy)]
enum Callback {
    Eligibility(v2::Hook),
    Limit(v21::Hook),
    Runtime(u64),
}

thread_local! {
    static POLICY_GATES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

struct PolicyGate<'a> {
    key: usize,
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl<'a> PolicyGate<'a> {
    fn enter(gate: &'a std::sync::Mutex<()>) -> Result<Option<Self>, LoadError> {
        let key = std::ptr::from_ref(gate) as usize;
        // Controlled Next can enter another contribution of this Mod on the same thread.
        if POLICY_GATES.with(|held| held.borrow().contains(&key)) {
            return Ok(None);
        }
        let guard = gate
            .lock()
            .map_err(|_| LoadError::native("policy", "poisoned Mod gate"))?;
        POLICY_GATES.with(|held| held.borrow_mut().push(key));
        Ok(Some(Self { key, _guard: guard }))
    }
}

impl Drop for PolicyGate<'_> {
    fn drop(&mut self) {
        POLICY_GATES.with(|held| held.borrow_mut().retain(|key| *key != self.key));
    }
}

struct CompositionMod {
    owner: String,
    callbacks: Vec<Callback>,
    release: Option<cm_abi::Release>,
    userdata: *mut c_void,
    instance: Option<cm_abi::v22::Handle>,
    gate: std::sync::Arc<std::sync::Mutex<()>>,
}

// Runtime serializes callbacks and release, including controlled synchronous Next.
unsafe impl Send for CompositionMod {}

fn header(value: Header, minimum: usize) -> Result<(), LoadError> {
    if value.struct_size < minimum as u32
        || value.struct_size > 4096
        || value.major != v2::ABI_MAJOR
        || value.minor != v2::ABI_MINOR
    {
        return Err(LoadError::native(
            "negotiate",
            "unsupported v2 size/version",
        ));
    }
    Ok(())
}

impl CompositionMod {
    fn load(prepared: Preflighted, config: &[u8], build_id: &str) -> Result<Self, LoadError> {
        let Preflighted {
            manifest,
            snapshot,
            needed,
            resources,
        } = prepared;
        let library = native::open(&manifest, snapshot, &needed)?;
        let entry = unsafe { library.get::<v2::Entry>(b"cm_mod_entry_v2\0") }
            .map_err(|e| LoadError::native("entry", &e.to_string()))?;
        let base = v2::HostApi {
            header: v2::header::<v2::HostApi>(),
            capability: Bytes::from_static(v2::CAPABILITY),
            host_build_id: Bytes::borrowed(build_id),
            next: Some(crate::tool_policy::next),
            reserved: 0,
        };
        let mut capabilities = vec![
            Bytes::from_static(v2::CAPABILITY),
            Bytes::from_static(v21::CAPABILITY),
            Bytes::from_static(crate::state::CAPABILITY),
        ];
        let instance = if manifest.abi_minor == 2 {
            Some(crate::runtime::new_instance(&manifest.id)?)
        } else {
            None
        };
        let services =
            instance.map(|instance| Box::leak(Box::new(crate::runtime::services(instance))));
        if manifest.abi_minor == 2 {
            capabilities.extend(cm_abi::v22::CAPABILITIES.map(Bytes::from_static));
        }
        let mut host = cm_abi::v22::HostApi {
            base: v21::HostApi {
                base,
                capabilities: capabilities.as_ptr(),
                capability_count: capabilities.len() as u64,
                reserved: 0,
            },
            runtime: services.map_or(ptr::null(), |services| services as *const _),
        };
        if manifest.abi_minor == 1 {
            host.base.base.header = v21::header::<v21::HostApi>();
        } else if manifest.abi_minor == 2 {
            host.base.base.header = cm_abi::v22::header::<cm_abi::v22::HostApi>();
        }
        let mut table: *const Header = ptr::null();
        native::invoke("entry", |error| unsafe {
            entry(&host.base.base, &mut table, error)
        })?;
        if crate::tool_policy::NEXT_VIOLATION.load(std::sync::atomic::Ordering::Acquire) {
            return Err(LoadError::native(
                "entry",
                "Next used outside an active callback",
            ));
        }
        if table.is_null() || !(table as usize).is_multiple_of(align_of::<u32>()) {
            return Err(LoadError::native(
                "negotiate",
                "null/misaligned v2 size prefix",
            ));
        }
        if unsafe { table.cast::<u32>().read() } < size_of::<Header>() as u32 {
            return Err(LoadError::native("negotiate", "short v2 header prefix"));
        }
        let prefix = unsafe { table.read() };
        let minimum = if manifest.abi_minor == 2 {
            size_of::<cm_abi::v22::ModApi>()
        } else if manifest.abi_minor == 1 {
            size_of::<v21::ModApi>()
        } else {
            size_of::<v2::ModApi>()
        };
        if prefix.major != 2
            || prefix.minor != manifest.abi_minor
            || prefix.struct_size < minimum as u32
            || prefix.struct_size > 4096
        {
            return Err(LoadError::native(
                "negotiate",
                "unsupported table size/version",
            ));
        }
        if !(table as usize).is_multiple_of(align_of::<v2::ModApi>()) {
            return Err(LoadError::native("negotiate", "misaligned v2 table"));
        }
        let api = unsafe { table.cast::<v2::ModApi>().read() };
        if api.reserved != 0
            || api.init.is_none()
            || unsafe { native::text(api.mod_id, 128)? } != manifest.id
            || api.contribution_count
                != manifest
                    .contributions
                    .iter()
                    .filter(|hook| hook.kind != Kind::OutputLimit && !hook.kind.runtime())
                    .count() as u64
            || api.contribution_count > 128
            || (api.contribution_count != 0 && api.contributions.is_null())
            || !(api.contributions as usize).is_multiple_of(align_of::<v2::Contribution>())
        {
            return Err(LoadError::native(
                "negotiate",
                "invalid v2 Mod declarations/count/pointers",
            ));
        }
        let mut descriptors = BTreeMap::new();
        for index in 0..api.contribution_count as usize {
            let descriptor = unsafe { api.contributions.add(index).read() };
            header(descriptor.header, size_of::<v2::Contribution>())?;
            if descriptor.header.struct_size != size_of::<v2::Contribution>() as u32
                || descriptor.reserved != 0
                || descriptor.callback.is_none()
            {
                return Err(LoadError::native(
                    "negotiate",
                    "invalid v2 contribution header/callback",
                ));
            }
            let id = unsafe { native::text(descriptor.id, 128)? };
            let capability = unsafe { native::text(descriptor.capability, 128)? };
            let resource = unsafe { native::text(descriptor.resource, 128)? };
            if descriptors
                .insert(
                    id,
                    (
                        capability,
                        resource,
                        descriptor.kind,
                        Callback::Eligibility(descriptor.callback.unwrap()),
                    ),
                )
                .is_some()
            {
                return Err(LoadError::native(
                    "negotiate",
                    "duplicate actual contribution",
                ));
            }
        }
        if manifest.abi_minor >= 1 {
            // Prefix size/version/alignment were checked before touching the optional tail.
            let tail = unsafe { table.cast::<v21::ModApi>().read() };
            let expected = manifest
                .contributions
                .iter()
                .filter(|hook| hook.kind == Kind::OutputLimit)
                .count();
            if tail.reserved != 0
                || tail.limiter_count != expected as u64
                || tail.limiter_count > 128
                || tail.limiter_stride != size_of::<v21::Limiter>() as u64
                || (tail.limiter_count != 0 && tail.limiters.is_null())
                || !(tail.limiters as usize).is_multiple_of(align_of::<v21::Limiter>())
            {
                return Err(LoadError::native(
                    "negotiate",
                    "invalid limiter count/stride/pointer",
                ));
            }
            for index in 0..tail.limiter_count as usize {
                let descriptor = unsafe { tail.limiters.add(index).read() };
                if descriptor.header.struct_size != size_of::<v21::Limiter>() as u32
                    || descriptor.header.major != 2
                    || descriptor.header.minor != 1
                    || descriptor.reserved != 0
                    || descriptor.callback.is_none()
                {
                    return Err(LoadError::native("negotiate", "invalid limiter descriptor"));
                }
                let id = unsafe { native::text(descriptor.id, 128)? };
                let capability = unsafe { native::text(descriptor.capability, 128)? };
                let resource = unsafe { native::text(descriptor.resource, 128)? };
                if descriptors
                    .insert(
                        id,
                        (
                            capability,
                            resource,
                            Kind::OutputLimit.abi(),
                            Callback::Limit(descriptor.callback.unwrap()),
                        ),
                    )
                    .is_some()
                {
                    return Err(LoadError::native(
                        "negotiate",
                        "duplicate actual contribution",
                    ));
                }
            }
        }
        let mut runtime_api = None;
        if manifest.abi_minor == 2 {
            let tail = unsafe { table.cast::<cm_abi::v22::ModApi>().read() };
            let expected = manifest
                .contributions
                .iter()
                .filter(|hook| hook.kind.runtime())
                .count();
            if tail.reserved != 0
                || tail.contribution_count != expected as u64
                || tail.contribution_count > 128
                || tail.contribution_stride != size_of::<cm_abi::v22::RuntimeContribution>() as u64
                || (tail.contribution_count != 0 && tail.contributions.is_null())
                || !(tail.contributions as usize)
                    .is_multiple_of(align_of::<cm_abi::v22::RuntimeContribution>())
                || tail.runtime.is_null()
                || !(tail.runtime as usize).is_multiple_of(align_of::<cm_abi::v22::ModRuntimeApi>())
            {
                return Err(LoadError::native(
                    "negotiate",
                    "invalid runtime count/stride/pointer",
                ));
            }
            // Validate the readable header before copying the full optional table.
            if unsafe { tail.runtime.cast::<u32>().read() } < size_of::<Header>() as u32 {
                return Err(LoadError::native("negotiate", "short runtime API header"));
            }
            let prefix = unsafe { tail.runtime.cast::<Header>().read() };
            if !crate::runtime::valid_header::<cm_abi::v22::ModRuntimeApi>(prefix) {
                return Err(LoadError::native("negotiate", "invalid runtime API header"));
            }
            let api = unsafe { tail.runtime.read() };
            if api.reserved != 0
                || api.dispatch.is_none()
                || api.cancel.is_none()
                || api.request_release.is_none()
            {
                return Err(LoadError::native(
                    "negotiate",
                    "missing runtime callbacks/reserved",
                ));
            }
            runtime_api = Some(api);
            let mut routes = std::collections::BTreeSet::new();
            for index in 0..tail.contribution_count as usize {
                let descriptor = unsafe { tail.contributions.add(index).read() };
                if !crate::runtime::valid_header::<cm_abi::v22::RuntimeContribution>(
                    descriptor.header,
                ) || descriptor.reserved != 0
                    || descriptor.route == 0
                    || !routes.insert(descriptor.route)
                {
                    return Err(LoadError::native(
                        "negotiate",
                        "invalid runtime descriptor/route",
                    ));
                }
                let id = unsafe { native::text(descriptor.id, 128)? };
                let capability = unsafe { native::text(descriptor.capability, 128)? };
                let resource = unsafe { native::text(descriptor.resource, 128)? };
                if !(crate::runtime::valid_name(&manifest.id, &resource)
                    || descriptor.kind == cm_abi::v22::KIND_SAMPLING_BUDGET
                        && resource == cm_abi::v22::SAMPLING_BUDGET_CAPABILITY
                    || descriptor.kind == cm_abi::v22::KIND_SUBMIT_REVIEW
                        && resource == cm_abi::v22::SUBMIT_REVIEW_CAPABILITY)
                {
                    return Err(LoadError::native(
                        "negotiate",
                        "runtime name outside owner namespace",
                    )
                    .owner(&manifest.id, Some(&id)));
                }
                if descriptors
                    .insert(
                        id,
                        (
                            capability,
                            resource,
                            descriptor.kind,
                            Callback::Runtime(descriptor.route),
                        ),
                    )
                    .is_some()
                {
                    return Err(LoadError::native(
                        "negotiate",
                        "duplicate actual runtime contribution",
                    ));
                }
            }
        }
        let mut callbacks = Vec::new();
        let mut runtime_contributions = Vec::new();
        for hook in &manifest.contributions {
            let (capability, resource, kind, callback) =
                descriptors.remove(&hook.id).ok_or_else(|| {
                    LoadError::native("negotiate", "missing actual contribution")
                        .owner(&manifest.id, Some(&hook.id))
                })?;
            if capability != hook.capability || resource != hook.resource || kind != hook.kind.abi()
            {
                return Err(LoadError::native(
                    "negotiate",
                    "actual contribution differs from manifest",
                )
                .owner(&manifest.id, Some(&hook.id)));
            }
            if let Callback::Runtime(route) = callback {
                let kind = match hook.kind {
                    Kind::Lifecycle => crate::runtime::Kind::Lifecycle,
                    Kind::Tool => crate::runtime::Kind::Tool,
                    Kind::ContextSection => crate::runtime::Kind::ContextSection,
                    Kind::SamplingBudget => crate::runtime::Kind::SamplingBudget,
                    Kind::SubmitReview => crate::runtime::Kind::SubmitReview,
                    _ => {
                        return Err(LoadError::native(
                            "negotiate",
                            "runtime binding kind mismatch",
                        ));
                    }
                };
                runtime_contributions.push(crate::runtime::Contribution {
                    owner: manifest.id.clone(),
                    id: hook.id.clone(),
                    name: hook.resource.clone(),
                    kind,
                    route,
                    instance: instance.expect("ABI 2.2 instance"),
                });
            }
            callbacks.push(callback);
        }
        if !descriptors.is_empty() {
            return Err(LoadError::native(
                "negotiate",
                "undeclared actual contribution",
            ));
        }
        event(
            "negotiated",
            json!({"mod": manifest.id, "abi_major": 2, "abi_minor": manifest.abi_minor}),
        );
        // Exposed snapshots stay pinned even if native code violates the borrow contract.
        let resources = Box::leak(resources.into_boxed_slice());
        let views: Vec<_> = resources
            .iter()
            .map(|resource| v2::Resource {
                path: Bytes::borrowed(&resource.path),
                content: Bytes {
                    data: resource.bytes.as_ptr(),
                    len: resource.bytes.len() as u64,
                },
            })
            .collect();
        let views = Box::leak(views.into_boxed_slice());
        let context = v2::InitContext {
            header: v2::header::<v2::InitContext>(),
            resources: views.as_ptr(),
            resource_count: views.len() as u64,
            config: Bytes {
                data: config.as_ptr(),
                len: config.len() as u64,
            },
            reserved: 0,
        };
        let mut loaded = Self {
            owner: manifest.id.clone(),
            callbacks,
            release: api.release,
            userdata: ptr::null_mut(),
            instance,
            gate: std::sync::Arc::new(std::sync::Mutex::new(())),
        };
        let result = native::invoke("init", |error| unsafe {
            (api.init.unwrap())(&context, &mut loaded.userdata, error)
        });
        if !loaded.userdata.is_null() && loaded.release.is_none() {
            return Err(LoadError::native(
                "init",
                "nonnull v2 userdata has no owner release",
            ));
        }
        if let Err(error) = result {
            if let Err(cleanup) = loaded.release() {
                event(
                    "release-failed",
                    json!(crate::runtime_plan::resource_error(
                        cleanup.owner(&manifest.id, None),
                        &manifest.hooks(),
                    )),
                );
            }
            return Err(error);
        }
        if let Some(api) = runtime_api
            && let Err(error) = crate::runtime::install(
                instance.expect("ABI 2.2 instance"),
                &manifest.id,
                loaded.userdata,
                api,
                runtime_contributions,
                std::sync::Arc::clone(&loaded.gate),
            )
        {
            if let Err(cleanup) = loaded.release() {
                event("release-failed", json!(cleanup));
            }
            return Err(error);
        }
        Ok(loaded)
    }

    fn hook(&self, callback: usize, input: &v2::Input) -> Result<(u32, bool), LoadError> {
        let _gate = PolicyGate::enter(&self.gate)?;
        #[repr(C)]
        struct Output {
            before: [u8; 16],
            decision: v2::Decision,
            after: [u8; 16],
        }
        let mut output = Output {
            before: [0x5a; 16],
            decision: v2::Decision {
                header: v2::header::<v2::Decision>(),
                decision: cm_abi::KEEP,
                reserved: 0,
            },
            after: [0xa5; 16],
        };
        let mut cancelled = false;
        let Callback::Eligibility(callback) = self.callbacks[callback] else {
            return Err(LoadError::native(
                "policy",
                "internal typed callback mismatch",
            ));
        };
        let result = native::invoke("policy", |error| unsafe {
            let status = callback(self.userdata, input, &mut output.decision, error);
            cancelled = status == v2::CANCELLED;
            if cancelled { cm_abi::OK } else { status }
        });
        result?;
        let value = output.decision;
        if output.before != [0x5a; 16]
            || output.after != [0xa5; 16]
            || value.header.struct_size != size_of::<v2::Decision>() as u32
            || value.header.major != 2
            || value.header.minor != 0
            || value.reserved != 0
            || ![cm_abi::KEEP, cm_abi::FORCE_SERIAL].contains(&value.decision)
        {
            return Err(LoadError::native(
                "policy",
                "invalid v2 decision/header/canary",
            ));
        }
        Ok((value.decision, cancelled))
    }

    fn limit(&self, callback: usize, input: &v21::Input) -> Result<(v21::Output, bool), LoadError> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| LoadError::native("output_limit", "poisoned Mod gate"))?;
        #[repr(C)]
        struct Guarded {
            before: [u8; 16],
            output: v21::Output,
            after: [u8; 16],
        }
        let Callback::Limit(callback) = self.callbacks[callback] else {
            return Err(LoadError::native(
                "output_limit",
                "internal typed callback mismatch",
            ));
        };
        let mut guarded = Guarded {
            before: [0x5a; 16],
            output: v21::Output {
                header: v21::header::<v21::Output>(),
                decision: v21::KEEP,
                limit: 0,
                reserved: 0,
            },
            after: [0xa5; 16],
        };
        let mut cancelled = false;
        native::invoke("output_limit", |error| unsafe {
            let status = callback(self.userdata, input, &mut guarded.output, error);
            cancelled = status == v2::CANCELLED;
            if cancelled { cm_abi::OK } else { status }
        })?;
        if guarded.before != [0x5a; 16] || guarded.after != [0xa5; 16] {
            return Err(LoadError::native("output_limit", "invalid output canary"));
        }
        crate::output_limit::validate(&guarded.output, input.original_limit)?;
        Ok((guarded.output, cancelled))
    }

    fn release(&mut self) -> Result<(), LoadError> {
        if let Some(instance) = self.instance {
            crate::runtime::can_release(instance)?;
        }
        let _gate = self
            .gate
            .lock()
            .map_err(|_| LoadError::native("release", "poisoned Mod gate"))?;
        let userdata = std::mem::take(&mut self.userdata);
        if !userdata.is_null() {
            let release = self
                .release
                .ok_or_else(|| LoadError::native("release", "missing v2 release"))?;
            native::invoke("release", |error| unsafe { release(userdata, error) })?;
            event("userdata-released", json!({"mod": self.owner, "count": 1}));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyGate;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn controlled_next_retains_gate_until_the_outer_callback_returns() {
        let gate = Arc::new(Mutex::new(()));
        let outer = PolicyGate::enter(&gate).unwrap();
        assert!(outer.is_some());
        let middle = Mutex::new(());
        let middle_guard = PolicyGate::enter(&middle).unwrap();
        assert!(PolicyGate::enter(&gate).unwrap().is_none());
        let other = Arc::clone(&gate);
        std::thread::spawn(move || assert!(other.try_lock().is_err()))
            .join()
            .unwrap();
        drop(middle_guard);
        drop(outer);
        assert!(gate.try_lock().is_ok());
        assert!(PolicyGate::enter(&gate).unwrap().is_some());
    }
}
