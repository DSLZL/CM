//! Private staging: no registration becomes visible until every init succeeds.
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::align_of;
use std::mem::size_of;
use std::ptr;

use cm_abi::Bytes;
use cm_abi::Header;
use cm_abi::PolicyInput;
use cm_abi::v2;
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
        config: Vec<u8>,
    ) -> Result<Self, LoadError> {
        let digest = plan.sha256();
        let config = Box::leak(config.into_boxed_slice());
        let mut staged = Self {
            plan,
            digest,
            modules: Vec::new(),
            bindings: BTreeMap::new(),
        };
        for prepared in modules {
            let owner = prepared.manifest.id.clone();
            let hooks = prepared.manifest.hooks();
            event(
                "init-start",
                json!({"mod": owner, "plan_sha256": staged.digest}),
            );
            let loaded = if prepared.manifest.format_version == 1 {
                NativeMod::load(prepared).map(Module::Legacy)
            } else {
                CompositionMod::load(prepared, config, &staged.plan.host.build_id)
                    .map(Module::Composition)
            };
            let module = match loaded {
                Ok(module) => module,
                Err(error) => {
                    let error = error.owner(&owner, None);
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
                let error =
                    LoadError::native("init", "Next used outside a dispatch").owner(&owner, None);
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

    pub(crate) fn release(&mut self) -> Result<(), LoadError> {
        let mut first = None;
        for (owner, module) in self.modules.iter_mut().rev() {
            event("release-start", json!({"mod": owner}));
            let result = match module {
                Module::Legacy(module) => module.release(),
                Module::Composition(module) => module.release(),
            };
            if let Err(error) = result {
                let error = error.owner(owner, None);
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

struct CompositionMod {
    callbacks: Vec<v2::Hook>,
    release: Option<cm_abi::Release>,
    userdata: *mut c_void,
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
        let host = v2::HostApi {
            header: v2::header::<v2::HostApi>(),
            capability: Bytes::from_static(v2::CAPABILITY),
            host_build_id: Bytes::borrowed(build_id),
            next: Some(crate::tool_policy::next),
            reserved: 0,
        };
        let mut table: *const Header = ptr::null();
        native::invoke("entry", |error| unsafe { entry(&host, &mut table, error) })?;
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
        header(unsafe { table.read() }, size_of::<v2::ModApi>())?;
        if !(table as usize).is_multiple_of(align_of::<v2::ModApi>()) {
            return Err(LoadError::native("negotiate", "misaligned v2 table"));
        }
        let api = unsafe { table.cast::<v2::ModApi>().read() };
        if api.reserved != 0
            || api.init.is_none()
            || unsafe { native::text(api.mod_id, 128)? } != manifest.id
            || api.contribution_count != manifest.contributions.len() as u64
            || api.contribution_count == 0
            || api.contribution_count > 128
            || api.contributions.is_null()
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
                        descriptor.callback.unwrap(),
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
        let mut callbacks = Vec::new();
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
            json!({"mod": manifest.id, "abi_major": 2, "abi_minor": 0}),
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
            callbacks,
            release: api.release,
            userdata: ptr::null_mut(),
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
                event("release-failed", json!(cleanup.owner(&manifest.id, None)));
            }
            return Err(error);
        }
        Ok(loaded)
    }

    fn hook(&self, callback: usize, input: &v2::Input) -> Result<(u32, bool), LoadError> {
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
        let result = native::invoke("policy", |error| unsafe {
            let status =
                (self.callbacks[callback])(self.userdata, input, &mut output.decision, error);
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

    fn release(&mut self) -> Result<(), LoadError> {
        let userdata = std::mem::take(&mut self.userdata);
        if !userdata.is_null() {
            let release = self
                .release
                .ok_or_else(|| LoadError::native("release", "missing v2 release"))?;
            native::invoke("release", |error| unsafe { release(userdata, error) })?;
            event("userdata-released", json!({"count": 1}));
        }
        Ok(())
    }
}
