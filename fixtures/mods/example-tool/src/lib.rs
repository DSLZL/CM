#[path = "../../../runtime-sdk/fixture.rs"]
mod fixture;
use cm_sdk::{Init, abi::Bytes, v22};

fn create(init: Init) -> Result<fixture::Fixture, String> {
    fixture::Fixture::new("example-tool", init)
}
const DESCRIPTORS: &[v22::RuntimeContribution] = &[
    v22::RuntimeContribution { header: v22::header::<v22::RuntimeContribution>(), id: Bytes::from_static("echo"),
        capability: Bytes::from_static(v22::TOOL), resource: Bytes::from_static("example-tool__echo"),
        kind: v22::KIND_TOOL, reserved: 0, route: 1 },
    v22::RuntimeContribution { header: v22::header::<v22::RuntimeContribution>(), id: Bytes::from_static("context"),
        capability: Bytes::from_static(v22::CONTEXT_SECTION), resource: Bytes::from_static("example-tool__context"),
        kind: v22::KIND_CONTEXT_SECTION, reserved: 0, route: 2 },
];

#[cfg(not(feature = "negative"))]
cm_sdk::export_mod!(fixture::Fixture, "example-tool", create, DESCRIPTORS);

#[cfg(feature = "negative")]
mod negative {
    use super::*;
    use cm_sdk::{Host, abi};
    use std::ffi::c_void;
    use std::mem::size_of;
    static HOST: std::sync::OnceLock<Host> = std::sync::OnceLock::new();
    unsafe extern "C" fn init(context: *const abi::v2::InitContext, userdata: *mut *mut c_void,
        error: *mut abi::ErrorBuffer) -> u32
    {
        unsafe { cm_sdk::initialize(context, userdata, error, *HOST.get().expect("entry"), create) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cm_mod_entry_v2(host: *const abi::v2::HostApi, output: *mut *const abi::Header,
        error: *mut abi::ErrorBuffer) -> u32
    {
        unsafe { cm_sdk::boundary(error, || {
            if output.is_null() { return Err("null output".into()); }
            HOST.set(Host::negotiate(host)?).map_err(|_| "duplicate entry")?;
            let variant = option_env!("CM_RUNTIME_VARIANT").unwrap_or("normal");
            let mut descriptors = DESCRIPTORS.to_vec().into_boxed_slice();
            let mut runtime = Box::new(v22::ModRuntimeApi {
                header: v22::header::<v22::ModRuntimeApi>(), dispatch: Some(cm_sdk::dispatch::<fixture::Fixture>),
                cancel: Some(cm_sdk::cancel::<fixture::Fixture>),
                request_release: Some(cm_sdk::request_release::<fixture::Fixture>), reserved: 0,
            });
            match variant {
                "runtime-short" => runtime.header.struct_size = 4,
                "runtime-minor" => runtime.header.minor = 3,
                "runtime-reserved" => runtime.reserved = 1,
                "null-dispatch" => runtime.dispatch = None,
                "null-cancel" => runtime.cancel = None,
                "null-release" => runtime.request_release = None,
                "undeclared" => descriptors[0].resource = Bytes::from_static("example-tool__undeclared"),
                "reserved-name" => descriptors[0].resource = Bytes::from_static("exec_command"),
                "foreign-owner" => descriptors[0].resource = Bytes::from_static("lifecycle-audit__events"),
                "duplicate-name" => descriptors[1].resource = descriptors[0].resource,
                "duplicate-id" => descriptors[1].id = descriptors[0].id,
                "invalid-utf8" => descriptors[0].resource = Bytes { data: b"\xff".as_ptr(), len: 1 },
                "duplicate-route" => descriptors[1].route = 1,
                "descriptor-short" => descriptors[0].header.struct_size = 8,
                _ => {}
            }
            let mut table = Box::new(v22::ModApi {
                base: abi::v21::ModApi { base: abi::v2::ModApi {
                    header: v22::header::<v22::ModApi>(), mod_id: Bytes::from_static("example-tool"),
                    contributions: std::ptr::null(), contribution_count: 0, init: Some(init),
                    release: Some(cm_sdk::release::<fixture::Fixture>), reserved: 0,
                }, limiters: std::ptr::null(), limiter_count: 0,
                    limiter_stride: size_of::<abi::v21::Limiter>() as u64, reserved: 0 },
                runtime: Box::into_raw(runtime), contributions: descriptors.as_ptr(),
                contribution_count: descriptors.len() as u64, contribution_stride: size_of::<v22::RuntimeContribution>() as u64,
                reserved: 0,
            });
            match variant {
                "short-tail" => table.base.base.header.struct_size -= 8,
                "null-runtime" => table.runtime = std::ptr::null(),
                "null-array" => table.contributions = std::ptr::null(),
                "stride" => table.contribution_stride -= 8,
                "count" => table.contribution_count += 1,
                "too-many" => table.contribution_count = 129,
                "reserved" => table.reserved = 1,
                _ => {}
            }
            Box::leak(descriptors);
            *output = Box::into_raw(table).cast();
            Ok(())
        }) }
    }
}
