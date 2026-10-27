#[path = "../../../runtime-sdk/fixture.rs"]
mod fixture;
use cm_sdk::{Init, abi::Bytes, v22};

fn create(init: Init) -> Result<fixture::Fixture, String> {
    fixture::Fixture::new("lifecycle-audit", init)
}
const DESCRIPTORS: &[v22::RuntimeContribution] = &[v22::RuntimeContribution {
    header: v22::header::<v22::RuntimeContribution>(),
    id: Bytes::from_static("audit"),
    capability: Bytes::from_static(v22::LIFECYCLE),
    resource: Bytes::from_static("lifecycle-audit__events"),
    kind: v22::KIND_LIFECYCLE,
    reserved: 0,
    route: 1,
}];
cm_sdk::export_mod!(fixture::Fixture, "lifecycle-audit", create, DESCRIPTORS);
