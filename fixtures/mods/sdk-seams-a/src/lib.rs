#[path = "../../../sdk-seams/fixture.rs"]
mod fixture;
use cm_sdk::{abi::Bytes, v22, v23};
const OWNER: &str = "sdk-a";

extern "C" fn cache_proof_constructor() {
    fixture::constructor();
    fixture::record("author-cache-proof", v22::Handle::NONE, "");
}

#[used]
#[unsafe(link_section = ".init_array")]
static CONSTRUCTOR: extern "C" fn() = cache_proof_constructor;
const DESCRIPTORS: &[v22::RuntimeContribution] = &[
    v22::RuntimeContribution {
        header: v22::header::<v22::RuntimeContribution>(),
        id: Bytes::from_static("around"),
        capability: Bytes::from_static(v23::TOOL_CONTINUATION),
        resource: Bytes::from_static("exec_command"),
        kind: if cfg!(feature = "replacement") {
            v23::KIND_TOOL_REPLACEMENT
        } else {
            v23::KIND_TOOL_AROUND
        },
        reserved: 0,
        route: 1,
    },
    v22::RuntimeContribution {
        header: v22::header::<v22::RuntimeContribution>(),
        id: Bytes::from_static("stream"),
        capability: Bytes::from_static(v23::RESPONSE_STREAM),
        resource: Bytes::from_static(v23::RESPONSE_STREAM),
        kind: v23::KIND_RESPONSE_STREAM,
        reserved: 0,
        route: 2,
    },
    v22::RuntimeContribution {
        header: v22::header::<v22::RuntimeContribution>(),
        id: Bytes::from_static("cli"),
        capability: Bytes::from_static(v23::CLI_COMMAND),
        resource: Bytes::from_static("sdk-a__hello"),
        kind: v23::KIND_CLI_COMMAND,
        reserved: 0,
        route: 3,
    },
    v22::RuntimeContribution {
        header: v22::header::<v22::RuntimeContribution>(),
        id: Bytes::from_static("tui"),
        capability: Bytes::from_static(v23::TUI_COMMAND),
        resource: Bytes::from_static("sdk-a__notice"),
        kind: v23::KIND_TUI_COMMAND,
        reserved: 0,
        route: 4,
    },
];
cm_sdk::export_sdk_mod!(fixture::Fixture, "sdk-a", fixture::create, DESCRIPTORS);
