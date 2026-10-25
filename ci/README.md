# CM Linux x64 CI

CM source is DSLZL/CM; the independent GitHub-hosted ubuntu-24.04 X64 producer and cache owner is DSLZL/CM-build-linux-x64. The only CM target is x86_64-unknown-linux-gnu. All compilation, checks, tests, smoke runs and experiments execute there. Local work edits and reviews source/configuration and lightweight evidence.

## Publication inputs

ci/source-files.txt lists the exact reviewed public source inputs. Existing .gitignore rules remain unchanged. Assistant settings, task packs, reports, specs and journals stay local; do not force-add or copy them into public directories. The journal-only .gitattributes is outside this payload.

The source workflow checks tracked paths against .gitignore, payload/worker mappings, CI Python compilation, unconfigured rejection and the pinned upstream/release baseline. It does not execute product acceptance or read ignored developer materials. New product results require a new exact source commit and independent worker run.

## Host producer and identity

adapters/codex-e4568a3/source.json pins the original upstream commit/tree, original input hashes and separate official release reference. The worker preserves the complete pristine Git snapshot and original lock, creates a separate Host worktree, applies the three registered patches and copies only the explicit overlay paths. This includes the native runtime/ABI crates, CLI startup, the actual Core gate, terminal exec cleanup and their manifest/lock edges. The existing app-server Clippy cleanup remains explicit. The complete source delta, original/final locks and their hashes are recorded separately from pristine S0. No full upstream development tree is published in CM or bundled with the Host.

The builder runs host.py prepare before loading real Cargo mappings, then installs Rust 1.95.0 and native dependencies. host.py native reuses the pinned upstream V8 resolver and records verified V8 bytes, actual Rust binaries, native tools/packages/files. Generated native identity files are required during cache identification, after materialization; they are not publication inputs. Cargo runs from its manifest directory so workspace .cargo configuration is discovered.

The ephemeral runner uses the pinned upstream CI user-namespace setup (unprivileged_userns_clone=1 and apparmor_restrict_unprivileged_userns=0). The worker first builds/checks bwrap in a fresh helper unit, runs a real namespace smoke check before Host compilation, records kernel/sysctl observations separately, and supplies its actual digest through upstream CODEX_BWRAP_SHA256. This does not qualify compatibility with stock AppArmor restrictions. host.py seal refuses existing Host target artifacts and canonicalizes full source/overlay, final lock, actual tools/native/V8, target, profiles, features and flags. Relative paths and file bytes/modes enter the identity; traversal order, mtime and temporary roots do not. User Mod selections and compiled Mod payloads are absent. Host inputs, including the compiled helper digest, are sealed before Host compilation and embedded through CM_HOST_IDENTITY_JSON; codex cm-host-identity reads the compiled-in JSON. host_release_id, host_api_version, protocol_contract_id and host_build_id have separate roles. Final artifact_sha256 is recorded externally after packaging, avoiding self-reference.

The worker runs producer rejection tests, fmt, clippy with warnings denied, actual package tests and locked Host/helper builds. Acceptance reuses the fixed upstream package builder with the just-built CLI, code-mode host and bwrap, and its verified ripgrep resource. The package includes identity, original license notices, a resolved dependency/license inventory and cm-runtime-files.json. The latter binds required component paths, executable modes, hashes and resolved system-library paths; normal packaged business startup checks it before native entry. The unpackaged Cargo CLI inode and its integration-test hard links use the development entry. Upstream's 0.0.0 development-package copies also require exact development metadata and a full CLI digest equal to the original compile-time build artifact. Formal 0.3.0-p04 packages always require their CM inventory. No runtime environment switch enables this entry, and the isolated P04 runtime has no build path. The consumer separately inventories the actual ELF/library closure and rejects a missing package inventory. Complete license-compliance certification remains later work.

The P01 regression producer still checks the real embedded identity, stale-output refusal, source/final lock drift, representative CLI commands and four unchanged Core command-approval canonicalization tests. Current-source P01/P02/P03 reports retain separate p01-baseline-acceptance.json, p02-baseline-acceptance.json and p03-baseline-acceptance.json names. P04 producer success only means its frozen inputs are ready. Only the independent consumer may write the six P04 acceptance results. Historical accepted runs do not accept a new Host revision.

A separately downloaded, digest-pinned official rust-v0.163.0 installation and isolated official profile must remain byte-identical throughout the baseline. The official CLI initializes its own helper files before the protected snapshot; complete before/after manifests are retained. That release only publishes a musl Linux reference; this read-only fixture does not add a CM musl target. Its release commit differs from the pinned development source, so binary equivalence is not claimed.

## Runtime collection and P03 compatibility

The current P04 source is a dev-small candidate, pending its exact independent Actions run. Worker materialization sets opt-level=3 only for cm-runtime and sha2 to keep full executable hashing practical at startup; these package overrides enter the sealed Host source identity. The P03 collection protocol composes precompiled policies at core.tool_parallel_eligibility.v1 on new local embedded codex exec sessions. The original eligibility query runs before the policy chain; final_parallel = original_parallel AND NOT force_serial. The chain does not wrap the asynchronous tool handler. Remote/LocalDaemon and other session paths with selected Core Mods fail before native execution; metadata commands never load Mods. TUI, resume/fork, Code Mode, other Hook seams and a complete public SDK/manager remain later work.

The runtime reads at most 32 plain directories under CODEX_HOME/mods. Each candidate has a bounded mod.toml. An optional separate CODEX_HOME/cm-runtime.toml uses format_version=1 and enabled=[Mod IDs]: missing selects all, an explicit empty list selects none, and unknown/duplicate IDs fail. All candidate manifests are parsed and locked, including disabled candidates; execution compatibility and payload/resource verification apply to the selected set. A missing mods directory means an empty set.

The legacy ABI 1.0 and format 1 manifest remain valid without changes:

```toml
format_version = 1
id = "serial-fixture"
version = "0.1.0"
payload = "payload.so"
payload_size = 12345 # Replace with the exact precompiled payload byte count.
payload_sha256 = "<64 lowercase SHA-256 hex digits>"
target = "x86_64-unknown-linux-gnu"
abi_major = 1
abi_minor = 0
required_capabilities = ["core.tool_parallel_eligibility.v1"]
dependencies = []
contribution = "core.tool_parallel_eligibility.v1"
```

Unknown/duplicate keys, symlinks, multiply linked files, unsupported declarations, paths, sizes, hashes, ELF targets, RPATH/RUNPATH, filters/audit resolution and non-allowlisted native dependency names are rejected before dlopen. Every path component is opened relative to verified directory descriptors without following symlinks. The verified byte buffer becomes a sealed, read-only memfd; loading uses its absolute /proc/self/fd path with RTLD_NOW | RTLD_LOCAL. No package path is reopened for loading. Constructor execution is possible as soon as dlopen begins; ABI/entry/init failures are classified as already_native_executed and never become Ready.

crates/cm-abi/include/cm_mod_v1.h is the C contract. It uses fixed-width repr(C) layouts, borrowed UTF-8 pointer/length views, caller-owned bounded output/error storage and Mod-owned userdata/release. The entry reads size before header/table fields. Only KEEP and FORCE_SERIAL decisions are valid; final eligibility is original_parallel AND decision != FORCE_SERIAL. The existing per-runtime Core RWLock still controls actual execution. A callback error is fatal and never silently falls back to KEEP. In-flight tools drain before that error returns to the normal turn error path. Calls are synchronous, serialized and reject ordinary runtime reentry; cancellation is checked at synchronous boundaries. Normal shutdown stops admission, drains tool leases and native calls, then releases owners once in reverse initialization order. Libraries and sealed payloads stay pinned until process exit; removing files affects only the next process.

Native Mods execute with Host permissions. This ABI and loader are not a memory/process sandbox. Invalid pointers, abort, segfault or a stuck callback may terminate or hang the process; a watchdog kill is recorded as failure containment, not successful cancellation or isolation. There is no hot unload.

## Composition ABI and immutable plan

Host API 0.3.0 advertises the legacy capability, core.tool_parallel_eligibility.compose.v1 and core.exec_output_limit.v1. Existing format 2 / ABI 2.0 packages still export cm_mod_entry_v2 with unchanged DTOs. crates/cm-abi/include/cm_mod_v2.h and cm-abi::v2 declare that protocol; no v1 table tail is read as v2 data. ABI 2.1 adds the typed output-limit tail described below.

A format 2 manifest uses the common id/version/payload/digest/target fields above, abi_major=2, abi_minor=0, required_capabilities=["core.tool_parallel_eligibility.compose.v1"], and these fields:

```toml
dependencies = [{ id = "other-mod", version = "0.1.0" }]
conflicts = []
contributions = [
  { id = "policy", kind = "around", capability = "core.tool_parallel_eligibility.compose.v1", resource = "core.tool_parallel_eligibility.v1", order_before = [], order_after = [], priority = 0 }
]
resources = [{ path = "data.txt", size = 24, sha256 = "<exact resource SHA-256>" }]
```

Dependencies match exact selected versions and determine initialization order only. No dependency is downloaded or implicitly enabled. Order references use mod-id::contribution-id within one resource/phase; missing references, cycles and cross-phase edges fail. Stable ID order breaks topological ties. Priority is bounded diagnostic metadata, with no arbitration role. Two replacement claims on the same resource fail before order/priority can choose a winner. Mod/contribution namespaces cm and core (including their dotted prefixes) are reserved.

Phases are before -> around/replacement -> legacy_filter -> after. Before/after observe and return KEEP. Around calls its own synchronous Next token zero or one time; zero calls requires FORCE_SERIAL. A replacement is an exclusive terminal policy. Downstream restrictions and errors are latched. Legacy v1 filters run outside the v2 body and cannot be skipped by around. Once a chain starts, all after observers are attempted during success/error/cancellation cleanup; the first fatal error wins. Initial cancellation enters no callback.

Next is bound to the active dispatch, owner, stack frame and OS thread. Repeated, stale, wrong-owner/thread/scope and malformed-buffer calls fail even when the Mod swallows the status. Only this controlled synchronous path may nest; it does not lock Runtime again or expose Rust objects/Futures across C. Out-of-dispatch violations poison further admission. An already running native function cannot be forcibly cancelled.

RuntimePlan is canonical data with a schema/domain, actual Host executable hash/build identity, all candidate manifest digests, selected Mod payload/resources/content-tree digests, configuration presence/raw digest, independent dependency/hook graphs and resolved orders. It contains no absolute profile path or inode/mtime/discovery order. PreparedPlan privately owns verified sealed payloads and resource/config snapshots. Before the first dlopen it revalidates the whole candidate inventory, every locked input and the current executable identity. Any drift rejects that old plan. After this input linearization point the collection consumes only owned snapshots; disk edits affect a later process.

Loading/negotiation/init occurs in private staging, in dependency order. Actual descriptor IDs/capabilities/kinds/resources must exactly equal the manifest. All init calls must succeed before one registration commit/Ready event. Failure attempts every allocated owner's release in reverse initialization order, including a failing init with nonnull userdata, and keeps the first error. Libraries and exposed snapshots stay pinned until process exit. Native code with an invalid or missing owner release cannot be safely freed by the Host.

Limits: 32 packages, 128 contributions, 64 resources; manifest/config 64 KiB each; payload 64 MiB each/256 MiB selected total; resource 8 MiB each/64 MiB total; IDs 128 bytes, relative paths 512 bytes, native errors 1024 bytes and table size 4096 bytes. Resources may contain arbitrary bytes; init receives only declared read-only views.

## Independent Mod and acceptance

ci/scripts/native_mod.py reuses the existing execute, cargo_args, source and packaging helpers. It freezes and hashes the packaged Host before building the author fixture. fixtures/mods/serial-eligibility has its own workspace, committed lock and initially empty target directory, and depends only on cm-abi. Its actual dependency inventory must exclude Core/runtime; the Host dependency inventory must exclude the concrete Mod. The payload, header, license and independent input/build receipt remain in the remote artifact. Rebuilding the ABI probe after the Host freeze cannot replace the packaged Host; complete package/executable hashes are checked again afterward.

The Actions acceptance uses a local Responses SSE provider and real builtin exec_command processes with Unix-socket barriers. It observes actual A/B handler entry, the original Core gate's pending/admitted states, real tool results and thread/turn/call identities. Empty and removed sets must allow B before A releases; the restrictive Mod must keep B waiting until A finishes. No elapsed-time overlap estimate substitutes for those barriers.

Additional child processes cover pre-load constructor rejection, short tables and version/length/status errors, independent allocator release, catchable panic, actual abort/segfault, cancellation, held callback drain and an explicitly classified stuck callback kill. A focused integration test loads the sealed original after both path replacement and in-place modification. Separate logs retain the original failed process outcomes. All five P02 regression reports are written only after every required assertion succeeds.

The shared composition include is checked with rustfmt --edition 2024 --check during helper preparation before Host compilation; author builds require that successful recorded phase. ci/scripts/runtime_composition.py runs those current-source P01/P02 regressions, then freezes/reuses the same H and independently builds composition A/B plus fixed invalid binaries. Each author has a separate workspace, committed lock and initially empty target; all depend only on cm-abi. No combination rebuilds H or any Mod. Set/per-object exact limits and limit+1 cases, canonical plan permutations, separate graphs, staged input drift, exclusive conflicts, actual registration errors, Next/error/cancellation behavior, failed init/release cleanup and mixed v1/v2 are exercised by Actions.

The P03 business matrix reuses the same SSE provider, builtin exec_command and Unix socket A/B barriers, including actual Core write-gate Pending, outputs and real thread/turn/call IDs. Successful selection cases run under a real exec/network observer and reject compiler/linker/JIT calls and undeclared service connections. Signal-cancellation regressions keep direct child delivery. Probe-only plan/ABI cases are identified separately from real Core business. A stuck synchronous callback is recorded as a killed process failure. This observation is not the P04 toolchain-free isolated consumer gate.

The controlled Core fixture disables unrelated upstream plugins/apps and analytics and inherits only explicit runtime environment keys. The observer tracks fixture connections and kernel-returned Unix socketpair identities, including the exact upstream process-setup re-exec. It joins split syscalls by thread ID and redacts socket payloads before evidence export; descriptors, targets, byte counts and results remain. Literal observer checks run before Host compilation; actual runtime traces remain required.

Six separate P03 reports preserve common source/workflow/runner/Host/mod provenance with disjoint-key assertions; the root acceptance records only CM-P03-AC01 through AC06. Raw child results are written before assertions, and a finally path retains bounded UTF-8/NUL-free logs/JSON without profiles, packages or caches.

## P04 output limit and compiler-free consumer candidate

crates/cm-abi/include/cm_mod_v21.h and cm-abi::v21 add ABI 2.1 without changing the v1.0/v2.0 layouts or entry signature. Size, version, alignment, count and stride are checked before optional tail access. The new limiter has a separate typed input/output and resource, core.exec_output_limit.v1. A format 2 / ABI 2.1 manifest declares kind="output_limit", capability/resource="core.exec_output_limit.v1", zero priority and no ordering edges; limiter IDs determine stable order. Required capabilities must include every declared contribution capability. Existing eligibility descriptors and synchronous Next rules retain their 2.0 semantics.

The actual ExecCommandHandler resolves the original max_output_tokens after parsing arguments and invokes the synchronous policy before process allocation. KEEP requires limit=0 and retains the original Option, including absent/default and Some(0). LIMIT must be positive and no larger than the original resolved limit; multiple limits compose by minimum. Invalid output/error buffers, unknown statuses, canaries, unobserved cancellation and Next misuse are fatal and attributed to their owner/resource. Observed cancellation stops later callbacks and command admission. Core keeps its existing approval, sandbox, timeout, execution, model-policy minimum and truncation formatting. write_stdin, other tools and a global output budget are outside this seam.

fixtures/runtime-consumer/acceptance.sh invokes runtime_consumer.py produce in the existing producer. It first runs all current-source P01/P02/P03 regressions on the newly built H. H and its package are frozen before the independent serial-eligibility A and output-limit B author builds. B depends only on cm-abi and uses an initially empty target for each prebuilt positive/negative payload. C/Rust layout checks, zero/equal/invalid bounds and a two-limiter minimum case accompany the ABI. No consumer selection builds or links a Mod.

The producer hands off runtime inputs in a tar with an exact mode/content manifest. The trusted worker validates the same-run artifact ID/digest and archive paths/links before extraction. Its separate runtime-consumer job has actual cache-mode:none, no CM source checkout, Rust setup or cache actions. Preparation copies only runtime components, OS Python standard library, declared drivers and recursively resolved ELF interpreter/DT_NEEDED libraries into a canonical rootfs inventory with hashes, modes and OS package versions. Unknown RPATH/RUNPATH, source/build materials, compiler/manager executables and escaping links fail. The outer producer/consumer launcher and observer stay outside that root.

Consumption uses strict user/mount/PID/IPC/UTS/network namespaces, no capabilities, a cleared environment, closed nonstandard FDs, read-only runtime inputs and only profile/work/evidence/tmp writes. Actual namespace, mount, route, interface, process-root and FD snapshots plus internal-provider and external TCP/DNS canaries are required. The original sandbox stays enabled; real commands must execute the packaged nested bwrap and rg. Namespace, helper or library failure is terminal; there is no host-root bind or build fallback.

The same profile/raw H/A/B pool runs empty, A, B, A+B, remove A and disable B in fresh processes. The real provider must receive the expected full or truncated controlled command output, with actual command-completion sentinels, Core gate barriers and matching call/thread/turn identities. Each invalid startup/callback/helper/package/library candidate retains its real rc/trace and is followed by a known successful selection. Startup rejection has no Ready; callback rejection truthfully retains earlier Ready/commit. A separately initialized official install/profile stays read-only and receives directly comparable before/after inventories.

An observer outside the runtime boundary traces actual exec, file/library mappings and network calls. Unknown executables/peers and unclassified executable-memory generation fail; this is qualification of fixed audited native fixtures, not generic malicious-native JIT detection. Both sendto and recvfrom payloads are redacted, including resumed syscalls and failure exports. Observer, input-manifest, archive and receipt positive/negative self-checks precede Host compilation; they do not substitute for the actual consumer matrix.

Only a successful actual runtime-consumer job can produce P04 acceptance. Its six reports bind producer/consumer source/workflow/run/attempt/request, frozen Host, input/rootfs digests and actual audit. The worker receipt also binds both job IDs, input/output artifact IDs and upload digests. The source dispatcher independently checks those exact jobs/artifacts; skipped or producer-only success cannot pass P04. Product/rootfs/cache artifacts remain remote, with only bounded UTF-8/NUL-free metadata and logs collected locally after authorization.

## Independent dispatch and cache authority

ci/worker-files.json maps six infrastructure inputs to the builder. Both worker workflows, both policy/record scripts and the cache-authority JavaScript action deploy together at an exact reviewed builder commit. The action reads the runner-injected effective cache mode, checks it against the expected none/read/write authority, and exposes only that validated enum to later shell steps. The producer additionally verifies its exact source checkout; preflight and consumer require actual none before proceeding. The worker fixes its source/builder identities in reviewed YAML and temporarily checks out the requested exact public CM SHA. No repository variables or copied gh credentials are needed for an operator dispatch.

.github/cm-ci.json maps fixtures/runtime-consumer/acceptance.sh through the existing acceptance entry. P04 changes five of the six mapped worker files: both workflow templates, worker_policy.py/record_run.py and the cache-authority JavaScript. Its action.yml metadata remains unchanged. .github/cm-build-routing.json remains configured=false: automatic/source fanout is still disabled and CM_BUILD_FANOUT_TOKEN is not configured. Direct operator dispatch is distinct from validating fanout.

Only the verified source default-branch HEAD and trusted worker revision may write builder-owned producer caches. Other reviewed source SHAs get platform-enforced cache-mode read. Preflight, source checks, receipts and the independent runtime consumer use none. Cargo downloads and sccache snapshots remain separate; compiler/target/config/native-qualified keys never cross platforms or repositories. RUSTC_WRAPPER=sccache, CARGO_INCREMENTAL=0 and SCCACHE_GHA_ENABLED=false remain required in the producer; target/ is not cached.

Worker logs retain sccache statistics, restore/save observations and final acceptance JSON separately from the binary payload. Product receipts bind source/workflow repositories and SHAs, target, run/attempt/job, Host/package/helper/Mod hashes and final GitHub upload digest. Cache hits do not replace validation. Artifacts and caches remain remote; developer machines only collect lightweight evidence.

## Verification boundary

P04 remains not_run until the exact published source/worker revisions complete current-source P01/P02/P03 regressions, all six consumer checks and evidence review. Failed/partial runs cannot accept a newer source revision. A package or loader pass cannot establish whole-product or release readiness. No local build, test, lint or simulated CI is permitted. Publication and dispatch follow the current explicit session authorization; credentials and product Releases require separate concrete authorization.
