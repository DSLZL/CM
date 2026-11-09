# CM native build CI

CM source is DSLZL/CM. Each native target owns a separate builder repository and its caches. All compilation, checks, tests, smoke runs and experiments execute on the matching GitHub-hosted worker. Local work edits and reviews source/configuration and lightweight evidence. The established product mapping remains CM-S03 on GNU Linux x64; additional targets require their own native implementation and qualification. Historical acceptance retains its exact original source, worker and run identities. The first-party provenance boundaries are described in [distribution.md](../docs/distribution.md). Signing a candidate does not accept it. Python case or report fixes retain compatible production artifacts and successful case checkpoints; every run still verifies current proof inputs and API authority.

## Native platform routing

[cm-platforms.json](../.github/cm-platforms.json) is the closed six-target registry. `enabled` controls infrastructure dispatch, independently of product qualification. A reviewed native recipe may be enabled for qualification runs; product support requires its separate native acceptance. Unimplemented targets stay disabled.

| Platform | Independent repository | Native runner | Rust target | Routing |
| --- | --- | --- | --- | --- |
| Linux x64 | DSLZL/CM-build-linux-x64 | ubuntu-24.04 | x86_64-unknown-linux-gnu | Existing entry |
| Linux arm64 | DSLZL/CM-build-linux-arm64 | ubuntu-24.04-arm | aarch64-unknown-linux-gnu | Qualification candidate; support pending |
| macOS arm64 | DSLZL/CM-build-macos-arm64 | macos-26 | aarch64-apple-darwin | Disabled |
| macOS x64 | DSLZL/CM-build-macos-x64 | macos-26-intel | x86_64-apple-darwin | Disabled |
| Windows x64 | DSLZL/CM-build-windows-x64 | windows-2025 | x86_64-pc-windows-msvc | Disabled |
| Windows arm64 | DSLZL/CM-build-windows-arm64 | windows-11-arm | aarch64-pc-windows-msvc | Disabled |

The existing `cm-linux-x64.yml` dispatcher filename is retained for callers and exposes a platform choice. Unknown or disabled entries fail before any remote mutation. Its master `cm-build-routing.json` switch remains disabled until fanout and credentials are explicitly configured. A worker must match its exact repository, runner OS/architecture, native process architecture and Rust target. Source checks remain on hosted Linux x64; selecting another platform never moves product work into the source repository. Declaring a repository here does not create it or claim a successful native build.

Repository/runner-label/enablement metadata is administrative. The current compiler target remains an explicit product input; changing another platform's routing does not discard a compatible Linux Host or case checkpoint. Native/compiler/runtime identities continue to govern reuse.

## Publication inputs

ci/source-files.txt lists the exact reviewed public source inputs. Existing .gitignore rules remain unchanged. Assistant settings, task packs, reports, specs and journals stay local; do not force-add or copy them into public directories. The journal-only .gitattributes is outside this payload.

The source workflow checks tracked paths against .gitignore, payload/worker mappings, CI Python compilation, reuse/recovery boundaries, unconfigured rejection and the pinned upstream/release baseline. It does not execute product acceptance or read ignored developer materials. Each validation binds its exact source and independent worker run; reused production and test results retain their original execution identities.

## Host producer and identity

adapters/codex-e4568a3/source.json pins the original upstream commit/tree, original input hashes and separate official release reference. The worker preserves the complete pristine Git snapshot and original lock, creates a separate Host worktree, applies the nine registered patches and copies only the explicit overlay paths. This includes the native runtime/ABI crates, CLI startup, the actual Core gate, terminal exec cleanup, managed launcher/TUI integration, main sampling admission and their manifest/lock edges. The existing app-server Clippy cleanup remains explicit. The complete source delta, original/final locks and their hashes are recorded separately from pristine S0. No full upstream development tree is published in CM or bundled with the Host.

The builder runs host.py prepare before loading real Cargo mappings, then installs Rust 1.95.0 and native dependencies. host.py native reuses the pinned upstream V8 resolver and records verified V8 bytes, actual Rust binaries, native tools/packages/files. Generated native identity files are required during cache identification, after materialization; they are not publication inputs. Cargo runs from its manifest directory so workspace .cargo configuration is discovered.

The ephemeral runner uses the pinned upstream CI user-namespace setup (unprivileged_userns_clone=1 and apparmor_restrict_unprivileged_userns=0). The worker first builds/checks bwrap in a fresh helper unit, runs a real namespace smoke check before Host compilation, records kernel/sysctl observations separately, and supplies its actual digest through upstream CODEX_BWRAP_SHA256. This does not qualify compatibility with stock AppArmor restrictions. host.py seal refuses existing Host target artifacts and canonicalizes full source/overlay, final lock, actual tools/native/V8, target, profiles, features and flags. Relative paths and file bytes/modes enter the identity; traversal order, mtime and temporary roots do not. User Mod selections and compiled Mod payloads are absent. Host inputs, including the compiled helper digest, are sealed before Host compilation and embedded through CM_HOST_IDENTITY_JSON; codex cm-host-identity reads the compiled-in JSON. host_release_id, host_api_version, protocol_contract_id and host_build_id have separate roles. Final artifact_sha256 is recorded externally after packaging, avoiding self-reference.

The worker runs producer rejection tests, fmt, clippy with warnings denied, actual package tests and locked Host/helper builds. An exact product-input Host cache hit reuses its original successful Host Cargo checks with explicit producer provenance; current formatting, helper checks and acceptance still run. Acceptance reuses the fixed upstream package builder with the verified CLI, code-mode host and bwrap, and its verified ripgrep resource. The package includes identity, original license notices, a resolved dependency/license inventory and cm-runtime-files.json. The latter binds required component paths, executable modes, hashes and resolved system-library paths; normal packaged business startup checks it before native entry. The unpackaged Cargo CLI inode and its integration-test hard links use the development entry. Upstream's 0.0.0 development-package copies also require exact development metadata and a full CLI digest equal to the original compile-time build artifact. Formal 0.3.0-p04 packages always require their CM inventory. No runtime environment switch enables this entry, and the isolated P04 runtime has no build path. The consumer separately inventories the actual ELF/library closure and rejects a missing package inventory. Complete license-compliance certification remains later work.

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

The same profile/raw H/A/B pool runs empty, A, B, A+B, remove A and disable B in fresh processes. The real provider must receive the expected full or truncated controlled command output, with actual command-completion sentinels, Core gate barriers and matching call/thread/turn identities. Each invalid startup/callback/helper/package/library candidate retains its real rc/trace and is followed by a known successful selection. Startup rejection has no Ready; callback rejection truthfully retains earlier Ready/commit. A separately initialized official install/profile stays read-only and receives directly comparable before/after inventories. Before freezing the copied fixture, only startup aliases targeting the exact original official binary are relocated to the identical copied binary through internal relative links; original/prepared profile inventories and the relocation map are retained. The producer validates the completed handoff archive with the same strict member/link policy as the consumer.

An observer outside the runtime boundary traces actual exec, file/library mappings and network calls. Unknown executables/peers and unclassified executable-memory generation fail; this is qualification of fixed audited native fixtures, not generic malicious-native JIT detection. Both sendto and recvfrom payloads are redacted, including resumed syscalls and failure exports. Observer, input-manifest, archive and receipt positive/negative self-checks precede Host compilation; they do not substitute for the actual consumer matrix.

Only a successful actual runtime-consumer job can produce P04 acceptance. Its six reports bind producer/consumer source/workflow/run/attempt/request, frozen Host, input/rootfs digests and actual audit. The worker receipt also binds both job IDs, input/output artifact IDs and upload digests. The source dispatcher independently checks those exact jobs/artifacts; skipped or producer-only success cannot pass P04. Product/rootfs/cache artifacts remain remote, with only bounded UTF-8/NUL-free metadata and logs collected locally after authorization.

## Independent dispatch and cache authority

ci/worker-files.json maps the 20 current infrastructure inputs to the existing Linux x64 builder. Workflows, policy/record/retry scripts, platform configuration/module, the runtime-case registry and both cache actions deploy together at an exact reviewed builder commit. Additional targets obtain their own reviewed deployment mapping when their recipes are implemented. The action reads the runner-injected effective cache mode, checks it against the expected none/read/write authority, and exposes only that validated enum to later shell steps. The producer additionally verifies its exact source checkout; preflight and consumer require actual none before proceeding. The worker fixes its source/builder identities in reviewed YAML and temporarily checks out the requested exact public CM SHA. No repository variables or copied gh credentials are needed for an operator dispatch.

.github/cm-ci.json maps fixtures/runtime-consumer/acceptance.sh through the existing acceptance entry. P04 changes five of the six mapped worker files: both workflow templates, worker_policy.py/record_run.py and the cache-authority JavaScript. Its action.yml metadata remains unchanged. .github/cm-build-routing.json remains configured=false: automatic/source fanout is still disabled and CM_BUILD_FANOUT_TOKEN is not configured. Direct operator dispatch is distinct from validating fanout.

Only the verified source default-branch HEAD and trusted worker revision may write builder-owned producer caches. Other reviewed source SHAs get platform-enforced cache-mode read. Preflight, source checks, receipts and the independent runtime consumer use none. Cargo downloads, sccache snapshots and verified Host binaries remain separate; keys never cross platforms or repositories. RUSTC_WRAPPER=sccache, CARGO_INCREMENTAL=0 and SCCACHE_GHA_ENABLED=false remain required in the producer; target/ is not cached.

### Repository cache budget

The owner-approved cap is **10,000,000,000 bytes per repository**, shared by Cargo downloads, sccache, Host/linked targets, benchmark seeds and every other Actions cache namespace. Six repositories do not share one 10 GB pool. Existing caches can be restored when a new save is skipped. Artifact storage/retention is separate and does not gain a paid allowance from this policy.

Every authorized ordinary and benchmark save uses the worker-owned `cache-save` action after the original eligibility checks. Immediately before an upload it revalidates exact source/write authority, inventories only explicit runner-temporary candidate paths, and reserves a conservative tar/PAX plus gzip/zstd size allowance. It checks both live aggregate usage and the full paginated cache inventory, including unrelated cache keys. Same-job reservations remain charged after an upload failure, preventing stale usage from authorizing several individually affordable saves whose combined size exceeds the cap. Unknown capacity, an invalid inventory or insufficient headroom skips that save and retains `cache-save-plan-*.json`; it never deletes caches or expands billing.

Normal cache writers, the cold benchmark seed writer and the trust-write probe share one repository concurrency group, while read/none work uses independent groups. The trust-read negative probe intentionally calls the real save action under runner-enforced read authority to verify denial; it never receives write authority. `queue: max` retains up to 100 pending writers under the [Actions concurrency policy](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency). Every cache-writing workflow must use this group and the same save action. This is an admission policy for the reviewed workflows; no repository billing setting is changed. A budget denial can mean an unchanged future build must restore an older compatible snapshot or rebuild after a genuine miss.

### Compiler cache and unchanged Host reuse

The sccache compatibility prefix covers the actual compiler/native tool and library identities, target, profiles, features, flags and Cargo configuration. Runner image release numbers are recorded as provenance, without invalidating compatible compiler entries. The exact legacy prefix for the current complete identity is a migration fallback; there is no broader compiler or platform fallback. Ordinary CM source files no longer invalidate that entire namespace: sccache itself hashes compilation inputs. Immutable snapshot keys still include the source SHA, with a compatible fallback restore. An archive `cache-hit=false` can therefore mean a successful fallback restore; internal compiler hits/misses are reported separately. The local working set is 8 GiB, increased from the saturated 2 GiB snapshot. sccache-restored.json, sccache-after-helper.json, sccache-after-host.json and final statistics expose capacity and per-stage counter changes without logging compiler environments.

Host identity separates product inputs from the full publication/validation manifest. It still covers the complete transformed upstream source, final lock, adapter pin/patches/compiled overlays, Rust/native/V8 identities, helper bytes, Cargo configuration, flags, profiles and units. host-cm-inputs.json continues to record every public input; host-product-inputs.json records the subset used by the embedded identity. Editing an external test driver, workflow or README alone does not change the Host binary identity. The exact new validation source/worker SHAs remain in each fresh report.

After sealing those inputs and running identity/cache rejection tests, the producer restores only the exact Host-build/check-command key, with no fallback. The snapshot contains codex, codex-code-mode-host, their file hashes/modes, original fmt/Clippy/test/build logs and original source/workflow/run/attempt/job. Before reuse it checks the complete identity, expected file set, every digest, successful checks against the current expected Cargo commands, producer repositories and the executable's real embedded identity. Unexpected, damaged or incompatible entries fail; they are not silently treated as valid old targets. Only two verified binaries enter the otherwise fresh Host output directory. Cargo fingerprints, incremental state and arbitrary target files are not restored.

An accepted hit skips the unchanged Host Cargo compilation/checks and records them under reused-host-build, retaining their original producer rather than relabeling old logs as newly executed. host-baseline-build.json.compilation distinguishes built/reused origins from validation_source_sha. Current formatting, helper/identity checks, packaging, representative Core tests, independent author builds and actual producer/consumer acceptance still execute. A miss follows the normal complete build. A new Host snapshot requires successful Host quality checks and its own producer baseline, with the exact current origin, package manifest and both binary hashes rechecked. The trusted write producer may retain that validated snapshot after an unrelated later acceptance failure; missing or changed baseline evidence rejects saving. A cached build does not make the failed run accepted.

Each of the seven acceptance compilation/check recipes has an independent v2 cache and receipt. Its key binds the sealed Host identity, its own Cargo command/profile/target paths and protocol; only the Core or TUI private probe also binds its corresponding instrumented source. Every restored file/mode/digest and original producer/check is verified. Verified legacy v1 snapshots can seed matching target receipts. Each completed target can be saved after a later target or runtime failure; an incomplete target cannot. External Python case edits do not invalidate compilation inputs. Cargo fingerprints and arbitrary target directories are absent; compiler object hits alone do not skip linking.

### Reuse frozen products and resume passed runtime steps

Before toolchain installation, the worker searches recent runs for a successful producer with identical production source inputs, compiler commands/environment and runner image. Its consumer may have failed. A match directly references the original product and runtime-input artifact IDs/digests: toolchain installation, Cargo/cache setup, author fixture builds, packaging and both large uploads are skipped. Only current runtime Python tests and validation provenance are uploaded as a small overlay. Original producer metadata remains unchanged. Expired artifacts, changed production inputs or a changed runner image require a new producer; service lookup failures stop the run instead of silently rebuilding.

Only the eight explicitly registered private Rust probe sources are separate from production inputs. A Core/TUI probe change restores the original frozen inputs on the hosted builder, prepares pinned source/toolchain, builds only the required target and uploads a separate test-build artifact. Host/Mod bytes and the two large base artifacts keep their original IDs/digests. The consumer verifies the successful test-build job, immutable artifact, source inputs, binary receipt and exact allowlist before installing probe bytes and proof metadata. It never replaces Host/Mod paths. Original producer.json remains intact; effective runtime metadata and the current validation/receipt retain distinct production and test-build origins. Rust fixtures that produce real Mod payloads remain production inputs.

The consumer retains cache-mode:none. It replaces only allowlisted test files/probes, inventories the updated input, constructs the strict rootfs and reruns isolation probes. The registry in runtime_cases.py defines independent P04/M01–M05 cases and stateful transaction groups; existing G02A/review/G03 cases and the two library checks retain separate checkpoints. Each executed case needs a successful command, its own outer execution/network audit, unchanged read-only inputs and an untouched external canary. Passed checkpoints survive another case failing; failed or unaudited cases cannot be reused.

Checkpoint v2 searches a bounded history independently of the selected product producer, including runs whose consumer failed or was cancelled. A newer run without that checkpoint cannot hide an earlier compatible pass, and one result may cite several original runs. Keys bind the exact runner image/system runtime, normalized command, declared native/data inputs and the bounded Python dependency closure across controlled imports, constants, helpers and class methods. Explicit ci_progress calls do not affect business dependencies; protocol print output does. Unknown dynamic lookups conservatively include controlled modules and record a reason. Shared helper edits invalidate their users. The current full rootfs inventory, isolation/canary checks and report aggregation always run. Old combined matrices cannot become partial v2 passes; new cases need an initial checkpoint fill.

Live logs print producer hits, target cache decisions, `CM runtime reuse: <case> origin run <id>` and execution reasons/dependency changes. retry-plan.json and runtime-step-results.json retain case decisions, original run/attempt/source/workflow, artifact refs and executed/reused counts. Reports merge only validated text fragments; profiles, processes, sockets and barriers are reconstructed per transaction. Receipts bind original product/input artifacts separately from current test builds, validation and consumer evidence. Failed or partial workflows never accept the product.

The independent consumer prints stage/case starts, completion/failure and elapsed seconds immediately, with a 30-second heartbeat while a subprocess is running. Detailed product output remains in sanitized evidence files; only structured progress reaches the live Actions log. consumer-phase-results.jsonl records outer phase durations and return codes. The final observer verifies each distinct executed Host path once after all product processes exit, preserving exact digest checks for canonical, copied and intentionally mutated executables.

Cases use up to three concurrent slots with separate profile/work/evidence paths and private namespaces, sharing only immutable inputs. Library removal/recovery precedes the M03/M04 groups. Each executed case has separate traces and an outer audit before checkpoint publication. An unrelated failure does not suppress other cases. Same-profile lifecycle, update/rollback and restart transactions stay atomic; negative candidates reconstruct a known successful selection. Hosted source checks cover dependency isolation, partial target success, multiple checkpoint origins, missing/expired indexes, tampering and probe overlay rejection. They do not replace actual cold/warm, Rust-probe and Python-failure Actions qualification.

P04 reuses input digests within one matrix process only after confirming `/inputs` is mounted read-only. Every inventory still checks current paths, links and file metadata; the digest key includes device/inode, mode, size, mtime and ctime, and escaping links are excluded. Writable profiles/work trees continue to hash each time. The outer consumer independently hashes the complete rootfs again before accepting results. The P04 report records computed/reused counts and bytes avoided; mutation-with-restored-mtime, alias, writable-path and writable-mount rejection checks run before compilation.

Worker logs retain sccache statistics, restore/save observations and final acceptance JSON separately from the binary payload. Product receipts bind source/workflow repositories and SHAs, target, run/attempt/job, Host/package/helper/Mod hashes and final GitHub upload digest. Cache hits do not replace validation. Artifacts and caches remain remote; developer machines only collect lightweight evidence.

## Verification boundary

CM-M05 remains not_run until the exact published source/worker revisions complete qualification, the actual independent Mod-only update and all six consumer checks with evidence review. Failed/partial runs cannot accept a newer source revision. A package or loader pass cannot establish whole-product or release readiness. No local build, test, lint or simulated CI is permitted. Publication and dispatch follow the current explicit session authorization; credentials and product Releases require separate concrete authorization.

## CM-M01 regression acceptance

The CM-M01 regression uses fixtures/mods/binary-manifest-cases/acceptance.sh and ci/scripts/mod_manifest.py. The producer retains current P01/P02/P03 reports, freezes H, independently builds the configuration-aware author variant, then publishes binary format 3 package inputs and an external archive receipt. Source/build.rs attachments are exercised only in the producer metadata audit, outside the strict consumer handoff.

The cache-none consumer first runs the complete P04 matrix, missing-library rejection and recovery. It then runs the actual packaged CLI metadata/configuration/lock matrix under the same outer observer. Root acceptance has the six CM-M01 IDs; p04-baseline-acceptance.json is a separate current-source regression. P04 reports are not relabeled as M01. Worker policy explicitly requires the consumer for both CM-P04 and CM-M01; the exact producer input, consumer upload and successful jobs remain bound in the existing receipt.

Public contracts and usage are in docs/mod-manifest.md and schemas/. Product changes enter the Host overlay/identity; the standalone M01 driver, fixtures, docs and public descriptive schemas do not. A product change needs a new H; later driver-only corrections can reuse the verified exact Host cache. No M01 check is accepted before the published dual revisions run and their reports, raw observations and API receipts are reviewed. The current candidate has not been tested locally; all product gates execute in the independent Linux x64 Actions repository.

## CM-M03 managed-package regression

Public commands, retention rules and runtime limits are in [docs/managed-package.md](../docs/managed-package.md). `managed.patch` follows the existing four patches and adds the actual TUI backend boundary; the manager reuses the existing runtime/configuration/package resolver and sealed native loader. The previously accepted M03 Host API was 0.5.0; M04 below uses 0.6.0 and has its own qualified Host input identity.

`fixtures/managed-package/acceptance.sh` uses the existing producer and isolated consumer. `managed_package.py` prepares two SDK packages and a constructor sentinel only in the author phase, and binds precise transaction/ELF unit results to the successful Host-test log. Exact consumer/observer self-check text runs before Host compilation. No author compiler or Mod build source enters the consumer; the inert post-install sentinel is a test attachment. Necessary fixture scripts remain distinct from product source.

The compiler-free consumer first runs P04, M01 and M02 matrices with separate baseline acceptance roots, then the public manager matrix. It exercises ZIP/directory/explicit installs, idempotence, two writers, faults/interruption and recovery, dependency rejection, retained data and live generations. A writable official profile and the read-only official installation are inventoried around actual management/launch commands. Unicode Host/home paths, argument boundaries, direct/launch exit statuses and same-PID signal delivery are observed. The empty-argv PTY test drives the actual Embedded InProcess TUI, controlled provider, native tool/context, builtin execution and normal drain; a reachable implicit daemon socket must receive no connection. Remote/executor overrides and missing helpers fail before native entry. Static ELF/version/CPU negatives and actual missing-library recovery retain their original observations.

The root acceptance maps only the six original M03 report names. All prior report files, actual observer trace, frozen H/artifact identities and original successful Host/cache provenance remain separate. The outer observer hashes every Host execution under the declared input/work/profile roots against frozen H. Only the canonical and fixed Unicode-copy Host paths can bind executed sandbox aliases/helpers; decoded UTF-8 trace paths, aliases and bwrap FD identities have positive/negative self-checks. M03's accepted results are recorded in its section above; current M04 checks and their exact Actions/receipt evidence are recorded below. Driver-only fixes after freezing H may reuse that exact H and original checks; the full S04 performance matrix and release readiness remain outside this result.

## CM-M04 file-state acceptance

Public ownership, limits, compatibility and commands are in [docs/file-state.md](../docs/file-state.md). The current source adds generation v2, `state.files.v1`, process-lifetime shared leases, explicit expected-object replacement, complete offline checkpoints, current-config rollback and retryable owner cleanup. Host source/API/overlay changes require one newly qualified H. Later changes confined to drivers or author fixtures reuse the exact qualified Host and linked acceptance checks; current runtime acceptance still executes.

`runtime_state.prepare` independently builds v1, compatible-v1 and incompatible-v2 SDK Mod binaries, preserving their source/environment/dependency/payload identities and the frozen production H. Precise state/profile test results are bound to the successful Host-test log and identified as a different test binary. The consumer receives only precompiled payloads and necessary Python fixtures. P04/M01/M02 run concurrently; after joining and missing-library recovery, M03 runs before M04. Every nonzero phase propagates failure. Per-case logging and the existing 30-second heartbeat remain active.

The M04 root has only `restart-disable-remove.json`, `empty-set-restart.json`, `mod-state-retention.json`, `precompiled-state-rollback.json`, `migration-interruption.json` and `runtime-dependency-ownership.json`. P01–M03 results retain separate acceptance roots. Each actual PTY MCP listener is independently bound to its Host PID/socket and observed accept, rather than granting an unobserved loopback port. Final immutable-input and credential-redaction audits, source/worker/run/attempt/request identities, successful producer/consumer jobs and upload digests remain required. All six M04 gates passed on source [`41c5fde`](https://github.com/DSLZL/CM/commit/41c5fde583d85fafe13ecbad4895cf03cece1dbb) / worker [`4520956`](https://github.com/DSLZL/CM-build-linux-x64/commit/45209569ce74096f9155588a7710ddb89238182d): [qualification 40807296438/1](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40807296438) and [independent unchanged-input reuse 40812023657/1](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40812023657). The reviewed originals, receipt-named report copies and final job/API conclusions agree. Both rounds reuse identical H bytes and the original successful Host/linked build evidence while current runtime checks rerun; the reuse producer recorded 153 sccache hits, zero misses and zero compilations, with all five linked recipes reused in 0.514 seconds. Author fixture builds remain separately reported. The consumer exposes stage/case progress, elapsed time and 30-second running heartbeats. These controlled Linux x64 results leave full upstream Core/TUI, S04, other platforms and release gates pending.


## CM-M05 author and zero-build user candidate

[The author guide](../docs/mod-author-guide.md), [user guide](../docs/mod-user-guide.md)
and `templates/native-mod` describe the fixed reviewed source path. The template
is an independent cdylib workspace pinned to SDK source `d3abb2b`; its lock includes
only cm-native-mod, cm-sdk and cm-abi. Cargo format/Clippy/test/build and packaging
run on the independent worker. Editor configuration disables the named automatic
build paths; it cannot police unrelated installed extensions.

`cm-mod-author.yml` is a trusted CM dispatcher; the template carries an identical
reference workflow. Existing routing remains disabled. Missing routing/token or an
unavailable CI blocks with no local build fallback. Source CI runs the dispatcher
negative cases with a mocked transport; those cases are not a successful fanout.
No credentials or repository settings are changed by M05.

Worker `build_kind=qualification` follows the existing Host/linked acceptance cache
contract, then builds all required regressions and M05 author variants after H is
frozen. `build_kind=mod-only` requires the exact successful M05 qualification origin:
run/attempt, source/workflow revisions, request, and input/consumer/receipt artifact
IDs and SHA-256 digests. Trusted worker policy checks actual API status/jobs/ancestry,
expiry, all six qualified reports and downloaded artifact bytes before current CM
source handles those inputs. Current Host production inputs must still match H.
Only the current target Mod and its pinned SDK/ABI dependencies compile in an empty
author target. Strace records actual compiler/linker descendants; unexpected crates,
helper build tools, native source or linker outputs outside that target fail closed.
No Host, helper, private Core or other fixture build step runs on this path.
On test-only retries, Mod-only also reuses the successful producer's artifacts and
skips author compilation, toolchain setup and both product/input uploads. Reuse
requires the same build kind and exact qualification origin in addition to product
inputs and runner image; Mod-only artifacts cannot satisfy a qualification request.

The Mod-only handoff preserves original v1/error/baseline inputs and their original
source; only the current v2 package, runtime drivers and provenance change. The
compiler-free cache-none consumer executes current M05 install, real native tool
outputs, explicit replacement, restart/disable/enable/remove, state/other-Mod/H
retention, metadata sentinel/redaction and diagnostic cases, plus actual runtime
library removal/recovery. Qualification additionally runs current P01–M04 regressions.
The six root reports have M05 IDs; earlier acceptance roots keep their own IDs.
Per-case starts, completion/failure and 30-second heartbeat remain active.

Metadata schema 2 exposes a redacted noncanonical `plan_projection`; canonical
RuntimePlan/lock bytes and hashes stay internal to their existing integrity flow.
Public errors keep bounded attribution and typed native ABI status while omitting
untrusted free text. Static success remains unqualified.

Observed Linux x64 results: [qualification](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40897458239)
passed all eight runtime stages. A [test-only replay](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40902527878)
reused seven stages and executed the changed missing-library test; strict consume
dropped from 1655 to 21 seconds. [Independent Mod-only](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40904210846)
compiled only the Mod and pinned SDK/ABI crates, preserving H. Its [unchanged replay](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40905730144)
on source `dd4890a` / worker `d353841` reused all three stages: producer 18 seconds,
strict consume 13 seconds, no compilation or large artifact uploads. Each run keeps
original build/execution origins separate from current validation. These scoped
Linux x64 observations do not establish full program or release readiness.

## G02A candidate

The [turn budget](../docs/turn-budget.md) adds a general Host admission seam and an
independent `examples/mods/turn-budget` author workspace. Host API 0.7.0 advertises
`core.turn_sampling_budget.v1`; ABI 2.2 layouts stay unchanged. One new H is required
for the new framework seam. It is frozen before the separate A author target starts;
install, restart, disable and remove compile neither artifact.

The six `g02a-*` stages run distinct driver commands and own distinct evidence and
root reports. Each uses the existing successful-stage checkpoint and outer audit.
A case-only Python edit invalidates its reachable AST dependencies, preserving
unaffected passes. Shared helpers, runtime inputs, commands or audit changes
invalidate their consumers. Producer reuse keeps the original artifact IDs/digests
and skips compilation and large uploads; current input/isolation checks, validation
overlay, logs and receipt still run. Necessary input/AST self-checks run before the
expensive toolchain/build steps and also on a producer hit. Existing observer smoke
checks retain their helper dependency and run before H compilation.

Counting, real pending-input/Stop continuation, failed terminal/history, scope,
provider/native cancellation, process resume/fork and managed installation use
packaged H. Internal model/step and scope branches are separately labelled private
Core probes, included in M02's existing test executable with no second compilation.
The strict consumer also runs an actual M05 API 0.6.0 Host from a pinned successful
qualification receipt/input artifact, only for pre-native installation rejection.
Its exact path, bytes and metadata-only command are bound by the outer audit.
Missing/expired reference artifacts block explicitly. P01–M05 regressions retain
their own reports; only the six G02A reports form this task's acceptance root.

No G02A source CI, Cargo check, runtime case or cold/warm qualification has executed
for this candidate. A workflow success must still be checked against every report,
actual jobs, source/workflow revisions and original build/execution provenance.

## G03 candidate

The mapped G03 candidate adds seven `concurrency-*` checkpoints to the existing twenty stages. Each owns its reports and AST dependencies. Python case fixes reuse the unchanged producer bundle, Host and acceptance executables; they do not rebuild or upload H. Core and TUI probes reuse the already compiled M02/review executables and retain separate identities from production H.

The cold worker regenerates protocol TypeScript/JSON, compressed exports and the config schema with the pinned upstream generators before sealing Host sources. It records the exact changed schema paths and final source manifest, runs protocol contract checks, and never generates assets locally. The strict observer binds normal Code Mode executable memory to the sealed helper hash, translated PID lineage, actual Host transport and nested cell events. It retains the raw counts and fails unclassified mappings; normal business V8 execution is distinct from forbidden Mod compilation/JIT. G03 runtime acceptance and cold/warm/single-case reuse proof remain NOT_RUN for this candidate.


## G06 candidate

The mapped CM-G06 candidate adds 59 explicit `g06-*` transactions and the seven original SDK reports. Production H keeps its own sealed product inputs. The two author workspaces each build v1, v2 and replacement payloads in separate targets, depending only on cm-sdk/cm-abi; the C ABI probe has a seventh target. Author cache keys include their own Rust/manifest/lock inputs, ABI/SDK source, reachable builder/Cargo-recipe code, recipe and compiler identity, without the Host build identity. Existing ordinary 2.2 author templates remain pinned.

The private continuation and stream probes reuse the M02 Core test executable. Production CLI, Core probe and existing TUI probe keep separate hashes and provenance. `runtime_cases.g06_native_dependencies` declares the exact payload/probe closure for each transaction and is deployed through the existing worker file map. Host execution and native dependencies still invalidate the affected cases; an individual Python case edit changes its reachable AST closure. New self-checks cover one SDK author change, unchanged Host-independent author keys, individual case invalidation and per-payload checkpoint invalidation.

An exact producer hit continues to skip Host compilation and large product/input uploads. Current test overlays, input/isolation/audit checks, receipts and dependency explanations remain current. Build and consumer stage logs use the existing progress stream. Successful checkpoints are reused independently of a failed sibling; failed evidence is retained. The compiler-free consumer runs the packaged CLI and native payloads, never SDK source or a build fallback.

All G06 formatting, Clippy, compiler checks, cold/warm runs, controlled Python/Rust invalidation proofs and runtime acceptance remain NOT_RUN. The original seven AC, earlier qualification evidence, parent integration and release readiness remain separate; see [SDK support](../docs/sdk-support.md).

## S04 candidate

The dedicated `benchmark.yml` worker workflow measures 36 independent author slots
and 30 starts of the original qualified H/A/B/C in the strict offline consumer.
Cold/warm builds use empty linked targets; a controlled A-only source change keeps
H/B/C unchanged. Exact successful samples retain their original execution identity
on retries. Per-state runtime checkpoints prevent an unrelated Python test fix from
replaying every successful state. Current shared isolation/audit changes still
invalidate their consumers. Ordinary S03 build configuration stays unchanged.

Worker deployment now maps 16 canonical files, including the benchmark reusable
workflow and role action. The benchmark requires explicit reviewed source, request,
real PR and optional prior-run/seed identities. Cache saves use the owner's confirmed
10 GB repository limit and live usage, capped at the free-tier ceiling. The preflight,
author seed saves and trust writer share this check; none requires the payment-gated
storage-limit API. Preflight uses a planning reserve; author saves check actual
pending bytes against the total limit. A verified reused cold H pass can repair a
missing Cargo-download seed without repeating its build or product upload. That
locked fetch disables its compiler wrapper so a traced background sccache server
cannot keep download-only preparation alive. Missing confirmation, failed usage
lookup or insufficient space denies writes without cache deletion, paid expansion
or re-uploading the large H compiler seed.
R12 completed all 36 author and 30 runtime slots, with all six automated checks
passing. It retained 21 author passes, added three warm H builds, three changed-A
builds and nine unchanged H/B/C observations, and uploaded no native product.
All 30 original runtime measurements were reused with current isolation and four
outer audits; new business measurements and forbidden build calls were zero.
The missing H Cargo seed was saved after a 110.676 s download-only repair with no
linked target or repeated cold H build. Actual repository usage was 9,193,468,682
bytes, inside the confirmed 10 GB ceiling. Real cache authority and 11 canaries pass.
Warm H reuse is partial: each sample has 1,947 hits and 2,056 misses. Raw snapshots
remain authoritative; reports derive only cumulative hit/miss/error deltas and
preserve null size gauges. Report-only changes do not invalidate native, runtime
or unchanged-package measurements. Earlier failed and cancelled evidence remains.
See [measurement boundaries, reports and
operation](../docs/reproducibility-report.md) before publication or dispatch.

## Final program validation

The existing independent `build.yml` accepts `build_kind=program` with the exact source SHA and unique request ID. It skips both native build jobs and both signing branches, prepares a current validation overlay, consumes the fixed qualified S03 runtime input, and emits a separate program receipt. The original `.github/cm-ci.json` product mapping remains CM-S03. See [Linux x64 integration](../docs/linux-x64-integration.md) for fixed inputs, 18 new cases, strict checkpoint reuse, the four final reports, and support boundaries. This branch writes no cache and has no fallback build or native product upload.

## Linux ARM64 native mechanism preflight

`worker-files-linux-arm64.json` maps seven infrastructure files to the existing
public `DSLZL/CM-build-linux-arm64` repository. Its sole workflow runs on native
`ubuntu-24.04-arm`, binds the current public source and worker `main` revisions,
and requires actual runner-enforced `cache-mode: none`. The disabled platform
exception is restricted to the `platform_preflight` role and `native-preflight`
job; normal product entry points continue to reject disabled platforms.

The default `initial-mechanisms` stage prepares the pinned upstream source and existing overlay without
building Codex CLI or schemas. It builds only ABI/runtime loader tests and two
independent fixture libraries, reuses the real sealed-snapshot replacement test,
and runs existing C layout and SDK boundary probes. Its test identity and ELF
hashes are explicitly private probe evidence. ARM ELF machine and GNU property
checks retain the x64 branch and reject unknown processor requirements.

A minimal C-only rootfs tests namespaces, capability removal, read-only inputs,
hidden source/Cargo paths, denied compiler executions and separated loopback
networks. The trusted observer uses the existing consumer syscall list and audit
functions. Two intentional failed compiler executions are recorded separately;
they are not presented as zero attempted builds. This initial stage uses the
system bubblewrap binary. Logs retain stages, return codes, elapsed times and 30-second
heartbeats; only text evidence is uploaded. No cache is restored or saved.

The initial mechanism run passed at source `07bde6992075a238bebeccb40058ac149c7d4c6b`
and worker `37e71a70f427ac36bd888d756b159c7ca38d0919`
([run 42580220275](https://github.com/DSLZL/CM-build-linux-arm64/actions/runs/42580220275)).
That evidence covers the original source revision and system bubblewrap only.

The separate `stage=packaged-helper` prepares the same pinned upstream
source, reuses the production helper's fmt/clippy/test/build commands for native
`codex-bwrap`, and runs the same minimal-rootfs observer with that exact ARM64
binary. It records its version, ELF hash, libcap inputs, successful executable
path and unchanged bytes after the probe. Empty native override variables are
rejected too: upstream treats an empty `CODEX_SKIP_BWRAP_BUILD` as a skip request.
This stage skips the ABI/loader Rust tests and fixtures; it builds no Codex CLI
and uploads no product. The default `initial-mechanisms` stage retains those
original probes. Both stages write no cache.

The packaged-helper mechanism passed at source `12d3abf4e79f911415013c68b13ff4084caff372`
and worker `78bbd51f0bbafd7cd450103f7db9a646b6968738`
([run 42588901092](https://github.com/DSLZL/CM-build-linux-arm64/actions/runs/42588901092)).
This covers that exact helper and its isolation checks; its package declares no
unit tests. The functional evidence is the actual version and rootfs execution.

The `stage=native-inputs-terminal` candidate uses the same pinned upstream V8
resolver as production, with the explicit ARM64 target. It verifies the trusted
release checksum chain, records archive/binding hashes, and checks every unpacked
archive member is a little-endian ARM64 ELF64 relocatable object. V8 download and
archive commands have separate logs, timeouts and the existing 30-second heartbeat.
A small native Python PTY probe uses the session/controlling-terminal setup of the
existing TUI fixtures. It checks Unicode input, foreground process ownership,
window size, terminal restoration on normal/error/SIGINT exit, and rejection of
non-terminal input. It runs before source preparation and the V8 download so a
terminal failure stops early. This is a terminal mechanism check; full Codex TUI business
and V8 link/execution still require their actual product runs.

This stage compiles no Rust, helper, fixture, schema or CLI, skips earlier isolation
probes, uploads text only and writes no cache. The earlier exact-revision ABI,
loader and helper results retain their original origins. The new stage, complete
V01, production H, cache reuse and runtime qualification remain NOT_RUN until
their own hosted evidence is reviewed. The platform stays disabled. The shared
helper recipe and loader changes also require affected Linux x64 regression
evidence before final integration.


## GNU Linux ARM64 candidate

The shared GNU Linux pipeline now has a native ARM64 candidate in `DSLZL/CM-build-linux-arm64`, using `ubuntu-24.04-arm` and `aarch64-unknown-linux-gnu`. Enabling its infrastructure permits qualification runs; it does not grant product support. ARM64 preflight results cover their recorded component mechanisms only. Full Host/A/B/C/helper, strict consumer, reuse and affected Linux x64 regression evidence must come from the candidate's own hosted runs.

The fixed builder repository chooses the runner, target and artifact namespace. The closed native facts select ELF machine 62/183, x86-64/armv8-a CPU declarations, compiler flags, interpreter and system-library architecture. Unknown targets and foreign worker/CPU/target bindings reject. Frozen Python drivers carry the same target through a cleared rootfs environment. Each binary retains its own target; no x64 reference executes on ARM64.

Source and hook-slot manifests retain complete audit records, while only the selected target's overlay, distribution policy and slot descriptor enter its Host identity. The ARM64 verifier policy pins builder repository ID 1451045850 and the ARM64 GitHub CLI archive; the x64 policy remains separate. An inactive platform's policy or slot listing does not invalidate the current Host. Test case/report edits remain outside the compiler identity and use their actual dependency checkpoints.

For the first release of each new platform, historical native Host upgrade and old-Host rejection checks are deferred by user decision. The ARM64 consumer retains the full catalog and emits `qualification-scope.json`: every G05 case, `g01-binding-other-host`, `g06-old-host-reject`, and the historical branches of A/B plug-and-play, S01 compatibility and S02 boundaries are NOT_RUN. It does not download x64 legacy Hosts or build substitute old CLIs. The support matrix's `upgrade-h0-h1` row stays declared with a reason. Current-H install, composition, enable/disable, state/transaction and identity/ABI/capability checks remain required. Existing x64 historical acceptance is unchanged.

All cache namespaces in each independent repository share the 10,000,000,000-byte admission limit. Unknown capacity or an over-budget save skips writing; restored artifacts preserve their original production and execution origins. The source dispatcher master switch stays off, and the four macOS/Windows product routes remain disabled until their own reviewed native candidates.
