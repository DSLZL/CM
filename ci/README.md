# CM Linux x64 CI

CM source is DSLZL/CM; the independent GitHub-hosted ubuntu-24.04 X64 producer and cache owner is DSLZL/CM-build-linux-x64. The only CM target is x86_64-unknown-linux-gnu. All compilation, checks, tests, smoke runs and experiments execute there. Local work edits and reviews source/configuration and lightweight evidence.

## Publication inputs

ci/source-files.txt lists the exact reviewed public source inputs. Existing .gitignore rules remain unchanged. Assistant settings, task packs, reports, specs and journals stay local; do not force-add or copy them into public directories. The journal-only .gitattributes is outside this payload.

The source workflow checks tracked paths against .gitignore, payload/worker mappings, CI Python compilation, unconfigured rejection and the pinned upstream/release baseline. It does not execute product acceptance or read ignored developer materials. New product results require a new exact source commit and independent worker run.

## Host producer and identity

adapters/codex-e4568a3/source.json pins the original upstream commit/tree, original input hashes and separate official release reference. The worker preserves the complete pristine Git snapshot and original lock, creates a separate Host worktree, applies the three registered patches and copies only the explicit overlay paths. This includes the native runtime/ABI crates, CLI startup, the actual Core gate, terminal exec cleanup and their manifest/lock edges. The existing app-server Clippy cleanup remains explicit. The complete source delta, original/final locks and their hashes are recorded separately from pristine S0. No full upstream development tree is published in CM or bundled with the Host.

The builder runs host.py prepare before loading real Cargo mappings, then installs Rust 1.95.0 and native dependencies. host.py native reuses the pinned upstream V8 resolver and records verified V8 bytes, actual Rust binaries, native tools/packages/files. Generated native identity files are required during cache identification, after materialization; they are not publication inputs. Cargo runs from its manifest directory so workspace .cargo configuration is discovered.

The ephemeral runner uses the pinned upstream CI user-namespace setup (unprivileged_userns_clone=1 and apparmor_restrict_unprivileged_userns=0). The worker first builds/checks bwrap in a fresh helper unit, runs a real namespace smoke check before Host compilation, records kernel/sysctl observations separately, and supplies its actual digest through upstream CODEX_BWRAP_SHA256. This does not qualify compatibility with stock AppArmor restrictions. host.py seal refuses existing Host target artifacts and canonicalizes full source/overlay, final lock, actual tools/native/V8, target, profiles, features and flags. Relative paths and file bytes/modes enter the identity; traversal order, mtime and temporary roots do not. User Mod selections and compiled Mod payloads are absent. Host inputs, including the compiled helper digest, are sealed before Host compilation and embedded through CM_HOST_IDENTITY_JSON; codex cm-host-identity reads the compiled-in JSON. host_release_id, host_api_version, protocol_contract_id and host_build_id have separate roles. Final artifact_sha256 is recorded externally after packaging, avoiding self-reference.

The worker runs producer rejection tests, fmt, clippy with warnings denied, actual package tests and locked Host/helper builds. Acceptance reuses the fixed upstream package builder with the just-built CLI, code-mode host and bwrap, and its verified ripgrep resource. The package includes identity, original license notices and a resolved dependency/license inventory. Required ELF/system-baseline and complete license-compliance gates remain later work.

The P01 regression producer still checks the real embedded identity, stale-output refusal, source/final lock drift, representative CLI commands and four unchanged Core command-approval canonicalization tests. Its new run report is host-baseline-acceptance.json; the P02 root report uses only the five P02 checks. The historical accepted P01 run does not accept a new Host revision.

A separately downloaded, digest-pinned official rust-v0.163.0 installation and isolated official profile must remain byte-identical throughout the baseline. The official CLI initializes its own helper files before the protected snapshot; complete before/after manifests are retained. That release only publishes a musl Linux reference; this read-only fixture does not add a CM musl target. Its release commit differs from the pinned development source, so binary equivalence is not claimed.

## P02 native loader candidate

The current source is a dev-small candidate, pending its exact independent Actions run. It implements only core.tool_parallel_eligibility.v1 for one Mod on a new local embedded codex exec session. The same packaged Host is exercised with no Mod, an installed Mod and that Mod removed. Remote/LocalDaemon and other session paths with a Core Mod fail before native execution; metadata commands never load Mods. TUI, resume/fork, Code Mode qualification, multiple Mods and a complete public SDK/manager remain later work.

The candidate reads CODEX_HOME/mods. An absent or empty directory means no Mod. Any candidate entry must be one plain directory containing mod.toml and a bounded regular payload; extra candidates are errors. The manifest has exactly these required fields:

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

Unknown/duplicate keys, symlinks, multiply linked files, unsupported declarations, paths, sizes, hashes, ELF targets, RPATH/RUNPATH, filters/audit resolution and non-allowlisted native dependency names are rejected before dlopen. The verified byte buffer becomes a sealed, read-only memfd; loading uses its absolute /proc/self/fd path with RTLD_NOW | RTLD_LOCAL. No package path is reopened for loading. Constructor execution is possible as soon as dlopen begins; ABI/entry/init failures are classified as already_native_executed and never become Ready.

crates/cm-abi/include/cm_mod_v1.h is the C contract. It uses fixed-width repr(C) layouts, borrowed UTF-8 pointer/length views, caller-owned bounded output/error storage and Mod-owned userdata/release. The entry reads size before header/table fields. Only KEEP and FORCE_SERIAL decisions are valid; final eligibility is original_parallel AND decision != FORCE_SERIAL. The existing per-runtime Core RWLock still controls actual execution. A callback error is fatal and never silently falls back to KEEP. Calls are synchronous, serialized and non-reentrant; cancellation is checked before and after. Normal shutdown stops admission, drains tool leases and native calls, then calls the Mod's release once. Libraries and sealed payloads stay pinned until process exit; removing files affects only the next process.

Native Mods execute with Host permissions. This ABI and loader are not a memory/process sandbox. Invalid pointers, abort, segfault or a stuck callback may terminate or hang the process; a watchdog kill is recorded as failure containment, not successful cancellation or isolation. There is no hot unload.

## Independent Mod and acceptance

ci/scripts/native_mod.py reuses the existing execute, cargo_args, source and packaging helpers. It freezes and hashes the packaged Host before building the author fixture. fixtures/mods/serial-eligibility has its own workspace, committed lock and initially empty target directory, and depends only on cm-abi. Its actual dependency inventory must exclude Core/runtime; the Host dependency inventory must exclude the concrete Mod. The payload, header, license and independent input/build receipt remain in the remote artifact. Rebuilding the ABI probe after the Host freeze cannot replace the packaged Host; complete package/executable hashes are checked again afterward.

The Actions acceptance uses a local Responses SSE provider and real builtin exec_command processes with Unix-socket barriers. It observes actual A/B handler entry, the original Core gate's pending/admitted states, real tool results and thread/turn/call identities. Empty and removed sets must allow B before A releases; the restrictive Mod must keep B waiting until A finishes. No elapsed-time overlap estimate substitutes for those barriers.

Additional child processes cover pre-load constructor rejection, short tables and version/length/status errors, independent allocator release, catchable panic, actual abort/segfault, cancellation, held callback drain and an explicitly classified stuck callback kill. A focused integration test loads the sealed original after both path replacement and in-place modification. Separate logs retain the original failed process outcomes. All five root P02 reports are written only after every required assertion succeeds.

## Independent dispatch and cache authority

ci/worker-files.json maps six infrastructure inputs to the builder. Both worker workflows, both policy/record scripts and the cache-authority JavaScript action deploy together at an exact reviewed builder commit. The action reads the runner-injected effective cache mode, checks it against trusted preflight, and exposes only that validated enum to later shell steps. The worker fixes its source/builder identities in reviewed YAML and temporarily checks out the requested exact public CM SHA. No repository variables or copied gh credentials are needed for an operator dispatch.

.github/cm-ci.json maps the P02 producer through the existing acceptance entry. No worker recipe change is needed for this candidate. .github/cm-build-routing.json remains configured=false: automatic/source fanout is still disabled and CM_BUILD_FANOUT_TOKEN is not configured. Direct operator dispatch is distinct from validating fanout.

Only the verified source default-branch HEAD and trusted worker revision may write builder-owned caches. Other reviewed source SHAs get platform-enforced cache-mode read. Preflight, source checks and receipts use none. Cargo downloads and sccache snapshots remain separate; compiler/target/config/native-qualified keys never cross platforms or repositories. RUSTC_WRAPPER=sccache, CARGO_INCREMENTAL=0 and SCCACHE_GHA_ENABLED=false remain required; target/ is not cached.

Worker logs retain sccache statistics, restore/save observations and final acceptance JSON separately from the binary payload. Product receipts bind source/workflow repositories and SHAs, target, run/attempt/job, Host/package/helper/Mod hashes and final GitHub upload digest. Cache hits do not replace validation. Artifacts and caches remain remote; developer machines only collect lightweight evidence.

## Verification boundary

P02 is not accepted until the exact published commit completes all five real independent-worker checks and evidence review. Failed/partial runs cannot accept a newer source revision. A package or loader pass cannot establish whole-product or release readiness. Compiler-free installation/combination acceptance remains a later gate. No local build, test, lint or simulated CI is permitted. Publication and dispatch follow the current explicit session authorization; credentials and product Releases require separate concrete authorization.
