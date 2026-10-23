# CM Linux x64 CI

CM source is DSLZL/CM; the independent hosted ubuntu-24.04 X64 producer and cache owner is DSLZL/CM-build-linux-x64. The only CM target is x86_64-unknown-linux-gnu. All compilation, checks, tests, smoke runs and experiments execute there. Local work edits and reviews source/configuration and lightweight evidence.

## Publication inputs

ci/source-files.txt lists the exact reviewed public source inputs. Existing .gitignore rules remain unchanged. Assistant settings, task packs, reports, specs and journals stay local; do not force-add or copy them into public directories. The journal-only .gitattributes is outside this payload.

The source workflow checks tracked paths against .gitignore, payload/worker mappings, CI Python compilation, unconfigured rejection and the pinned upstream/release baseline. It does not execute product acceptance or read ignored developer materials. New product results require a new exact source commit and independent worker run.

## P01 Host producer

adapters/codex-e4568a3/source.json pins the original upstream commit/tree, original input hashes and separate official release reference. The worker preserves the complete pristine Git snapshot, creates a separate Host worktree, applies cli.patch and copies crates/cm/src/host_identity.rs into the real Codex CLI. No full upstream development tree is published in CM or bundled with the Host.

The builder runs host.py prepare before loading real Cargo mappings, then installs Rust 1.95.0 and native dependencies. host.py native reuses the pinned upstream V8 resolver and records verified V8 bytes, actual Rust binaries, native tools/packages/files. Generated native identity files are required during cache identification, after materialization; they are not publication inputs. Cargo runs from its manifest directory so workspace .cargo configuration is discovered.

The worker first builds/checks bwrap in a fresh helper unit and supplies its actual digest through upstream CODEX_BWRAP_SHA256. host.py seal refuses existing Host target artifacts and canonicalizes full source/overlay, final lock, actual tools/native/V8, target, profiles, features and flags. Relative paths and file bytes/modes enter the identity; traversal order, mtime and temporary roots do not. User Mod selections are absent. Host inputs, including the compiled helper digest, are sealed before Host compilation and embedded through CM_HOST_IDENTITY_JSON; codex cm-host-identity reads the compiled-in JSON. host_release_id, host_api_version, protocol_contract_id and host_build_id have separate roles. Final artifact_sha256 is recorded externally after packaging, avoiding self-reference.

The current candidate is a dev-small P01 identity baseline. Capabilities are empty and the loader/Mod ABI is not implemented. P02 must produce a new candidate after actual adapter/loader integration. A package pass cannot establish whole-product or release readiness.

The worker runs producer rejection tests, fmt, clippy with warnings denied, actual package tests and locked Host/helper builds. Acceptance checks the real embedded identity, source/final lock drift and stale-output refusal. It reuses the fixed upstream package builder with the just-built CLI, code-mode host and bwrap, and its verified ripgrep resource. The package includes identity, original license notices and a resolved dependency/license inventory. Required ELF/system-baseline and complete license-compliance gates remain later work.

The same Host runs representative CLI commands and four unchanged Core command-approval canonicalization tests (command_canonicalization::tests) with an empty Mod set. A separately downloaded, digest-pinned official rust-v0.163.0 installation and isolated official profile must remain byte-identical. That release only publishes a musl Linux reference; this read-only fixture does not add a CM musl target. Its release commit differs from the pinned development source, so binary equivalence is not claimed. Full no-compiler Mod combinations remain later gates.

## Independent dispatch and cache authority

ci/worker-files.json maps four infrastructure inputs to the builder. Both worker workflows and both policy/record scripts deploy together at an exact reviewed builder commit. The worker fixes its source/builder identities in reviewed YAML and temporarily checks out the requested exact public CM SHA. No repository variables or copied gh credentials are needed for an operator dispatch.

.github/cm-ci.json now maps the concrete P01 producer. .github/cm-build-routing.json remains configured=false: automatic/source fanout is still disabled and CM_BUILD_FANOUT_TOKEN is not configured. Direct operator dispatch is distinct from validating that fanout. Any later fanout token must be scoped to this builder only (Actions write, Contents read), never forwarded to source execution.

Only the verified source default-branch HEAD and trusted worker revision may write builder-owned caches. Other reviewed source SHAs get platform-enforced cache-mode read. Preflight, source checks and receipts use none. Cargo downloads and sccache snapshots remain separate; compiler/target/config/native-qualified keys never cross platforms or repositories. RUSTC_WRAPPER=sccache, CARGO_INCREMENTAL=0 and SCCACHE_GHA_ENABLED=false remain required; target/ is not cached.

Worker logs retain sccache statistics and restore/save observations. Product receipts bind source/workflow repositories and SHAs, target, run/attempt/job, Host/package/helper hashes and final GitHub upload digest. Cache hits do not replace validation. Artifacts and caches remain remote; developer machines only collect lightweight evidence.

## Current verification boundary

This implementation has not run yet. All five P01 product acceptance criteria remain not_run until the exact published commit completes the real independent worker and its evidence is reviewed. No local build, test, lint or simulated CI is permitted. Publication and dispatch follow the current explicit session authorization; credentials require separate concrete authorization.
