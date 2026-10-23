# CM Linux x64 CI

Source CI runs independently of product builds. Product dispatch remains disabled until real Cargo units, acceptance code and scoped dispatch credentials are configured.

## Publication boundary

Follow the existing .gitignore without exceptions. ci/source-files.txt lists the required project CI files only. Ignored development directories, task packs, reports, specs, journals and local assistant settings stay local. Do not force-add them or copy them into another publication directory. The existing journal-only .gitattributes is outside this CI payload.

CI uses the standalone scripts in ci/scripts and the worker workflows in ci/worker. There is no development-task runtime dependency. The source workflow checks every tracked path against .gitignore using git check-ignore --no-index, including files that might have been force-added.

## Source and independent builder

| Role | Repository | Default branch |
| --- | --- | --- |
| Source and dispatch control | DSLZL/CM | main |
| Linux x64 execution and cache owner | DSLZL/CM-build-linux-x64 | main |

.github/workflows/cm-source-check.yml checks the tracked CI payload, Python compilation and rejection of unconfigured product builds. It also verifies the fixed Codex commit, distinct release commit, Rust toolchain and four upstream build inputs declared in .github/cm-ci.json. It records the real hosted runner/run identity and retains logs/hashes. It does not validate local task documents or build products.

.github/workflows/cm-linux-x64.yml provides manual dispatch and verifies an exact independent builder run. Automatic dispatch is deferred until product configuration and authority are ready. ci/worker-files.json maps four infrastructure inputs to their builder destinations; deploy both workflows and both scripts together in one reviewed builder commit. The builder checks out the exact source SHA temporarily.

All compilation, checks, tests and experiments run only on GitHub-hosted ubuntu-24.04 / X64, target x86_64-unknown-linux-gnu. Local work edits source, configuration and lightweight evidence only.

## Configuration and cache boundaries

.github/cm-build-routing.json and .github/cm-ci.json deliberately retain configured=false. Repository/branch names are recorded; product Cargo units, acceptance code and dispatch credentials are not wired. These states must fail closed. Complete the real mappings and authority before enabling product execution.

The builder requires fixed CM_SOURCE_REPOSITORY and CM_BUILDER_REPOSITORY variables. Source dispatch requires CM_BUILD_FANOUT_TOKEN scoped to the selected builder with Actions: write and Contents: read; never forward it to product code. This route currently supports public source checkout; private-source credentials are not wired.

Only the verified source default-branch HEAD and trusted builder workflow may write builder-owned caches. Other reviewed source SHAs use platform-enforced cache-mode: read; source checks and dispatch use none. Retain separate Cargo download and runner-directory sccache archives, Linux/X64/GNU/compiler/config-qualified keys, RUSTC_WRAPPER=sccache, CARGO_INCREMENTAL=0 and SCCACHE_GHA_ENABLED=false. Do not archive target/ or copy cache archives across repositories.

Receipts bind the exact source SHA, independent workflow SHA, run/attempt/job and actual artifact digest. Cache hits do not replace checks; CI provenance alone does not establish product acceptance. User installation consumes prebuilt Host/Mod binaries without dispatching builds.

## Unrun gates

Source infrastructure check results are recorded by the source workflow for the exact commit. Variables/credentials, dispatcher/builder execution and product/runtime acceptance remain pending. No local test, lint, compile or simulated CI is permitted. Local task-pack acceptance remains not_run/blocked because its ignored inputs are not published.

References: [context availability](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability), [cache access modes](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching), [workflow dispatch](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event).
