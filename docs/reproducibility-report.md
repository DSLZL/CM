# Build-cache and zero-build loading measurements

CM-S04 measures author builds separately from loading already qualified native
artifacts. Frozen-artifact runtime verification passes **30/30 fresh starts
(AC06)**. Full CM-S04 verification remains **incomplete**: the 36 author slots and
repository cache-authority probes await the campaign under the owner's confirmed
10 GB limit. Earlier runs were blocked by a payment-gated capacity API.
Infrastructure checks and the 11 compiler-cache canaries
pass. Historical qualifications identify the input bytes; they are not new
benchmark measurements or a release.

## Current hosted evidence

The completed reuse qualification used fixture source
`eb8e1b41bed40f3c9d61fd7d8fe646235d393c22` and worker
`29a2315383a526296c6cdd0a7612db6ff6e0fc99`.
[Source CI](https://github.com/DSLZL/CM/actions/runs/42390695029) passed its
13 infrastructure and negative checks. The
[runtime qualification run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42387064859)
measured all three ten-state blocks with source `635c4ad` and worker `608e5a2`.
All 30 samples passed and retain the original Host/Mod bytes; compiler, linker,
Mod JIT and build service calls are zero. Seven profiles restored from the earlier
failed campaign also completed actual Host starts after the fixture-only identity
repair.

The [same-input reuse run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42390902502)
passed all 30 slots by restoring their verified checkpoints. It retained every
original sample ID, execution origin, dependency fingerprint and measurement;
there were **zero new business-process measurements**. Current isolation, frozen
verification and all three outer audits passed independently. Checkpoint archives
were uploaded for subsequent retries; these are not new native builds or product
packages. Both collectors report AC06 pass and AC01–AC05 incomplete/failed, so
the workflow conclusions remain failure.

The [first reuse attempt](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42389110477)
failed before any Host business start because the fresh rootfs lacked the common
profile parent. Its ten failed restores and twenty unstarted slots remain recorded.
The current driver creates the parent before entering a block, with a regression
check that executes the actual entrypoint.

The [retained failed run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42385569218)
contains one successful behavior sample and nine startup failures in its first
block. Its restored profiles retained device/inode identities from a previous
runner, so the unchanged Host correctly rejected them with `state_ownership`.
The later blocks were not started. These behavior results do not qualify AC06.
Its text traces, failed samples and six reports remain attached to that run.

The following medians are from the three fresh observations per state in the
runtime qualification run. All rows include strace and 5 ms external polling.
Startup means spawn to observed ready; business includes the finite TUI response
and turn/callback settlement after ready. RSS is the sampled Host-only VmHWM,
converted from KiB to MiB; its exact lifetime peak is unavailable. These are instrumented observations, not a
pure dlopen measurement or a startup SLA. Full raw distributions remain in
`zero-build-loading-measurements.json`.

| State | Observations | Startup (s) | Business (s) | Host RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Empty | 3 | 11.162 | 1.889 | 343.4 |
| A | 3 | 11.260 | 2.425 | 347.2 |
| B | 3 | 11.221 | 2.797 | 347.0 |
| C | 3 | 11.182 | 2.406 | 347.0 |
| A+B+C | 3 | 11.114 | 2.827 | 348.1 |
| Disabled | 3 | 10.886 | 1.909 | 343.6 |
| Reenabled A+B+C | 3 | 11.064 | 2.827 | 347.8 |
| Remove A | 3 | 11.231 | 2.802 | 346.4 |
| Remove B | 3 | 10.911 | 2.369 | 347.0 |
| Remove C | 3 | 11.008 | 1.876 | 327.6 |

## Execution and sample boundaries

Only the independent `DSLZL/CM-build-linux-x64` workflow
`.github/workflows/benchmark.yml` executes these measurements, on GitHub-hosted
`ubuntu-24.04`, GNU Linux x64. Source CI checks infrastructure on the same platform.
No local build, import, AST check, lint, native test or benchmark establishes a pass.

The author campaign has 36 slots: three repetitions of cold, warm and a controlled
single-Mod change, each with H and Mods A/B/C. A is turn-budget, B is
review-before-send and C is tool-concurrency. Every measured build starts with an
empty target. Warm runs restore exact Cargo downloads and compiler objects without
restoring linked outputs. They require actual sccache hits. For the single-A change,
only A compiles; H/B/C retain their original package identity and verified bytes.
The experimental A change includes an assertion exercising the changed diagnostic.

Each author target records its real fmt, Clippy, test, build and package phases,
compiler requests, before/after cache statistics, Cargo timing material, environment
and archive/ELF hashes. GNU time records command/descendant CPU and peak RSS.
Daemon compiler executions are not claimed as observed child processes. Pure linker
time is unavailable and is never substituted with Cargo build time.

The runtime campaign has 30 slots: three sequential ten-state blocks using one
managed profile per block. The states are empty, A, B, C, A+B+C, disabled,
reenabled A+B+C, remove A, remove B and remove C. Installation, enablement, disablement
and removal preserve retained user data. Each new measurement launches a fresh H
process and uses the actual provider/tool path and applicable A/B/C assertions.
There is no hot-unload claim.

Runtime inputs are the exact original H/A/B/C bytes bound to the qualified run in
[`runtime-loading.json`](../ci/benchmarks/runtime-loading.json). The consumer fetches
current text fixtures without checking out Rust source. It independently verifies
original signatures and identities, then runs in the existing minimal offline
rootfs with current namespace, inventory, network and execution audits. No compiler,
SDK source, native source attachment, build-service call or Mod JIT is permitted.
Normal sealed Code Mode V8 business execution keeps its existing narrow audit.

Startup, business completion and observed process exit use monotonic time. Host RSS
is sampled from the exact Host PID every 5 ms; children are excluded and the exact
lifetime peak is unavailable. The frozen Host emits a dlopen-start event without a
matching completion timestamp. Start-to-ready includes initialization; pure dlopen
latency is unavailable. Raw timestamps and limitations stay in the reports.

## Cache ownership, compatibility and capacity

All cache lookups belong to the platform build repository. H and each Mod have
separate Cargo-download and compiler-object stores. Keys bind the pinned compiler,
native tool identity, flags and runner image. Source/lock/SDK/generator inputs also
participate in the actual compiler cache and measurement dependency fingerprints.
There are no cross-repository lookups or broad restore prefixes.

The existing H compiler seed is read-only. It is verified against its exact key,
API identity, original successful producer job and compatibility fingerprint; the
8.4 GB archive is not saved again by this experiment. Cold repetition 1 may save one
bounded Cargo seed per role and one compiler seed per Mod. The campaign reserves at
most 256 MiB of new repository cache, including the small trust probe. Tiny isolated
invalidation/corruption probes use at most 16 MiB of local compiler-cache objects.

Before any new repository cache save, preflight, the author save plan and trust
writer check live usage against the owner-confirmed repository limit and the
free-tier ceiling. On 2026-11-08 (Asia/Taipei), the owner confirmed a 10G total limit
and no paid expansion. Configuration conservatively uses 10,000,000,000 bytes.
The shared check reads the usage API and reserves the campaign's 256 MiB budget;
it does not call the storage-limit API, which returned HTTP 402 requiring a valid
payment method. The limit's provenance remains explicit as owner confirmation.
Missing or invalid confirmation, failed usage lookup or insufficient headroom
denies writes. Author saves also check actual seed size and runner disk reserve.
No cache deletion, billing change or hidden cold fallback is permitted. The runtime
consumer and local-disk canary jobs remain independent.

The trust probes use the runner's actual cache authority: a trusted default-branch
writer creates a tiny seed; a reader checks out an actual open same-repository PR
but executes only reviewed worker code. It restores that seed and attempts a save,
then checks that no denied key exists. A real missing key, an intentionally failed
cache-service request, corrupted compiler objects and unknown native origins have
separate evidence and outcomes. No successful miss substitutes for a service error.

## Retrying a failure

`reuse_run_id` explicitly names a completed benchmark workflow. Its worker/source
ancestry, artifact API records, digests, original sample IDs and successful results
must verify. Failed results remain retained and are never reusable passes.

Author reuse is per stage/repetition/role and reachable method dependency. A Python
measurement fix reuses unaffected successful rows without compiling or uploading
their native packages. Runtime reuse is per block/state with verified before/after
profile checkpoints. Changed assertions rerun dependent states; other successful
states retain their original measurement and execution origin. A shared audit change
invalidates all affected states. Report-only changes recompute reports. Restoring a
checkpoint is not counted as another measurement or another cold/warm repetition.

Portable fixture checkpoints require one explicit relocation: after validating
the artifact, archive and original file-tree digests, the fixture updates only
the home/state/lease device and inode fields in its state identity. It preserves
the logical home ID, state contents and generation. Each restoration records the
original and restored file-tree hashes and the complete before/after identity;
the changed profile bytes are not reported as equal. Production Host ownership
checks and the frozen native artifacts remain unchanged.

Every run still verifies current identities, isolation and audit requirements.
Raw failed evidence is immutable. Heartbeats, phase logs and job/step timings remain
available while the campaign runs and after a failure.

## Reports and interpretation

All six files are emitted under the report artifact's `evidence/` directory, even
when a check fails or a sample is missing. `acceptance.json` maps the original six
checks to them and fails incomplete campaigns.

| Check | Report | Evidence |
| --- | --- | --- |
| AC01 | `author-build-benchmark-runs.json` | 36 author slots, original/reused identities, builds and failures |
| AC02 | `author-cache-measurements.json` | Raw cache deltas, phases, distributions and Actions costs |
| AC03 | `runtime-reproducibility-levels.json` | Source inputs, ELF bytes, runtime generations, archives and behavior |
| AC04 | `repository-cache-coverage.json` | Worker ownership, partitions, capacity and actual invalidation probes |
| AC05 | `cache-trust-failures.json` | Actual read/write/miss/service/corruption probes and current self-check evidence |
| AC06 | `zero-build-loading-measurements.json` | 30 runtime slots, current isolation audit and unchanged native bytes |

The five reproducibility levels are independent. Actual unequal ELF/archive hashes
remain unequal. Tar/gzip timestamps are retained; no normalization manufactures byte
equality. Runtime-generation hashes remain distinct from structured-plan hashes.
Experimental author archives are unsigned; signed-package reproducibility is
unavailable. Raw values, units, minimum, maximum, median, mean and sample standard
deviation are retained where measured; missing values are explicit.

Dispatch requires the exact reviewed source SHA on its default branch, a unique
`request_id`, and an actual open CM `pr_number` for the authority probe. Optional
`seed_id` and `reuse_run_id` select explicit existing lineage. Review capacity,
original artifact expiry, runner-image compatibility and expected 66 slots before
authorizing a campaign. Publishing this candidate and dispatching Actions need
separate authorization. The ordinary S03 production workflow and acceptance root
remain unchanged. A green workflow alone does not establish program completion,
cross-platform support or release readiness.
