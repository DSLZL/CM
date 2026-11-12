# Build-cache and zero-build loading measurements

CM-S04 measures author builds separately from loading already qualified native
artifacts. The completed measurement campaign has **36/36 author slots** and
**30/30 runtime slots**, with all six automated acceptance checks passing. The
runtime measurements retain their original 30 actual Host starts. Exact retries
reuse measurements; they do not count another independent repetition.
These GNU Linux x64 observations do not establish a release or cross-platform support.

## Hosted measurement evidence

The [completed campaign](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42406989617)
used source `7076650` and worker `459985f`. Its
[source CI](https://github.com/DSLZL/CM/actions/runs/42406649722) passed 19 check
groups. All 15 jobs succeeded and the six reports contain 66 unique original
sample identities. Twenty-one successful author samples were retained unchanged
from earlier campaigns. The 15 new author observations comprise three warm H
builds, three A-only change builds and nine unchanged H/B/C package observations.
No new native product artifact was uploaded by this campaign.

| Role | Cold median (s) | Warm median (s) | A-only change |
| --- | ---: | ---: | --- |
| H | 2881.503 | 2335.112 | Original ELF/package observed; no build |
| A | 8.833 | 6.738 | 5.305 s median |
| B | 8.800 | 6.336 | Original ELF/package observed; no build |
| C | 8.624 | 6.300 | Original ELF/package observed; no build |

Each cold/warm cell has three independent original measurements with empty linked
targets. Phase times include actual generation, fmt, Clippy, tests, builds and
packaging; setup, archive restore/save and uploads retain separate Actions timings.
The image/compiler/native cohort matches, but physical-runner equivalence is not
assumed. All three warm H measurements restored both exact archives and recorded
1,947 compiler-object hits, 2,056 misses and zero cache errors each. Rust contributed
968 hits; C/C++ and assembler contributed 699 and 280. This is partial cache reuse,
not a claim that unchanged source eliminates every compiler, test or link step.

Cold and warm builds have one source-input hash and one identical ELF hash per
role. Their six archive hashes per role remain unequal: actual tar/gzip timestamps
are retained. The changed A source and all nine unchanged H/B/C ELF/package
observations are recorded separately. No normalization manufactures byte equality.

The missing H Cargo seed was repaired with a locked download lasting 110.676 s.
Its trace contains only Cargo and rustc metadata queries, with no sccache daemon or
native output. The linked target remained absent; the original cold H sample and
product were retained. The save checked 386,604,096 uncompressed bytes plus
16,777,216 bytes of safety against live usage and the owner's confirmed
10,000,000,000-byte ceiling. Actual cache `10171734918` stores 321,957,922 bytes;
repository usage afterwards was 9,193,468,682 bytes. The existing 8.4 GB H compiler
seed remains read-only. No paid capacity API, billing expansion or cache deletion
is required. The former 256 MiB value is a planning reserve, not another size cap.

The trusted writer and actual PR reader passed with an exact 614-byte seed, a
denied PR save, a real missing key, a real service failure and three isolated
pollution rejections. PR code was never executed. All 11 compiler-cache canaries
passed. Current runtime isolation and four outer audits also passed while reusing
all 30 original measurements: zero new business measurements and no compiler,
linker, Mod JIT or build-service calls. Checkpoint archives were uploaded again;
they remain distinct from native product uploads.

Earlier failures remain attached to their original runs. The
[first free-limit run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42393282434)
failed at Git-directory binding and first-party license packaging. The
[next run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42394875517)
passed nine Mod cold samples but failed the unchanged Host publication seal because
five license paths were unregistered. The
[following run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42397015293)
retained 21 author passes but lacked the exact H Cargo seed after the old extra
256 MiB save gate. A [cancelled repair attempt](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42403381140)
started a never-idle sccache daemon under `strace -f`; download-only repair now clears
its compiler wrapper. None of those incomplete campaigns is relabelled as passing.

The earlier completed reuse qualification used fixture source
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
bounded Cargo seed per role and one compiler seed per Mod. Preflight uses a 256 MiB
planning reserve; each author save checks its actual uncompressed seed size plus
earlier reservations and a 16 MiB safety reserve against current repository usage.
The planning estimate is not a separate hard limit on a valid Cargo seed. Tiny
isolated invalidation/corruption probes use at most 16 MiB of local compiler objects.

Before any new repository cache save, preflight, the author save plan and trust
writer check live usage against the owner-confirmed repository limit and the
free-tier ceiling. On 2026-11-08 (Asia/Taipei), the owner confirmed a 10G total limit
and no paid expansion. Configuration conservatively uses 10,000,000,000 bytes.
The shared check reads the usage API and uses the pending bytes for that check;
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

If a verified reused H cold pass lacks its exact Cargo seed, cold repetition 1 can
prepare the same source/native identity and fetch locked downloads only. It checks
the current worker authority, original sample and fingerprint, requires an empty
linked target, and saves only after the actual-size capacity check. Existing seeds
skip this repair. The original build metrics and product artifact stay unchanged;
repair does not rerun successful H compilation or upload another native package.

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

Cache report deltas contain cumulative hits, misses and errors, counted once.
Sizes and capacity limits remain raw before/after gauges; a null gauge stays
unknown and is never treated as zero. Original measurement snapshots remain intact.

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

<!-- CM-S04 cache read authority probe; this PR supplies no executable worker code. -->
