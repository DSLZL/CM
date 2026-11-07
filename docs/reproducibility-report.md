# Build-cache and zero-build loading measurements

CM-S04 measures author builds separately from loading already qualified native
artifacts. The candidate has not run. Its six acceptance checks, native tests,
performance results and quality gate are **NOT_RUN**. Historical qualifications
identify the input bytes; they are not new benchmark measurements or a release.

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

Before any new repository cache save, preflight and the save step check actual
usage and the repository storage limit, free-tier bound and runner disk reserve.
Unknown or insufficient capacity denies saving and gates the author/cache-write
campaign. It does not trigger cache deletion, billing changes or a hidden cold
fallback. On 2026-11-07 the read-only storage-limit request returned HTTP 402, so the
current capacity is unconfirmed. The runtime consumer and local-disk canary jobs
remain independent. See the official [storage-limit API](https://docs.github.com/en/rest/actions/cache#get-github-actions-cache-storage-limit-for-a-repository).

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
