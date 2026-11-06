# Discover and install official precompiled Mods

The S03 index commands are a candidate implementation pending independent Linux
Actions qualification. They use the fixed official publisher `DSLZL/CM` and
namespace `github:1430833890`. No public catalog endpoint is assumed. Obtain an
index and its proofs from the reviewed distribution channel after establishing
[Host trust](distribution.md).

## Preview an exact selection

Use an absolute private CM home, a file index or explicit HTTP(S) index URL, and
exact `ID@VERSION` selections. A file index has a fixed `.bundle.jsonl` sidecar;
referenced archives and proofs are relative to the index's directory.

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile index list --source /downloads/catalog.json
/opt/cm/bin/codex cm --home /srv/cm-profile index plan --source /downloads/catalog.json --mod sdk-a@0.1.0 --out /srv/cm-plans/sdk-a.json
/opt/cm/bin/codex cm --home /srv/cm-profile index install --plan /srv/cm-plans/sdk-a.json
```

Create the plan directory as an owned private directory first. The plan must be a
new absolute file outside protected Host, store, state, index and official Codex
paths. Keep it unchanged between review and installation. Supply repeated `--mod`
arguments to preview a batch; dependencies must be explicitly included. Selection
order does not change the resolved plan. New versions require an explicit preview.
The plan includes the existing enabled Mods; selecting another package does not
silently remove them.

`list` reads index metadata and its signature without downloading every Mod.
`plan` verifies the selected bytes and compares the actual manifests through the
existing RuntimePlan, lock, configuration, ABI/capability, dependency, exclusive
resource and state rules. It can retain verified immutable objects in the managed
store, but does not activate a generation or write Mod state. Metadata preparation
does not execute constructors, entrypoints, callbacks or installation scripts.

`install` rechecks the saved source snapshot, home identity, active generation,
Host, configuration, plan, lock and objects. One existing transaction commits the
whole selection. Drift or failure requires another preview; it does not activate
a partial set. Verified cached objects may remain after a failed operation.

## Read support labels separately

`origin_verified` means the fixed publisher and signing policy verified the index
or artifact. `declared_compatible` means this selected manifest passed the current
static plan checks. `list` leaves compatibility unset until a plan is prepared.

`platform_verified` requires a separate signed post-consumer qualification for
the exact record, Host/package identity, Mod contents, backend, target, CPU/glibc,
configuration and state contracts. Missing evidence or different conditions keeps
this label false. A malformed or tampered mandatory proof rejects the operation.
SDK, exact-host and prepared-slot support levels keep their existing boundaries;
ABI 2.3 remains experimental.

The signature does not establish safe native behavior, sandbox a Mod or qualify
other combinations. Output retains the tested scope and exclusions. See the
[support matrix](support-matrix.md) for accepted historical evidence.

## Use a complete offline cache

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile index plan --source /downloads/catalog.json --mod sdk-a@0.1.0 --out /srv/cm-plans/offline.json --offline
/opt/cm/bin/codex cm --home /srv/cm-profile index install --plan /srv/cm-plans/offline.json --offline
```

Offline mode requires the previously cached exact source snapshot, selected
archives, receipts, signature bundles and any referenced qualification. The
independent pinned verifier must also be available. Missing bytes reject the
operation without network access, compilation or a build-service fallback.

Online refresh checks a signed snapshot and rejects an older timestamp or a
conflicting accepted release identity. Revoked records cannot be selected.
Refresh does not replace a running process's frozen Mod set or activate an update.
Offline output shows the cached snapshot time and `revocation_fresh=false`;
neither cached nor online signed data guarantees the newest release or live
revocation freshness.

## Transport and archive boundary

HTTP(S) uses the exact original origin, bounded redirects, connect/read/total
timeouts and streamed byte limits. Credentials, query strings, fragments,
cross-origin redirects, HTTPS downgrades and compressed HTTP transfers are
rejected. File inputs and all referenced paths are bounded and cannot escape
their declared root through traversal or symlinks.

The raw archive size, SHA-256 and signed receipt are checked before ZIP parsing.
Existing entry/count/byte/CRC/type limits also reject traversal, absolute paths,
links, duplicate names, ancestor conflicts and ASCII case collisions. Failure
does not execute attached sources or introduce an installer toolchain.

The main consumer's six intermediate reports remain `behavior_pass`. A separate
trusted signing job issues qualifications without running candidate code; a fresh
unprivileged minimal consumer verifies actual positive and negative support
display. Final reports and the worker receipt bind both consumers, signed proof
artifacts and original producer. This sequence must pass on the independent
worker before S03 acceptance; it does not establish general release readiness.
