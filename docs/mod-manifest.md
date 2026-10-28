# Precompiled CM Mods: manifest, configuration and lock

CM currently targets Linux x86_64 GNU. A Mod contains an already compiled native
`.so`, a `mod.toml` manifest and optional resources or inert data attachments.
Copy an equivalent directory or `.cmod` ZIP into the CM profile's `mods/` and
restart. Selection does not compile code, fetch dependencies or request a build.
Native Mods execute in the Host process; these checks do not provide a memory
sandbox or make an arbitrary native pointer safe.

This document describes the M01 candidate contract. Actions acceptance and
release readiness are separate; declarations in a manifest are not verification.

## Manifest format 3

[mod.schema.json](../schemas/mod.schema.json) describes the JSON representation
of `mod.toml`. Unknown fields, including install/post-install commands, fail.
Formats 1 and 2 retain their existing exact-version and entry contracts.

```toml
format_version = 3
id = "example.limit"
version = "1.2.3"
kind = "sdk"
dependencies = [{ id = "example.base", version = ">=1.0.0, <2.0.0", optional = true }]
conflicts = []
contributions = [{ id = "limit", kind = "output_limit", capability = "core.exec_output_limit.v1", resource = "core.exec_output_limit.v1" }]
resources = []

[binary]
path = "payload.so"
size = 12345
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
target = "x86_64-unknown-linux-gnu"
entry = "cm_mod_entry_v2"
glibc_min = "2.17"
cpu = "x86-64"

[compat]
abi_major = 2
abi_minor_min = 1
abi_minor_max = 1
host_api_min = "0.4.0"
required_capabilities = ["core.exec_output_limit.v1"]

[state]
owner = "example.limit"
schema = "counter-state"
version = 1
preserve = true

[provenance]
repository = "https://github.com/example/mod"
revision = "0000000000000000000000000000000000000000"
release_notes = "Describe the published binary and its limitations."
license = "Apache-2.0"
```

Replace example size/digests/revision with the actual published inputs. Source
claims are untrusted declarations; an external author receipt binds the archive
SHA and build provenance. Archive SHA is outside the archive to avoid self hashing.

`sdk` uses the Host's explicit ABI, API and full capability IDs. `exact_host`
additionally requires `[compat.exact_host]` with the Host's `build_id` and actual
`executable_sha256`. `advanced_hook` also requires `patch_map_sha256`; it remains
unsupported until a separate G01 qualification. Matching a build or ABI number
does not establish a successful compatibility run.

The binary uses `abi_minor_min` as its native entry protocol; `abi_minor_max`
describes its declared upper bound. Both must belong to the current Host's
1.0/2.0/2.1 support. ABI 1.0 uses `cm_mod_entry_v1` and its original single legacy
contribution; it cannot receive configuration. ABI 2.0/2.1 use
`cm_mod_entry_v2`, and actual descriptors are checked after native loading.
The only declared CPU baseline is `x86-64`; the current glibc must meet
`glibc_min`. This is a startup check, not certification of every Linux distribution.

New dependencies use semver 1.0.27 `VersionReq`: bare `1.2.3` means a caret
requirement; use `=1.2.3` for an exact requirement. Commas intersect comparisons.
Prereleases require an explicitly matching prerelease comparator. Build metadata
does not affect matching, but the lock still binds full version strings and bytes.
Only the selected installed set is resolved: a missing required dependency fails;
an absent optional dependency is allowed; a selected optional dependency must match.
Contribution references must exist even when the missing owner was optional.
Initialization dependencies and contribution order remain separate graphs with
stable ID ordering. Cycles, duplicates and exclusive replacement conflicts fail.

## Packages and bounds

The ZIP reader accepts stored/deflate entries without encryption. It does not
extract to disk or invoke an unzip process. Multipart, ZIP64, prefixed archives,
duplicate/noncanonical paths, links, special entries, overlapping data, damaged
CRC and inconsistent local/central metadata fail. Directory reads use relative
file descriptors and NOFOLLOW; hard linked files fail. ELF inspection rejects
executables/PIE with an interpreter, wrong architectures, unknown DT_NEEDED,
RPATH/RUNPATH and unsupported loader features before `dlopen`.

Bounds: 32 candidates, 256 entries and depth 16 per new package, 64 KiB manifest
or runtime configuration, 64 MiB payload, 8 MiB per resource/data attachment,
128 MiB package/archive and 256 MiB total candidate snapshots. The selected
runtime retains P03's aggregate 256 MiB payload/64 MiB resource limits,
128 contributions and 64 resources. IDs are at most 128 bytes; relative paths
at most 512 bytes. Source attachments are data and are never build inputs at
installation. Source-only packages still fail because a valid `.so` is required.

For format 3, canonical paths, actual sizes and SHA-256 of **all files** determine
content identity, including raw manifest, configuration declarations, license,
provenance and inert attachments. Directory slots, file times, inodes, ZIP order
and compression are absent from that identity. Archive bytes have a separate
external receipt. Existing formats retain their historical identity contract.

## Configuration

[cm-runtime.schema.json](../schemas/cm-runtime.schema.json) describes the CM file.
This namespace is separate from Codex's ordinary `-c` overrides and config.toml.

```toml
format_version = 2
enabled = ["example.limit"]

[mods."example.limit"]
token = "user-supplied value"

[profiles.review.mods."example.limit"]
limit = 192
```

The Mod may add a versioned static configuration contract to its manifest:

```toml
[config]
schema_version = 1
defaults = { limit = 256 }
schema = { type = "object", additionalProperties = false, required = ["limit", "token"], properties = { limit = { type = "integer", minimum = 1, maximum = 512 }, token = { type = "string", minLength = 1 } } }
```

Layers are defaults → user `mods` → selected `profiles` → current parameters.
Use `--cm-profile review` and repeatable `--cm-set 'example.limit.limit=128'`.
The value after `=` is a TOML value. Objects merge recursively; arrays and scalars
replace. Present keys/types/constraints are checked in every layer; required
fields are checked on the merged configuration of selected Mods.

The schema subset is exactly object/properties/required/additionalProperties=false,
array/items, string/integer/number/boolean, enum, minimum/maximum, min/maxLength
and min/maxItems. Integer bounds are signed 64-bit integers and are compared
without float rounding. Other keywords, `$ref`, datetime, nonfinite numbers and
executable validators fail. Schema/defaults each have a 32 KiB bound and depth 16.
This is not a general JSON Schema implementation or an RFC 8785 claim.

New format native init borrows only its owner's sorted canonical JSON view.
Legacy Mods retain raw format 1 selection bytes; with format 2 they receive the
equivalent legacy selection projection, without other Mods' values. Reports,
locks and diagnostics contain hashes, layer names and defined field paths, not
configuration values. A native Mod can still inspect its process memory.
State metadata alone retains its original descriptive meaning. The unverified M04 candidate adds explicit `state.files.v1` for format 3 / ABI 2 packages with a valid `[state]` owner, schema and positive version. It provides bounded ordinary files in a managed home; [file-state.md](file-state.md) defines the namespace, compatibility, offline checkpoint and rollback contract. ABI 2.2 process-local Mod/thread/turn values keep their existing lifetime and are separate from these files.

## Metadata commands and mod.lock

```sh
codex cm list
codex --cm-profile review cm plan
codex cm doctor
codex --cm-set 'example.limit.limit=128' cm lock
codex --cm-set 'example.limit.limit=128' cm lock --check
```

These commands parse and inspect data without calling a native constructor,
entry or init, opening a Core session, contacting a remote endpoint or building
anything. `--remote` is rejected before a handshake. `list` displays declared,
unsupported and verified fields separately; M01 has no trusted online
qualification source and never upgrades a self declaration to verified.

[mod-lock.schema.json](../schemas/mod-lock.schema.json) documents canonical
`schema_version=1`, `domain=cm.mod-lock.v1`. The lock includes Host build and
actual executable identity, candidates/selected content and provenance,
configuration hashes/origins, both graphs and stable order. It contains neither
absolute input paths nor configuration secrets. A lock cannot create a
`PreparedPlan` or bypass input snapshots and commit checks.

`plan` is read only. `doctor` reports `absent` when there is no lock and checks
it when present. `lock --check` requires an exact current canonical record and
never rewrites it. `lock` explicitly writes through an exclusive 0600 temporary
file in the managed profile, flushes/syncs, revalidates inputs and atomically
renames it. Pre-rename failures leave the prior lock intact. A directory sync
failure after rename is reported as a committed-file durability error.

Ordinary business startup always prepares current inputs; it does not require
or execute mod.lock. Adding/removing a package and restarting therefore does
not require a manual lock update. Explicit checks reject stale Host, content,
configuration or parameter identity.
