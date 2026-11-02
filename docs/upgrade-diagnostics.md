# Prepare a profile for a new Host

CM-G05 passed its recorded Linux GNU x86_64 upgrade cases in the
[qualification run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/41527027753)
and the [unchanged-input warm run](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/41528312220).
The command prepares an independent profile for the packaged Host that executes it.
Keep both versioned Host packages and the old profile until you have checked the
candidate's behavior and data. Actions artifacts identify exact builds; they are
not a public Release or a claim that every Mod combination is supported.

Stop runtimes using the old profile, then run the new Host by its absolute path:

```sh
/opt/cm-new/bin/codex cm --home /srv/cm-old upgrade /srv/cm-candidate --check
/opt/cm-new/bin/codex cm --home /srv/cm-old upgrade /srv/cm-candidate
/opt/cm-new/bin/codex cm --home /srv/cm-candidate launch -- exec "Use example-tool__echo"
```

`--check` reads and validates inputs without creating candidate files or executing
native Mod code. Materialization checks those inputs again and commits one new
candidate generation. It leaves the old Host, profile, selection, locks, packages
and state intact. The destination must have an existing parent and be a new or
private empty directory, outside either Host package and the old or official home.

The candidate preserves installed and enabled selections, consumed package
identities, pinned configuration, and reachable retained state. A disabled Mod
stays disabled. If the source lock used `--cm-profile` or `--cm-set`, supply the
same options to the new command; a configuration that cannot reproduce that lock
is rejected. Configuration values are omitted from public diagnostics.

An exact-bound package may need an author's precompiled variant:

```sh
/opt/cm-new/bin/codex cm --home /srv/cm-old upgrade /srv/cm-candidate \
  --check --variant /downloads/hook-for-cm-new.cmod
```

Use the same explicit variant for materialization. Each variant must match one
installed Mod ID and its content version, and must satisfy the target Host's
ABI, capabilities, platform and exact identity requirements. Duplicate or unknown
IDs are rejected. Changing content versions uses the existing `replace` command.
The upgrader does not search for packages or rewrite an old package's bindings.

Static success reports `declared_compatible=true` and `verified=false`. Native
function tables and actual behavior require execution. A CI qualification applies
only to its exact Host build/ELF/map, package and payload bytes, selection lock,
configuration/state contracts, environment and cases. Manifest provenance is a
declaration; changing a local label cannot inherit an earlier verified result.

Structured errors include `compatibility_dimension`, Mod/resource/field when
available, and a next action. ABI, Host API, target/CPU, system, native package, capability,
protocol/resource, selection graph, state and exact Host failures remain distinct.
Unsupported declarations fail before native initialization. A busy source writer
or state lease fails immediately; stop the owning runtime and retry explicitly.
Missing or incompatible runtime libraries require a compatible prebuilt package.

Only declared `state.files.v1` regular files are copied, with the existing owner,
size, depth and entry limits. The candidate gets a new home identity, lease and
state tree. Retained owners survive disable/remove. Symlinks, hardlinks, unsafe
ownership, pending cleanup and nonempty incompatible state contracts are rejected.
Credentials, sessions, unrelated databases and old checkpoints are not copied.

To continue with the retained version, launch its own Host and home:

```sh
/opt/cm-old/bin/codex cm --home /srv/cm-old launch
```

This uses the old data. Candidate writes remain in the candidate; there is no
inverse migration or automatic merge. Checkpoint restore continues to require
the same home, Host, generation, configuration and owner contracts.

A failure before publication may leave a private inactive destination containing
copied immutable objects. It has no active candidate descriptor. Inspect it and
choose a fresh destination for another attempt. `committed_durability` means the
descriptor was renamed but durability could not be confirmed: inspect the candidate
with the new Host before taking further action. Never delete it or retry over it
on the assumption that nothing committed.

Native Mods share Host process permissions. An independent candidate protects
this managed upgrade flow; it cannot undo arbitrary native writes or external
service effects. Current platform scope is Linux GNU x86_64; broader platform,
performance and release gates remain separate.
