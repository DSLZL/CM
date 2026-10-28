# Managed file state and restart rollback

This is the unverified M04 source candidate for Linux x86_64 GNU, Host release `cm-host-0.7.0-m04` / API 0.6.0. Its product checks have not run. The previous M03 acceptance does not qualify these new operations.

## Opt in and ownership

A format 3 / ABI 2 Mod opts in by adding `state.files.v1` to `[compat].required_capabilities` and declaring:

```toml
[state]
owner = "example-tool" # Must equal the manifest ID.
schema = "notes"
version = 1
preserve = true
```

Owner and schema use the existing bounded ASCII ID syntax, excluding `.` and `..`; version is a positive u32. State metadata without this capability remains descriptive. ABI 2.2's process-local Mod/thread/turn state does not become persistent.

At actual managed startup, `CM_MOD_STATE_ROOT` identifies the verified working tree. A Mod uses `ROOT/owner/schema/version/` for its own ordinary files. UTF-8 names and spaces inside that directory are supported. CM creates private owned directories; Mods must create private regular files, keep their permissions private and synchronize writes as their application requires. Do not store data in another owner's directory or reuse a path obtained from an old generation.

The namespace is under `HOME/state/cm-files-v1/`, separate from earlier arbitrary `HOME/state` contents. Its random home identity binds the home, namespace and lease inodes. `trees/<id>` holds working data, `checkpoints/<sha256>` holds independent complete snapshots, and generation format 2 binds the selected working tree and owner contracts. Old generation format 1 is accepted only without a file-state contract. Internal markers/descriptors are not user configuration; copying a managed home is not a supported identity migration.

The Host validates the environment against the selected and current generation before native entry. Unmanaged file-state use, forged roots and delayed launches pointing at an obsolete state tree fail. General native code still runs with Host permissions and can write elsewhere. CM cannot reverse arbitrary external writes or provide a native sandbox.

## Restart and replacement

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile state path example-tool
/opt/cm/bin/codex cm --home /srv/cm-profile disable example-tool
/opt/cm/bin/codex cm --home /srv/cm-profile remove example-tool
/opt/cm/bin/codex cm --home /srv/cm-profile replace example-tool /tmp/new.cmod --from OLD_CONTENT_SHA256
```

Enable, disable, remove, replace and rollback take effect in a new process. Receipts report `restart_required`; live callbacks and libraries retain their original collection until process exit. Disable/remove preserve files and configuration. `state path` is a non-executing read-only query and does not allocate storage or a lease.

`replace` checks the exact installed content-tree SHA and preserves the previous enabled state. Ordinary same-ID/different-content installation still fails. Schema and version must match the allocated state exactly; the new artifact may have different bytes. A mismatch rejects nonempty state even for a disabled owner. After explicit offline cleanup, or for a genuinely empty state directory, a new contract can be allocated. No author migration callback executes during management.

## Offline checkpoint and rollback

Exit every CM runtime using this home before these operations:

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile state checkpoint
/opt/cm/bin/codex cm --home /srv/cm-profile rollback GENERATION_SHA256
/opt/cm/bin/codex cm --home /srv/cm-profile rollback GENERATION_SHA256 --restore CHECKPOINT_SHA256
```

The runtime keeps a shared flock until process exit, including failed or pinned native cleanup. State-changing managers take the ordinary profile writer lock first, then a nonblocking exclusive state lease. A live runtime produces `state_busy`; it is not killed. Ordinary enable/disable/remove can still publish the next collection. Helper execs do not inherit the lease descriptor.

A checkpoint copies all allocated owners, including retained disabled/removed data, into a private independent tree. CM verifies bytes, modes, hashes, ownership and complete membership before publishing the canonical manifest. It binds home, Host, exact generation/configuration identity and each owner's artifact/schema/version. A complete old working directory alone is not an authenticated restore plan.

Rollback selects historical immutable artifacts while revalidating the **current** configuration. It does not overwrite `config.toml` or `cm-runtime.toml`. Unknown removed-package configuration remains inert in a managed home until reinstallation. Incompatible values reject rollback. The current Host identity must still match; this is not a cross-Host migration mechanism.

With `--restore`, the checkpoint must match the exact target generation. Missing, truncated, altered, foreign or incompletely copied snapshots fail. CM builds and syncs a fresh private tree, validates every copied owner, then publishes a new generation through the existing single active-descriptor rename. Other current owners are preserved. Before that rename, failure or termination leaves the old active descriptor and data intact; unreachable staging is never loaded. A post-rename sync failure reports `committed_durability` with uncertain durability. Retrying does not silently reverse an already committed descriptor.

This supports bounded offline ordinary files. It does not snapshot online databases, perform live migration, run install scripts or download/build a Mod. The checkpoint is immutable by convention, protected by validation at restore; same-user native code is outside a sandbox and can damage local bytes.

## Explicit cleanup

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile state clean example-tool --confirm example-tool
```

The owner must be disabled or removed, the confirmation must match exactly, and all runtimes must have exited. Dependency-breaking selection changes still fail; there is no implicit cascade. CM validates the source, publishes a fresh working view containing other owners, commits it, then deletes this owner's data from the previous current tree.

The receipt distinguishes `committed`, `cleanup_pending`, `current_working_state_removed` and `cleanup_operation`. Physical deletion can fail after commit. Fix the filesystem condition and repeat the same clean command; it resumes only that recorded old owner/tree, including partially removed headers. New allocation or restore for that owner requires any pending cleanup to finish. The command preserves configuration, sessions, immutable package objects, separate checkpoints and other historical working trees. It is not secure erasure or history garbage collection.

## Bounds and evidence

Each owner has at most 1 GiB of file bytes, 4096 entries including directories, depth 16 and 512 UTF-8 bytes per relative path measured from the working-tree root. There are at most 131072 snapshot entries in total and a 16 MiB checkpoint manifest. Symlinks, multiply linked files, sockets, FIFOs, devices, foreign ownership, public permissions, extra owner/schema/version entries and changed inputs fail before activation or initial deletion. Reaching a bound rejects the operation; limits are not silently truncated.

The independent compiler-free consumer uses the same frozen H and unchanged B while actual precompiled Mod versions write/read files through exec, stdio and empty-argv PTY TUI. It exercises real permission failures and restore interruption, busy leases, mismatches, compatibility, retained data and cleanup retry. Precise injected ENOSPC/pre-commit/post-rename failures are separate producer tests, not claims about the published Host. Current P01–M03 regressions, execution/network audit, final input audit, log redaction and 30-second progress heartbeat remain required. Product results stay `not_run` until the exact source/worker/run/attempt/artifact/receipt evidence has been reviewed.
