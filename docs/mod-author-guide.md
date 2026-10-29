# Native Mod author workflow

Start from `templates/native-mod`. Edit source only on the development machine.
Open files without a Cargo workspace and disable build extensions for strict source
viewing. The template's editor settings turn off automatic checks, build.rs,
proc macros, Cargo autoreload, automatic tasks and formatting. Review other editor
extensions separately. Never fetch product archives, target trees or caches locally.

The SDK is pinned to CM revision `d3abb2bea2dda5964ba2725b1abd095c3f46678b`,
version 0.1.0 / ABI 2.2. The standalone Cargo lock contains only this Mod, cm-sdk,
and cm-abi. Actual `--locked` resolution, format, strict Clippy, tests, ELF build
and packaging run only on the independent GitHub-hosted Ubuntu 24.04 X64 worker.
Host/Core/TUI are not author dependencies. Preserve SDK request ownership, allocator
ownership, cancellation and quiescence rules in [the SDK contract](runtime-sdk.md).

The current trusted source is only `DSLZL/CM`, at the fixed template path. Submit
the reviewed change there. CM's `.github/workflows/cm-mod-author.yml` requests the existing
`DSLZL/CM-build-linux-x64` worker. With routing `configured=false` or no existing
fanout token, it reports `blocked`; no secret is created and no local build starts.
External author repositories/PRs are not admitted to trusted worker caches.

The actual worker has two explicit kinds:

* `qualification` checks the affected Host inputs and regressions, freezes H, then
  independently builds the template and controlled update/error examples.
* `mod-only` requires the exact successful qualification origin JSON. The worker
  verifies its run/attempt/jobs, input/consumer/receipt artifact identities, Host
  build/ELF/package digest and SDK pin. It restores the exact frozen H and fixture
  packages, builds only the current target Mod, then reruns current M05 behavior
  in the strict compiler-free consumer. Missing or expired origins block; there
  is no implicit Host rebuild. Earlier baseline reports keep their earlier source.

The source dispatcher emits `host-origin.json` after verifying a successful qualification.
For a direct operator dispatch, assemble the same exact fields from that run's API
and artifact records; `worker-receipt.json` binds the input and consumer artifacts.
The origin JSON is an explicit
input, not `latest` or a branch name. Operator dispatch is separate from automatic
fanout authorization. Changes to Host production inputs require a new qualification;
changes only to the author Mod, Python checks or fixtures use the verified origin.

Increment Cargo and manifest versions together when changing behavior. The worker
records source and SDK revisions, source/lock/dependency manifests, commands,
toolchain/flags, H identity and payload/archive hashes in `author-receipt.json`.
Safe compiler diagnostics contain relative file/line/column/code/stage and the
actual worker CI URL, with source snippets and arbitrary messages omitted.

Use the produced `.cmod` and verified Host with [the user commands](mod-user-guide.md).
Metadata does not qualify native initialization. Native faults can terminate the
Host; neither static validation nor diagnostic redaction is a native-code sandbox.
The default template completes synchronously. Declared file-state schema/version
must remain compatible across replacement; see the existing state contract before
adding persistent writes. No Code Mode, advanced Hook, other platform, general
third-party ecosystem or Release support is implied by this template.
