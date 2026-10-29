# Managed Host and precompiled Mods

CM-M03's six acceptance checks passed at source `135e709064822e0c5004b2ee6d4f002e55559248` and worker `88560536e4c5a51aad097d54bfb08b56ff1f20cb`: [source CI](https://github.com/DSLZL/CM/actions/runs/40678252966) and [independent Linux x64 producer, runtime consumer and receipt](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40678408254). This qualifies the managed-package scope below; full upstream Core tests and release qualification remain pending.

The package targets `x86_64-unknown-linux-gnu`. The qualified runtime is the actual GitHub-hosted Ubuntu 24.04 X64 GNU environment used by the independent consumer. No glibc 2.17, other distribution, musl, Windows or macOS compatibility is claimed. Native Mods run with Host permissions; validation and `RTLD_LOCAL` provide no memory or process sandbox.

## Complete Host package

Keep the complete package together, including `bin/codex`, `bin/codex-code-mode-host`, `codex-resources/bwrap`, `codex-path/rg`, `cm-host.json`, `cm-runtime-files.json`, `dependency-inventory.json` and license notices. Component modes, hashes and resolved system-library paths are checked. An executable copied out of its package cannot serve as the managed launcher.

Use the package's absolute executable path. No global installation, shell wrapper or `PATH` change is required. M04 uses `cm-host-0.7.0-m04`, Host API 0.6.0, adding `state.files.v1` with the existing native ABI layouts. Its Linux x64 qualification and independent reuse results, exact product/worker revisions and file-state usage are recorded in [file-state.md](file-state.md). The linked M03 run above qualifies the earlier 0.6.0/0.5.0 package.

## Independent home and commands

Choose a new or empty absolute directory whose parent already exists. CM marks it as owned and makes it private. An existing nonempty directory without the CM marker is rejected, including an existing Codex profile. Host and home must not overlap the package or the default official profile. CM does not adopt, migrate or delete official configuration, authentication or sessions.

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile install /tmp/example.cmod
/opt/cm/bin/codex cm --home /srv/cm-profile list
/opt/cm/bin/codex cm --home /srv/cm-profile doctor
/opt/cm/bin/codex cm --home /srv/cm-profile disable example-tool
/opt/cm/bin/codex cm --home /srv/cm-profile enable example-tool
/opt/cm/bin/codex cm --home /srv/cm-profile remove example-tool
/opt/cm/bin/codex cm --home /srv/cm-profile launch --
/opt/cm/bin/codex cm --home /srv/cm-profile launch -- exec 'a prompt with spaces'
```

`install` accepts an absolute path to a complete ZIP `.cmod` or an equivalent directory. After the home exists, a completed package may instead be copied into its `mods/` inbox. `launch` validates and imports completed inbox packages before starting the selected generation. Names ending in `.part`, `.tmp` or `.partial` are ignored. Use a temporary name until copying finishes. Other incomplete or invalid inputs reject the launch; there is no partial activation.

Installing the same ID and content is idempotent. A different content hash under an installed ID is rejected. M04 adds explicit `replace ID PACKAGE --from OLD_CONTENT_SHA256`, preserving the enabled state and checking state compatibility before commit. The expected hash is the installed content-tree SHA, distinct from archive or payload SHA. Dependencies are neither downloaded nor enabled implicitly. Disable or remove fails if it breaks the enabled collection. Consumed inbox content cannot silently re-enable or reinstall a disabled or removed package; explicit management remains available.

An empty launch argument list enters the real TUI. Arguments after `--` remain separate OS arguments, without a shell or global command lookup. Only TUI and local `exec` business entry points are supported by this launcher. It replaces itself with the verified Host, preserving PID, exit status and signals. The child receives the independent `CODEX_HOME` and `CODEX_SQLITE_HOME`. Management bypasses upstream helper/.env initialization in an inherited official home.

## Generations, configuration and retention

`store/objects/<sha256>` contains validated package files, and `store/generations/<sha256>` contains immutable canonical generation records. One regular `cm-profile.json` selects the Host identity and generation. `.cm-owner` and `.cm-write.lock` protect ownership and writer coordination. These files are internal state, not user-editable configuration.

A writer holds the home lock, validates the existing resolver/configuration/two graphs, stages and syncs files, publishes immutable objects and a generation without replacement, then atomically renames the active descriptor. It revalidates inputs and directory identities before that rename. A pre-commit error retains the previous active descriptor. If rename succeeds but directory sync fails, `committed_durability` explicitly reports that the new descriptor is committed with uncertain durability; it does not claim rollback.

`enable`, `disable` and `remove` change references for the next process and report `restart_required`. A running process keeps owned snapshots, its generation and native libraries until process exit. Removal preserves configuration, state, sessions, prior generations and object bytes. M04's bounded offline checkpoint/restore and explicit current-data cleanup are described in [file-state.md](file-state.md); immutable history has no garbage collection. A terminated writer can leave unreachable staging files, which are never discovered as packages.

`cm-runtime.toml` retains the configuration layers described in [the manifest contract](mod-manifest.md). For managed homes the generation owns the enabled set; `enabled` in that TOML does not override management commands. Use `--cm-profile` and repeated `--cm-set` on both management and launch when choosing those configuration layers. A changed configuration needs `launch` or a management transaction to validate the next generation. Managed `cm lock` refreshes that generation; `cm lock --check` compares the current canonical plan without executing Mods. Unmanaged M01 metadata behavior remains available.

Managed homes retain configuration namespaces for removed packages as inert data, including named profiles. Only installed contracts are resolved or supplied to native code. Reinstall and rollback validate those retained values against the selected artifact's current contract; an incompatible value rejects the transaction. Explicit command-line overrides still require an installed namespace, and unmanaged homes still reject unknown namespaces.

## Backend and native requirements

Managed TUI resolves to the actual Embedded `InProcess` backend before native initialization. It skips implicit daemon discovery. Explicit remote endpoints, executor environment overrides, `environments.toml`, and `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH` are unsupported and rejected. Required package helpers must exist. There is no fallback to an official binary, old daemon or build service.

Installation uses the same bounded manifest, configuration, package and ELF parsers as startup and never calls `dlopen`, an entry point, post-install scripts, `ldd`, package managers or a compiler. It rejects links, special files, unsafe paths, malformed ZIP metadata, digest/size drift, incompatible ABI/target/capabilities and dependency or contribution conflicts. Static ELF checks reject executable/interpreter payloads, forbidden dynamic search paths/dependencies, GLIBC version requirements above the declaration or current runtime, and GNU mandatory CPU properties above the x86-64 baseline. These metadata checks do not analyze every machine instruction or qualify every native symbol/version combination. Missing runtime libraries still produce a real startup failure.

## Evidence and rebuild boundary

The independent producer records Host source/toolchain/native inputs and original successful Cargo-check provenance. Its separate cache-none consumer receives frozen packages without a product checkout or compiler and runs the public CLI, actual PTY TUI, native tools/context and builtin commands. It records malformed inputs, writer races/faults, writable official-profile protection, generation retention, exit/signal behavior, missing helpers/libraries and recovery under an outer execution/network observer. Internal precise fault tests are identified separately from the published Host.

The six M03 reports are `prebuilt-host-package.json`, `drop-in-install.json`, `independent-prebuilt-launcher.json`, `atomic-mod-installation.json`, `prebuilt-backend-selection.json` and `native-runtime-dependencies.json`. P01–M02 regression reports remain separate. A green workflow alone is insufficient: source/worker SHAs, run/attempt/request, successful jobs, artifact digests and receipt must match the observed results.

A change to the runtime, CLI/TUI patch, dependency lock or another sealed Host input requires a new H. A later driver/fixture-only correction can reuse the exact verified H and its original checks; current acceptance still runs. Private Core test compilation is recorded separately from building the production CLI. This does not establish the full S04 performance matrix, complete Core suite or release readiness.
