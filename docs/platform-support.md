# Linux runtime qualification

CM-G04 is a candidate qualification for prebuilt Host and Mod packages on
`x86_64-unknown-linux-gnu`. Its five acceptance checks have not run yet.
Earlier M03/G03 results retain their original scope and execution identities.

| Environment or producer | G04 status |
| --- | --- |
| GitHub-hosted ubuntu-24.04 X64, strict runtime rootfs | Pending current qualification |
| Cargo producer | Existing build backend; current qualification pending |
| Bazel producer | Deferred; not implemented |
| Older glibc, other distributions or CPU models | Deferred; no inferred support |
| Windows, macOS, ARM64, musl | Deferred |

The binary contract records ELF architecture, interpreter, native libraries,
versioned symbol requirements, mandatory GNU CPU properties, file hashes and
resolved package versions. The highest imported GLIBC symbol is an encoded
requirement, not proof that the entire package works on that old glibc. Build
flags and GNU notes also do not prove every instruction supports an older CPU.
Only the actual tested runner CPU, kernel, glibc and rootfs may be marked verified.
The rootfs identity is a content inventory SHA-256, not an OCI image digest.
When a valid checkpoint is reused, its verified CPU/kernel and execution origin
stay attached to that historical execution. The current validation runner and
rootfs content inventory are recorded separately; reuse does not certify another CPU.

The canonical package contains `bin/codex`, `bin/codex-code-mode-host`,
`codex-resources/bwrap`, `codex-path/rg`, Host identity, runtime and dependency
inventories, and licenses. `codex app-server` is a subcommand of the delivered
CLI. Embedded/InProcess is exercised through the real managed terminal UI.
A standalone `codex-app-server` executable package is not shipped or qualified.
Legacy Host binaries under the qualification fixture are test references,
not additional package variants.

The strict consumer receives frozen binaries and audited fixture drivers. It
has no compiler, project checkout, build credentials or external build-service
access. Python belongs to the test harness, not the product dependency list.
Controlled local providers remain available inside its isolated network.
Native Mods still share Host process permissions; qualification is not a native
code sandbox or a promise to undo arbitrary native side effects.

The five reports are `linux-binary-contract.json`, `compiler-free-runtime.json`,
`linux-runtime-support.json`, `prebuilt-package-inventory.json` and
`runtime-qualification-failures.json`. They retain exact source/worker/run,
original producer and per-case execution origins. Missing libraries are tested
by removing a real rootfs dependency, with a successful managed profile and
recovery inside one checkpoint. Helper, inventory, package, ABI and loader
environment failures also each have a private profile and recovery transaction.
Existing actual ELF/glibc/CPU and backend failures retain
their original independent checks and raw evidence.

Changes to Python cases do not enter the Host build identity. Valid producer
and unrelated checkpoint results remain reusable. A change to the actual outer
audit contract invalidates affected checkpoints even when the Host is unchanged.
This qualification does not complete the parent integration or release gate.
