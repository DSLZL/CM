# Linux runtime qualification

CM-G04 qualifies prebuilt Host and Mod packages on `x86_64-unknown-linux-gnu`
within the recorded environment below. All five acceptance checks passed in
[worker run 41340572671](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/41340572671).
Earlier M03/G03 results retain their original scope and execution identities.

| Environment or producer | G04 status |
| --- | --- |
| GitHub-hosted ubuntu-24.04 X64, strict runtime rootfs | Verified within the recorded environment |
| Cargo producer | Used; audited prebuilt outputs qualified |
| Bazel producer | Deferred; not implemented |
| Older glibc, other distributions or CPU models | Deferred; no inferred support |
| Windows, macOS, ARM64, musl | Deferred |

The observed runtime used glibc 2.39, kernel `7.0.0-1017-azure`, an AMD EPYC
9V74 80-Core Processor and runner image `ubuntu24 / 20261026.354.1`. Its rootfs
content inventory SHA-256 is
`f4f2df94bf562a263eb0cee5c18c435663137b1f004c8d1feb8cd75c260c21c9`.
The CLI and Code Mode helper import GLIBC symbols through 2.39; the seven
audited example Mods import symbols through 2.34. These are encoded requirements,
not additional qualified environments.

Qualification source was `343badcca36d1dceed640bcc3cee6eb693a98151` and worker
revision was `20bf70fd641fd8395fa70242453613ad4c0ad364`. The run reused the exact
producer artifacts from run `41335382854`, retained 189 passed checkpoints and
executed seven repaired checks: all 196 passed. No Host/Mod compilation or large
product re-upload occurred in the replay. The consumer audit recorded zero
compiler, linker, Mod JIT or build-service calls.

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
