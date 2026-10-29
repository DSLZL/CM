# Native greeting Mod

Open as source only. Disable workspace build extensions in the editor's Extensions
view, or open the source files without opening a Cargo workspace. The supplied
VS Code settings disable automatic checks, build scripts, proc macros and formatting;
they do not control other extensions you install. No local toolchain is required.

Edit `src/lib.rs`, the package version in `Cargo.toml`/`Cargo.lock`, and `mod.toml`.
Keep the SDK Git revision exact. This standalone workspace contains only the Mod,
`cm-sdk`, and `cm-abi`; it never includes Codex Core or TUI. The binary fields in
the source manifest are placeholders sealed by the worker, not an installable package.

Submit the reviewed source to CM and use the fixed independent Linux x64 author
workflow. CM's source-side entry is `.github/workflows/cm-mod-author.yml`; the template
includes an identical reference at `.github/workflows/author.yml`. Copying it to a
different repository reports blocked; only the reviewed CM source is trusted. The actual worker
is `DSLZL/CM-build-linux-x64`. Missing cross-repository authorization is `blocked`,
with no local build fallback. Arbitrary third-party repositories need separate
trust/worker configuration and are not enabled by this template.

The worker runs locked format/lint/tests/build, checks the dependency inventory,
and packages `mod.toml` plus the actual ELF as `.cmod`. The consumer uses a prebuilt
Host and never needs this source, Cargo, a linker, or a build service.

This tool completes synchronously and retains no request after completion. An
asynchronous extension must own copied inputs, observe cancel, and complete exactly
once with QUIESCENT before request/scope teardown. SDK scope state is ephemeral;
the declared file state is preserved on disable/remove and compatible replacement.
See the author guide for the existing file-state and process-trust boundaries.

Use [the author guide](../../docs/mod-author-guide.md) and
[the user guide](../../docs/mod-user-guide.md) in the CM source repository.
