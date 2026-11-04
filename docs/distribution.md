# CM experimental distribution

CM is a custom Codex Host and independently precompiled native Mods. It is not an official OpenAI release. The qualified distribution target is GitHub-hosted Ubuntu 24.04, X64, x86_64-unknown-linux-gnu. Other targets and general release readiness remain unqualified.

## Verify the Host before running it

The bootstrap trust anchor is an independently obtained GitHub CLI, its reviewed archive SHA-256 and the pinned trusted-root material. Do not run a candidate Host or its bundled verifier to establish that candidate's trust.

The canonical policy is crates/cm/src/distribution-policy.json. It pins the source and worker repository names AND numeric IDs, signing workflow, main ref, issuer and verifier release/archive digest. distribution-root.jsonl fixes the offline roots. Obtain these from a previously trusted copy or review their digests through an independent channel. Download the pinned verifier before going offline; check its archive SHA-256 before extracting its executable.

Use that independent verifier's attestation verify command with the receipt as subject, the supplied bundle, --custom-trusted-root, --repo DSLZL/CM-build-linux-x64, --signer-workflow DSLZL/CM-build-linux-x64/.github/workflows/build.yml, --cert-identity https://github.com/DSLZL/CM-build-linux-x64/.github/workflows/build.yml@refs/heads/main, --cert-oidc-issuer https://token.actions.githubusercontent.com, --source-ref refs/heads/main, --source-digest and --signer-digest set to receipt.signer.workflow_sha, --deny-self-hosted-runners and --format json. Require success, the fixed numeric sourceRepositoryIdentifier, verified timestamps, the SLSA v1 predicate, the exact receipt subject digest and the matching signer run/attempt invocation URL.

Then check the receipt schema/policy, materials' digests and every unpacked asset, using assets.json and sbom.spdx.json. For a downloaded archive also compare its raw bytes' SHA-256 and size before extraction. GitHub's uploaded ZIP digest, the raw inner archive digest, the canonical object digest, manifest digest and payload digest have different roles. None substitutes for another. An externally signed receipt avoids an archive containing its own digest.

Source materials identify the original upstream commit/tree, CM delta, original/final lock roles, toolchain/flags/native inputs, resource generators and independent Mod target receipts. A current test/signature run does not rewrite the original compilation origin. Source attachments are data; installation never executes build.rs, post-install.sh, proc macros or a source archive.

## Offline Mod installation

After establishing Host trust independently, copy the Mod, its canonical receipt and offline bundle. The trusted Host uses its compiled-in helper digest and embedded policy/roots:

    codex cm --home /absolute/private/profile install /absolute/mod.cmod --receipt /absolute/mod.json --bundle /absolute/bundle.jsonl

The same paired flags apply to replace. Both flags are required together. Invalid or absent evidence in this explicit mode rejects the operation; it never falls back to a development install. Verification precedes an identical-object/no-op return. Directory installs bind the same canonical files as archive installs; raw archive checks apply when transporting an archive.

A legacy install without flags remains available for development and is reported as unverified_provenance. scan does not create trusted evidence. An explicit, successful verified install can associate proof with identical existing bytes. Immutable generation records retain receipt/bundle bytes, not a permanent trusted boolean. Listing, activation and runtime preparation revalidate the association against current object bytes and policy. New replacement bytes lose the old association.

## Provenance and native execution

A verified source/signature is an origin statement. A candidate signature is not consumer acceptance or a release approval. ABI, capability, exact Host, CPU/glibc, native dependencies and state compatibility remain independent gates.

Mods run native code in the Host process with the same user privileges. Provenance verification does not sandbox a Mod. Review the author and actual code before enabling it. Installation/list/doctor do not load the Mod; an explicitly selected runtime or command can run ELF constructors, entrypoints and callbacks. There is no local compiler, remote combination build or JIT installer, and no live hot unload guarantee.

M04 rollback covers only the declared, owned managed file state and its compatibility rules. It cannot undo arbitrary filesystem/network effects, external services or writes made outside that ownership model. An old valid signature does not make incompatible state safe to restore.

## SBOM and acceptance boundary

The SPDX-2.3 document covers actual distributed file digests and resolved production components. NOTICE.json records collected license texts and declarations; build tools/proc macros, static/runtime dependencies, system libraries and the verifier's embedded Go modules keep separate roles. Missing source/license/NOTICE/material or asset mappings reject signing. These are collected facts, not a legal compliance certification.

The order is producer/current source and quality checks, material validation, candidate attestation, disconnected compiler-free consumer, complete syscall audit, and final worker receipt/API reconciliation. Failed rounds remain failed evidence. Only the signing job has OIDC/attestation write permission; consumers have read permission and no cache authority.

Offline proof has no live revocation or newest-release guarantee. Updating the verifier, policy or trusted roots requires a newly reviewed Host. Previously valid contents must still satisfy current policy, ABI and state checks. The five S01 checks and the controlled retry/warm-run evidence must be qualified on the independent worker before acceptance; a source check or a signature alone does not qualify a release.
