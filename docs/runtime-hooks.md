# Exact-bound prepared policy hooks

The CM-G01 candidate accepts format-3 `advanced_hook` packages for one prepared
Core slot on Linux x86_64 GNU. Native acceptance is pending. The Host API is
0.10.0; the existing C ABI 1.0/2.0/2.1/2.2 tables are unchanged.

| Request | Candidate behavior |
| --- | --- |
| `core.tool_parallel_eligibility.v1` policy slot | ABI 2; before, around, replacement, after |
| Native detour, symbol/address/signature search | Unsupported; no backend installed |
| Arbitrary Rust object layout, inline body, async state machine | Unsupported |
| Hot unload | Unsupported; disable and start a fresh process |

Use capability `core.tool_parallel_eligibility.compose.v1` and resource
`core.tool_parallel_eligibility.v1` for every contribution. Other resources and
kinds are rejected before `dlopen`, as are missing or mismatched identities.
The ordinary dependency and contribution graphs still apply; competing
replacements conflict across SDK and advanced packages.

The precompiled package binds the actual values printed by this Host:

```sh
codex cm-host-identity
codex cm doctor
```

Set `kind = "advanced_hook"`, ABI major 2 and the existing `cm_mod_entry_v2` entry.
`compat.exact_host.build_id` is `host_build_id` from the embedded identity.
`compat.exact_host.executable_sha256` is the SHA-256 of the actual delivered
`bin/codex`. `compat.exact_host.patch_map_sha256` is the embedded map digest.
All three are required. A directory name, version label or copied sidecar is
insufficient. Ordinary `exact_host` packages may omit a map binding; declaring
one always requires an exact match. Ordinary SDK packages keep their ABI contract.

The sealed map contains the prepared-slot descriptor, final patched Core/runtime
and ABI/Cargo source fingerprints, compiler, target, profile definitions (including
LTO), configuration and flags.
The map excludes its own digest, the final executable hash and Host build ID.
The Host build ID covers the map inputs; the Mod binds the completed ELF after
the build. Runtime trusts the embedded map and actual executable bytes.
These source fingerprints qualify a prepared bridge; they do not establish a
machine-code detour or compatibility with an unknown Rust layout.

Core computes its original eligibility once. Next runs the downstream policy
chain synchronously, with one call allowed for its active owner, generation and
thread. Repeated, stale, foreign-owner, foreign-thread or out-of-scope calls fail.
An around short circuit must force serial execution and only stops the policy
chain. Core retains its original lock and dispatches each admitted handler once.
The final decision can restrict original eligibility, never promote it.
Fatal errors remain fatal through cleanup; cancellation does not erase them.

G01 uses independently compiled composition Mod payloads against the same frozen
Host in a compiler-free isolated consumer. Real CLI/Core checks and supplementary
private policy/lifetime probes are labeled separately. ASLR qualification needs
three fresh real CLI processes and at least two observed load bases. Unsupported
requests never trigger a local compiler, remote build or fallback installation.

Each G01 transaction has its own profile, evidence, dependency fingerprint and
checkpoint. A Python-only assertion repair reuses verified product inputs and
unrelated checks. A changed loader, slot contract or production Rust input needs
a new Host; changed Mod/probe inputs invalidate their actual consumers.

Native Mods share Host permissions. These checks are not a sandbox: invalid
pointers, aborts and stuck callbacks can terminate or hang the process.
