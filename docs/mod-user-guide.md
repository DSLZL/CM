# Precompiled Mods: user commands

Use a verified Linux GNU x64 Host package and its absolute executable path. Install
the package's declared runtime libraries first. Compare the exact worker run,
attempt, source/workflow revisions, artifact digests and receipt before trusting it.
There is no local toolchain or per-combination build service in this flow.

Keep an independent home for this exact Host. The official Codex home stays separate;
automatic profile adoption between different Host builds is unsupported.

```sh
/opt/cm/bin/codex cm-host-identity
/opt/cm/bin/codex cm --home /srv/cm-profile install /downloads/native-mod.cmod
/opt/cm/bin/codex cm --home /srv/cm-profile list
/opt/cm/bin/codex cm --home /srv/cm-profile plan
/opt/cm/bin/codex cm --home /srv/cm-profile doctor
/opt/cm/bin/codex cm --home /srv/cm-profile launch -- exec "Use native-mod__greet"
/opt/cm/bin/codex cm --home /srv/cm-profile disable native-mod
/opt/cm/bin/codex cm --home /srv/cm-profile launch -- exec "Continue without the Mod"
/opt/cm/bin/codex cm --home /srv/cm-profile enable native-mod
```

Enable, disable, replace and remove change the next startup. Restart existing
runtimes to apply them. Disable/remove preserve data and immutable objects.
`cm launch --` without business arguments enters the actual local Embedded TUI.
Use `--cm-profile NAME` and `--cm-set MOD.FIELD=TOML_VALUE` for existing configuration
selection; `profile` and `run` are not CM subcommands.

To update, obtain a separately built compatible package, take the exact installed
content hash from `list`'s `mods["native-mod"].content_sha256`, then replace explicitly:

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile replace native-mod /downloads/native-mod-v2.cmod --from INSTALLED_CONTENT_SHA256
/opt/cm/bin/codex cm --home /srv/cm-profile remove native-mod
```

`list`, `plan`, and `doctor` are read-only: no native entry, constructor, install
script, dynamic-loader probe, compiler or network build. Static success remains
`qualification.verified=false`. Runtime libraries and native initialization require
explicit execution; native Mods have the process's privileges and are not sandboxed.

Metadata output schema 2 uses `plan_projection`, with untrusted provenance text
replaced by its declaration hash. It is a display projection, not a canonical plan.
`plan_sha256` and `lock_sha256` still identify the internal unredacted plan/lock.
Structured JSON errors retain code/stage/Mod/field, expected/actual,
native-execution status and a next action. Text errors retain stage/code/Mod,
native-execution status and the next action. Raw error text and unverified URLs
are omitted. Compare the Host identity and verified author receipt for actual
source/ABI/CI attribution.
Exclusive conflicts retain safe contribution identities in `related_contributions`.

`cm lock` writes explicitly; `cm lock --check` checks explicitly. File state,
checkpoints, `rollback --restore` and exact cleanup follow [state management](file-state.md).
Unsupported ABI/capability/backend/platform, missing libraries, incompatible state,
invalid origin, unavailable CI or expired artifacts fail explicitly. Obtain a
compatible prebuilt artifact; do not install a compiler or build locally to repair it.
