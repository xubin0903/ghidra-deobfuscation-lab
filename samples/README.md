# samples/

Smoke-test binaries for scripts in this lab. Gitignored except this README and tiny helpers.

Keep samples that belong to another reverse project in **that** project. Copy **into this folder** only if you need a local fixture, and only pure / standalone test samples.

## Layout

- `cff/aarch64/` — AArch64 OLLVM/Hikari CFF test `.so`s (CFF / BCF / indirect-branch / modified-state variants)
- `cff/x64/`, `cff/x86/` — x86-64 / x86 CFF test binaries + recovered references
- `cff/ref/` — reference deobfuscators for cross-checking
- `out/` — script run logs and `*.patch.json` / `*.cff-kb.json` outputs

Import a sample with `-noanalysis` when a script linear-disassembles itself; otherwise auto-analyze first. See each script's doc under `docs/scripts/`.
