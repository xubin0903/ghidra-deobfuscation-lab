# samples/

Smoke-test binaries for scripts in this lab. Gitignored except this README and tiny helpers.

Keep samples that belong to another reverse project in **that** project. Copy **into this folder** only if you need a local fixture, and only pure / standalone test samples.

## Layout

- `cff/aarch64/` — AArch64 OLLVM/Hikari CFF test `.so`s (CFF / BCF / indirect-branch / modified-state variants)
- `cff/x64/`, `cff/x86/` — x86-64 / x86 CFF test binaries + recovered references
- `cff/ref/` — reference deobfuscators for cross-checking
- `deflat-testsuite/` — **public, reproducible fixtures**: `tools\fetch-samples.ps1` downloads them (pinned commit, SHA-256 checked in `tools\fetch-samples.sha256`), `tools\import-samples.ps1` puts them into the regression project. They come from the open-source deobfuscator [cq674350529/deflat](https://github.com/cq674350529/deflat): a 30-line `check_password()` and a 20-line `target_function()` (sources included) that its author compiled with Obfuscator-LLVM `-fla` (flattening: ARMv7, x86-64, Mach-O arm64) and `-bcf` (bogus control flow: ARMv7, x86) so that deobfuscation tools have something safe to be tested on. They are not third-party software and do nothing but check a 4-character string / print a number.
- `out/` — script run logs and `*.patch.json` / `*.cff-kb.json` outputs

Import a sample with `-noanalysis` when a script linear-disassembles itself; otherwise auto-analyze first. See each script's doc under `docs/scripts/`.

## Reproducing the regression fixtures from scratch

```powershell
.\tools\fetch-samples.ps1      # samples\deflat-testsuite\  (12 files, ~230 KB)
.\tools\import-samples.ps1     # -> projects\cfftest, folders arm32 / aarch64 / x64 / x86, auto-analysis on
.\tools\cff-regress.ps1 -Only arm32_cp,x64_cp,macho_cp,arm32_bcf,x86_bcf
```

The other fixtures listed in `tools\cff-regress.expected.json` (`sample_cff.so`, the `-O2` SDK, `CFF_full*.bin`, `ezam`) are local and not redistributed; the harness only runs the fixtures whose program exists in the project.
