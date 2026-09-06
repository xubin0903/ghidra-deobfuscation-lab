# Ghidra Deobfuscation Lab

A [Ghidra](https://github.com/NationalSecurityAgency/ghidra) workstation layout plus a library of analysis / deobfuscation scripts, grown while reversing obfuscated Android/native targets.

The main piece is the **control-flow-flattening suite** (`scripts/deobfuscation/`): [`CffScan`](docs/scripts/CffScan.md) detects OLLVM / Hikari / Arkari flattened functions, [`CffRecover`](docs/scripts/CffRecover.md) recovers the real CFG by concrete p-code emulation (no pattern matching of the state encoding), and [`CffDeflatten`](docs/scripts/CffDeflatten.md) patches the case tails so the decompiler shows plain `if/for` again — with a multi-seed re-emulation verify, a structural check, and a byte-exact undo log. Validated on x86, x86-64 and AArch64 fixtures including a 235-function `-O2` tail-merged SDK (227 functions patched and verified, 152 of them with the dispatcher removed entirely); `tools/cff-regress.ps1` re-runs the whole fixture set and compares against a recorded baseline. [`BcfClean`](docs/scripts/BcfClean.md) folds OLLVM bogus-control-flow opaque predicates the same way (constant conditions on never-written globals, emulation verify, undo). Seven of the regression fixtures are public and reproducible (`tools/fetch-samples.ps1`). Details and honest limits are in each script's page. See the [cookbook](docs/cookbook/README.md) for the playbooks.

Current install this lab is pinned to: **Ghidra 12.1.3 PUBLIC** (tag `Ghidra_12.1.3_build`, 2026-08-18).

```
scripts/    Java + PyGhidra scripts (the actual content of this repo)
docs/       how-to + one page per script + cookbook
tools/      launch / headless / fetch wrappers (PowerShell)
ghidra/     Ghidra itself          (NOT in git — tools\fetch-ghidra.ps1 downloads it)
jdk/        Temurin JDK 21         (NOT in git — tools\fetch-jdk21.ps1; Ghidra 12.1.3 needs JDK 21)
projects/   local Ghidra projects  (NOT in git)
samples/    test binaries          (NOT in git; the fixtures referenced in the docs are not redistributed)
```

The scripts themselves are portable: point any Ghidra 12.x Script Manager at `scripts/` (bundle icon → add directory). The PowerShell wrappers assume the layout above on Windows; on Linux/macOS call `analyzeHeadless` yourself with `-scriptPath` set to the `scripts/*` directories.

## Quick start

```powershell
# GUI
.\tools\ghidra.ps1

# Headless import + analyze
.\tools\ghidra-headless.ps1 -ProjectDir E:\Projects\ghidra\projects\lab -ProjectName lab -Import E:\path\to\binary.exe

# PyGhidra (native CPython)
.\tools\pyghidra.ps1
```

First GUI run: **Window → Script Manager → bundle icon (script directories) → add** `E:\Projects\ghidra\scripts`.

## Requirements

| Piece | This machine / this repo |
|---|---|
| OS | Windows 11 x64 |
| Ghidra | 12.1.3 PUBLIC under `ghidra\` |
| JDK | Temurin 21 bundled under `jdk\` — **do not use system JDK 23** |
| Python | 3.12.5 (optional, PyGhidra / Debugger) |

Official release:

- File: `ghidra_12.1.3_PUBLIC_20260817.zip`
- SHA-256: `93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`
- https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build

## Docs

- [Install / launch](docs/install.md)
- [How to load and run scripts](docs/using-scripts.md)
- [Headless](docs/headless.md)
- [Script catalog](docs/scripts/README.md)
- [Deobfuscation cookbook](docs/cookbook/README.md)

## Re-download / upgrade

```powershell
.\tools\fetch-ghidra.ps1          # latest PUBLIC zip into dist\
.\tools\fetch-ghidra.ps1 -Extract # also unpack into ghidra\
```

Never extract a new Ghidra zip **on top of** an old install. Wipe `ghidra\` first.

## License

MIT (see [LICENSE](LICENSE)). Ghidra itself is Apache-2.0 and is not redistributed here. The CFF detection heuristic follows mrphrazer's flattening score; the dispatch-table tracer follows xkilldash9x's write-up — both credited in the respective docs.
