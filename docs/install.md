# Install and launch

## What is in this repo

| Path | What |
|---|---|
| `ghidra/` | Extracted **Ghidra 12.1.3 PUBLIC** (gitignored) |
| `jdk/` | Portable **Temurin JDK 21** (gitignored). Ghidra 12.1.3 wants JDK 21, **not** the system JDK 23 |
| `dist/` | Downloaded zips (gitignored) |
| `scripts/` | Our scripts |
| `docs/` | This documentation |
| `tools/` | Launch / fetch wrappers |
| `projects/` | Local Ghidra projects (gitignored) |

## One-shot fetch (from an empty `ghidra/` + `jdk/`)

```powershell
cd E:\Projects\ghidra
.\tools\fetch-jdk21.ps1
.\tools\fetch-ghidra.ps1 -Extract
.\tools\ghidra.ps1
```

Pinned artifacts:

| File | SHA-256 |
|---|---|
| `ghidra_12.1.3_PUBLIC_20260817.zip` | `93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54` |
| `OpenJDK21U-jdk_x64_windows_hotspot_21.0.11_10.zip` | `d3625e7cadf23787ea540229544b6e2ab494b3b54da1801879e583e1dfee0a64` |

Official Ghidra release: https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build

Do **not** extract a new Ghidra zip on top of an old install. `fetch-ghidra.ps1 -Extract` wipes `ghidra\` first.

## Launch

```powershell
.\tools\ghidra.ps1            # GUI, bundled JDK 21 on PATH
.\tools\pyghidra.ps1          # GUI via native CPython 3 (PyGhidra)
.\tools\ghidra-headless.ps1   # see docs/headless.md
```

`tools\_common.ps1` prefers `jdk\` (Temurin 21). If that folder is empty, it falls back to a system JDK **>= 21**. On this machine LaunchSupport already accepted Oracle JDK 23 (`application.java.min=21`, max empty). Still install Temurin 21 when the zip is around — that is the official pin.

```powershell
.\tools\fetch-jdk21.ps1
```

## First-run Script Manager

1. Window → Script Manager
2. Toolbar **bundle** icon (script directories)
3. Add `E:\Projects\ghidra\scripts`
4. Filter by category / name. Our scripts live under `scripts\deobfuscation`, `analysis`, `export`, `java`, `python`, `headless`.

Details: [using-scripts.md](using-scripts.md)

## Why not clone NSA/ghidra source?

The PUBLIC zip is the runnable product (native decompiler, processors, docs). The GitHub source tree is a Gradle build and needs JDK 25 + VS build tools. This lab wants a **usable Ghidra**, not a from-source build.
