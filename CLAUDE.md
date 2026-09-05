# Ghidra Script Lab

This repo is a **local Ghidra workstation + script library** consumed by other reverse-engineering projects. It is not an application product.

## Hard rules

- Web lookup: use Cursor's **built-in** `WebSearch` / `WebFetch`. Do **not** route web access through the Tavily MCP tools in this project.
- Prefer local sources first: Ghidra's own `*-src.zip` under `ghidra\Ghidra\**\lib\` answers most API questions offline.
- GitHub downloads: `gh` / HTTPS. Never clone the entire NSA source tree into this repo unless asked.
- Never run a byte-writing script (`CffDeflatten` without `dryRun`, `undo=`) against the shared project under `projects\`; copy the project directory to `%TEMP%` and work on the copy.

## Layout

```
ghidra/          extracted Ghidra PUBLIC install (gitignored)
jdk/             portable Temurin JDK 21 for this Ghidra (gitignored)
dist/            downloaded zips (gitignored)
scripts/         our Ghidra scripts (Java / PyGhidra / categorized)
  java/
  python/
  deobfuscation/
  analysis/
  export/
  headless/
docs/            how to run Ghidra + per-script docs
  scripts/       one markdown file per script
  cookbook/      obfuscation playbooks
tools/           launch / headless wrappers
projects/        local Ghidra projects (gitignored)
samples/         optional test binaries (gitignored)
```

## Runtime

- Ghidra **12.1.3 PUBLIC** (`ghidra_12.1.3_PUBLIC_20260817.zip`)
- Official pin: **JDK 21 64-bit** (Temurin) under `jdk\`. `application.java.min=21`, max empty, so JDK 23 on this box is a working fallback until 21 is extracted.
- Launch via `tools\ghidra.ps1` so `JAVA_HOME` is the bundled JDK (or the >=21 fallback).
- Headless: `tools\ghidra-headless.ps1`
- PyGhidra (CPython 3.9–3.14): `tools\pyghidra.ps1` — machine has Python 3.12.5

## Scripts

- Put new scripts under `scripts/<category>/`.
- Every script gets a matching `docs/scripts/<name>.md` covering: purpose, when to run, GUI steps, headless example, inputs, outputs, limitations.
- Java `GhidraScript` is the default (works GUI + headless). Python scripts target **PyGhidra**, not Jython 2.7.
- Register the `scripts/` tree in Script Manager (bundle icon → add directory). See `docs/using-scripts.md`.

## Deobfuscation

This lab grows scripts as obfuscated targets show up: control-flow flattening, bogus control flow, string encryption, junk code, custom VMs, JNI name recovery, packer stubs. Do not dump random malware samples into the tree unless asked.

## Other projects

Other reverse projects should:

1. Call `e:\Projects\ghidra\tools\ghidra.ps1` (or headless wrapper).
2. Import their binary into a project under that other repo, **or** under `e:\Projects\ghidra\projects\`.
3. Point Script Manager at `e:\Projects\ghidra\scripts`.
