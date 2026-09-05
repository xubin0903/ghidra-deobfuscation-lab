# scripts/

This directory is the **Script Manager root** (`-scriptPath`). Ghidra indexes `*.java` / `*.py` recursively. Subfolders are categories.

| Folder | Category | What belongs here |
|---|---|---|
| `java/` | Java | Tiny Java smoke tests / shared helpers |
| `python/` | Python | **PyGhidra (CPython 3)** scripts only |
| `deobfuscation/` | Deobfuscation | Flatten, strings, junk CFG, VM, JNI, packers |
| `analysis/` | Analysis | Listing, xrefs, recovery |
| `export/` | Export | JSON/CSV/header dumps other projects scrape |
| `headless/` | Headless | Scripts written to run unattended |

Every new file needs `docs/scripts/<Name>.md` and a row in `docs/scripts/README.md`.

How to load: [docs/using-scripts.md](../docs/using-scripts.md)
