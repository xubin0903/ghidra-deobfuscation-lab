# tools/

Launch and fetch wrappers. Always go through these so Ghidra never sees the system JDK 23.

| Script | Does |
|---|---|
| `ghidra.ps1` | GUI (`ghidraRun.bat`) with bundled JDK 21 |
| `pyghidra.ps1` | GUI via PyGhidra / CPython 3 |
| `ghidra-headless.ps1` | `analyzeHeadless.bat` + `-scriptPath` this lab's `scripts\` |
| `fetch-ghidra.ps1` | Download + SHA-256 + optional extract into `ghidra\` |
| `fetch-jdk21.ps1` | Download Temurin 21 zip + extract into `jdk\` |
| `_common.ps1` | Shared path / env helpers. Dot-source only. |

See [install.md](../docs/install.md) and [headless.md](../docs/headless.md).
