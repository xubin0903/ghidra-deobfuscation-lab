# tools/

Launch and fetch wrappers. Always go through these so Ghidra never sees the system JDK 23.

| Script | Does |
|---|---|
| `ghidra.ps1` | GUI (`ghidraRun.bat`) with bundled JDK 21 |
| `pyghidra.ps1` | GUI via PyGhidra / CPython 3 |
| `ghidra-headless.ps1` | `analyzeHeadless.bat` + `-scriptPath` this lab's `scripts\` |
| `fetch-ghidra.ps1` | Download + SHA-256 + optional extract into `ghidra\` |
| `fetch-jdk21.ps1` | Download Temurin 21 zip + extract into `jdk\` |
| `cff-regress.ps1` | One-command regression for the CFF suite: scratch copy of the lab project → `CffDeflatten all` per fixture → counts vs `cff-regress.expected.json` → `undo` → byte-exact check with `HashMemory`. Exit 1 on regression |
| `cff-regress.expected.json` | The fixture list + recorded baseline numbers the regression compares against |
| `fetch-samples.ps1` / `fetch-samples.sha256` | Download the public test-suite binaries (cq674350529/deflat: OLLVM `-fla` / `-bcf` builds of two tiny test programs, pinned commit, SHA-256 checked) into `samples\deflat-testsuite\` |
| `import-samples.ps1` | Import those into the regression project (`projects\cfftest`, folders by architecture) |
| `_common.ps1` | Shared path / env helpers. Dot-source only. |

See [install.md](../docs/install.md) and [headless.md](../docs/headless.md).

## CFF regression

```powershell
.\tools\cff-regress.ps1                  # all fixtures (~6 min; the -O2 SDK is most of it)
.\tools\cff-regress.ps1 -Quick           # skip fixtures marked "slow" (~2 min)
.\tools\cff-regress.ps1 -Only sample_cff,x64
.\tools\cff-regress.ps1 -KeepScratch     # keep the %TEMP% copy + all logs / patch jsons
.\tools\cff-regress.ps1 -UpdateExpected  # record the current numbers as the new baseline
```

Per fixture it reports `patched / verified / reverted / full / partial / lowconf / cave-exhausted / patches / undoExact`. Hard failures (exit 1, scratch kept): fewer verified or more reverted than the baseline, `undo` not byte-exact or not function-count-exact, patches reported but bytes unchanged, error lines in the log. Warnings: fewer full-mode functions or a changed low-confidence count. Fixtures whose program is not in the project are skipped, not failed. Run it before and after every engine change; only update the baseline after reading the plan diff.

Seven of the fixtures (five CffDeflatten, two BcfClean) are public and reproducible on any machine (`fetch-samples.ps1` + `import-samples.ps1`, see [samples/README.md](../samples/README.md)); the others are local binaries under `projects/cfftest` that are not redistributed.
