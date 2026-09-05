# HeadlessSummary

**Path:** `scripts/headless/HeadlessSummary.java`  
**Lang:** Java GhidraScript  
**Category:** Headless

## Purpose

Print a one-screen summary of `currentProgram` (name, path, language, compiler spec, image base, function count, export count). Default `-postScript` when another project first wires this lab.

## When

- After a headless import, to confirm the loader picked the right language
- CI / batch logs

## Headless

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Import C:\bins\target.exe `
  -PostScript HeadlessSummary.java
```

Works in GUI too, but it is meant for unattended runs.

## Inputs / outputs

- Input: `currentProgram`
- Output: `key=value` lines on stdout
- Does not mutate the DB
