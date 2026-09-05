# ListFunctions

**Path:** `scripts/analysis/ListFunctions.java`  
**Lang:** Java GhidraScript  
**Category:** Analysis

## Purpose

Dump every function in `currentProgram`: name, entry address, body size (address count). Smoke-test that Script Manager / headless can see this lab's `scripts/` tree.

## When

- After auto-analyze, to see if function recovery looks sane
- As the first headless `-postScript` when wiring another project to this lab

## GUI

1. `.\tools\ghidra.ps1`
2. Open a program
3. Script Manager → Analysis → `ListFunctions.java` → Run
4. Output window prints TSV

## Headless

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Process target.exe `
  -PostScript ListFunctions.java
```

## Inputs / outputs

- Input: `currentProgram`
- Output: stdout / Ghidra console. Does not mutate the DB.

## Limits

- Size is `getBody().getNumAddresses()`, not file size.
- Thunks and externs are included.
