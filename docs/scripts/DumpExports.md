# DumpExports

**Path:** `scripts/export/DumpExports.java`  
**Lang:** Java GhidraScript  
**Category:** Export

## Purpose

Dump Ghidra **external entry points** (PE export table / ELF exported symbols) as a JSON array: `name`, `addr`, `kind`. Other projects can scrape the console output.

## When

- You need a symbol list for a Frida / IDA / another-Ghidra pass
- After auto-analyze, to see if the loader recovered exports

## GUI

Script Manager → Export → `DumpExports.java` → Run. Copy the JSON from the console.

## Headless

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Process target.exe `
  -PostScript DumpExports.java
```

Redirect stdout if you want a file. The wrapper does not write JSON to disk (keep that in the consuming project).

## Inputs / outputs

- Input: `currentProgram` symbol table
- Output: JSON array on stdout, then `count=N`
- Does not mutate the DB

## Limits

- This is **exports / entry points**, not the full function list. Use `ListFunctions` for that.
- Forwarded PE exports and delayed imports may not show up the way you expect.
- Names are Ghidra primary symbols, which may already have been renamed.
