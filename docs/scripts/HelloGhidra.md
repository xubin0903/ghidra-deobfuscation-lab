# HelloGhidra

**Path:** `scripts/java/HelloGhidra.java`  
**Lang:** Java GhidraScript  
**Category:** Java

## Purpose

Smallest possible Java script: print program name, image base, language. Use this to verify Script Manager sees `scripts\` and that headless `-scriptPath` works.

## GUI

Script Manager → Java → `HelloGhidra.java` → Run.

## Headless

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Process target.exe `
  -PostScript HelloGhidra.java
```
