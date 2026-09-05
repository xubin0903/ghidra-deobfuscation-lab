# Headless (batch) mode

Wrapper: `tools\ghidra-headless.ps1` → `ghidra\support\analyzeHeadless.bat`

Always uses bundled JDK 21 and passes `-scriptPath E:\Projects\ghidra\scripts`.

## Import + auto-analyze

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Import C:\bins\target.exe
```

Creates the project dir if missing. Ghidra default analyzers run after import.

## Import without analysis, then a script

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Import C:\bins\target.exe `
  -Analysis:$false `
  -PostScript ListFunctions.java
```

## Re-process an already-imported program

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Process target.exe `
  -PostScript DumpExports.java
```

## Extra script directories

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\other\ghidra-proj `
  -ProjectName other `
  -Process target.exe `
  -ScriptPath E:\Projects\other\extra-scripts `
  -PostScript TheirScript.java
```

Our `scripts\` is still on the path.

## Raw analyzeHeadless args

Anything after the named params is forwarded:

```powershell
.\tools\ghidra-headless.ps1 `
  E:\Projects\ghidra\projects\lab lab `
  -import C:\bins\a.exe `
  -processor x86:LE:64:default `
  -cspec gcc
```

Full flag list lives in the install: `ghidra\support\analyzeHeadlessREADME.html` after extract.

## Notes

- Headless needs a **project directory + project name**, not a `.gpr` path.
- `-process` matches the program name **inside** the Ghidra project.
- Java scripts are the least-fragile choice in headless. PyGhidra headless is a separate path (`pyghidra` module); do not assume `.py` Script Manager files run the same way.
- Log spam goes to stdout. Failures often hide after `ERROR REPORT`.
- Do **not** put a bare `--` before `-postScript` args. PowerShell 5.1 can bind the next token to `-Process` and you get `cannot mix -import and -process`. The wrapper strips `--` from leftover tokens. Write `dryRun` / `kb=` immediately after `-PostScript Name`.
