# projects/

Local Ghidra project files (`.gpr` + `.rep`). Gitignored.

Default lab project:

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Import <binary>
```

Other reverse repos should keep **their** projects next to their samples, and only reuse this lab's `ghidra\` + `scripts\` + `jdk\`.
