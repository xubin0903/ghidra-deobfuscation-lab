# Using scripts

Scripts in this lab are meant to be reused by other reverse projects. Drop new ones under `scripts/<category>/` and write `docs/scripts/<name>.md` in the same change.

## Languages

| Kind | When |
|---|---|
| **Java `GhidraScript`** | Default. GUI + headless, no Jython/PyGhidra quirks. |
| **PyGhidra (CPython 3)** | Prefer when you already have Python tooling (capstone, unicorn, z3). Launch Ghidra with `tools\pyghidra.ps1`. |
| **Jython 2.7** | Legacy. Ghidra 12 still ships it, but new scripts here are **not** Jython. |

Ghidra 12 Script Manager `.py` files may still bind to Jython unless you started in PyGhidra mode. If a Python script dies with `Ghidra was not started with PyGhidra`, relaunch via `tools\pyghidra.ps1`.

## Register the script tree (GUI)

1. Launch `.\tools\ghidra.ps1`
2. Open a program (or at least a project)
3. **Window → Script Manager**
4. Toolbar **bundle / directory** icon
5. **Add** `E:\Projects\ghidra\scripts` (the directory, not a single file)
6. Enable the script, then double-click or the green run button

Script Manager recursively indexes `*.java` and `*.py` under that root. Subfolders become categories.

## Metadata header (required)

Java:

```java
// @category Deobfuscation
// @menupath Tools.Deobfuscation.Example
// @description One-line what it does
public class ExampleScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("currentProgram=" + currentProgram.getName());
    }
}
```

Python (PyGhidra):

```python
# @category Deobfuscation
# @menupath Tools.Deobfuscation.Example
# @description One-line what it does

from ghidra.program.model.listing import CodeUnit

println("currentProgram=" + currentProgram.getName())
```

`@category` is how Script Manager groups the file. Keep it aligned with the folder (`Deobfuscation`, `Analysis`, `Export`, `Headless`).

## Headless

See [headless.md](headless.md). Always pass `-scriptPath E:\Projects\ghidra\scripts` (the wrapper does this).

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Import C:\bins\target.exe `
  -PostScript ListFunctions.java
```

## Other projects consuming this lab

Point their Script Manager / `-scriptPath` at `E:\Projects\ghidra\scripts`. Launch *their* analysis with this lab's JDK:

```powershell
E:\Projects\ghidra\tools\ghidra.ps1
# or
E:\Projects\ghidra\tools\ghidra-headless.ps1 -ProjectDir <their project> -ProjectName <name> ...
```

Do not copy scripts into the other repo unless that repo needs a frozen snapshot.

## Adding a new script (checklist)

1. `scripts/<category>/<Name>.java` or `.py`
2. `docs/scripts/<Name>.md` — purpose, when, GUI, headless, I/O, limits
3. One-line entry in `docs/scripts/README.md`
4. If it is a deobfuscation technique, link it from `docs/cookbook/`
