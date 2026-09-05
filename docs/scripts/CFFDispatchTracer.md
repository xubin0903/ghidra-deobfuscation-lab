# CFFDispatchTracer

**Path:** `scripts/deobfuscation/CFFDispatchTracer.java`  
**Lang:** Java GhidraScript  
**Category:** Deobfuscation  
**Targets:** OLLVM / Hikari **control-flow flattening** (CFF) on ARM64 first, ARM32 / x86-64 as a bonus  
**Does not:** emulate, symbolic-execute, or rewrite the original CFG into a linear listing

Algorithm is the one in [xkilldash9x / cff_expose.md](https://gist.github.com/xkilldash9x/e8ee393a5c681677b38c58f178e203a4): CFF is information-preserving. The dispatcher **must** keep a table of code pointers in a readable data section. Recover the table statically, you recover the cases.

## What the obfuscation looks like

Canonical ARM64 OLLVM/Hikari dispatcher (from the gist):

```
dispatcher:
    ADRP  X8, dispatch_table
    ADD   X8, X8, :lo12:table
    LDR   X9, [data_region, X0]     ; state index
    LDR   X10, [X8, X9, LSL #3]     ; table[state]
    BR    X10                       ; case N

case_N:
    ; original basic block
    MOV   W0, #next_state           ; often MBA-wrapped
    STR   W0, [data_region, ...]
    B     dispatcher
```

Three artifacts that are **always** there:

| Artifact | Where | How this script finds it |
|---|---|---|
| Dispatch table | `.data` / `.bss` / `__data` / dump `RAM` | contiguous pointer-size values that rebase into `.text` |
| State variable | writable data | not recovered as a named global (future work); MBA immediates are annotated instead |
| Case blocks | `.text`, often **inside** a mega-function, not at `FUN_*` entries | table dests |

### Positive fingerprints (run the script)

- Huge function (`JNI_OnLoad` tens of KB) whose graph is a hairball / one giant switch
- Indirect `BR` / `BX` / `jmp reg` that Ghidra did not turn into a switch
- `.data` filled with 8-byte values that look like code addresses (ASLR-tagged in a dump)
- Decompiler spews MBA: `((-x \| K) + (-x & K)) ^ 0xFFFFFFFF`
- Exports are only `JNI_OnLoad` + a couple of stubs; real natives come from `RegisterNatives` **after** the CFF body

### Negative / do **not** expect miracles

- **VMProtect / Themida / custom bytecode VM** — no 1:1 native CFG. Use the [custom-vm cookbook](../cookbook/custom-vm.md).
- **Bogus control flow / opaque predicates** only, no dispatch table — [bogus-control-flow](../cookbook/bogus-control-flow.md).
- **Switch-based CFF that already lives in `.text` as `add pc, …` ARM tables** — Ghidra may already have this; try `AddReferencesInSwitchTable` first.
- **CFF that encrypts the table** or builds it at runtime — static scan sees zeros / garbage. Need a dump **after** init, or a decrypt pass first.

## Algorithm (three strategies + cluster)

Matches gist §2.1–2.3.

**A — Reference scan.** Walk every instruction in executable blocks. For each xref into a data/bss block, read pointer-size bytes, try ASLR rebase, keep it if the dest lands in `.text`. Then grow forward/backward while the next slot is also a code pointer. This is the gist "Strategy A" and usually finds the primary table.

**B — Raw / ASLR scan.** After A, vote an ASLR **slide** (`dest_offset - raw_stored`). Then linearly scan initialized data blocks (skip >16MB, skip `.got`/`.plt`/`.eh_frame`) and keep every pointer that rebases into `.text`. Covers tables nobody in `.text` has a direct xref to yet (common in dumps).

**C — Trampoline.** Small functions (≤160 bytes) that contain `BR`/`BX`/`jmp reg` **and** a data xref. Follow those xrefs and grow. Gist "Strategy C".

**Cluster.** Consecutive hits `ptrSize` apart become a table. Score:

- `interior` = dests that are **not** a tiny function entry (CFF cases sit in the middle of a mega-function; vtable slots are `FUN_*` entries)
- unique-dest ratio: a vtable is almost all unique method pointers; a CFF table often repeats dispatcher/return stubs
- a computed-branch that xrefs the table **forces** `likelyCff = true`

Default: a table is CFF if `n >= minTable` (6) **and** (`interior/n >= 0.40` **or** unique ratio `< 0.55`). Dispatcher xref overrides that.

**MBA pass.** ARM64 `MOVZ`/`MOVK`/`MOVN` windows reconstructed into a 32-bit immediate; plus plain `MOV #imm`. Annotate values that look like a state index (`< 0x2000`) or a two-half MBA key. **Does not algebraically simplify** the gist example `((-x|K)+(-x&K))^~0` — that is the next script. You still get the constants sitting on the listing.

**Apply (default).** For each likely table:

- label `cff_dispatch_table_<addr>`
- define `pointer32` / `pointer64` on each slot
- DATA xref slot → dest
- bookmark category `CFF` on slots and on dispatcher `BR`
- EOL comments `CFF[i] -> dest` / `CFF case table=… idx=…`
- optional `cff_<table>_<i>` labels on unnamed dests

**JumpTable override (opt-in).** Same mechanism as Ghidra's own `SwitchOverride.java`: `COMPUTED_JUMP` refs + `JumpTable.writeOverride` + `CreateFunctionCmd.fixupFunctionBody`. **Only** when the dispatcher is in a function **and** dest count is in `[2, maxSwitch]` (default 96). A 5k-slot JNI_OnLoad table must **not** be jammed into one switch — Ghidra will die. Leave the dialog on **No** for mega-tables.

## GUI

1. Import the **ELF / so / memory dump** (if the table is filled at runtime, dump **after** `JNI_OnLoad`).
2. Auto-analyze. You do **not** need a perfect decompiler.
3. Script Manager → Deobfuscation → `CFFDispatchTracer.java`.
4. Dialog: *Apply JumpTable override on SMALL local tables?*  
   - **No** (recommended first run, especially SDK mega-functions)  
   - **Yes** only if you already know this binary uses per-function tables of tens of dests, not thousands
5. Optional: write `<binary>.cff-kb.json` next to the file.
6. Console: `Phase A/B/C`, `cffTables`, `cffSlots`, `dispatchers`.
7. Bookmarks window → filter category **CFF**. Graph / decompiler on a dispatcher `BR` should now see dests if you enabled override.

Second run on the same DB reuses CFF bookmarks as a knowledge base (gist iterative KB).

## Headless

Scan + annotate, no switch override, write KB + DOT:

```powershell
E:\Projects\ghidra\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\<other>\ghidra-proj `
  -ProjectName lab `
  -Process libfoo.so `
  -PostScript CFFDispatchTracer.java `
  kb=E:\Projects\<other>\out\libfoo.cff-kb.json `
  dot=E:\Projects\<other>\out\libfoo.cff.dot
```

Do **not** put a bare `--` before script args. PowerShell 5.1 binds the next token to `-Process`. `ghidra-headless.ps1` already treats leftover tokens as `-postScript` args and strips `--` if you slip.

Small-table override + consume previous KB:

```powershell
... -PostScript CFFDispatchTracer.java applySwitch kbIn=E:\Projects\<other>\out\libfoo.cff-kb.json kb=E:\Projects\<other>\out\libfoo.cff-kb.json
```

Dry run (console only, no DB writes):

```powershell
... -PostScript CFFDispatchTracer.java dryRun minTable=8
```

### Script args

| Arg | Default | Meaning |
|---|---|---|
| `applySwitch` | off | JumpTable override for tables with `2..maxSwitch` dests |
| `dryRun` | off | no bookmarks / labels / pointers / overrides |
| `noMba` | MBA on | skip MOVZ/MOVK scan |
| `minTable=N` | 6 | minimum contiguous slots to call it a table |
| `maxSwitch=N` | 96 | override size cap |
| `kb=path` | none | write JSON knowledge base |
| `kbIn=path` | none | load JSON before scanning (iterative) |
| `dot=path` | none | Graphviz of dispatcher → dests (big tables collapse to one node) |

GUI with no args pops the override question. Headless with no args = annotate only (safe).

## Inputs / outputs

**Input:** analyzed `currentProgram` (xrefs help strategy A; dumps still work via B).

**Output (DB):**

- Bookmarks `Analysis / CFF`
- EOL comments on slots, dests, dispatchers, MBA immediates
- pointer data + DATA xrefs
- optional JumpTable override

**Output (files, optional):** JSON KB (`tables[].entries[{idx,slot,dest}]`, `dispatchers`, `mba`, `slide`) and a DOT graph other projects can render.

Does **not** patch bytes. Does **not** decrypt strings. Does **not** invent JNI names (see [jni-names](../cookbook/jni-names.md) after the table is labeled).

## How other reverse projects should use this

1. Point Script Manager / `-scriptPath` at `E:\Projects\ghidra\scripts`.
2. Keep the sample in **that** project. Do not copy packed SDKs into this lab.
3. First pass: **no** `applySwitch`, write `kb=`.
4. Open the biggest CFF function, jump bookmarks, read dest comments — that is the recovered CFG outline.
5. If a **local** dispatcher is still a computed jump with ≤96 dests, re-run with `applySwitch` **or** select the `BR` + dests and run Ghidra's `SwitchOverride`.
6. MBA comments tell you the next-state constants. A follow-up script can rewrite `state = MBA()` to `state = N` once we have a sample of the exact MBA shape.

## Limits / false positives

- **vtables / IAT-looking pointer runs** in `.data` — filtered by interior ratio + unique-dest ratio + ignoring `.got`/`.plt`. A weird compiler still leaks. Check `interior=` in the console; vtables have interior ≈ 0.
- **Unrelocated file vs dump.** File on disk may store unslid pointers. Slide voting covers `raw`, `raw+imageBase`, `raw-imageBase`, and dest−raw. If B finds nothing, rebase/load the dump instead of the file.
- **Thumb bit** on ARM32: odd dests are masked.
- **Shared mega-table** used by many functions: dests are labeled globally; do not override that as one switch.
- Ghidra `JumpTable(Address, List, boolean, int)` matches 12.1.3 `SwitchOverride.java`. If NSA changes the ctor, the override path throws and the rest of the script still stands.
- MBA pass is **annotation**, not simplification.

## When it "fails"

| Symptom | What to do |
|---|---|
| `cffTables=0` | dump after init; check pointer size (need 4 or 8); lower `minTable=4`; look at console `Phase A/B` — if A=0 B=0 the table is not in data or not pointers-to-text |
| Thousands of tables that are vtables | raise interior threshold by not using `applySwitch`; inspect `interior=` — if 0, ignore |
| Decompiler still a hairball | table is recovered but override skipped (size). Use comments/bookmarks; or split analysis per-case by going to `cff_*` labels |
| `switch override failed` | leave `applySwitch` off; Ghidra function body is already a mess |

Packed loaders whose CFF tables are reloc-fixed pointer runs at the **tail** of `.data`: dump after init (or apply relocations) and run the tracer on that image, not on the ciphertext blob. The 12 MiB entropy blob is a different layer — do not expect dest recovery there.
