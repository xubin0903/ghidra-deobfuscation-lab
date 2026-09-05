# Control-flow flattening (OLLVM / Hikari / similar)

## What it looks like

- One giant function, a `switch (state)` (or computed goto) in a loop
- Real basic blocks become `state = NEXT; break;`
- Dispatcher block dominates everything
- Decompiler either times out or dumps a 5k-line switch
- On ARM64 OLLVM/Hikari: `ADRP+LDR+BR` against a **pointer table in `.data`/`.bss`**

That last bullet is the structural invariant. CFF does not encrypt code. It stores "which block next" in addressable memory. Static analysis is enough.

Write-up this lab follows: [xkilldash9x, *The Dispatch Table Problem*](https://gist.github.com/xkilldash9x/e8ee393a5c681677b38c58f178e203a4) (CFFDispatchTracer: 95.8% of 5,254 entries on a 1.2MB ARM64 anti-fraud SDK, no emulation).

## How the obfuscator actually builds it

Read from the passes themselves (OLLVM `Flattening.cpp`, goron/**Arkari** `Flattening.cpp` + `IndirectBranch.cpp`). Every variant does the same four things:

1. **LowerSwitch first.** The dispatcher is a `switch(state)` in the IR, then lowered to a **binary compare tree** (`cmp state,K; b.eq case`). So on disk the "dispatcher" is a *subtree* of `cmp`/branch blocks, not one indexed jump — its own fan-out is 2.
2. **A state variable**, `i32` (or `i64` in 64-bit builds), initialised in the prologue to a random high-entropy constant; each case ends `state = NEXT; br loopEnd`. Case values are **random and non-sequential** (`scramble32` / `std::mt19937_64`), so you cannot read the order statically — you must evaluate.
3. **Conditional blocks** become one `select(cond, caseTrue, caseFalse)` → `csel`(AArch64)/`cmov`(x86) writing the state, then the same single back edge.
4. **Structure:** prologue → `loopEntry` (load+switch = dispatcher) ; `loopEnd` (unconditional back edge = pre-dispatcher, highest fan-in) ; every real block branches to it. Blocks are shuffled; there is no spatial locality.

**Two flavors, two tools:**

- **Plain `-fla` / `-irobf-fla`:** the compare tree reads the state variable directly. **Arkari hardens it**: two volatile slots `switchVar` + `switchXorVar` with a rolling delta, so the real state is `switchVar ^ switchXorVar` — static "find the constant" fails, but *emulation* just computes it. → recover/patch with the **`Cff*` trio** below.
- **`-fla` **plus** `-irobf-indbr`:** the switch is lowered to an `indirectbr` through an **encrypted page table** (module key + function key + pointer-enc, AArch64 optionally PtrAuth). This is the packed-loader case: the pointer table is ciphertext on disk. → static table recovery with **CFFDispatchTracer** (after a dump / with reloc applied); the compare-tree tools do not apply.

## Ghidra built-ins

Ghidra does **not** unflatten CFG for you. If it already recovered a switch, you are done with that function.

- `SwitchOverride.java` (Decompiler scripts): select the computed `BR`/`jmp` **and** dest instructions, or pre-add `COMPUTED_JUMP` refs and park the cursor on the branch.
- `AddReferencesInSwitchTable.java`: ARM `add pc, …` in-code tables, not OLLVM data-section tables.

## Scripts in this lab

**Compare-tree flavor (plain `-fla`, incl. Arkari XOR / 64-bit state) — emulation suite:**

- **[CffScan](../scripts/CffScan.md)** — detect flattened functions (dominator flattening score + scaffold), low false positive. Run first; find the dispatcher + state var.
- **[CffRecover](../scripts/CffRecover.md)** — emulate each case to its true successor(s); write the real CFG as comments / bookmarks / DOT / JSON. No byte changes. Defeats Arkari's `switchVar ^ switchXorVar` for free.
- **[CffDeflatten](../scripts/CffDeflatten.md)** — patch case tails to direct branches so the **decompiler** shows clean if/for (AArch64 + x86/x64). `dryRun` + undo log; only touches edges it proved pure.
- Shared engine: `scripts/deobfuscation/CffCore.java`.

**Pointer-table flavor (`-irobf-indbr`, packed/encrypted loaders):**

- **[CFFDispatchTracer](../scripts/CFFDispatchTracer.md)** — gist strategies A/B/C: ref scan, ASLR rebase, trampoline `BR`. Labels tables, comments dests, optional JumpTable override for **small** local tables. Does not patch bytes.
- **[HikariCffIslands](../scripts/HikariCffIslands.md)** — after reloc: drop dispatcher dests, bookmark work islands. Still not a CFG rewrite.

| You have | Use |
|---|---|
| A `.so`/exe, dispatcher is a `cmp state,K` tree, want to read it | `CffScan` → `CffRecover` |
| …and you want clean decompiler output (AArch64 / x86) | `CffScan` → `CffDeflatten dryRun` → apply |
| Dispatcher is `LDR [table,idx]; BR`, table is real pointers | `CFFDispatchTracer` |
| …table is ciphertext / reloc-filled (packed loader) | dump after init, then `CFFDispatchTracer` |

Run these **before** wasting hours in the decompiler.

## Playbook — compare-tree CFF (the common case)

1. Import + auto-analyze the `.so`/exe.
2. `CffScan all` → note the flagged dispatchers (or scan one with `func=`).
3. `CffRecover func=0x…` → read the `CFF next ->` comments / open the DOT graph to understand the logic **without** changing anything.
4. If you want clean pseudocode and the arch is AArch64/x86: `CffDeflatten func=0x… dryRun`, review the plan, then run it without `dryRun`; re-run Auto Analyze and press `F5`. Keep the `.cff-patch.json` so you can `undo=`. Never apply on a shared project: copy the project directory (it is relocatable) and apply on the copy.
5. Anything reported `unresolved` (a real data-dependent loop inside a case), `impure`, *incomplete* (an arm the emulator could not follow) or **LOW CONFIDENCE** (the recovered graph cannot come from a flattened function — typically a bytecode interpreter that merely looks flattened, or a mid-case block mistaken for a head): inspect by hand; the scripts deliberately leave it alone rather than guess.
6. `-O2` builds (tail-merged `b dispatcher` blocks shared by many cases, PHI copies inside the compare tree, 64-bit case constants materialised with `mov/movk`, `state = NEXT` hoisted into the tree) are handled: shared blocks are copied into per-case stubs in the dead dispatcher, never modified in place. The limiting factor becomes code-cave size; `dryRun` reports `full mode abandoned (... code cave N bytes, M used)` when a function does not fit and falls back to partial mode.

## Playbook (other reverse projects)

1. Import the `.so` or a **post-init memory dump** (tables filled in `.bss` only exist after `JNI_OnLoad`).
2. Auto-analyze.
3. Headless or GUI: `CFFDispatchTracer.java` **without** `applySwitch` on the first pass. Write `kb=`.
4. Bookmarks → category `CFF`. Jump dispatcher `BR`s. Each table slot comment is `CFF[i] -> dest`.
5. For a **local** function whose table has tens of dests, re-run with `applySwitch` or use `SwitchOverride` by hand.
6. For a **shared mega-table** (JNI_OnLoad, thousands of slots): do **not** override. Walk dest labels; recover one semantic path at a time (RegisterNatives, anti-debug, …).
7. MBA immediates on the listing (`CFF/MBA imm=0x…`) are next-state / keys. Next script: constant-fold those. Not in this pass.
8. JNI names still missing → [jni-names](jni-names.md) after the CFF body is readable.

## Manual fallback (tiny functions)

1. Don't fight the decompiler first. Read the **graph**.
2. Name the state variable. Find every assignment.
3. For each assignment, the destination block is the real successor.
4. If the sample is small, patch `Jcc`/`BR`; if it is huge, you wanted `CFFDispatchTracer`.

## What this will not beat

Virtualization (custom bytecode), encrypted dispatch tables, hash-verified opaque predicates. Those are different cookbooks. CFF is the cheap obfuscation vendors actually ship; that is why this script exists.
