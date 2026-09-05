# CffDeflatten

**Path:** `scripts/deobfuscation/CffDeflatten.java` (engine: `scripts/deobfuscation/CffCore.java`)
**Lang:** Java GhidraScript
**Category:** Deobfuscation
**Targets:** state-machine CFF (OLLVM / Hikari / goron / **Arkari**), `-O0` through `-O2` (tail-merged) layouts. Patching implemented for **AArch64** and **x86 / x86-64** (validated on the bundled fixtures) and for **ARM32 / Thumb-2** (encoders only — see *Arch support*). Other arches → use [CffRecover](CffRecover.md) for annotations.
**Does:** rewrite case-tail branches to their recovered successors so the **Ghidra decompiler produces clean nested if/for** instead of a state machine. Every patched function is re-emulated under several input seeds and compared against the original (`verify`); full-mode functions additionally get a structural check that the dead dispatcher is unreachable. Anything that diverges is rolled back automatically. Writes a patch log for one-command undo.

The aggressive end of the suite. It runs the [CffRecover](CffRecover.md) engine, then **patches bytes** so the dispatcher becomes dead code and the original control flow is restored.

## Two modes per function

- **full** — every case *and* the prologue are patchable, so the whole dispatcher/compare-tree becomes unreachable. Its bytes are then reused as a **code cave** for small trampoline stubs. This is what lets the tool handle optimised (`-O2`) tails where the compare-tree carries real register copies (PHI resolution, rematerialised constants): the stub replays exactly the copies that are live and then jumps to the true successor. The prologue's fall-through/jump into the dispatcher is repointed to the first real block.
- **partial** — at least one case could not be resolved or patched, so the dispatcher has to stay live for it. Only tails that need **no** stub are rewritten in place; stub-needing tails are reported and left alone (the dispatcher still routes them correctly).

## What it rewrites

For each case the emulator resolved **and** marked *pure* (control reached the successor through dispatcher blocks only) **and** explored completely (every arm followed to a head / return):

| case shape | rewrite |
|---|---|
| unconditional: `… state store … ; B/JMP dispatcher` | `B/JMP successor` (via a stub when the dispatcher path carried live copies) — **every** tail the emulator saw leading to the successor is redirected, not just the first |
| conditional, decided by a **select** (`csel`/`cmov`): `CMP ; CSEL ; … ; B dispatcher` | select slot → `B.cc/Jcc succTrue ; B/JMP succFalse` (in place, or through per-arm stubs that replay the real code between select and tail plus the dispatcher copies) |
| conditional, decided by a **real branch** (`cmp ; b.le X ; …` — how `-O2` often lowers the select): each arm has its own `mov state ; b dispatcher` | the branch itself is left untouched; each arm's tail is redirected like an unconditional edge. No condition code is ever re-encoded, so polarity cannot be wrong. Arms that already go straight to a real block (the stack-protector check before `ret`) need nothing |
| tail in a block **shared** by several cases (`-O2` tail merging: PHI copies + `b dispatcher`) | the case's last **owned** instruction becomes `B stub`; the stub replays the shared body (relocatable only), then the dispatcher copies, then branches. The shared block itself is never modified |
| **select** in a shared block (tail-merged `cmp ; csel state ; b dispatcher`) | the case's hand-off becomes `B condStub`; condStub = private copy of the shared prefix (it carries the compare) + `B.cc stubT ; B stubF` |
| conditional tail branch straight into the dispatcher (`b.ne dispatcher`, `cbz wN, dispatcher`) | retargeted in place (AArch64 B.cond / CBZ / CBNZ / TBZ / TBNZ; x86 `jcc rel32`) |

State-store instructions that write the dispatcher's own slots (matched by operand, so Arkari's `eor`-encoded two-slot state is recognised too) are dropped as dead; everything else the tail computed is preserved (replayed verbatim in a stub when the in-place window is too small).

### Which dispatcher instructions get replayed

`-O2` compare trees interleave real work with the compares: PHI copies (`mov x19,x10 ; mov x24,x9 ; mov w28,w8`), rematerialised 64-bit constants (`mov x12,#… ; movk …`), even a case's own `state = NEXT` hoisted into the tree path that leads to it. `CffCore.analyzeRegionPath` decides **per write** (never per register — the same `mov w28,w8` is dead in pass 1 of the dispatcher loop and live in the last pass) what a bypass must replay:

- dead: the flow, pure compares, values computed *from* the state (copies of it, xor-decoded states, compare temporaries), no-op register moves (copy propagation across the `x19 ⇄ x10` dance), writes overwritten later on the path without a live reader, and values the successor kills on entry — where "kills" follows the ABI through calls (`getKilledByCallList`, argument registers count as read);
- live: everything else, replayed byte-for-byte in a stub (relocatable instructions only; a PC-relative `adrp`/`adr` on the path is a blocker).

## Safety (this is the important part)

The user's rule is *don't over-deobfuscate*. CffDeflatten patches an edge **only** when all of these hold, and leaves everything else byte-for-byte untouched:

- the case is `uncond` or `cond` **and** `pure` (impure / `multi` / `unresolved` / `ret` / `exit` are skipped);
- the case is **complete**: every fork the emulator met — including forks that only exist on the *other* arm of a real branch (explored under nested forcing) — was followed to a head, return or tail call. A stopped arm (step cap, fault) blocks the case, because a tail we never saw would keep jumping into the dead dispatcher;
- every instruction that has to move is relocatable (no PC-relative `adrp`/`lea`, no memory operand, no flow) and no surviving instruction reads the state register;
- every byte written in place is **owned** by the case (dominated by its head) and not entered from elsewhere (no block boundary inside the window); shared blocks are only ever *copied* into stubs;
- the new branch displacement is in range (AArch64 `B` ±128 MiB, `B.cond` ±1 MiB; ARM `B` ±32 MiB; Thumb `B.W` ±16 MiB, `B<c>.W` ±1 MiB; x86 rel32) and there is room (in-place) or code-cave space (full mode).

The **recovery itself refuses** ("LOW CONFIDENCE", nothing patched) when the recovered graph cannot come from a flattened function: a cycle made only of unconditional edges, or a case head that *reads* the next-state register before writing it (a real variable that merely looks like a state — e.g. a bytecode interpreter loop — or a mid-case block mistaken for a head).

**Verification.** After writing, the original and patched function are both concretely emulated from the entry under **four input seeds** (zero, small positives, all-ones, pointer-like values into scratch memory with non-zero fill; calls are stepped over and, deterministically, clobber the caller-saved registers), and the sequence of real blocks visited plus the register file at each block are compared. Ignored per block: the state registers (nothing outside the dispatcher reads them), registers the dispatcher filled with state-derived scratch, and registers the block overwrites before reading. **Full-mode functions get an objective structural oracle on top:** after re-disassembly, no block reachable from the entry may overlap an unpatched dispatcher byte, and every real block that was reachable before must still be reachable. A mismatch reverts that function's patches (`keepOnMismatch` overrides). `verifySelfTest` demonstrates the harness: it deliberately swaps the arms of the first select and the function is rejected (checked on `_init`: `MISMATCH head #14: original 00114740 vs patched 00114824` → reverted).

This is still a test, not a proof — a patch that is wrong only on a path none of the four seeds drives could slip through the trace comparison; the structural oracle and the conservative recovery are what carry the rest.

Always start with `dryRun` and read the plan. Every applied patch is recorded (original + replacement bytes, grouped per function) in a JSON log; `undo=` restores the exact original bytes and re-disassembles only the restored ranges (the function body is recomputed from the entry, nothing else in the listing is cleared).

## Recommended workflow

```powershell
# 1. see the plan, change nothing
... -PostScript CffDeflatten.java func=0x114400 dryRun

# 2. apply (writes bytes + a patch log next to the program), then re-analyze
... -PostScript CffDeflatten.java func=0x114400

# 3. in the GUI: re-run Auto Analyze (or press F5) -> clean decompilation

# 4. changed your mind:
... -PostScript CffDeflatten.java undo=<program>.cff-patch.json
```

Programs must be analyzed first; pass `-Analysis:$false` so `analyzeHeadless` reuses the saved analysis instead of re-analyzing (full re-analysis of a large flattened `.so` is very slow).

### Args

| Arg | Default | Meaning |
|---|---|---|
| `func=0x…` | cursor | target function |
| `all` | off | patch every CffScan-flagged function |
| `force` | off | run even if not flagged CFF |
| `dryRun` | off | print the patch plan; **write nothing** (do this first) |
| `noVerify` | off | skip the before/after comparison (not recommended) |
| `keepOnMismatch` | off | keep patches even when verification fails (default: revert that function) |
| `noStubs` | off | never reuse the dead dispatcher as a code cave; in-place patches only (forces partial mode) |
| `noReanalyze` | off | do not re-disassemble patched ranges after writing |
| `debugPlan` | off | list every dispatcher instruction on each patched edge with its live/dropped verdict |
| `debugTrace` | off | on a verify mismatch, print both head sequences and the registers that differ |
| `verifySelfTest` | off | deliberately swap the arms of the first select patch; verify must revert the function (harness check) |
| `log=PATH` | `<program>.cff-patch.json` | where to write the undo log |
| `undo=PATH` | — | restore bytes from a previous log, then exit |
| `maxSteps=20000` | 20000 | recovery step cap |

## GUI

Script Manager → Deobfuscation → `CffDeflatten.java`. Run once (it asks nothing; use headless args or edit defaults for `dryRun`). After it finishes, re-run Auto Analyze and press `F5` on the function.

## Output

```
--- Java_com_adjust_sdk_sig_NativeLibHelper_nSign @001cc604 dispatcher=001cc780 mode=full (dispatcher becomes code cave, 836 stub bytes) ---
  cases=22 resolved=23 conditional=13 unresolved=0 -> planned patches=57
    001cc780  entry   dispatcher entry -> 001cd374 via stub 001cc784 (+3 copies)
    001ccba0  cond    if(ne) -> 001ccf54 else -> 001cd89c   [stubs: 001cc7b8 / 001cc7c4, post=2, copies=0/3]
    001ccf50  cond    if(eq) -> 001cccf8 else -> 001cd5bc   [shared compare replayed in stub 001cc854, lead=0, post=2, copies=3/3]
    001cd05c  uncond  -> 001cd8f0 via stub 001cc884 (+7 copies)
    ...
applied 57/57 patches across 1 function(s)
  verify Java_com_adjust_sdk_sig_NativeLibHelper_nSign: OK (46 head visits over 4 input seeds, dispatcher unreachable)
patch log: ...\sample_modified_ollvm.so.cff-patch.json   (undo: -postScript CffDeflatten.java undo=...)
```

## Verification (bundled fixtures)

End-to-end tested (apply → re-disassemble → decompile → undo) on scratch copies of the lab project; the project under `projects/` is never written. `tools\cff-regress.ps1` reproduces the table below in one command (and fails loudly when a change makes any number worse or `undo` stops being byte-exact).

| Sample | Arch | Result |
|---|---|---|
| `CFF_full_linux64.bin` | x86-64 `-O0` | 7/7 functions full-mode, verify OK (4 seeds + structural oracle); `target_function` / `calculate_factorial` decompile to source-level `if/else` + `for` |
| `CFF_full.bin` | x86 `-O0` | 7/7 functions full-mode, verify OK |
| `ezam` | x86-64 | 2/2 functions full-mode, verify OK |
| `sample_cff.so` (all 20 flagged) | AArch64 | 17 functions patched and verified (10 full, 7 partial), **0 reverted**; 1 function had no in-place-patchable edge; 2 refused up front as low confidence: `FUN_0012c4c8` (a bytecode interpreter whose loop looks flattened — correctly *not* touched) and `FUN_00124be8` (a head reads the state register). `_init`: full mode, decompiles to nested `if/else`. `undo` of all 482 patches restores the 125 KB text range byte-for-byte (SHA-256 identical to the pristine project) |
| `sample_modified_ollvm.so` (235 flagged, `-O2`, 64-bit state, tail merging, hoisted state assignments) | AArch64 | **157 functions patched, 157 verified, 0 reverted, 0 structural-oracle failures**; 49 of them full mode (dispatcher removed), 108 partial (in-place edges only — 13 of these fell back from full mode because the code cave was too small for the stubs); 74 functions had no in-place-patchable edge; 4 refused as low confidence. `nSign@0x1cc604`: full mode, 57 patches, decompiles to plain `do/while` + `if` code. `undo` of all 2860 patches restores the 1.25 MB text range byte-for-byte. (Previous engine on the same sample: 143 verified / 29 reverted under a single-seed verify.) |

## Arch support

| Arch | Status |
|---|---|
| AArch64 | validated on all AArch64 fixtures (`-O0`-like and `-O2` tail-merged) |
| x86 / x86-64 | validated (`-O0` fixtures) |
| ARM32 / Thumb-2 | **encoders only, not validated on a real flattened ARM32 binary** (this lab has no fixture). `B` / `B<c>` (A32), `B.W` / `B<c>.W` / 16-bit `B` / `B<c>` (Thumb), mode-aware NOP padding, TMode context per patch site (mixed-mode dispatchers are refused). Predicated state selects (`moveq r4,#K`) are **not modelled** by the engine yet: a case containing one is reported and skipped. Retargeting a conditional tail branch is not implemented for ARM32. Treat any ARM32 run as an experiment: `dryRun` first, keep the patch log |
| others | not supported; use [CffRecover](CffRecover.md) |

## Limits

- **Code cave size.** Full mode needs the dead dispatcher to hold every stub; heavily optimised functions with dozens of live rematerialised constants per edge can exhaust it (`full mode abandoned (... code cave N bytes, M used)`), in which case the function falls back to partial mode. Identical replay sequences already share one stub.
- A case whose arm the emulator could not follow (step cap on a data-dependent loop, emulator fault) is skipped as *incomplete*; raise `maxSteps=` or inspect by hand.
- Shared tails / shared compares whose body contains PC-relative code (`adrp`, `adr`) or calls cannot be replayed and block the case.
- Encrypted indirect-branch dispatchers are out of scope (no static compare tree to redirect) — see [CFFDispatchTracer](CFFDispatchTracer.md) and the [cookbook](../cookbook/control-flow-flattening.md).
- After applying, re-run Auto Analyze for the cleanest decompiler output; the script re-disassembles the patched ranges but a full re-analysis resolves types/xrefs best.
