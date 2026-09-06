# BcfClean

**Path:** `scripts/deobfuscation/BcfClean.java` (shares the emulator / verify harness of `CffCore.java`)
**Lang:** Java GhidraScript
**Category:** Deobfuscation
**Targets:** Obfuscator-LLVM **bogus control flow** (`-bcf`) and any other opaque predicate whose outcome is fixed at build time. Validated on **ARM32 (A32)** and **x86** fixtures; the encoders also cover **AArch64** (no fixture yet).
**Does:** find conditional branches whose condition depends only on immediates and on global variables the program never writes, evaluate each once by concrete emulation, and rewrite it — always taken → unconditional branch, never taken → NOP. The bogus arm becomes unreachable and the decompiler drops it. Every patched function is re-emulated before/after under four input seeds; a mismatch reverts it. Writes an undo log.

## What bogus control flow looks like

OLLVM's `-bcf` pass wraps every real block in

```c
if (x * (x - 1) % 2 == 0 || y < 10)   // always true: x*(x-1) is even, y is 0
    real_block();
else
    garbage_clone_of_real_block();
```

where `x` and `y` are global `int`s that nothing ever writes. In the binary that is a load of the two globals, a multiply / `and 1` / compare, and a conditional branch (`beq real` on ARM, `jnz real` on x86 after `setz/setl/or`), sometimes split over two blocks with the intermediate result spilled to a frame slot.

## How it decides

For every basic block of the function (or, after a decided branch, along the straight-line path into a block nobody else enters) the script walks the p-code of each instruction with a three-level constness lattice:

- **VAR** — depends on something unknown (arguments, memory, real variables);
- **IMM** — computed only from immediates and read-only memory (literal pools, `.rodata`);
- **DATA** — computed from immediates and at least one **frozen data global**: an address in a writable block that has no `WRITE` reference anywhere in the program, no relocation, and is not in `.got`/`.plt`/TLS (things the dynamic linker fills at load time are runtime values, not constants).

Tracking is per **byte** of the register file (`setz bl ; setl bh ; or bl,bh` keeps BL and BH constant while the rest of EBX stays unknown), per frame slot (`str r1,[sp,#0x14]` … `ldr r0,[sp,#0x14]`), and per p-code output — so an ARM `sub r2,r0,#1` stays constant although the sleigh shifter code reads `CY`, and `tst` makes `ZR` constant without caring about the old flags. A predicated ARM instruction whose condition is not constant poisons its outputs.

A conditional branch is folded only when its condition is **DATA** — an all-immediate condition is the compiler's or linker's business (C runtime start-up code compares link-time constants such as `__TMC_END__ - __bss_start`), an opaque predicate always involves a data global. The outcome is then read off an emulator that ran the same path from the block start with the program's memory (`.bss` reads as zero, exactly as at run time). In an `all` run, C runtime scaffolding (`frame_dummy`, `register_tm_clones`, `_init`, …) is skipped up front; `crt` re-enables it.

## Safety

- Every fold is a byte-for-byte replacement of the branch instruction with a branch/NOP of the same length; nothing else moves.
- The frozen-global test is what carries the semantics: a global written only through a pointer Ghidra did not resolve would defeat it. That is why the verify runs: after patching, the function is emulated from the entry under four seeds and every basic block visit (address + register file, minus the registers the block overwrites first) must match the original; a mismatch reverts the function. On the fixtures the first version got exactly this wrong once (a fold on a partially-known EBX) and the verify caught it.
- The undo log uses the same format as CffDeflatten's (`patches` with original bytes), so either script's `undo=` restores it.

## Recommended workflow

```powershell
# 1. plan
... -PostScript BcfClean.java all dryRun

# 2. apply (verify on), then re-run auto-analysis / press F5
... -PostScript BcfClean.java all

# 3. changed your mind
... -PostScript BcfClean.java undo=<program>.bcf-patch.json
```

Flattening *and* bogus control flow on the same function: run BcfClean first (it needs no CFF structure), then CffDeflatten.

### Args

| Arg | Default | Meaning |
|---|---|---|
| `func=0x…` | cursor | one function |
| `all` | off | every function of the program |
| `dryRun` | off | plan only, write nothing |
| `noVerify` | off | skip the before/after trace comparison |
| `keepOnMismatch` | off | keep patches even when verification fails |
| `crt` | off | do not skip C runtime scaffolding in an `all` run |
| `maxPath=256` | 256 | instructions followed per straight-line path |
| `debugPlan` | off | print the constness state after every analysed instruction |
| `log=PATH` | `<program>.bcf-patch.json` | undo log |
| `undo=PATH` | — | restore bytes from a log, then exit |

## Output

```
--- target_function @000083b4: 6 constant predicate(s) -> 6 patch(es) ---
    0000842c  beq 0x00008444   always taken -> 00008444   [condition depends only on immediates and never-written globals]
    ...
  verify target_function: OK (25 block visits over 4 input seeds)
applied 7 patches across 2 function(s)
patch log: ...\target_arm_bogus.bcf-patch.json   (undo: -postScript BcfClean.java undo=...)
```

## Verification (fixtures)

Public fixtures from the deflat test suite (`tools\fetch-samples.ps1`), run by `tools\cff-regress.ps1` (`arm32_bcf_clean`, `x86_bcf_clean`):

| Sample | Arch | Result |
|---|---|---|
| `target_arm_bogus` | ARMv7 A32 | 6 predicates in `target_function` + 1 in `main` folded, verify OK, undo byte-exact. Decompiles to the source's `if (n % 4 == 0) … else if … ` chain; the now-dead loads of `x` remain as `uVar1 = *DAT_…` (the decompiler keeps global reads) |
| `target_x86_bogus` | i386 `-O0` | 20 predicates in `target_function` + 1 in `main` folded, verify OK, undo byte-exact. Ghidra's decompiler collapses this function to `return CONCAT44(y, local_5c)` **both** after BcfClean and on the reference tool's own `target_x86_bogus_recovered` output — the `-O0` build allocates every block's locals with `mov eax,esp ; add eax,-0x10 ; mov esp,eax`, which defeats its stack analysis; the listing and the emulated behaviour are correct |
| CFF fixtures (`check_passwd_*`, `CFF_full*`, the SDK) | all | no constant predicate found — nothing is touched where there is nothing to fold |

## Limits

- Only branches whose condition is a **compile-time constant involving a data global** are folded. Opaque predicates built from runtime values (`argc*(argc+1)%2`, pointer comparisons) or from a global the program does write somewhere are left alone — as they must be.
- The predicate computation itself stays in place (dead loads of `x`/`y`); the decompiler usually shows them as unused assignments. A later pass could remove instructions that only feed a folded branch.
- Thumb functions are skipped (no fixture; the A32 encoders are what is validated). AArch64 has encoders but no fixture yet.
- A branch whose two arms are both genuinely reachable is never touched, so a function with no opaque predicate is left byte-for-byte as it was.
