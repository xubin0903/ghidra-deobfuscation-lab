# CffRecover

**Path:** `scripts/deobfuscation/CffRecover.java` (engine: `scripts/deobfuscation/CffCore.java`)
**Lang:** Java GhidraScript
**Category:** Deobfuscation
**Targets:** state-machine CFF (OLLVM / Hikari / goron / **Arkari**), any arch Ghidra can emulate (validated on AArch64 incl. an `-O2` SDK, x86, x86-64; arch-independent by construction)
**Does not:** patch bytes. Read-only recovery + annotations.

Recovers the **real control-flow graph** of a flattened function by **concrete p-code emulation** and writes it back as comments / bookmarks / a DOT graph / JSON. Use it when you want to *read and understand* an obfuscated function without changing it. When you want the decompiler itself cleaned up, run [CffDeflatten](CffDeflatten.md) (which uses this same engine).

## The idea (why emulation, not static dataflow)

Every real block ends with `state = NEXT; goto dispatcher`, where `NEXT` is a compile-time constant that **does not depend on function input**. So each block can be emulated *in isolation*: start the emulator at the block, let it fall through the dispatcher, and stop the moment execution lands on another real block — that block is the true successor.

This beats static "read the constant" passes because modern **Arkari/goron** CFF stores the state XOR-encoded across two volatile slots (`switchVar ^ switchXorVar`, with a rolling delta in the loop head). Static analysis sees a pile of XORs; the emulator just computes the effective value. 64-bit state variants work the same way.

Conditional blocks contain exactly one `csel`/`cmov` selecting between two next-states; CffRecover forces both outcomes to recover **both** successors and the condition code.

## Pipeline

1. `CffCore.detect` — locate dispatcher, pre-dispatcher, state hint. `discoverHeads` then walks the compare tree: a block is a tree node only if its compare reads a value **derived from the state** (the state register, a copy the tree made of it — the derived set is propagated node to node — or a reload from a known state slot — a slot the dispatcher loads into its compare chain or spills a state-derived value into, not just any frame slot the dispatcher touches), so a real block that happens to end in `cmp w11,#0x64 ; b.gt` is not swallowed, while `-O2` nodes that materialise 64-bit case constants with 14–70 `mov/movk` are (the size cap is relaxed once the state register is known). Jump stubs and split constants (`mov w8,#K` falling into its `cmp`) are folded — including a stub whose chain runs into a stub another chain already folded (`-O0` ARM: every tree leaf's `b loopEnd` shares one `loopEnd: b dispatcher`; the first version took the later ones for case heads); a register-only block that sets up anything but the next state / tree scratch is a real block. The dead `switchDefault` is dropped.
2. Emulate the **prologue** to the dispatcher and snapshot the machine (fallback context).
3. Emulate the cases in **discovery order from their own landing context**: every time an explored path lands on a head, the machine state at that moment is captured and later used to emulate that head. This matters for `-O2` trees, which perform PHI copies and even hoist a case's `state = NEXT` into the tree path leading to it — emulated from the dispatcher snapshot alone such a case looks like `-> itself`. Calls are stepped over; uninitialised reads return 0; data-dependent divide-by-zero faults are stepped over; a per-path step cap avoids run-away real loops → reported honestly as `unresolved`, never guessed.
4. Every fork point met by the probe run (any `csel`/`cmov`/`cset…`, an ARM32 **predicated** move such as `cpyne r2,r1` — forced by synthesising the CPSR flags for its condition or the inverse, so the whole predicated group up to the next flag write stays consistent — **and** real conditional branches) is forced true and false **one at a time** (first execution only, so a loop's back-branch terminates), which finds the deciding select without disturbing `cset→csel` dependency chains. Forks that only exist on a forced arm are explored under that forcing context (nested, capped at 64 runs per case), so a third state store hiding on the other arm of a real branch is found. A case whose arm could not be followed to a head / return is marked **incomplete** — CffDeflatten will not patch it.
5. Emit per-node results: `uncond`, `cond` (with the decider kind — `select`/`branch` — its condition, its natural taken-direction, and both successors), `multi`, `ret`, `exit`, or `unresolved`. Each edge is tagged **pure** (execution reached the successor through dispatcher blocks only), records **every tail** through which the case reached that successor (tail-merged `-O2` cases reach one successor through several `b dispatcher`s), the executed case instructions up to the tail, any live **dispatcher register copies** crossed, and whether it is a self-loop — so [CffDeflatten](CffDeflatten.md) knows what is safe to patch and what a bypass must replay.
6. Consistency checks on the whole recovery. A cycle made only of unconditional edges (real code would be an infinite loop; far more likely a dispatcher block was taken for a head), a case head that *reads* the next-state register before writing it (the "state" is a real variable — bytecode interpreters look flattened — or the head is a mid-case block), or — once every case is resolved and complete — a case head that **no recovered edge leads to** (the flattening pass gave every original block a predecessor; an orphan head means a decision the exploration never saw, typically a select hoisted several cases ahead of the node it decides, whose alternative value never reached that node's landing contexts) flags the function **low confidence**; the report says why and nothing is ever patched on that basis. The orphan check is what turned `FUN_001c0d84` on the SDK from "partially patched, verify OK" into "refused": its `csel x19,x8,x28` in the prologue decides a successor eight cases later, and the structural oracle of CffDeflatten had caught the missing edge only once the function became full-mode eligible.

## GUI

1. Import + analyze; confirm the function with [CffScan](CffScan.md).
2. Script Manager → Deobfuscation → `CffRecover.java` (cursor in the target function, or pass `func=`).
3. Read the `CFF next -> …` pre-comments and `Analysis / CFF` bookmarks, or open the DOT graph.

## Headless

```powershell
E:\Projects\ghidra\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\<proj> -ProjectName lab `
  -Process libfoo.so -Analysis:$false `
  -PostScript CffRecover.java func=0x114400 `
  dot=E:\Projects\<proj>\out\%s.cff.dot json=E:\Projects\<proj>\out\libfoo.cff.json
```

`all` recovers every function CffScan flags; `dryRun` prints without writing DB annotations.

### Args

| Arg | Default | Meaning |
|---|---|---|
| `func=0x…` | cursor | target function |
| `all` | off | recover every CffScan-flagged function |
| `force` | off | run even if not flagged CFF (e.g. a **suspect**) |
| `dryRun` | off | console only; no comments / bookmarks / labels |
| `labels` | off | also label case heads `cff_case_<addr>` |
| `dot=PATH` | — | Graphviz of the recovered CFG (`%s` → entry address for one file per function) |
| `json=PATH` | — | JSON node/edge list (incl. `pure`, `cond`, `true`/`false`) |
| `maxSteps=20000` | 20000 | per-path emulation step cap |

## Output

Console report + (unless `dryRun`) `PRE` comments and `Analysis / CFF` bookmarks on every case head, and a dispatcher bookmark. Re-running replaces the previous `CFF …` comment lines (your own comment lines on the same address are kept), so an engine upgrade does not stack stale annotations. Example (AArch64 `_init`, fully resolved):

```
  prologue -> 00114580
  00114580  -> 00114848
  001146fc  if(ne) -> 00114488 else -> 001146ac   [select@0011470c]
  001147f0  if(eq) -> 00114620 else -> 00114838   [select@00114808]
  ...
  nodes=21 resolved=21 conditional=6 unresolved=0
```

DOT edges are coloured (green = condition true, red = false); return blocks are double-circled.

## Verification

On `ezam` (x86-64) the first recovered edge is `prologue -> 0x4010c3`, identical to the reference unicorn deflattener's output for the same binary. Across the bundled fixtures (x86 / x86-64 / AArch64 / AArch64-64-bit) recovery resolves every case except genuine data-dependent inner loops, which are reported as `unresolved` rather than fabricated. On the 235-function `-O2` SDK the state-aware tree walk plus landing contexts brought `multi-way` from 14 to 0 and resolved conditional edges from 1564 to 2652 (branch-decided from 28 to 85). `UNRESOLVED` went from 301 to 277: 26 of those are cases whose successor depends on the incoming context (a `csel` hoisted into the prologue; the case merely copies the chosen register) — previously they were reported as *unconditional*, which was wrong; the rest are step-cap loops and fork-cap cases. 5 functions are flagged low confidence (4: a case head reads a state register — interpreter-like loops / mid-case blocks; 1: a case head no recovered edge leads to — a hoisted select the exploration could not follow). The recovered edges are what [CffDeflatten](CffDeflatten.md) then verifies by re-emulation against the original.

## Limits

- A case whose successor genuinely depends on runtime data (a real loop inside the case) hits the step cap → `unresolved`. Raise `maxSteps=` or inspect by hand.
- `multi` (>2 successors) is left for review — rare in OLLVM CFF, common if the function also carries a real `switch`.
- Nested fork exploration is bounded (`MAX_RUNS` = 64 emulation runs per case, `MAX_FORK_POINTS` = 16); a case beyond either cap is `unresolved` / incomplete.
- ARM32 predicated instructions (`moveq r4,#K` as the state select) are not forced yet; such a case is reported impure ("predicated instruction not modelled").
- Encrypted indirect-branch dispatchers (packed loaders, `-irobf-indbr`) can't be emulated statically; dump after init or use [CFFDispatchTracer](CFFDispatchTracer.md).
