# CffScan

**Path:** `scripts/deobfuscation/CffScan.java` (engine: `scripts/deobfuscation/CffCore.java`)
**Lang:** Java GhidraScript
**Category:** Deobfuscation
**Targets:** OLLVM / Hikari / goron / **Arkari** control-flow-flattening (CFF), any architecture Ghidra can disassemble (validated on AArch64 incl. an `-O2` 235-function SDK, and x86 / x86-64; the algorithm is architecture-independent, so ARM32/MIPS/etc. work but are not in the bundled fixture set)
**Does not:** modify code. Detection + triage only.

The first tool of the CFF suite. It answers **"which functions are control-flow-flattened, and where is the dispatcher / state variable?"** with a deliberately low false-positive rate, so you don't waste time and don't mistake a normal loop for obfuscation. Feed the addresses it flags to [CffRecover](CffRecover.md) and [CffDeflatten](CffDeflatten.md).

## Why a dedicated detector

CFF turns a function's natural branches into a state machine: a **dispatcher** reads a **state variable** and jumps to the matching **case block**; every case ends by writing the next state and jumping back. The tell is structural and hard to fake:

- one block (the dispatcher / loop head) **dominates almost the whole function** and sits on a back edge;
- **many** real blocks converge back onto it (fan-in ≫ a normal loop's 1–2 back edges);
- the dispatcher **branches on one variable** (after `LowerSwitch` this is a `cmp`/`sub` compare tree, so its own fan-out is only 2).

CffScan scores exactly these invariants (see the obfuscation write-up in the [cookbook](../cookbook/control-flow-flattening.md)).

## Algorithm

1. Build the intra-function CFG from Ghidra basic blocks; compute a dominator tree (Cooper–Harvey–Kennedy) with O(1) dominance queries and dominator-subtree sizes.
2. **Flattening score** (mrphrazer heuristic): `max over blocks B on a back edge of |dominated(B)| / |reachable|`. Near 1.0 for flattened functions, low for ordinary code. The block achieving the score is the **dispatcher / loop head**. Computed in O(V+E) from the subtree sizes, so there is **no function-size cap** — `JNI_OnLoad`-scale mega-functions are scored too.
3. From it, find the **pre-dispatcher** (highest-fan-in convergence block), **fan-in** (≈ number of real cases), **clean-convergence ratio** (fraction of real blocks whose only successor is the hub — OLLVM emits an unconditional back edge at every case tail), and **hub-domination fraction**.
4. Classify:
   - **cff** — `score ≥ min` **and** the hub dominates ≥ `HUB_DOM` of the body **and** dispatcher fan-out ≥ 2 **and** fan-in ≥ `fanin` **and** (clean ratio ≥ 0.6 **or** a very strong score+hub+fan-in that covers modified/64-bit variants).
   - **suspect** — high score but weak scaffold (e.g. a big function with one small dominating loop, or a hand-written unwinder). Printed for manual review, **not** auto-actioned.
   - **no** — everything else.

This combination is what keeps libgcc/libstdc++ loops (`_Unwind_RaiseException`, `__cxa_guard_acquire`, `_M_release`, …) **out** of the `cff` tier while still catching real flattened leaf functions with only 3–4 cases.

## GUI

1. Import + auto-analyze the binary.
2. Script Manager → Deobfuscation → `CffScan.java` (put the cursor in a function to scan just that one, or it scans the whole program).
3. Read the console table; jump the **Bookmarks → CFF** entries (one per flagged dispatcher).

## Headless

Scan a whole program (this is the default when there is no cursor):

```powershell
E:\Projects\ghidra\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\<proj> -ProjectName lab `
  -Process libfoo.so -Analysis:$false `
  -PostScript CffScan.java json=E:\Projects\<proj>\out\libfoo.cff.json
```

One function:

```powershell
... -PostScript CffScan.java func=0x114400
```

(Programs must already be analyzed; pass `-Analysis:$false` to reuse the saved analysis. `key=value` args also work as `key value` — both survive `analyzeHeadless.bat`'s cmd parsing.)

### Args

| Arg | Default | Meaning |
|---|---|---|
| `all` | auto | scan every function (default when headless / no cursor) |
| `func=0x…` | — | scan only the function at this address |
| `min=0.90` | 0.90 | flattening-score threshold for the **cff** tier |
| `suspect=0.60` | 0.60 | threshold for the **suspect** tier |
| `fanin=3` | 3 | minimum pre-dispatcher fan-in (raise to cut noise on tiny functions) |
| `nodes=6` | 6 | minimum basic-block count |
| `top=100` | 100 | max rows printed per tier |
| `json=PATH` | — | write a JSON report (`cff` + `suspect` arrays) |
| `noBookmark` | off | do not drop CFF bookmarks |

## Output

Console table + `Analysis / CFF` bookmarks on each flagged dispatcher, plus optional JSON:

```
  _init            @00114400 score=0.981 nodes=53 fanIn=29 preOut=2 dispOut=2 clean=0.724 hubDom=0.981 ret=2 disp=001144a0 state=w8
```

- `disp` — dispatcher address (jump here to see the compare tree).
- `state` — best-effort name of the state variable/register (`w8`, `ECX`, …).
- `fanIn` ≈ number of real case blocks; `hubDom` — how much of the function the dispatcher dominates.

## Worked results (bundled fixtures under `samples/cff/`)

| Sample | Arch | Result |
|---|---|---|
| `sample_cff.so` | AArch64 | 18–19 flattened functions incl. `_init` (disp `0x1144a0`, state `w8`); libgcc loops correctly **not** flagged |
| `sample_modified_ollvm.so` | AArch64 | 64-bit-state variant, incl. `Java_..._nSign` (disp `0x1cc780`, state `x11`) |
| `ezam`, `CFF_full_linux64.bin` | x86-64 | `target_function` etc. (state `ECX`) |
| `CFF.bin`, `CFF_full.bin` | x86 | `target_function` etc. |

## Limits / tuning

- A flattened function whose max-fan-in block is a **shared epilogue** may report a low `hubDom`; the score-argmax anchor handles most, but if a known-CFF function lands in **suspect**, lower `fanin=` or hand it to `CffRecover force`.
- Encrypted / runtime-filled **indirect-branch** dispatchers (`-irobf-indbr`, the packed-loader case) have no readable compare tree; use [CFFDispatchTracer](CFFDispatchTracer.md) instead — see the [cookbook](../cookbook/control-flow-flattening.md) for which tool fits which flavor.
- Detection is per-function; run `all` to sweep a whole SDK.
