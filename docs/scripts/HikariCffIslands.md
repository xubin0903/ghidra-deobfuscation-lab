# HikariCffIslands

**Path:** `scripts/deobfuscation/HikariCffIslands.java`
**Lang:** Java GhidraScript
**Category:** Deobfuscation
**For:** reloc-filled Hikari/OLLVM CFF dispatch tables on **AArch64**. Structural classification (dispatcher vs work; `svc` / `byte_xor` / `call`) is architecture-generic and works on any Hikari/OLLVM-flattened AArch64 target. Sample binaries are **not** bundled in this lab.

`CFFDispatchTracer` finds and labels the pointer tables. This script takes each **unique table destination**, decodes a short instruction window (≤48), and splits it into:

- **dispatcher** — short island ending in `BR`/`braa…`, containing an indexed table load (`ldr …, [x, w, uxtw#3]`) or `adrp+cset`, and no "heavy" work instruction. Dropped.
- **work island** — everything else; bookmarked + commented + labeled when it matches a tag.

It does **not** rewrite the CFG and does **not** `applySwitch`.

## When

- You imported the **relocated** image (Ghidra applied `R_AARCH64_RELATIVE`), so table slots hold real `.text` VAs, not disk zeros.
- You want j. bookmarks/labels to navigate, not a decompiler miracle.
- Runtime-filled / encrypted tables still read as garbage — dump after init first.

Auto-analysis is **not** required: if `.text` is sparse (e.g. `-noanalysis`), the script linear-disassembles executable blocks itself before decoding, and also disassembles individual dests on demand. Pass `noDisasm` to skip that.

## Script args

| Arg | Default | Meaning |
|---|---|---|
| `dryRun` | off | classify + print only; no bookmarks / comments / labels |
| `noDisasm` | off | do **not** auto-disassemble; only classify dests already decoded |
| `minRun=N` | 32 | minimum contiguous code-pointer slots to treat a data run as a table |
| `maxBlockMiB=N` | 0 (unlimited) | skip data blocks larger than N MiB (perf guard for big dumps) |

Note: dispatch tables often sit at the **tail** of a large RW block, so by default the whole block is scanned — that is intended. Only set `maxBlockMiB` if you have a giant post-dump `RAM` block you know is not a table.

## Headless

```powershell
E:\Projects\ghidra\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\cff-test `
  -ProjectName cff `
  -Import <path-to-relocated-image> `
  -Analysis:$false `
  -PostScript HikariCffIslands.java `
  dryRun
```

Write `dryRun` immediately after `-PostScript Name` — do **not** put a bare `--` before it (PowerShell 5.1 binds the next token to `-Process`).

## Outputs (DB, unless `dryRun`)

- Bookmarks `Analysis / CFF` on work-island dests, comment `CFF work island: <tag>` (shares the `CFF` category with `CFFDispatchTracer`; the tracer's KB loader only ingests `CFF slot …` comments, so these are ignored there).
- EOL comment `CFF work <tag>` on the dest.
- Label `cff_work_<tag>_<addr>` on default-named dests.
- Console: `runs`, per-run slot counts, `dispatcher / work / tagged / undecoded`, and a per-tag histogram.

## Tags

`svc` (contains `svc`), `byte_xor` (`ldrb`+`strb`), `call` (any `BL`). These are architecture-generic structural tags; matching is by mnemonic, not substring.

## Limits

- Encrypted / runtime-filled tables: dests stay garbage. Dump after init first.
- A single non-code slot inside a table splits it into two runs; with `minRun=32` a fragmented real table can drop below threshold. Lower `minRun=` if a known table is missed.
- `dispatcher` detection assumes the canonical `…; BR Xt` shape; a dispatcher that never uses an indexed load nor `adrp+cset` may be misfiled as work.
