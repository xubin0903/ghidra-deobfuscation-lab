# HashMemory

**Path:** `scripts/headless/HashMemory.java`
**Lang:** Java GhidraScript
**Category:** Headless
**Does:** print a SHA-256 for every initialized memory block and one for all of them together. Read-only.

Purpose: an objective "the bytes are exactly what they were" oracle. The CFF regression harness ([`tools/cff-regress.ps1`](../../tools/README.md)) runs it on the pristine copy, after `CffDeflatten` applied its patches (hash must change) and after `undo=` (hash must be back to the pristine value). Use it the same way around any byte-patching script.

## Headless

```powershell
E:\Projects\ghidra\tools\ghidra-headless.ps1 `
  -ProjectDir <proj> -ProjectName lab -Process libfoo.so -Analysis:$false `
  -PostScript HashMemory.java exec out=C:\tmp\hashes.txt
```

### Args

| Arg | Meaning |
|---|---|
| `exec` | only executable blocks |
| `block=NAME` | only this block (repeat for several) |
| `out=PATH` | append the `TOTAL` line to this file as well |

## Output

```
BLOCK .text 00108000-0023a3ff bytes=1254400 sha256=07b2…0144
BLOCK .rodata …
TOTAL program=sample_modified_ollvm.so blocks=9 bytes=1301224 sha256=…
```

## Limits

- Uninitialized blocks (`.bss`) are skipped — they have no bytes to hash.
- `exec` relies on the loader's permission flags. An ELF imported as raw segments (`segment_0.3` …) may carry no execute flag at all, so the default (all initialized blocks) is the safe choice for round-trip checks; the regression harness uses the default.
- Hashes cover bytes only, not the listing (instructions, comments, function bodies). A round trip that restores bytes but changes analysis is invisible here; that is what the CFF verify trace is for.
