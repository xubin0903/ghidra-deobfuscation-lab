# FindEncryptedStringRefs

**Path:** `scripts/deobfuscation/FindEncryptedStringRefs.java`  
**Lang:** Java GhidraScript  
**Category:** Deobfuscation

## Purpose

Heuristic scan: flag functions whose listing has a lot of **non-zeroing XOR**, rotates, or add/sub. Typical shape of inlined string/buffer decryptors.

**Does not decrypt.** It prints candidates. Follow [string-encryption cookbook](../cookbook/string-encryption.md).

## When

- `.rdata` looks like entropy, no C strings
- You have not found the decrypt helper yet
- First pass before writing a sample-specific decrypt script

## GUI

Script Manager → Deobfuscation → `FindEncryptedStringRefs.java` → Run.

Columns: `name entry xor add rol/ror score`

## Headless

```powershell
.\tools\ghidra-headless.ps1 `
  -ProjectDir E:\Projects\ghidra\projects\lab `
  -ProjectName lab `
  -Process target.exe `
  -PostScript FindEncryptedStringRefs.java
```

## Inputs / outputs

- Input: analyzed listing (garbage in if you skipped auto-analyze)
- Output: TSV on stdout
- Does not mutate the DB, does not patch bytes

## Limits

- Crypto, checksums, hashers, PRNGs all look the same. Expect false positives (`memcpy`-ish xor loops, SSE, etc.).
- Covers x86 (`xor`/`pxor`) and ARM/AArch64 (`eor`/`eon`/`veor`, `ror`/`extr`, and the ARM barrel-shifter `, ror` operand form). MIPS uses `xor`/`xori` (matched). Add more mnemonics if a new ISA shows up.
- Inlined decryptors that are 3 XORs will be missed (`MIN_HITS = 4`).
