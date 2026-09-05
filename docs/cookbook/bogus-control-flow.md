# Bogus control flow / junk jumps

## What it looks like

- `if ((x * (x-1)) % 2 == 0)` always-true predicates
- Extra jumps to dead blocks that never execute
- Decompiler spews `if (true)` / `if (false)` or huge nested conditions that fold to constants
- IDA/Ghidra graph is a hairball but the real path is a straight line

## Ghidra built-ins

- Decompiler already folds a lot of constant predicates. If PCode still has the junk, the compiler/obfuscator emitted **non-constant** predicates (hash, `rdtsc`, `GetTickCount`).
- **Simplify** + commit decompiler results does not strip the assembly. You still want to NOP / patch the junk for listing readability.

## Scripts in this lab

None yet that patch CFG. When we write one it will live at `scripts/deobfuscation/` and get a `docs/scripts/` page.

## Manual playbook

1. Find the predicate: xrefs to the compare, or search for `CMOV` / `Jcc` after a mul/xor sequence.
2. Emulate the predicate (Unicorn / Ghidra emulator / just run it) — confirm always-taken or never-taken.
3. Patch the `Jcc` to `JMP` or `NOP`.
4. Clear flow and re-disassemble the block.
5. Repeat. This is usually local, not whole-program.

## When to write a script

When the same predicate pattern hits hundreds of functions (OLLVM `-sub` / bogus CF with a shared helper). Then: pattern-match PCode or instruction bytes, patch, reanalyze.
