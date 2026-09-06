# Script catalog

Every script in `scripts/` must have a page here. Folder layout:

| Folder | Category | For |
|---|---|---|
| `scripts/java` | Java | Generic Java GhidraScript samples / utilities |
| `scripts/python` | Python | PyGhidra samples / utilities |
| `scripts/deobfuscation` | Deobfuscation | CFG flatten, string decrypt, junk, VM, packers |
| `scripts/analysis` | Analysis | Listing, xrefs, signatures, type recovery helpers |
| `scripts/export` | Export | Dumps other projects consume (JSON/CSV/C headers) |
| `scripts/headless` | Headless | Scripts written to run unattended |

## Index

| Script | Lang | Category | One-liner |
|---|---|---|---|
| [HelloGhidra](HelloGhidra.md) | Java | Java | Smoke-test: program name / image base / language |
| [ListFunctions](ListFunctions.md) | Java | Analysis | Print every function name + entry + size |
| [DumpExports](DumpExports.md) | Java | Export | Dump PE/ELF exports as JSON |
| [HeadlessSummary](HeadlessSummary.md) | Java | Headless | key=value summary for batch logs |
| [HashMemory](HashMemory.md) | Java | Headless | SHA-256 per memory block + total; byte-exact patch/undo oracle |
| [FindEncryptedStringRefs](FindEncryptedStringRefs.md) | Java | Deobfuscation | Heuristic: xor/add/rol loops (does **not** decrypt) |
| [CFFDispatchTracer](CFFDispatchTracer.md) | Java | Deobfuscation | OLLVM/Hikari dispatch-**table** recovery (static, no emu) |
| [HikariCffIslands](HikariCffIslands.md) | Java | Deobfuscation | Classify reloc-filled dests; bookmark work islands (not CFG rewrite) |
| [CffScan](CffScan.md) | Java | Deobfuscation | Detect state-machine CFF (flattening score + scaffold), low false positive |
| [CffRecover](CffRecover.md) | Java | Deobfuscation | Emulate each case → real CFG (landing contexts, nested forks, low-confidence checks); comments/DOT/JSON (no patching) |
| [CffDeflatten](CffDeflatten.md) | Java | Deobfuscation | Patch case tails → direct branches for clean decompilation; `-O2` tail merging, branch-decided edges, external stub block, 4-seed verify + structural oracle, undo log (AArch64 ELF/Mach-O, x86/x64, ARM32 validated; Thumb encoders only) |
| [BcfClean](BcfClean.md) | Java | Deobfuscation | Fold OLLVM bogus-control-flow opaque predicates (constant conditions on never-written globals) → unconditional branch / NOP; 4-seed verify, undo log (ARM32 + x86 validated) |
| [HelloPyGhidra](HelloPyGhidra.md) | Python | Python | Smoke-test PyGhidra (CPython 3) vs Jython |

> `CffScan` / `CffRecover` / `CffDeflatten` / `BcfClean` share one engine, `scripts/deobfuscation/CffCore.java` (a plain helper class, not a runnable script — no page of its own). `CFFDispatchTracer` targets the **pointer-table** CFF flavor (encrypted/`-irobf-indbr` loaders); the `Cff*` trio targets the **switch/compare-tree** flavor and can rebuild + patch the CFG. See the [cookbook](../cookbook/control-flow-flattening.md) for which is which.

When you add a script, add a row and a `docs/scripts/<Name>.md`.
