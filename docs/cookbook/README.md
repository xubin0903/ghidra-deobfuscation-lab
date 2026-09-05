# Deobfuscation cookbook

Playbooks, not scripts. Each page is "I see this obfuscation → which script / Ghidra feature / extra tool".

Scripts that implement a step live under `scripts/deobfuscation/` and are linked from here.

## Index

| Symptom | Start here |
|---|---|
| Opaque predicates / junk jumps / `if (1 == 1)` | [bogus-control-flow](bogus-control-flow.md) |
| Dispatcher + state var, every block returns to switch | [control-flow-flattening](control-flow-flattening.md) — run [CffScan](../scripts/CffScan.md) → [CffRecover](../scripts/CffRecover.md) → [CffDeflatten](../scripts/CffDeflatten.md) (compare-tree flavor); [CFFDispatchTracer](../scripts/CFFDispatchTracer.md) for the encrypted pointer-table flavor |
| Strings are `decrypt(enc, key)` or xor loops | [string-encryption](string-encryption.md) |
| Tiny bytecode VM, handler table | [custom-vm](custom-vm.md) |
| JNI `Java_com_foo_bar` missing, only `RegisterNatives` | [jni-names](jni-names.md) |
| Packer stub, UPX-like, custom unpack | [packers](packers.md) |

New obfuscation from another project: add a cookbook page **and** a script (or a "no script yet, do it by hand" note). Do not dump the sample binary into this repo unless asked.
