# Custom VM / bytecode handlers

## What it looks like

- Tiny interpreter loop: fetch opcode → switch/table → handler
- Handlers are short, operate on a fake CPU (regs array + pc + sp)
- Real logic is in a bytecode blob, not in native CFG
- VMProtect / Themida / custom game anti-cheat VMs are this family (much nastier)

## Ghidra built-ins

- Label the opcode table. If it is a pointer array, Ghidra jump-table recovery may already create a switch.
- PCode emulator can step a handler; it will not lift the VM to native.

## Scripts in this lab

None yet. When we write one it should:

1. Find the dispatcher and opcode table.
2. Dump `(opcode -> handler address + short comment)`.
3. Optionally lift bytecode to a linear listing in a new memory block (as comments / a fake language). Full devirtualization is per-VM.

## Playbook

1. Identify fetch: `opcode = code[pc++]`.
2. Identify dispatch: `handlers[opcode]()` or a dense switch.
3. Name each handler (`VADD`, `VXOR`, `VJCC`, …) from what it does to the fake regs.
4. Dump a trace (Frida / Unicorn / Ghidra emulator) for one interesting native function that enters the VM.
5. Only then decide if a lifter is worth it. Most of the time a handler map + one trace is enough for the other project.
