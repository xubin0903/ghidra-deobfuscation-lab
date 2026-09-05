# Packers / unpack stubs

## What it looks like

- Tiny `.text`, fat overlay / extra section
- Imports reduced to `LoadLibrary` / `GetProcAddress` / `VirtualAlloc`
- Entry is a stub that decrypts the real image then jumps
- UPX, ASPack, custom game packers, "themida-lite"

## Ghidra built-ins

- Ghidra is a **static** tool. If the real image only exists after the stub runs, you need a dump from a debugger / emulator first.
- After you have an unpacked dump, import *that* here.

## Scripts in this lab

None yet. A packer-specific unpacker (in-Ghidra emulator walking the stub) is only worth it if we see the same stub across samples.

## Playbook

1. Identify packer (DIE, Detect It Easy, section names, entropy).
2. If it is UPX: `upx -d` outside Ghidra, then import the dump. Do not reinvent UPX.
3. If custom: run under x64dbg / Frida, dump at OEP (`VirtualProtect` RWX → RX is a common signal).
4. Import the dump into this Ghidra lab, then run analysis / deobfuscation scripts.
5. Keep the packed original in the *other* project, not here.

This lab is for reversing binaries you already have in other projects. Do not fetch random packed malware into `samples/` unless the user dropped it there.
