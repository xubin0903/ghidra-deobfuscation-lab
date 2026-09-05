# String encryption

## What it looks like

- `.rdata` is garbage, no readable C strings
- Cross-refs from a small helper: `decrypt(buf, len, key)` or inlined xor/add/rol loops
- Stack strings built byte-by-byte then used once
- JNI / C# / Go wrappers that decrypt on first use and cache

## Ghidra built-ins

- Search → For Scalars / For Strings still helps for leftover plaintext.
- Emulator (`EmulatorHelper`) can run the decryptor on a buffer without executing the rest of the binary.

## Scripts in this lab

- [FindEncryptedStringRefs](../scripts/FindEncryptedStringRefs.md) — heuristic: functions with xor/add loops over byte arrays. **Does not decrypt.** It points you at candidates.

## Playbook

1. Run `FindEncryptedStringRefs.java` (or dump xrefs to the suspected decrypt helper).
2. Confirm one call: note ciphertext address, length, key.
3. Either:
   - emulate the helper in Ghidra / Unicorn and `setEOLComment` the plaintext, or
   - reimplement the cipher in the script and patch / comment every call site.
4. After plaintext is known, create a Ghidra string at that address **only if** the bytes are actually replaced. Otherwise keep it as a comment so you don't lie to the listing.

## Do not

- Blindly XOR the whole `.rdata` with a one-byte key. You will smash pointers.
- Commit decrypted bytes into the binary file unless the other project asked for a patched dump.
