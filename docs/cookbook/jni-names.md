# JNI name recovery (Android `.so`)

## What it looks like

- Exports are only `JNI_OnLoad` / `JNI_OnUnload`
- Real natives registered via `RegisterNatives` with a `JNINativeMethod[]` table
- Or mangled `Java_com_foo_Bar_method` that Ghidra did not demangle
- Java side is in the APK (`jadx`); native side is here

## Ghidra built-ins

- Symbol table → filter `Java_`
- `JNI_OnLoad` decompilation often shows the `JNINativeMethod` array if types are set

## Scripts in this lab

None yet. Planned:

- Parse `JNINativeMethod { name, signature, fnPtr }` arrays and rename the functions.
- Apply `JNIEnv*` / `jobject` types to the first two args.

## Playbook

1. In the APK (other project / jadx): list `native` methods.
2. In Ghidra: xrefs to `RegisterNatives` (or the PLT stub).
3. At each call, the third arg is the method table, fourth is count.
4. Define a struct:

```c
struct JNINativeMethod {
    char *name;
    char *signature;
    void *fnPtr;
};
```

5. Rename `fnPtr` targets to `Java_<pkg>_<cls>_<method>`.
6. If names are encrypted, do [string-encryption](string-encryption.md) first.

Do not copy the APK into this repo. Point at the `.so` path from the Android project.
