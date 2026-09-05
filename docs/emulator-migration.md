# EmulatorHelper → PcodeEmulator migration (evaluation, Ghidra 12.1.3)

`ghidra.app.emulator.EmulatorHelper` is `@Deprecated(since="12.1", forRemoval=true)`. In 12.1.3 it is already only an adapter (`AdaptedEmulator`) over the new `ghidra.pcode.emu.PcodeEmulator`, so today both paths execute the same p-code machine; the day the adapter is deleted, `CffCore` stops compiling. This page records what the CFF engine uses, what the replacement API is (read from `Ghidra/Framework/Emulation/lib/Emulation-src.zip`, 12.1.3), and why the swap was **not** done in the same pass as the recovery/verify rework.

## Where the engine touches the emulator

All emulator access in `scripts/deobfuscation/CffCore.java` is confined to:

| Function | Uses |
|---|---|
| `newEmulator(program, trackWrites, fill)` | constructor, `enableMemoryWriteTracking`, `setMemoryFaultHandler` (uninitialised read → fill byte, unknown address → tolerate), `getStackPointerRegister`, `writeRegister` (SP/FP init) |
| `runPath(...)` | `getPCRegister`, `writeRegister(pc, …)`, `getExecutionAddress`, `step(monitor)`, `getLastError` (divide-by-zero skipped), `readRegister` / `writeRegister` (forcing selects), `dispose` |
| `Snapshot.take/restore` | `readRegister` for every base register, `getTrackedMemoryWriteSet`, `readMemory`, `writeMemory` |
| `traceRun(...)` | same as `runPath` minus forcing, plus register seeding and caller-saved clobbering at calls |

Nothing else (`CffScan`, `CffRecover`, `CffDeflatten`) touches an emulator directly.

## API mapping

| EmulatorHelper (old) | PcodeEmulator (new) |
|---|---|
| `new EmulatorHelper(program)` | `PcodeEmulator emu = new PcodeEmulator(language, callbacks)`; `PcodeThread<byte[]> t = emu.newThread()`; `EmulatorUtilities.initializeRegisters(t, program, pc)` (sets disassembly context — needed for ARM/Thumb TMode) |
| program memory visible to the emulator (lazy `ProgramMappedMemory`) | either eager `EmulatorUtilities.loadProgram(emu, program)` (copies every initialised block; fine for a `.so`), or lazy: implement `PcodeEmulationCallbacks.readUninitialized(thread, piece, set, reason)` on the **shared** state piece and fill from `program.getMemory()` for addresses the program defines |
| `setMemoryFaultHandler` → `uninitializedRead` fills a byte pattern | the same `readUninitialized` callback: for addresses the program does not define, write the fill byte via `piece.setVar(...)` and return the remaining set (empty). Uninitialised *register* reads arrive through the thread-local piece — fill zero there |
| `unknownAddress(addr, write)` → return true | not needed: the bytes state accepts any address |
| `readRegister(reg)` → `BigInteger` | `t.getState().getVar(reg, Reason.INSPECT)` → `byte[]` → `Utils.bytesToBigInteger(bytes, size, isBigEndian, false)`; or `t.getState().inspectRegisterValue(reg)` → `RegisterValue` |
| `writeRegister(reg, BigInteger)` | `t.getState().setVar(reg, arithmetic.fromConst(value, reg.getMinimumByteSize()))` or `setRegisterValue(new RegisterValue(reg, v))` |
| `writeRegister(pc, addr)` + `getExecutionAddress()` | `t.overrideCounter(addr)` (also resets the decode context; call `overrideContext` for Thumb) / `t.getCounter()` |
| `step(monitor)` → boolean, `getLastError()` | `t.stepInstruction()`; failures are exceptions: `PcodeExecutionException` (`LowlevelError` "Divide by 0" surfaces as its cause), `DecodePcodeExecutionException`, `AccessPcodeExecutionException`. To "skip" an instruction after a fault: `t.overrideCounter(next)` (and `t.dropInstruction()` if a frame is pending) |
| `advancePast` (skip a call) | `t.overrideCounter(fallThrough)`; or `t.inject(addr, "emu_skip_decoded();")` for a permanent skip |
| `readMemory(addr, len)` / `writeMemory(addr, bytes)` | `emu.getSharedState().getVar(space, offset, len, true, Reason.INSPECT)` / `setVar(...)`; `setConcrete(addr, bytes)` for eager loads |
| `enableMemoryWriteTracking` / `getTrackedMemoryWriteSet` | `PcodeEmulationCallbacks.dataWritten(thread, piece, address, length, value)` — accumulate an `AddressSet` for writes to the shared (memory) piece only. Note: `Snapshot.restore` writes must be tracked too (today they are, because the adapter routes `setChunk` through the same filter) — with callbacks, write the restore through the state so the callback fires, or add the ranges by hand |
| CALLOTHER without a userop (e.g. `mrs x19,tpidr_el0` in the SDK prologues) | `PcodeEmulationCallbacks.handleMissingUserop(...)` → return `true` to treat as handled; `AbstractPcodeMachine.createUseropLibrary()` already installs the language's userop library (`PcodeUseropLibraryFactory`) |
| `getStackPointerRegister()` | `program.getCompilerSpec().getStackPointer()`; `EmulatorUtilities.initializeForFunction(t, function)` also picks a stack range |
| `dispose()` | nothing (plain Java objects) |

## Behavioural differences to test for

1. **Uninitialised register reads.** The adapter's thread-local piece calls our fault handler (fill 0). A plain `PcodeEmulator` throws `AccessPcodeExecutionException` for uninitialised *unique* reads and returns whatever the callback initialised for registers — the callback must fill registers with zero or the prologue snapshot behaves differently.
2. **Instruction decode context.** `overrideCounter` clears the context; on ARM (Thumb) the TMode context must be re-applied (`EmulatorUtilities.initializeRegisters` does it; the adapter does it in `setProcessorContext`).
3. **Error reporting.** `step()` returned `false` + `getLastError()`; the new API throws. `runPath` decides "divide fault → skip" by matching the message; keep matching on `LowlevelError` message text or on the exception class.
4. **Performance.** The adapter adds a filter layer per memory access; a direct `PcodeEmulator` should be slightly faster. `JitPcodeEmulator` exists (`ghidra.pcode.emu.jit`) but forcing selects by rewriting registers between instructions defeats JIT batching — stay with the interpreter.

## Recommendation

Do the swap as its own change, with the fixture results of this pass as the regression baseline:

1. Introduce a tiny `Emu` interface inside `CffCore` (`pc()`, `getCounter/setCounter`, `readReg/writeReg`, `readMem/writeMem`, `step()` → `StepResult {ok, error}`, `trackedWrites()`, `dispose()`), implement it with `EmulatorHelper`, and make `runPath`/`traceRun`/`Snapshot` use only the interface. Run every fixture: results must be identical (they will be — pure refactor).
2. Add the `PcodeEmulator` implementation behind the same interface (callbacks for fill / write tracking / missing userops, eager `loadProgram`), selectable by a static flag.
3. Compare `CffRecover all` output and `CffDeflatten all` verify results on all fixtures with both backends; only when they match, delete the `EmulatorHelper` backend and the `@SuppressWarnings("removal")`.

Not done in this pass on purpose: the recovery, tree walk, liveness analysis and verify changed substantially at the same time; swapping the emulator underneath would have made any regression ambiguous. Everything the swap needs is listed above; the engine surface it has to cover is the four functions in the first table.
