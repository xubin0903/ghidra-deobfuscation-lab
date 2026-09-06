// CffDeflatten — turn a flattened function back into straight-line code by
// PATCHING each real block to jump directly to its recovered successor, so the
// Ghidra decompiler produces clean nested if/for instead of a state-machine.
//
// @category Deobfuscation
// @menupath Tools.Deobfuscation.CFF Deflatten (patch)
// @description Patch CFF case tails to their emulated successors (AArch64 + x86/x64 validated, ARM32/Thumb encoders unvalidated); handles -O2 tail merging, replays live dispatcher copies, verifies by multi-seed trace + structural check, writes an undo log.
//
// This is the aggressive counterpart to CffRecover. It only rewrites edges it
// can prove: a case is patched ONLY if recovery marked it pure (execution
// reached the successor through dispatcher blocks alone) and resolved, and the
// dispatcher path carried nothing the successor needs that the patch cannot
// replay. Anything impure / multi-way / unresolved is left byte-for-byte
// untouched — the point is to delete the dispatcher scaffold, never to guess
// real logic away.
//
// Two operating modes per function:
//   * full   — every case (and the prologue) is patchable. The whole dispatcher
//              becomes dead code and is reused as a code cave for trampoline
//              stubs, so optimised (-O2) tails that carry real register copies
//              (PHI resolution) inside the compare tree are handled: the stub
//              replays those copies, then jumps to the real successor.
//   * partial— some case cannot be patched, so the dispatcher must stay intact.
//              Only tails that need no stub are rewritten in place.
//
// Transform per case tail (in place):
//   unconditional:  <... state store ...>  B/JMP dispatcher    =>  B/JMP successor   (every tail of the case)
//   conditional  :  CMP; CSEL/CMOV; <dead>; B/JMP dispatcher  =>  B.cc/Jcc succTrue; B/JMP succFalse; NOP pad
//   branch-decided: CMP; B.cc armT; <armF: state; B disp>; armT: <state; B disp>
//                   => the branch stays, each arm's own tail is redirected (no condition re-encoded)
// With stubs (full mode, dead dispatcher = code cave):
//   conditional  :  CSEL ... B dispatcher  =>  B.cc stubT; B stubF   where stubX = <tail instrs after CSEL> <tree copies> B succX
//   shared tail  :  <owned hand-off> -> B stub, stub = <shared tail body> <tree copies> B succ   (the shared block is never written)
//   shared select:  <owned hand-off> -> B condStub, condStub = <shared compare prefix> B.cc stubT; B stubF
// The flag-setting compare is kept (in place or copied), so the branch
// condition is exactly the one the select used.
//
// After writing, the original and the patched function are both emulated from
// the entry under four input seeds and the sequence of real blocks + registers
// is compared (`verify`, on by default); full-mode functions must additionally
// leave every unpatched dispatcher byte unreachable. A mismatch reverts that
// function's patches.
//
// Args (headless: after -postScript CffDeflatten.java):
//   func=0x114400   target function (GUI default: function under cursor)
//   all             every function CffScan flags as CFF
//   force           run even if CffScan does not flag the function
//   dryRun          print the patch plan; write nothing (RECOMMENDED first)
//   noVerify        skip the before/after trace comparison
//   keepOnMismatch  keep patches even if verification fails (default: revert that function)
//   noStubs         never reuse the dead dispatcher as a code cave (in-place patches only)
//   noReanalyze     do not clear+redisassemble patched sites
//   verifySelfTest  deliberately swap the arms of the first select patch; verify must revert it (harness check)
//   log=PATH        write a JSON patch log (default: <program>.cff-patch.json next to the binary)
//   undo=PATH       restore bytes from a previous patch log, then exit
//   maxSteps=20000  per-path emulation step cap (recovery)

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

public class CffDeflatten extends GhidraScript {

	private enum Arch {
		ARM64, ARM32, X86, OTHER
	}

	private static final int TRACE_MAX_HEADS = 2000;  // per seed
	private static final int TRACE_MAX_STEPS = 300000;

	private Arch arch;
	private boolean thumbFn;        // ARM32: the function being planned is Thumb code (TMode context = 1)
	private Register tmodeReg;      // ARM32: the TMode context register
	private boolean dryRun;
	private boolean reanalyze = true;
	private boolean verify = true;
	private boolean keepOnMismatch;
	private boolean allowStubs = true;
	private boolean allowExternal = true;   // stubs may go to a new memory block when the dispatcher cave is unusable / too small
	private Address externalBase;           // where that block would start (chosen once per run, also in dryRun)
	private StubAllocator external;         // shared pool over [externalBase, externalBase + EXTERNAL_RESERVE)
	private MemoryBlock externalBlock;      // the block, once created
	private static final long EXTERNAL_RESERVE = 4L << 20; // address space reserved for planning; the block is sized to what was used
	private static final String EXTERNAL_BLOCK_NAME = "cff_stubs";
	private boolean selfTestFlip;   // verifySelfTest: deliberately invert the first select's condition; verify MUST catch it
	private boolean flipped;
	private boolean debugTrace;     // debugTrace: on a verify mismatch, print both head sequences and the diverging registers
	private boolean debugPlan;      // debugPlan: print every dispatcher instruction on each patched edge with its live/dropped verdict
	private final List<FnPlan> plans = new ArrayList<FnPlan>();

	private static final class Patch {
		Address at;
		byte[] orig;
		byte[] repl;
		String kind;
		String desc;
		Address fn;
	}

	private static final class FnPlan {
		Function f;
		CffCore.Detect d;
		CffCore.Recovery r;
		boolean full;
		int stubBytes;
		int externalBytes;      // trampoline bytes placed in the external stub block
		boolean thumb;          // ARM32: function (and its stubs) run in Thumb mode
		final List<Patch> patches = new ArrayList<Patch>();
		final List<String> lines = new ArrayList<String>();   // report rows
		final List<String> skips = new ArrayList<String>();
		final Set<String> deadRegs = new HashSet<String>();  // state registers etc.: ignored by the before/after register comparison
		final Set<String> regionDead = new HashSet<String>(); // registers whose writes on a dispatcher path are dead everywhere (compare copy)
		final Map<Address, Set<String>> ignoreAt = new HashMap<Address, Set<String>>(); // per-head registers verify may ignore
		final Map<String, Address> stubCache = new HashMap<String, Address>();          // identical replay stubs are shared
		final Set<String> stateScratch = new HashSet<String>();                          // registers the dispatcher fills with state-derived values
		Set<String> stateSlots = new HashSet<String>();     // memory operands the dispatcher reads (state var + spills)
		Set<String> derivedSlots = new HashSet<String>();   // subset whose reloads are state-derived (memory-resident state only)
		Trace before;
		boolean applied;
		String verifyResult;
	}

	/** One whole-function trace per input seed. */
	private static final class Trace {
		final List<List<CffCore.TraceEvent>> perSeed = new ArrayList<List<CffCore.TraceEvent>>();

		int headVisits() {
			int n = 0;
			for (List<CffCore.TraceEvent> l : perSeed) {
				n += l.size();
			}
			return n;
		}
	}

	/**
	 * Input vectors for the before/after comparison. Zeroed inputs alone
	 * follow one path; the other seeds push argument-dependent branches the
	 * other way (small positives, all-ones, pointer-like values into the
	 * emulator's scratch area with non-zero memory).
	 */
	private static final CffCore.TraceSeed[] SEEDS = {
		new CffCore.TraceSeed("zero", new long[] { 0 }, (byte) 0),
		new CffCore.TraceSeed("small", new long[] { 1, 2, 3, 4, 5, 6, 7, 8 }, (byte) 0x01),
		new CffCore.TraceSeed("ones", new long[] { -1L }, (byte) 0xFF),
		new CffCore.TraceSeed("ptr", new long[] { 0x7ff000020000L, 0x7ff000030000L, 0x10, 0x7ff000040000L }, (byte) 0x41),
	};

	/** The instruction through which a case hands control to the dispatcher on one edge. */
	private static final class Term {
		Instruction insn;                 // the unconditional branch into the dispatcher
		Instruction condInsn;             // a conditional branch whose TAKEN target is the dispatcher (retargeted in place)
		Address regionEntry;              // fell into the dispatcher without a branch: the first dispatcher address
		Address directTarget;             // the edge never crossed the dispatcher (already direct)
		/**
		 * Tail-merged layout: the `b dispatcher` lives in a block SHARED with
		 * other cases. {@code site} is the last instruction this case owns on the
		 * path (its slot receives `b stub`); {@code moved} are the instructions
		 * the stub must replay before the dispatcher copies: {@code site} itself
		 * when it is not a jump, then the shared block's body up to the tail.
		 */
		Instruction site;
		final List<Instruction> moved = new ArrayList<Instruction>();
		String fail;
		final List<Instruction> linear = new ArrayList<Instruction>(); // x86 short-jmp rescue: relocatable instructions right before insn
	}

	/**
	 * One redirectable edge: a tail (the instruction handing control to the
	 * dispatcher) that always leads to {@code succ}, plus the dispatcher
	 * copies that path performed. Unconditional nodes have one per tail
	 * (usually exactly one); a case whose decision is a real conditional
	 * branch has one per arm — the branch itself is left untouched and each
	 * arm's own tail is redirected, so no condition code is ever re-encoded.
	 */
	private static final class EdgePlan {
		Address succ;
		Address tail;
		Term term;
		CffCore.PathEffects eff;
		boolean needStub;
	}

	private static final class NodePlan {
		CffCore.Node node;
		String kind = "none";             // uncond | branch | cond | none
		final List<EdgePlan> edges = new ArrayList<EdgePlan>(); // uncond / branch
		Term term;                        // cond (select): the tail
		Instruction sel;
		final List<Instruction> pre = new ArrayList<Instruction>();  // cond: owned instructions borrowed from before the select (run first in the stubs)
		final List<Instruction> post = new ArrayList<Instruction>(); // cond: real code between select and tail (replayed in the stubs)
		Address windowEnd;                // cond: end of the owned, contiguous bytes the branch pair may overwrite
		/**
		 * cond, select in a block SHARED with other cases (tail-merged compare):
		 * {@code site} is this case's last owned instruction before it; its slot
		 * gets `b condStub`, where condStub = {@code lead} (the site itself unless
		 * it is a jump, then the shared instructions up to the select: they carry
		 * the compare) followed by the branch pair.
		 */
		Instruction site;
		final List<Instruction> lead = new ArrayList<Instruction>();
		boolean condStub;
		CffCore.PathEffects effT;         // cond
		CffCore.PathEffects effF;
		boolean needStubs;
		boolean postWritesFlags;
		String blocker;
	}

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		CffCore.Args a = CffCore.parseArgs(getScriptArgs(), new String[] { "func", "log", "undo", "maxSteps" });
		boolean all = a.flag("all");
		boolean force = a.flag("force");
		dryRun = a.flag("dryRun");
		reanalyze = !a.flag("noReanalyze");
		verify = !a.flag("noVerify");
		keepOnMismatch = a.flag("keepOnMismatch");
		allowStubs = !a.flag("noStubs");
		allowExternal = !a.flag("noExternalStubs");
		selfTestFlip = a.flag("verifySelfTest");
		debugTrace = a.flag("debugTrace");
		debugPlan = a.flag("debugPlan");
		CffCore.MAX_STEPS = a.getInt("maxSteps", CffCore.MAX_STEPS);
		Address single = a.get("func") != null ? parseAddr(a.get("func")) : null;

		if (a.get("undo") != null) {
			undo(a.get("undo"));
			return;
		}

		arch = archOf();
		println("=== CffDeflatten ===");
		println("program=" + currentProgram.getName() + " language=" + currentProgram.getLanguageID() + " arch=" + arch
				+ " dryRun=" + dryRun + " verify=" + verify + " stubs=" + allowStubs);
		if (arch == Arch.OTHER) {
			printerr("patching not supported for this architecture (AArch64, ARM32/Thumb, x86/x64 only). Use CffRecover for annotations.");
			return;
		}
		if (arch == Arch.ARM32) {
			tmodeReg = currentProgram.getRegister("TMode");
			println("NOTE: ARM32 (A32) patching is validated on the deflat check_passwd fixture; Thumb-2 has encoders but no fixture yet"
					+ " (IT-block predication is reported, not modelled). Retargeting a conditional tail branch is not implemented for ARM32.");
		}
		if (allowStubs && allowExternal) {
			externalBase = chooseExternalBase();
			if (externalBase != null) {
				external = new StubAllocator(new AddressSet(externalBase, externalBase.add(EXTERNAL_RESERVE - 1)),
						risc() ? 4 : 1);
				println("external stub block: " + EXTERNAL_BLOCK_NAME + " would start @" + externalBase
						+ " (created only if a stub needs it; noExternalStubs disables)");
			}
			else {
				println("external stub block: no free address range after the image; dispatcher-cave stubs only");
			}
		}

		List<Function> targets = new ArrayList<Function>();
		if (single != null) {
			Function f = getFunctionContaining(single);
			if (f == null) {
				printerr("no function at " + single);
				return;
			}
			targets.add(f);
		}
		else if (!all && currentAddress != null && getFunctionContaining(currentAddress) != null) {
			targets.add(getFunctionContaining(currentAddress));
		}
		else {
			FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
			while (fit.hasNext()) {
				Function f = fit.next();
				if (!f.isExternal() && !f.isThunk()) {
					targets.add(f);
				}
			}
			all = true;
		}

		int totalPatches = 0;
		int fullFns = 0;
		for (int i = 0; i < targets.size(); i++) {
			if (monitor.isCancelled()) {
				break;
			}
			Function f = targets.get(i);
			CffCore.Detect d = CffCore.detect(currentProgram, f, monitor);
			if (!d.isCff && !force) {
				if (!all) {
					println("  " + f.getName() + " not flagged CFF (score=" + String.format("%.3f", d.score)
							+ "); use force to override");
				}
				continue;
			}
			monitor.setMessage("CffDeflatten " + f.getName());
			CffCore.Recovery r = CffCore.recover(currentProgram, d, monitor);
			FnPlan p = plan(f, d, r);
			// the per-head ignore sets for verify must come from the ORIGINAL listing:
			// a shared-tail hand-off moves the head's killing writes into a stub, so
			// killedOnEntry() computed after patching would report false mismatches
			for (Address h : r.nodes.keySet()) {
				ignoredAt(p, h);
			}
			for (Address h : r.watch) {
				ignoredAt(p, h);
			}
			r.trim(); // planning is done with the per-path detail; verification only needs heads + region
			plans.add(p);
			println("");
			String ext = p.externalBytes > 0 ? ", " + p.externalBytes + " bytes in " + EXTERNAL_BLOCK_NAME : "";
			println("--- " + f.getName() + " @" + f.getEntryPoint() + " dispatcher=" + d.dispatcher + " mode="
					+ (p.full ? "full (dispatcher becomes code cave, " + p.stubBytes + " stub bytes" + ext + ")"
							: "partial" + (p.externalBytes > 0 ? " (stubs" + ext + ")" : ""))
					+ " ---");
			println("  cases=" + (r.nodes.size() - 1) + " resolved=" + r.resolved + " conditional=" + r.conditional
					+ " unresolved=" + r.unresolved + " -> planned patches=" + p.patches.size());
			for (String line : p.lines) {
				println("    " + line);
			}
			for (String s : p.skips) {
				println("    (skip " + s + ")");
			}
			totalPatches += p.patches.size();
			if (p.full) {
				fullFns++;
			}
		}

		println("");
		int extUsed = external == null ? 0 : external.used();
		if (dryRun) {
			println("dryRun: " + totalPatches + " patches across " + plans.size() + " function(s), " + fullFns
					+ " fully deflattened; nothing written.");
			if (extUsed > 0) {
				println("dryRun: would create memory block " + EXTERNAL_BLOCK_NAME + " @" + externalBase + " ("
						+ externalBlockSize(extUsed) + " bytes) for " + extUsed + " bytes of trampolines");
			}
			println("re-run without dryRun to apply. see docs/scripts/CffDeflatten.md");
			return;
		}
		if (extUsed > 0) {
			createExternalBlock(extUsed);
		}

		// One function at a time: trace the original, write, re-disassemble, trace
		// again, compare, revert on mismatch. Patches are function-local (stubs
		// live in the function's own dead dispatcher or the shared stub block),
		// and keeping only one function's traces alive is what lets a 200+
		// function run fit in memory.
		int applied = 0;
		int reverted = 0;
		for (FnPlan p : plans) {
			if (p.patches.isEmpty()) {
				continue;
			}
			if (verify) {
				p.before = trace(p);
			}
			applied += apply(p);
			if (p.applied && (reanalyze || verify)) {
				reflow(p);
			}
			if (!verify || !p.applied) {
				continue;
			}
			Trace after = trace(p);
			String res = compareTraces(p, p.before, after);
			if (res == null && p.full) {
				// objective oracle for full mode: the re-disassembled CFG must not
				// reach any unpatched dispatcher byte, and no real block may be lost
				res = checkFullModeCfg(p);
			}
			if (res == null) {
				p.verifyResult = "OK (" + p.before.headVisits() + " head visits over " + p.before.perSeed.size()
						+ " input seeds" + (p.full ? ", dispatcher unreachable" : "") + ")";
				println("  verify " + p.f.getName() + ": " + p.verifyResult);
			}
			else {
				p.verifyResult = "MISMATCH " + res;
				printerr("  verify " + p.f.getName() + ": " + p.verifyResult);
				if (debugTrace) {
					dumpTraces(p, p.before, after);
				}
				if (!keepOnMismatch) {
					revert(p);
					reflow(p);
					reverted++;
					printerr("    -> patches of " + p.f.getName() + " reverted (use keepOnMismatch to keep them)");
				}
			}
			p.before = null; // traces are large; drop them as soon as the verdict is in
		}
		println("applied " + applied + "/" + totalPatches + " patches across " + plans.size() + " function(s)");
		if (externalBlock != null && !externalBlockInUse()) {
			// every function that needed the block was reverted: leave no empty block behind
			String name = externalBlock.getName();
			if (removeStubBlock(externalBlock)) {
				println("external stub block " + name + " removed again (no surviving stub uses it)");
				externalBlock = null;
			}
		}

		String logPath = a.get("log");
		if (logPath == null) {
			logPath = new File(defaultDir(), currentProgram.getName() + ".cff-patch.json").getAbsolutePath();
		}
		writeLog(logPath, applied);
		println("patch log: " + logPath + "   (undo: -postScript CffDeflatten.java undo=" + logPath + ")");
		if (reverted > 0) {
			println("verify reverted " + reverted + " function(s); the rest are clean.");
		}
		println("done. re-run auto-analysis (or press F5) for the cleanest decompilation. see docs/scripts/CffDeflatten.md");
	}

	// ------------------------------------------------------------- planning --

	private FnPlan plan(Function f, CffCore.Detect d, CffCore.Recovery r) throws Exception {
		FnPlan p = new FnPlan();
		p.f = f;
		p.d = d;
		p.r = r;
		// Registers the before/after comparison may ignore: the state registers
		// (compare register, next-state register, select destinations). NB: they
		// are NOT assumed dead for the replay analysis — an -O2 tree can hoist a
		// case's `state = NEXT` into the tree path leading to it, so a write to
		// the state register on a dispatcher path is live whenever the successor
		// does not overwrite it first; the per-write liveness decides that.
		if (r.heads.stateIncoming != null) {
			p.deadRegs.add(r.heads.stateIncoming);
		}
		if (r.heads.stateBase != null) {
			p.deadRegs.add(r.heads.stateBase);
		}
		for (CffCore.Node node : r.nodes.values()) {
			if (node.status.equals("cond") && "select".equals(node.deciderKind) && node.selectAddr != null) {
				Instruction sel = getInstructionAt(node.selectAddr);
				Register dst = sel == null ? null : sel.getRegister(0);
				if (dst != null) {
					p.deadRegs.add(dst.getBaseRegister().getName());
				}
			}
		}
		// The only register that is dead everywhere on a dispatcher path is the
		// compare copy the dispatcher makes for itself (`mov x8,x9` -> x8): it is
		// rewritten at every dispatcher entry and case heads never read it (the
		// recovery refuses functions where one does).
		if (r.heads.stateIncoming != null && r.heads.stateBase != null && !r.heads.stateIncoming.equals(r.heads.stateBase)) {
			p.regionDead.add(r.heads.stateBase);
		}
		// slots that hold the state or a spill of it — NOT every slot the dispatcher
		// touches: an -O2 tree reloads / spills real PHI values through the frame too
		p.stateSlots = r.heads.stateSlots;
		// reloads from these slots are state-derived ONLY when the state itself lives in memory (-O0);
		// an -O2 tree may reload real spilled values, which must be replayed, not dropped
		p.derivedSlots = r.heads.stateIncoming == null ? p.stateSlots : Collections.<String> emptySet();

		if (r.lowConfidence) {
			// a graph no flattened function can produce: do not build on it at all
			p.skips.add("LOW CONFIDENCE recovery, nothing patched: " + r.confidenceNote);
			return p;
		}
		if (arch == Arch.ARM32) {
			thumbFn = isThumbAt(f.getEntryPoint());
			p.thumb = thumbFn;
			// every byte we touch or reuse must be in the function's ISA mode
			for (Address a : r.dispatchRegion.getAddresses(true)) {
				if (isThumbAt(a) != thumbFn) {
					p.skips.add("dispatcher mixes ARM and Thumb code; not patched");
					return p;
				}
			}
		}

		List<Address> heads = new ArrayList<Address>(r.nodes.keySet());
		Collections.sort(heads);
		List<NodePlan> nps = new ArrayList<NodePlan>();
		boolean anyBlocker = false;
		for (Address h : heads) {
			CffCore.Node node = r.nodes.get(h);
			NodePlan np = analyzeNode(p, node);
			nps.add(np);
			if (np.blocker != null) {
				anyBlocker = true;
			}
			// NB: registers a dispatcher path leaves dead are NOT excluded from
			// verification globally; compareTraces() ignores, per head, only the
			// registers that head kills on entry (plus the state registers).
		}
		// Where may stubs go? In full mode the dead dispatcher is the first
		// choice (keeps the code local); the external stub block takes the
		// overflow. In partial mode the dispatcher stays live and owns no spare
		// byte, so stubs can ONLY go to the external block — without it, every
		// edge that needs a trampoline stays flattened.
		boolean extOk = allowStubs && allowExternal && external != null && externalInRange(f);
		if (allowStubs && allowExternal && external != null && !extOk) {
			p.skips.add("external stub block @" + externalBase + " is out of branch range for this function; dispatcher-cave stubs only");
		}
		int align = risc() ? riscAlign() : 1;
		// full mode: nothing keeps the dispatcher alive, so its bytes may host stubs.
		// The prologue's own way into the dispatcher must be covered too: either
		// it is a plain fall-in (firstHead known, redirected by an entry patch) or
		// the entry block is itself a case whose plan redirects its exit(s).
		boolean entryCovered = r.firstHead != null;
		if (!entryCovered) {
			for (NodePlan np : nps) {
				if (np.node.head.equals(f.getEntryPoint()) && np.blocker == null && !np.kind.equals("none")) {
					entryCovered = true;
				}
			}
		}
		if (!entryCovered) {
			CffCore.Node en = r.nodes.get(f.getEntryPoint());
			p.skips.add("prologue exit not redirectable (entry node status=" + (en == null ? "missing" : en.status)
					+ ", successors=" + (en == null ? "-" : en.succs) + "); partial mode");
		}
		p.full = allowStubs && !anyBlocker && entryCovered && !r.dispatchRegion.isEmpty();
		if (p.full) {
			StubAllocator alloc = new StubAllocator(r.dispatchRegion, align);
			StubAllocator extSnap = null;
			if (extOk) {
				alloc.setFallback(external);
				extSnap = external.copy();
			}
			// reserve the dispatcher entry slot(s) used by tails that fall into it
			List<Address> entries = new ArrayList<Address>();
			for (NodePlan np : nps) {
				if (np.term != null && np.term.regionEntry != null) {
					entries.add(np.term.regionEntry);
				}
				for (EdgePlan e : np.edges) {
					if (e.term != null && e.term.regionEntry != null) {
						entries.add(e.term.regionEntry);
					}
				}
			}
			for (Address at : entries) {
				int len = branchLen();
				if (!r.dispatchRegion.contains(at, at.add(len - 1))) {
					p.full = false;
					p.skips.add("dispatcher entry " + at + " too small for a branch; partial mode");
					break;
				}
				alloc.reserve(at, len);
			}
			if (p.full) {
				int extBefore = external == null ? 0 : external.used();
				String failure = emitAll(p, nps, alloc, true);
				if (failure == null) {
					p.stubBytes = alloc.used();
					p.externalBytes = external == null ? 0 : external.used() - extBefore;
					return p;
				}
				// something in the full plan did not work out: the dispatcher must
				// stay intact, so throw the whole plan away and redo it in partial mode
				p.patches.clear();
				p.lines.clear();
				p.skips.clear();
				p.stubCache.clear();
				if (extSnap != null) {
					external.restore(extSnap);
				}
				p.skips.add("full mode abandoned (" + failure + "; dispatcher cave " + alloc.capacity() + " bytes, " + alloc.used()
						+ " used); partial mode");
				p.full = false;
			}
		}
		if (!anyBlocker && !allowStubs) {
			p.skips.add("noStubs: dispatcher kept although every case resolved");
		}
		StubAllocator palloc = null;
		if (extOk) {
			palloc = new StubAllocator(new AddressSet(), align); // no local cave: everything goes external
			palloc.setFallback(external);
		}
		int extBefore = external == null ? 0 : external.used();
		emitAll(p, nps, palloc, false);
		p.externalBytes = external == null ? 0 : external.used() - extBefore;
		return p;
	}

	/**
	 * Is the external stub block reachable from this function with a plain
	 * unconditional branch (B ±128 MiB on AArch64, ±32/16 MiB on ARM/Thumb,
	 * rel32 on x86)?
	 */
	private boolean externalInRange(Function f) {
		if (externalBase == null) {
			return false;
		}
		long d = Math.abs(externalBase.add(EXTERNAL_RESERVE).subtract(f.getEntryPoint()));
		long d2 = Math.abs(externalBase.subtract(f.getEntryPoint()));
		long dist = Math.max(d, d2) + f.getBody().getNumAddresses();
		switch (arch) {
		case ARM64:
			return dist < (1L << 27) - 0x10000;
		case ARM32:
			return dist < (thumbFn ? (1L << 24) : (1L << 25)) - 0x10000;
		case X86:
			return dist < (1L << 31) - 0x10000;
		default:
			return false;
		}
	}

	/**
	 * Emit every node plan. {@code full}: the dispatcher is dead, so its entry
	 * slots may be redirected and any failure invalidates the whole plan
	 * (returns the reason). Otherwise the dispatcher stays live: failures are
	 * recorded as skips, and nothing that writes into the dispatcher is emitted.
	 */
	private String emitAll(FnPlan p, List<NodePlan> nps, StubAllocator alloc, boolean full) {
		for (NodePlan np : nps) {
			if (np.blocker != null) {
				if (!np.node.status.equals("ret") && !np.node.status.equals("exit")) {
					p.skips.add(np.node.head + ": " + np.blocker);
				}
				continue;
			}
			if (np.kind.equals("none")) {
				continue;
			}
			if (np.kind.equals("cond")) {
				if (np.needStubs && alloc == null) {
					p.skips.add(np.node.head + ": needs a trampoline (" + stubReason(np) + ") but the dispatcher must stay live"
							+ " and no external stub block is available");
					continue;
				}
				int mark = p.patches.size();
				try {
					emitSelect(p, np, alloc, full);
					debugEffects(p, "true path", np.effT);
					debugEffects(p, "false path", np.effF);
				}
				catch (Exception e) {
					if (full) {
						return np.node.head + ": " + e.getMessage();
					}
					dropPatchesFrom(p, mark); // no orphan stubs for an edge that was not redirected
					p.skips.add(np.node.head + ": " + e.getMessage());
				}
				continue;
			}
			// uncond / branch: one independent redirect per tail
			for (EdgePlan e : np.edges) {
				if (e.needStub && alloc == null) {
					p.skips.add(np.node.head + " tail " + e.tail + ": needs a trampoline (" + edgeStubReason(e)
							+ ") but the dispatcher must stay live and no external stub block is available");
					continue;
				}
				int mark = p.patches.size();
				try {
					emitEdge(p, np, e, alloc, full);
					debugEffects(p, "edge " + e.tail + " -> " + e.succ, e.eff);
				}
				catch (Exception ex) {
					if (full) {
						return np.node.head + ": " + ex.getMessage();
					}
					dropPatchesFrom(p, mark);
					p.skips.add(np.node.head + " tail " + e.tail + ": " + ex.getMessage());
				}
			}
		}
		return null;
	}

	private void dropPatchesFrom(FnPlan p, int mark) {
		while (p.patches.size() > mark) {
			Patch dropped = p.patches.remove(p.patches.size() - 1);
			p.stubCache.values().remove(dropped.at);
		}
	}

	private void debugEffects(FnPlan p, String label, CffCore.PathEffects eff) {
		if (!debugPlan || eff == null) {
			return;
		}
		p.lines.add("      " + label + ": " + eff.live.size() + " live / " + eff.dropped.size() + " dropped; dead="
				+ eff.deadRegs);
		for (Instruction in : eff.live) {
			p.lines.add("        LIVE  " + in.getMinAddress() + "  " + in);
		}
		for (Instruction in : eff.dropped) {
			p.lines.add("        drop  " + in.getMinAddress() + "  " + in);
		}
	}

	private String edgeStubReason(EdgePlan e) {
		StringBuilder sb = new StringBuilder();
		if (e.term != null && e.term.regionEntry != null) {
			sb.append("falls through into the dispatcher");
		}
		if (e.eff != null && !e.eff.live.isEmpty()) {
			if (sb.length() > 0) {
				sb.append(", ");
			}
			sb.append(e.eff.live.size() + " live dispatcher instruction(s) to replay");
		}
		return sb.length() == 0 ? "tail layout" : sb.toString();
	}

	private String stubReason(NodePlan np) {
		StringBuilder sb = new StringBuilder();
		if (np.term != null && np.term.regionEntry != null) {
			sb.append("tail falls through into the dispatcher");
		}
		int copies = 0;
		if (np.effT != null) {
			copies += np.effT.live.size();
		}
		if (np.effF != null) {
			copies += np.effF.live.size();
		}
		if (copies > 0) {
			if (sb.length() > 0) {
				sb.append(", ");
			}
			sb.append(copies + " live dispatcher instruction(s) to replay");
		}
		if (np.kind.equals("cond") && (np.postWritesFlags || arch == Arch.X86)) {
			if (sb.length() > 0) {
				sb.append(", ");
			}
			sb.append(np.postWritesFlags ? "flags clobbered between select and branch" : "real code between select and branch");
		}
		return sb.length() == 0 ? "tail layout" : sb.toString();
	}

	private NodePlan analyzeNode(FnPlan p, CffCore.Node node) throws Exception {
		NodePlan np = new NodePlan();
		np.node = node;
		if (node.status.equals("ret") || node.status.equals("exit")) {
			return np; // nothing to patch, nothing keeps the dispatcher alive
		}
		if (!node.pure) {
			np.blocker = "impure (" + node.note + ")";
			return np;
		}
		if (node.status.equals("unresolved") || node.status.equals("multi")) {
			np.blocker = node.status + (node.note.length() > 0 ? " (" + node.note + ")" : "");
			return np;
		}
		if (!node.complete) {
			// some arm of the case was never followed to a head: a tail may be
			// missing from the plan and would keep jumping into the (dead) dispatcher
			np.blocker = "exploration incomplete (" + node.note + ")";
			return np;
		}
		if (node.status.equals("uncond")) {
			Address succ = node.succs.get(0);
			String fail = edgesFor(p, node, succ, np.edges);
			if (fail != null) {
				np.blocker = fail;
				return np;
			}
			if (np.edges.isEmpty()) {
				return np; // already a direct edge
			}
			np.kind = "uncond";
			return np;
		}
		// cond
		if ("branch".equals(node.deciderKind)) {
			// a real conditional branch decides: leave it alone, redirect each arm's tail
			for (Address t : node.convergingTails) {
				np.blocker = "both outcomes leave through the same tail @" + t
						+ " (select lowered to a branch with a shared state store; not rewritten)";
				return np;
			}
			String fail = edgesFor(p, node, node.succTrue, np.edges);
			if (fail == null) {
				fail = edgesFor(p, node, node.succFalse, np.edges);
			}
			if (fail != null) {
				np.blocker = fail;
				return np;
			}
			if (np.edges.isEmpty()) {
				return np; // both arms already direct (e.g. the stack-protector check before ret)
			}
			np.kind = "branch";
			return np;
		}
		if (!"select".equals(node.deciderKind)) {
			np.blocker = "unknown decider kind '" + node.deciderKind + "' @" + node.selectAddr;
			return np;
		}
		Address tailT = node.tailTo.get(node.succTrue);
		Address tailF = node.tailTo.get(node.succFalse);
		if (node.directTo.contains(node.succTrue) || node.directTo.contains(node.succFalse)) {
			np.blocker = "one outcome already reaches its block directly";
			return np;
		}
		if (tailT == null || tailF == null || !tailT.equals(tailF)) {
			np.blocker = "the two outcomes leave the case through different branches (" + tailT + " / " + tailF + ")";
			return np;
		}
		Set<Address> tailsT = node.tailsTo.get(node.succTrue);
		Set<Address> tailsF = node.tailsTo.get(node.succFalse);
		if (tailsT == null || tailsF == null || tailsT.size() != 1 || tailsF.size() != 1) {
			np.blocker = "select-decided case leaves through several tails (" + tailsT + " / " + tailsF + ")";
			return np;
		}
		String keyT = CffCore.Node.edgeKey(tailT, node.succTrue);
		String keyF = CffCore.Node.edgeKey(tailF, node.succFalse);
		List<Address> traceT = node.caseTraceByEdge.get(keyT);
		List<Address> traceF = node.caseTraceByEdge.get(keyF);
		Term t = tailFor(p, node, tailT, traceT);
		np.term = t;
		if (t.fail != null) {
			np.blocker = t.fail;
			return np;
		}
		if (t.condInsn != null) {
			np.blocker = "select feeds a conditional branch into the dispatcher @" + tailT;
			return np;
		}
		np.sel = getInstructionAt(node.selectAddr);
		if (np.sel == null) {
			np.blocker = "select instruction missing @" + node.selectAddr;
			return np;
		}
		if (traceT == null || traceF == null) {
			np.blocker = "case trace too long to locate the select on the path";
			return np;
		}
		// instructions executed after the select up to the tail, on both arms;
		// the select is the last decision, so the two arms must run the same code
		int si = traceT.indexOf(node.selectAddr);
		int sf = traceF.indexOf(node.selectAddr);
		if (si < 0 || sf < 0) {
			np.blocker = "select @" + node.selectAddr + " is not on the recorded path to the tail";
			return np;
		}
		boolean selOwned = ownedByHead(p, node.head, node.selectAddr);
		if (!selOwned) {
			// tail-merged compare: `cmp ; csel state ; b dispatcher` shared by several
			// cases. Replay it per case: this case's last owned instruction jumps to a
			// private copy of the shared prefix followed by the branch pair.
			int j = si - 1;
			while (j >= 0 && !ownedByHead(p, node.head, traceT.get(j))) {
				j--;
			}
			if (j < 0) {
				np.blocker = "select @" + node.selectAddr + " sits in a block shared with other cases and no owned hand-off precedes it";
				return np;
			}
			Instruction site = getInstructionAt(traceT.get(j));
			if (site == null) {
				np.blocker = "no instruction at hand-off " + traceT.get(j);
				return np;
			}
			FlowType sft = site.getFlowType();
			if (sft != null && sft.isJump()) {
				Address[] flows = site.getFlows();
				if (sft.isConditional() || sft.isComputed() || flows == null || flows.length != 1
						|| !flows[0].equals(traceT.get(j + 1))) {
					np.blocker = "hand-off @" + site.getMinAddress() + " into the shared compare is not a plain jump onto it";
					return np;
				}
			}
			else {
				if (!CffCore.isRelocatable(site)) {
					np.blocker = "hand-off @" + site.getMinAddress() + " into the shared compare cannot be moved: " + site;
					return np;
				}
				np.lead.add(site);
			}
			if (arch == Arch.X86 && site.getLength() < 5) {
				np.blocker = "hand-off @" + site.getMinAddress() + " into the shared compare is too short for jmp rel32";
				return np;
			}
			for (int i = j + 1; i < si; i++) {
				Instruction in = getInstructionAt(traceT.get(i));
				if (in == null) {
					np.blocker = "no instruction @" + traceT.get(i);
					return np;
				}
				FlowType ft = in.getFlowType();
				if (ft != null && ft.isJump()) {
					Address[] flows = in.getFlows();
					if (!ft.isConditional() && !ft.isComputed() && flows != null && flows.length == 1
							&& flows[0].equals(traceT.get(i + 1))) {
						continue;
					}
					np.blocker = "flow instruction between hand-off and shared select @" + in.getMinAddress();
					return np;
				}
				if (ft != null && (ft.isCall() || ft.isTerminal())) {
					np.blocker = "call between hand-off and shared select @" + in.getMinAddress();
					return np;
				}
				if (!CffCore.isRelocatable(in)) {
					np.blocker = "shared compare prefix cannot be moved: " + in.getMinAddress() + "  " + in;
					return np;
				}
				np.lead.add(in);
			}
			np.site = site;
			np.condStub = true;
		}
		List<Address> segT = traceT.subList(si + 1, traceT.size());
		List<Address> segF = traceF.subList(sf + 1, traceF.size());
		if (!segT.equals(segF)) {
			np.blocker = "the two arms execute different code after the select";
			return np;
		}
		// which of those instructions are real code to replay: everything except
		// the tail jump itself (a tail that FALLS into the dispatcher is real code)
		// and plain jumps onto the next executed instruction (jump-into-shared-tail)
		List<Instruction> raw = new ArrayList<Instruction>();
		Address windowEnd = np.sel.getMaxAddress().add(1); // end of the owned, contiguous bytes we may overwrite
		boolean contiguous = true;
		Address expectNext = np.sel.getFallThrough();
		for (int i = 0; i < segT.size(); i++) {
			Address a = segT.get(i);
			Instruction in = getInstructionAt(a);
			if (in == null) {
				np.blocker = "no instruction @" + a;
				return np;
			}
			boolean isTail = i == segT.size() - 1;
			FlowType ft = in.getFlowType();
			boolean owned = ownedByHead(p, node.head, a);
			if (contiguous && owned && a.equals(expectNext) && (t.site == null || a.compareTo(t.site.getMinAddress()) <= 0)) {
				windowEnd = in.getMaxAddress().add(1);
				expectNext = in.getFallThrough();
			}
			else {
				contiguous = false;
			}
			if (isTail && t.insn != null) {
				break; // the owned `b dispatcher`: replaced, not replayed
			}
			if (ft != null && ft.isJump()) {
				Address[] flows = in.getFlows();
				if (!ft.isConditional() && !ft.isComputed() && flows != null && flows.length == 1) {
					if (isTail && p.r.dispatchRegion.contains(flows[0])) {
						break; // the shared tail's `b dispatcher`
					}
					if (!isTail && flows[0].equals(segT.get(i + 1))) {
						continue; // plain jump onto the next executed instruction: straight line in the stub
					}
				}
				np.blocker = "flow instruction between select and dispatcher branch @" + a;
				return np;
			}
			if (ft != null && (ft.isCall() || ft.isTerminal())) {
				np.blocker = "call between select and dispatcher branch @" + a;
				return np;
			}
			raw.add(in);
		}
		// the overwritten window must not be a jump target from elsewhere
		BasicBlockModel bbm = new BasicBlockModel(currentProgram);
		CodeBlock selBlock = bbm.getFirstCodeBlockContaining(np.sel.getMinAddress(), monitor);
		if (!np.condStub && (selBlock == null || !selBlock.contains(windowEnd.subtract(1)))) {
			np.blocker = "code between the select and the hand-off is entered from elsewhere (block boundary)";
			return np;
		}
		Register selDst = np.sel.getRegister(0);
		String selDstName = selDst == null ? null : selDst.getBaseRegister().getName();
		// Drop the dead state machinery after the select: stores into the
		// dispatcher's slots and the register work that only feeds them
		// (Arkari: eor x8,x8,x9 ; mov x9,#xor ; str x8 ; str x9). Everything
		// else after the select is real code that must survive.
		boolean[] drop = new boolean[raw.size()];
		Set<String> deadVals = new HashSet<String>();
		for (int i = raw.size() - 1; i >= 0; i--) {
			Instruction in = raw.get(i);
			Set<String> outs = CffCore.regNames(in.getResultObjects());
			Set<String> ins = CffCore.regNames(in.getInputObjects());
			if (CffCore.hasStore(in)) {
				Set<String> keys = CffCore.memOperandKeys(in);
				boolean stateStore = false;
				for (String k : keys) {
					if (p.stateSlots.contains(k)) {
						stateStore = true;
					}
				}
				if (!stateStore && selDstName != null) {
					// a store OF the freshly selected state (`csel x8 ; str x8,[sp,#0xd0]`) is
					// a state store whatever slot it uses: nothing outside the dispatcher reads the state
					Set<String> vals = new HashSet<String>();
					for (String s : ins) {
						if (!isFrameRegName(s)) {
							vals.add(s);
						}
					}
					stateStore = vals.size() == 1 && vals.contains(selDstName);
				}
				if (stateStore) {
					drop[i] = true;
					for (String s : ins) {
						if (!isFrameRegName(s)) {
							deadVals.add(s);
						}
					}
				}
				continue;
			}
			if (!outs.isEmpty() && deadVals.containsAll(outs) && !CffCore.hasLoad(in)) {
				drop[i] = true;
				deadVals.removeAll(outs);
				for (String s : ins) {
					if (!isFrameRegName(s)) {
						deadVals.add(s);
					}
				}
			}
		}
		for (int i = 0; i < raw.size(); i++) {
			Instruction in = raw.get(i);
			if (drop[i]) {
				p.deadRegs.addAll(CffCore.regNames(in.getResultObjects()));
				continue;
			}
			np.post.add(in);
			if (!CffCore.isRelocatable(in)) {
				np.blocker = "instruction between select and branch cannot be moved: " + in.getMinAddress() + "  " + in;
				return np;
			}
			if (selDstName != null && CffCore.regNames(in.getInputObjects()).contains(selDstName)) {
				np.blocker = "real code after the select reads the state register: " + in.getMinAddress() + "  " + in;
				return np;
			}
			if (CffCore.writesFlags(in)) {
				np.postWritesFlags = true;
			}
		}
		if (selDstName != null) {
			p.deadRegs.add(selDstName);
		}
		np.effT = CffCore.analyzeRegionPath(currentProgram, node.pathTo.get(node.succTrue), node.succTrue, p.regionDead, p.deadRegs, p.derivedSlots);
		np.effF = CffCore.analyzeRegionPath(currentProgram, node.pathTo.get(node.succFalse), node.succFalse, p.regionDead, p.deadRegs, p.derivedSlots);
		noteStateDerived(p, node.succTrue, np.effT);
		noteStateDerived(p, node.succFalse, np.effF);
		if (np.effT.unsupported) {
			np.blocker = np.effT.note;
			return np;
		}
		if (np.effF.unsupported) {
			np.blocker = np.effF.note;
			return np;
		}
		String cc = normCond(node.cond);
		if (risc() && a64Cond(cc) < 0) {
			np.blocker = "unknown condition code '" + node.cond + "'";
			return np;
		}
		if (arch == Arch.X86 && x86CondOp(cc) < 0) {
			np.blocker = "unknown condition code '" + node.cond + "'";
			return np;
		}
		np.windowEnd = windowEnd;
		int pairLen = risc() ? 2 * branchLen() : 11; // b.cc + b  /  jcc rel32 + jmp rel32
		long window = windowEnd.subtract(np.sel.getMinAddress());
		if (np.condStub) {
			np.kind = "cond";
			np.needStubs = true; // the site slot only holds `b condStub`; everything else lives in stubs
			return np;
		}
		if (window < pairLen) {
			// the select is (almost) the last owned instruction: borrow the
			// relocatable, flag-preserving instructions right before it, they run
			// first in both stubs and their slots join the window
			Instruction prev = np.sel.getPrevious();
			while (window < pairLen && prev != null) {
				Address fa = prev.getFallThrough();
				if (fa == null || !fa.equals(prev.getMaxAddress().add(1)) || !CffCore.isRelocatable(prev)
						|| CffCore.writesFlags(prev) || !selBlock.contains(prev.getMinAddress())
						|| prev.getMinAddress().equals(node.head)) {
					break;
				}
				if (selDstName != null && CffCore.regNames(prev.getResultObjects()).contains(selDstName)) {
					break; // it feeds the select; cannot move after the decision
				}
				np.pre.add(0, prev);
				window += prev.getLength();
				prev = prev.getPrevious();
			}
			if (window < pairLen) {
				np.blocker = "no room for the branch pair at the select (" + window + " owned bytes, need " + pairLen + ")";
				return np;
			}
		}
		np.kind = "cond";
		boolean copies = !np.effT.live.isEmpty() || !np.effF.live.isEmpty();
		if (!contiguous || t.insn == null || t.site != null || !np.pre.isEmpty()) {
			np.needStubs = true; // path jumps around / tail falls into the dispatcher / is shared / window was borrowed
			return np;
		}
		if (risc()) {
			// in place: shift the surviving tail up over the select slot, branch pair at the end
			np.needStubs = copies || np.postWritesFlags;
		}
		else {
			// in place: nothing real between cmov and jmp, and room for jcc rel32 + jmp rel32
			np.needStubs = copies || !np.post.isEmpty() || window < 11;
		}
		return np;
	}

	/**
	 * Build one {@link EdgePlan} per tail the emulator saw leading to
	 * {@code succ}. Returns null on success (possibly adding nothing when the
	 * edge is already direct), or the reason the node cannot be patched.
	 */
	private String edgesFor(FnPlan p, CffCore.Node node, Address succ, List<EdgePlan> out) throws Exception {
		Set<Address> tails = node.tailsTo.get(succ);
		if (tails == null || tails.isEmpty()) {
			if (node.directTo.contains(succ)) {
				return null; // never crossed the dispatcher: already direct
			}
			return "no tail instruction recorded for the edge to " + succ;
		}
		for (Address tail : tails) {
			for (EdgePlan other : out) {
				if (other.tail.equals(tail)) {
					return "tail @" + tail + " leads to both " + other.succ + " and " + succ;
				}
			}
			EdgePlan e = new EdgePlan();
			e.succ = succ;
			e.tail = tail;
			String key = CffCore.Node.edgeKey(tail, succ);
			e.eff = CffCore.analyzeRegionPath(currentProgram, node.pathByEdge.get(key), succ, p.regionDead, p.deadRegs, p.derivedSlots);
			noteStateDerived(p, succ, e.eff);
			debugEffects(p, "analyze edge " + tail + " -> " + succ, e.eff);
			if (e.eff.unsupported) {
				return e.eff.note;
			}
			e.term = tailFor(p, node, tail, node.caseTraceByEdge.get(key));
			if (e.term.fail != null) {
				return e.term.fail;
			}
			if (e.term.directTarget != null) {
				continue;
			}
			e.needStub = !e.eff.live.isEmpty() || e.term.site != null || e.term.insn == null && e.term.condInsn == null;
			if (e.term.condInsn != null && arch == Arch.X86 && e.term.condInsn.getLength() < 6) {
				return "conditional tail jump @" + tail + " is a short jcc; no room for a rel32 retarget";
			}
			out.add(e);
		}
		return null;
	}

	private static boolean isFrameRegName(String n) {
		String u = n.toUpperCase();
		return u.equals("SP") || u.equals("X29") || u.equals("FP") || u.equals("RSP") || u.equals("RBP") || u.equals("ESP")
				|| u.equals("EBP");
	}

	/** Does the block containing {@code addr} belong to this case alone (dominated by its head)? */
	private boolean ownedByHead(FnPlan p, Address head, Address addr) throws Exception {
		CffCore.Cfg g = p.d.cfg;
		Integer hi = g.id.get(head);
		if (hi == null) {
			return false;
		}
		BasicBlockModel bbm = new BasicBlockModel(currentProgram);
		CodeBlock cb = bbm.getFirstCodeBlockContaining(addr, monitor);
		if (cb == null) {
			return false;
		}
		Integer bi = g.id.get(cb.getFirstStartAddress());
		if (bi == null) {
			return false;
		}
		return CffCore.dominates(g, hi.intValue(), bi.intValue());
	}

	/**
	 * Classify the instruction at {@code tailAddr} through which the case handed
	 * control to the dispatcher (taken from the emulation trace, so internal
	 * diamonds inside the case do not matter).
	 */
	private Term tailFor(FnPlan p, CffCore.Node node, Address tailAddr, List<Address> caseTrace) throws Exception {
		Term t = new Term();
		CffCore.Recovery r = p.r;
		if (tailAddr == null) {
			t.fail = "no tail instruction recorded";
			return t;
		}
		Instruction tail = getInstructionAt(tailAddr);
		if (tail == null) {
			t.fail = "no instruction at tail " + tailAddr;
			return t;
		}
		if (!ownedByHead(p, node.head, tailAddr)) {
			return sharedTailFor(p, node, tail, caseTrace);
		}
		FlowType ft = tail.getFlowType();
		if (ft != null && ft.isJump() && !ft.isConditional()) {
			Address[] flows = tail.getFlows();
			if (flows != null && flows.length == 1 && r.dispatchRegion.contains(flows[0])) {
				t.insn = tail;
				// x86 short-jmp rescue: relocatable instructions immediately before the jump
				Instruction prev = tail.getPrevious();
				for (int i = 0; i < 6 && prev != null; i++) {
					Address ftAddr = prev.getFallThrough();
					if (ftAddr == null || !ftAddr.equals(prev.getMaxAddress().add(1)) || !CffCore.isRelocatable(prev)
							|| !ownedByHead(p, node.head, prev.getMinAddress()) || prev.getMinAddress().equals(node.selectAddr)) {
						break;
					}
					t.linear.add(0, prev);
					prev = prev.getPrevious();
				}
				return t;
			}
			t.fail = "tail jump @" + tailAddr + " has no single resolved target inside the dispatcher";
			return t;
		}
		if (ft != null && ft.isJump()) {
			// `b.cc dispatcher` / `cbz wN, dispatcher`: the taken arm is this edge, the
			// fall-through stays in the case; only the displacement changes
			Address[] flows = tail.getFlows();
			Address fall = tail.getFallThrough();
			if (!ft.isComputed() && flows != null && flows.length == 1 && r.dispatchRegion.contains(flows[0]) && fall != null
					&& !r.dispatchRegion.contains(fall)) {
				t.condInsn = tail;
				return t;
			}
			t.fail = "tail @" + tailAddr + " is a conditional branch into the dispatcher that cannot be retargeted";
			return t;
		}
		Address next = tail.getFallThrough();
		if (next != null && r.dispatchRegion.contains(next)) {
			t.regionEntry = next;
			return t;
		}
		t.fail = "tail @" + tailAddr + " neither branches nor falls into the dispatcher";
		return t;
	}

	/**
	 * -O2 tail merging: the `b dispatcher` (and usually a few PHI copies before
	 * it) sit in a block several cases share, so it must not be rewritten.
	 * Walk the emulated case trace backwards from the tail to the last
	 * instruction this case owns; that instruction's slot becomes `b stub`, and
	 * the stub replays what was skipped (the owned instruction itself unless it
	 * is a plain jump, then the shared body) before the dispatcher copies.
	 * Everything replayed must be relocatable straight-line code.
	 */
	private Term sharedTailFor(FnPlan p, CffCore.Node node, Instruction tail, List<Address> caseTrace) throws Exception {
		Term t = new Term();
		Address tailAddr = tail.getMinAddress();
		FlowType tft = tail.getFlowType();
		boolean tailJumps = tft != null && tft.isJump();
		if (tailJumps) {
			Address[] flows = tail.getFlows();
			if (tft.isConditional() || tft.isComputed() || flows == null || flows.length != 1
					|| !p.r.dispatchRegion.contains(flows[0])) {
				t.fail = "shared tail @" + tailAddr + " is not a plain jump into the dispatcher";
				return t;
			}
		}
		else {
			Address next = tail.getFallThrough();
			if (next == null || !p.r.dispatchRegion.contains(next)) {
				t.fail = "shared tail @" + tailAddr + " neither branches nor falls into the dispatcher";
				return t;
			}
		}
		if (caseTrace == null || caseTrace.isEmpty()) {
			t.fail = "tail " + tailAddr + " sits in a block shared with other cases (no case trace to find the hand-off)";
			return t;
		}
		int k = caseTrace.size() - 1;
		if (!caseTrace.get(k).equals(tailAddr)) {
			t.fail = "tail " + tailAddr + " sits in a block shared with other cases (trace does not end at it)";
			return t;
		}
		// shared suffix: trace[j+1 .. k] where trace[j] is the last owned instruction
		int j = k - 1;
		while (j >= 0 && !ownedByHead(p, node.head, caseTrace.get(j))) {
			j--;
		}
		if (j < 0) {
			t.fail = "tail " + tailAddr + " sits in a block shared with other cases and no owned hand-off precedes it";
			return t;
		}
		Instruction site = getInstructionAt(caseTrace.get(j));
		if (site == null) {
			t.fail = "no instruction at hand-off " + caseTrace.get(j);
			return t;
		}
		boolean siteIsSelect = site.getMinAddress().equals(node.selectAddr) && "select".equals(node.deciderKind);
		FlowType sft = site.getFlowType();
		boolean siteJumps = sft != null && sft.isJump();
		if (siteIsSelect) {
			// the select falls straight into the shared tail: the select path owns
			// the slot (branch pair goes there), the shared body is replayed after it
		}
		else if (siteJumps) {
			Address[] flows = site.getFlows();
			if (sft.isConditional() || sft.isComputed() || flows == null || flows.length != 1) {
				t.fail = "hand-off @" + site.getMinAddress() + " into the shared tail is a conditional / computed jump";
				return t;
			}
		}
		else {
			if (!CffCore.isRelocatable(site)) {
				t.fail = "hand-off @" + site.getMinAddress() + " falls into a shared tail and cannot be moved: " + site;
				return t;
			}
			t.moved.add(site);
		}
		for (int i = j + 1; i < k; i++) {
			Instruction in = getInstructionAt(caseTrace.get(i));
			if (in == null) {
				t.fail = "no instruction @" + caseTrace.get(i);
				return t;
			}
			FlowType ft = in.getFlowType();
			if (ft != null && ft.isJump() && !ft.isConditional() && !ft.isComputed()) {
				Address[] flows = in.getFlows();
				if (flows != null && flows.length == 1 && flows[0].equals(caseTrace.get(i + 1))) {
					continue; // plain jump onto the next executed instruction: straight line in the stub
				}
			}
			if (!CffCore.isRelocatable(in)) {
				t.fail = "shared tail body cannot be moved: " + in.getMinAddress() + "  " + in;
				return t;
			}
			t.moved.add(in);
		}
		if (!tailJumps) {
			// the shared block falls into the dispatcher: the tail itself is real code to replay
			if (!CffCore.isRelocatable(tail)) {
				t.fail = "shared tail @" + tailAddr + " cannot be moved: " + tail;
				return t;
			}
			t.moved.add(tail);
		}
		if (arch == Arch.X86 && site.getLength() < 5) {
			// borrow relocatable owned instructions before the site until a jmp rel32 fits
			Instruction prev = site.getPrevious();
			int have = site.getLength();
			BasicBlockModel bbm = new BasicBlockModel(currentProgram);
			CodeBlock siteBlock = bbm.getFirstCodeBlockContaining(site.getMinAddress(), monitor);
			while (have < 5 && prev != null) {
				Address fa = prev.getFallThrough();
				if (fa == null || !fa.equals(prev.getMaxAddress().add(1)) || !CffCore.isRelocatable(prev)
						|| !ownedByHead(p, node.head, prev.getMinAddress()) || prev.getMinAddress().equals(node.selectAddr)
						|| siteBlock == null || !siteBlock.contains(prev.getMinAddress())) {
					break;
				}
				t.linear.add(0, prev);
				have += prev.getLength();
				prev = prev.getPrevious();
			}
			if (have < 5) {
				t.fail = "hand-off @" + site.getMinAddress() + " is too short for jmp rel32 and nothing before it can move";
				return t;
			}
		}
		t.site = site;
		return t;
	}

	// ---------------------------------------------------------- emission -----

	private int bytesOf(List<Instruction> l) {
		int n = 0;
		for (Instruction in : l) {
			n += in.getLength();
		}
		return n;
	}

	/** Fixed-width branch ISAs (AArch64, ARM, Thumb-2): branch pairs are two slots, NOP padding is per word. */
	private boolean risc() {
		return arch == Arch.ARM64 || arch == Arch.ARM32;
	}

	private int riscAlign() {
		return arch == Arch.ARM32 && thumbFn ? 2 : 4;
	}

	/** Bytes of the unconditional branch a stub / entry slot is built from (B, B.W, jmp rel32). */
	private int branchLen() {
		return risc() ? 4 : 5;
	}

	private boolean isThumbAt(Address at) {
		if (tmodeReg == null) {
			return false;
		}
		try {
			ghidra.program.model.lang.RegisterValue v = currentProgram.getProgramContext().getRegisterValue(tmodeReg, at);
			return v != null && v.hasValue() && v.getUnsignedValue().intValue() != 0;
		}
		catch (Exception e) {
			return false;
		}
	}

	/**
	 * Unconditional branch from {@code at} to {@code target} that fits a slot of
	 * {@code slot} bytes: AArch64 B (4), ARM B (4), Thumb B.W (4) or 16-bit B
	 * (2-byte slot). Throws when the displacement does not fit.
	 */
	private byte[] riscB(Address at, Address target, int slot) {
		if (arch == Arch.ARM64) {
			int enc = a64B(at, target);
			if (enc == 0 || slot < 4) {
				throw new IllegalStateException("branch out of range " + at + " -> " + target);
			}
			return enc(enc);
		}
		if (!thumbFn) {
			int enc = armB(at, target, 0xE);
			if (enc == 0 || slot < 4) {
				throw new IllegalStateException("ARM B out of range " + at + " -> " + target);
			}
			return enc(enc);
		}
		if (slot == 2) {
			int h = thumbB16(at, target);
			if (h == 0) {
				throw new IllegalStateException("Thumb 16-bit B out of range " + at + " -> " + target + " (2-byte slot)");
			}
			return halfword(h);
		}
		int[] hw = thumbBW(at, target);
		if (hw == null) {
			throw new IllegalStateException("Thumb B.W out of range " + at + " -> " + target);
		}
		return halfwords(hw);
	}

	/** Conditional branch counterpart of {@link #riscB}. */
	private byte[] riscBcc(Address at, Address target, String cc, int slot) {
		int c = a64Cond(cc); // the AArch64 and ARM condition encodings are identical
		if (c < 0) {
			throw new IllegalStateException("bad condition " + cc);
		}
		if (arch == Arch.ARM64) {
			int enc = a64Bcond(at, target, cc);
			if (enc == 0 || slot < 4) {
				throw new IllegalStateException("B.cond out of range " + at + " -> " + target);
			}
			return enc(enc);
		}
		if (!thumbFn) {
			int enc = armB(at, target, c);
			if (enc == 0 || slot < 4) {
				throw new IllegalStateException("ARM B<c> out of range " + at + " -> " + target);
			}
			return enc(enc);
		}
		if (slot == 2) {
			int h = thumbBcc16(at, target, c);
			if (h == 0) {
				throw new IllegalStateException("Thumb 16-bit B<c> out of range " + at + " -> " + target);
			}
			return halfword(h);
		}
		int[] hw = thumbBccW(at, target, c);
		if (hw == null) {
			throw new IllegalStateException("Thumb B<c>.W out of range " + at + " -> " + target);
		}
		return halfwords(hw);
	}

	/** Extend a branch to the slot it replaces, padding with the mode's NOP. */
	private byte[] riscPad(byte[] src, int slot) {
		if (src.length == slot) {
			return src;
		}
		byte[] out = new byte[slot];
		System.arraycopy(src, 0, out, 0, Math.min(src.length, slot));
		riscNopFill(out, src.length);
		return out;
	}

	private void riscNopFill(byte[] buf, int from) {
		if (arch == Arch.ARM64) {
			for (int i = from; i + 4 <= buf.length; i += 4) {
				putLE(buf, i, 0xD503201F, 4);
			}
		}
		else if (!thumbFn) {
			for (int i = from; i + 4 <= buf.length; i += 4) {
				putLE(buf, i, 0xE320F000, 4); // ARM NOP
			}
		}
		else {
			for (int i = from; i + 2 <= buf.length; i += 2) {
				putLE(buf, i, 0xBF00, 2); // Thumb NOP
			}
		}
	}

	// --- ARM (A32) ---------------------------------------------------------

	/** A32 B<c> imm24: target = PC(at+8) + imm24*4, range +-32 MiB. cond in bits 31:28. Returns 0 when out of range. */
	private int armB(Address at, Address target, int cond) {
		long disp = target.subtract(at.add(8));
		if ((disp & 3) != 0 || disp < -(1L << 25) || disp >= (1L << 25)) {
			return 0;
		}
		return (cond << 28) | 0x0A000000 | (int) ((disp >> 2) & 0x00FFFFFF);
	}

	// --- Thumb / Thumb-2 ----------------------------------------------------

	/** T2 encoding `B imm11` (16-bit): target = at+4 + imm11*2, range -2048..2046. Returns 0 when out of range. */
	private int thumbB16(Address at, Address target) {
		long disp = target.subtract(at.add(4));
		if ((disp & 1) != 0 || disp < -2048 || disp > 2046) {
			return 0;
		}
		return 0xE000 | (int) ((disp >> 1) & 0x7FF);
	}

	/** T1 encoding `B<c> imm8` (16-bit): range -256..254. */
	private int thumbBcc16(Address at, Address target, int cond) {
		long disp = target.subtract(at.add(4));
		if ((disp & 1) != 0 || disp < -256 || disp > 254 || cond >= 14) {
			return 0;
		}
		return 0xD000 | (cond << 8) | (int) ((disp >> 1) & 0xFF);
	}

	/** T4 encoding `B.W`: range +-16 MiB. Returns {hw1, hw2} or null. */
	private int[] thumbBW(Address at, Address target) {
		long disp = target.subtract(at.add(4));
		if ((disp & 1) != 0 || disp < -(1L << 24) || disp >= (1L << 24)) {
			return null;
		}
		int s = (int) ((disp >> 24) & 1);
		int i1 = (int) ((disp >> 23) & 1);
		int i2 = (int) ((disp >> 22) & 1);
		int j1 = (~(i1 ^ s)) & 1;
		int j2 = (~(i2 ^ s)) & 1;
		int imm10 = (int) ((disp >> 12) & 0x3FF);
		int imm11 = (int) ((disp >> 1) & 0x7FF);
		return new int[] { 0xF000 | (s << 10) | imm10, 0x9000 | (j1 << 13) | (j2 << 11) | imm11 };
	}

	/** T3 encoding `B<c>.W`: range +-1 MiB. Returns {hw1, hw2} or null. */
	private int[] thumbBccW(Address at, Address target, int cond) {
		long disp = target.subtract(at.add(4));
		if ((disp & 1) != 0 || disp < -(1L << 20) || disp >= (1L << 20) || cond >= 14) {
			return null;
		}
		int s = (int) ((disp >> 20) & 1);
		int j1 = (int) ((disp >> 19) & 1);
		int j2 = (int) ((disp >> 18) & 1);
		int imm6 = (int) ((disp >> 12) & 0x3F);
		int imm11 = (int) ((disp >> 1) & 0x7FF);
		return new int[] { 0xF000 | (s << 10) | (cond << 6) | imm6, 0x8000 | (j1 << 13) | (j2 << 11) | imm11 };
	}

	private byte[] halfword(int h) {
		byte[] b = new byte[2];
		putLE(b, 0, h, 2);
		return b;
	}

	/** Thumb-2 32-bit instruction: two little-endian halfwords, first one at the lower address. */
	private byte[] halfwords(int[] hw) {
		byte[] b = new byte[4];
		putLE(b, 0, hw[0], 2);
		putLE(b, 2, hw[1], 2);
		return b;
	}

	/** Redirect one tail to its successor (via a stub replaying the dispatcher copies when there are any). */
	private void emitEdge(FnPlan p, NodePlan np, EdgePlan e, StubAllocator alloc, boolean full) throws Exception {
		Address succ = e.succ;
		List<Instruction> live = e.eff.live;
		Address target = succ;
		String via = "";
		String tag = np.kind.equals("branch") ? "arm     " : "uncond  ";
		if (e.term.site == null && !live.isEmpty()) {
			// identical replay sequences to the same successor share one stub
			StringBuilder key = new StringBuilder();
			for (Instruction in : live) {
				key.append(in.getMinAddress()).append(',');
			}
			key.append('>').append(succ);
			Address stub = p.stubCache.get(key.toString());
			if (stub == null) {
				stub = alloc.allocate(bytesOf(live) + branchLen());
				byte[] sb = buildStub(stub, live, Collections.<Instruction> emptyList(), succ);
				addPatch(p, stub, sb, "stub", "replay " + live.size() + " dispatcher copy(ies) -> " + succ);
				p.stubCache.put(key.toString(), stub);
			}
			target = stub;
			via = " via stub " + stub + " (+" + live.size() + " copies)";
		}
		if (e.term.site != null) {
			// tail-merged: this case's last owned instruction jumps to a stub that
			// replays the shared tail body (and the dispatcher copies) itself
			List<Instruction> replay = new ArrayList<Instruction>(e.term.linear);
			replay.addAll(e.term.moved);
			Address stub = alloc.allocate(bytesOf(replay) + bytesOf(live) + branchLen());
			addPatch(p, stub, buildStub(stub, replay, live, succ), "stub",
					"shared tail: " + replay.size() + " replayed instr(s) + " + live.size() + " copy(ies) -> " + succ);
			Address at = e.term.linear.isEmpty() ? e.term.site.getMinAddress() : e.term.linear.get(0).getMinAddress();
			int slot = bytesOf(e.term.linear) + e.term.site.getLength();
			if (risc()) {
				addPatch(p, at, riscPad(riscB(at, stub, slot), slot), "handoff", "-> " + succ + " via shared-tail stub " + stub);
			}
			else {
				addPatch(p, at, pad(x86JmpBytes(at, stub), slot, false), "handoff", "-> " + succ + " via shared-tail stub " + stub);
			}
			p.lines.add(at + "  " + tag + "-> " + succ + " via shared-tail stub " + stub + " (+" + replay.size()
					+ " replayed, +" + live.size() + " copies)");
			return;
		}
		if (e.term.condInsn != null) {
			Instruction term = e.term.condInsn;
			Address at = term.getMinAddress();
			byte[] repl;
			if (arch == Arch.ARM64) {
				int orig = (int) currentProgram.getMemory().getInt(at);
				int enc = a64Retarget(orig, at, target);
				if (enc == 0 && alloc != null && !target.equals(succ)) {
					// the stub is beyond the branch's reach (B.cond/CBZ ±1 MiB, TBZ ±32 KiB):
					// hop through a plain B placed as close as the allocator allows
					Address hub = alloc.allocate(branchLen());
					int viaHub = a64Retarget(orig, at, hub);
					if (viaHub != 0) {
						addPatch(p, hub, riscB(hub, target, branchLen()), "stub", "hub: -> stub " + target + " for " + at);
						enc = viaHub;
						via = via + " (hub " + hub + ")";
					}
				}
				if (enc == 0) {
					throw new IllegalStateException("cannot retarget conditional branch " + at + " -> " + target);
				}
				repl = enc(enc);
			}
			else if (arch == Arch.ARM32) {
				throw new IllegalStateException("retargeting a conditional tail branch is not implemented for ARM32 @" + at);
			}
			else {
				repl = x86RetargetJcc(term, at, target);
			}
			addPatch(p, at, repl, "condtail", "taken -> " + succ + via);
			p.lines.add(at + "  " + tag + "if taken -> " + succ + via);
			return;
		}
		if (e.term.insn != null) {
			Instruction term = e.term.insn;
			Address at = term.getMinAddress();
			int len = term.getLength();
			if (risc()) {
				addPatch(p, at, riscPad(riscB(at, target, len), len), "uncond", "-> " + succ + via);
			}
			else if (len >= 5) {
				addPatch(p, at, pad(x86JmpBytes(at, target), len, false), "uncond", "-> " + succ + via);
			}
			else {
				// `jmp rel8` (2 bytes): borrow the relocatable instructions just
				// before it, move them into a stub and jump there instead
				if (alloc == null) {
					throw new IllegalStateException("short jmp (" + len + " bytes) at " + at + ", no room for jmp rel32");
				}
				List<Instruction> moved = new ArrayList<Instruction>();
				int have = len;
				for (int i = e.term.linear.size() - 1; i >= 0 && have < 5; i--) {
					Instruction in = e.term.linear.get(i);
					moved.add(0, in);
					have += in.getLength();
				}
				if (have < 5) {
					throw new IllegalStateException("short jmp at " + at + " and no movable instructions before it");
				}
				// dispatcher copies (if any) already sit in the stub `target` points to
				Address stub = alloc.allocate(bytesOf(moved) + branchLen());
				addPatch(p, stub, buildStub(stub, moved, Collections.<Instruction> emptyList(), target), "stub",
						"moved " + moved.size() + " tail instr(s) -> " + target);
				Address winStart = moved.get(0).getMinAddress();
				addPatch(p, winStart, pad(x86JmpBytes(winStart, stub), have, false), "uncond",
						"-> " + succ + via + " (tail moved to stub " + stub + ")");
				via = via + " (tail moved to stub " + stub + ")";
				at = winStart;
			}
			p.lines.add(at + "  " + tag + "-> " + succ + via);
			return;
		}
		// tail that falls into the dispatcher (typically the prologue): redirect the (now dead) dispatcher entry
		if (!full) {
			throw new IllegalStateException("tail falls into the dispatcher; its entry slot can only be redirected in full mode");
		}
		Address at = e.term.regionEntry;
		if (risc()) {
			addPatch(p, at, riscB(at, target, branchLen()), "entry", "dispatcher entry -> " + succ + via);
		}
		else {
			addPatch(p, at, x86JmpBytes(at, target), "entry", "dispatcher entry -> " + succ + via);
		}
		p.lines.add(at + "  entry   dispatcher entry -> " + succ + via);
	}

	/** Select-decided case: the select slot becomes B.cc T ; B F (in place or through stubs). */
	private void emitSelect(FnPlan p, NodePlan np, StubAllocator alloc, boolean full) throws Exception {
		CffCore.Node node = np.node;
		Instruction sel = np.sel;
		// window = [borrowed pre instructions] select .. last owned instruction on the
		// path (the tail branch itself when the tail is ours, the hand-off when the
		// tail is shared, the last instruction before the dispatcher when it falls in)
		Address start = np.pre.isEmpty() ? sel.getMinAddress() : np.pre.get(0).getMinAddress();
		int region = (int) np.windowEnd.subtract(start);
		String cc = normCond(node.cond);
		Address T = node.succTrue;
		Address F = node.succFalse;
		if (selfTestFlip && !flipped) {
			// deliberate wrong patch (swap the arms) to demonstrate that verify catches it
			flipped = true;
			Address tmp = T;
			T = F;
			F = tmp;
			p.lines.add(start + "  SELF-TEST: arms of this select deliberately swapped; verify must reject the function");
		}
		if (np.condStub) {
			// shared compare: site -> condStub = lead ; b.cc stubT ; b stubF
			Address stubT = T;
			Address stubF = F;
			if (!np.post.isEmpty() || !np.effT.live.isEmpty()) {
				stubT = alloc.allocate(bytesOf(np.post) + bytesOf(np.effT.live) + branchLen());
				addPatch(p, stubT, buildStub(stubT, np.post, np.effT.live, T), "stub",
						"true path: " + np.post.size() + " tail instr(s) + " + np.effT.live.size() + " copy(ies) -> " + T);
			}
			if (!np.post.isEmpty() || !np.effF.live.isEmpty()) {
				stubF = alloc.allocate(bytesOf(np.post) + bytesOf(np.effF.live) + branchLen());
				addPatch(p, stubF, buildStub(stubF, np.post, np.effF.live, F), "stub",
						"false path: " + np.post.size() + " tail instr(s) + " + np.effF.live.size() + " copy(ies) -> " + F);
			}
			int pairLen = risc() ? 2 * branchLen() : 11;
			int leadLen = bytesOf(np.lead);
			Address cs = allocForBcc(alloc, leadLen + pairLen, leadLen, stubT);
			byte[] cb = new byte[leadLen + pairLen];
			int off = 0;
			for (Instruction in : np.lead) {
				byte[] b = new byte[in.getLength()];
				currentProgram.getMemory().getBytes(in.getMinAddress(), b);
				System.arraycopy(b, 0, cb, off, b.length);
				off += b.length;
			}
			Address pairAt = cs.add(off);
			if (risc()) {
				byte[] bcc = riscBcc(pairAt, stubT, cc, branchLen());
				byte[] b = riscB(pairAt.add(branchLen()), stubF, branchLen());
				System.arraycopy(bcc, 0, cb, off, bcc.length);
				System.arraycopy(b, 0, cb, off + branchLen(), b.length);
			}
			else {
				byte[] jcc = x86Jcc(pairAt, stubT, cc);
				byte[] jmp = x86JmpBytes(pairAt.add(6), stubF);
				System.arraycopy(jcc, 0, cb, off, 6);
				System.arraycopy(jmp, 0, cb, off + 6, 5);
			}
			addPatch(p, cs, cb, "stub", "shared compare replayed: " + np.lead.size() + " instr(s) then if(" + cc + ") -> " + T
					+ " else -> " + F);
			Address at = np.site.getMinAddress();
			int slot = np.site.getLength();
			if (risc()) {
				addPatch(p, at, riscPad(riscB(at, cs, slot), slot), "handoff", "-> shared-compare stub " + cs);
			}
			else {
				addPatch(p, at, pad(x86JmpBytes(at, cs), slot, false), "handoff", "-> shared-compare stub " + cs);
			}
			p.lines.add(at + "  cond    if(" + cc + ") -> " + T + " else -> " + F + "   [shared compare replayed in stub " + cs
					+ ", lead=" + np.lead.size() + ", post=" + np.post.size() + ", copies=" + np.effT.live.size() + "/"
					+ np.effF.live.size() + "]");
			return;
		}
		if (!np.needStubs) {
			if (risc()) {
				// shift the tail instructions up over the select, then b.cc T ; b F
				byte[] buf = new byte[region];
				int off = 0;
				for (Instruction in : np.post) {
					byte[] b = new byte[in.getLength()];
					currentProgram.getMemory().getBytes(in.getMinAddress(), b);
					System.arraycopy(b, 0, buf, off, b.length);
					off += b.length;
				}
				Address bccAt = start.add(off);
				int bl = branchLen();
				if (off + 2 * bl > region) {
					throw new IllegalStateException("window too small for the branch pair");
				}
				byte[] bcc = riscBcc(bccAt, T, cc, bl);
				byte[] b = riscB(bccAt.add(bl), F, bl);
				System.arraycopy(bcc, 0, buf, off, bl);
				System.arraycopy(b, 0, buf, off + bl, bl);
				riscNopFill(buf, off + 2 * bl);
				addPatch(p, start, buf, "cond", "if(" + cc + ") -> " + T + " else -> " + F);
			}
			else {
				byte[] jcc = x86Jcc(start, T, cc);
				Address afterJcc = start.add(jcc.length);
				byte[] jmp = x86JmpBytes(afterJcc, F);
				int need = jcc.length + jmp.length;
				if (region < need) {
					throw new IllegalStateException("window too small for jcc+jmp");
				}
				byte[] buf = new byte[region];
				System.arraycopy(jcc, 0, buf, 0, jcc.length);
				System.arraycopy(jmp, 0, buf, jcc.length, jmp.length);
				for (int i = need; i < buf.length; i++) {
					buf[i] = (byte) 0x90;
				}
				addPatch(p, start, buf, "cond", "if(" + cc + ") -> " + T + " else -> " + F);
			}
			p.lines.add(start + "  cond    if(" + cc + ") -> " + T + " else -> " + F);
			return;
		}
		// stub form: b.cc stubT ; b stubF   (stubX = pre + post + copiesX + b X)
		Address stubT = T;
		Address stubF = F;
		List<Instruction> body = new ArrayList<Instruction>(np.pre);
		body.addAll(np.post);
		boolean tNeeds = !body.isEmpty() || !np.effT.live.isEmpty();
		boolean fNeeds = !body.isEmpty() || !np.effF.live.isEmpty();
		if (tNeeds) {
			stubT = alloc.allocate(bytesOf(body) + bytesOf(np.effT.live) + branchLen());
			addPatch(p, stubT, buildStub(stubT, body, np.effT.live, T), "stub",
					"true path: " + body.size() + " tail instr(s) + " + np.effT.live.size() + " copy(ies) -> " + T);
		}
		if (fNeeds) {
			stubF = alloc.allocate(bytesOf(body) + bytesOf(np.effF.live) + branchLen());
			addPatch(p, stubF, buildStub(stubF, body, np.effF.live, F), "stub",
					"false path: " + body.size() + " tail instr(s) + " + np.effF.live.size() + " copy(ies) -> " + F);
		}
		byte[] buf = new byte[region];
		String hubNote = "";
		if (risc()) {
			int bl = branchLen();
			if (region >= 2 * bl && bccInRange(start, stubT)) {
				byte[] bcc = riscBcc(start, stubT, cc, bl);
				System.arraycopy(bcc, 0, buf, 0, bl);
				byte[] b = riscB(start.add(bl), stubF, bl);
				System.arraycopy(b, 0, buf, bl, bl);
				riscNopFill(buf, 2 * bl);
			}
			else {
				// no room for the pair in place, or the stub is beyond B.cond's reach
				// (±1 MiB; the external stub block usually is): the select slot becomes
				// a plain B to a hub that holds `b.cc stubT ; b stubF` next to the stubs.
				// The condition flags survive the extra B untouched.
				Address hub = allocForBcc(alloc, 2 * bl, 0, stubT);
				byte[] hb = new byte[2 * bl];
				System.arraycopy(riscBcc(hub, stubT, cc, bl), 0, hb, 0, bl);
				System.arraycopy(riscB(hub.add(bl), stubF, bl), 0, hb, bl, bl);
				addPatch(p, hub, hb, "stub", "hub: b.cc/b pair for " + start);
				System.arraycopy(riscB(start, hub, bl), 0, buf, 0, bl);
				riscNopFill(buf, bl);
				hubNote = ", hub " + hub;
			}
		}
		else {
			// jcc rel32 + jmp rel32 need 11 bytes; route through a hub stub when the tail is shorter
			byte[] jcc = x86Jcc(start, stubT, cc);
			byte[] jmp = x86JmpBytes(start.add(jcc.length), stubF);
			if (region >= jcc.length + jmp.length) {
				System.arraycopy(jcc, 0, buf, 0, jcc.length);
				System.arraycopy(jmp, 0, buf, jcc.length, jmp.length);
				for (int i = jcc.length + jmp.length; i < buf.length; i++) {
					buf[i] = (byte) 0x90;
				}
			}
			else {
				Address hub = alloc.allocate(11);
				byte[] hb = new byte[11];
				byte[] hjcc = x86Jcc(hub, stubT, cc);
				byte[] hjmp = x86JmpBytes(hub.add(6), stubF);
				System.arraycopy(hjcc, 0, hb, 0, 6);
				System.arraycopy(hjmp, 0, hb, 6, 5);
				addPatch(p, hub, hb, "stub", "hub: jcc/jmp pair for " + start);
				byte[] j = x86JmpBytes(start, hub);
				if (region < j.length) {
					throw new IllegalStateException("window too small for jmp");
				}
				System.arraycopy(j, 0, buf, 0, j.length);
				for (int i = j.length; i < buf.length; i++) {
					buf[i] = (byte) 0x90;
				}
			}
		}
		addPatch(p, start, buf, "cond", "if(" + cc + ") -> " + T + " else -> " + F + " via stubs");
		p.lines.add(start + "  cond    if(" + cc + ") -> " + T + " else -> " + F + "   [stubs: " + (tNeeds ? stubT : "-")
				+ " / " + (fNeeds ? stubF : "-") + ", post=" + np.post.size() + ", copies=" + np.effT.live.size() + "/"
				+ np.effF.live.size() + hubNote + "]");
	}

	/** Can a conditional branch at {@code from} reach {@code to}? (AArch64 B.cond ±1 MiB, ARM ±32 MiB, Thumb B<c>.W ±1 MiB, x86 rel32.) */
	private boolean bccInRange(Address from, Address to) {
		long d = to.subtract(from);
		switch (arch) {
		case ARM64:
			return Math.abs(d) < (1L << 20) - 16;
		case ARM32:
			return Math.abs(d) < (thumbFn ? (1L << 20) : (1L << 25)) - 16;
		default:
			return true;
		}
	}

	/**
	 * Allocate {@code len} bytes for a stub whose conditional branch at offset
	 * {@code bccOffset} must reach {@code bccTarget}. The function-local cave is
	 * tried first; when the target sits in the far external block, the stub is
	 * put there as well so the B.cond stays in range.
	 */
	private Address allocForBcc(StubAllocator alloc, int len, int bccOffset, Address bccTarget) {
		Address at = alloc.allocate(len);
		if (bccInRange(at.add(bccOffset), bccTarget)) {
			return at;
		}
		if (external != null && isExternal(bccTarget)) {
			Address e = external.allocate(len);
			if (bccInRange(e.add(bccOffset), bccTarget)) {
				return e;
			}
		}
		throw new IllegalStateException("B.cond out of range " + at.add(bccOffset) + " -> " + bccTarget);
	}
	/** stub = <tail instructions after the select> <dispatcher copies> <branch to target>, all byte-copied. */
	private byte[] buildStub(Address at, List<Instruction> post, List<Instruction> copies, Address target) throws Exception {
		int n = bytesOf(post) + bytesOf(copies) + branchLen();
		byte[] out = new byte[n];
		int off = 0;
		for (Instruction in : post) {
			byte[] b = new byte[in.getLength()];
			currentProgram.getMemory().getBytes(in.getMinAddress(), b);
			System.arraycopy(b, 0, out, off, b.length);
			off += b.length;
		}
		for (Instruction in : copies) {
			byte[] b = new byte[in.getLength()];
			currentProgram.getMemory().getBytes(in.getMinAddress(), b);
			System.arraycopy(b, 0, out, off, b.length);
			off += b.length;
		}
		Address brAt = at.add(off);
		if (risc()) {
			byte[] b = riscB(brAt, target, branchLen());
			System.arraycopy(b, 0, out, off, b.length);
		}
		else {
			byte[] j = x86JmpBytes(brAt, target);
			System.arraycopy(j, 0, out, off, 5);
		}
		return out;
	}

	private boolean isExternal(Address at) {
		return external != null && external.contains(at);
	}

	private void addPatch(FnPlan p, Address at, byte[] repl, String kind, String desc) throws Exception {
		boolean ext = isExternal(at);
		if (arch == Arch.ARM32 && !ext && isThumbAt(at) != thumbFn) {
			throw new IllegalStateException("patch site " + at + " is in the other ISA mode (ARM/Thumb) than the function entry");
		}
		for (Patch q : p.patches) {
			Address qEnd = q.at.add(q.repl.length - 1);
			Address end = at.add(repl.length - 1);
			if (at.compareTo(qEnd) <= 0 && q.at.compareTo(end) <= 0) {
				throw new IllegalStateException("patch " + at + " overlaps " + q.at + " (" + q.kind + ")");
			}
		}
		Patch pt = new Patch();
		pt.at = at;
		pt.orig = new byte[repl.length];
		if (!ext) {
			currentProgram.getMemory().getBytes(at, pt.orig);
		}
		// external stub block: does not exist yet at plan time; it is created zero-filled
		pt.repl = repl;
		pt.kind = kind;
		pt.desc = desc;
		pt.fn = p.f.getEntryPoint();
		p.patches.add(pt);
	}

	/**
	 * First-fit allocator over the dead dispatcher bytes, with an optional
	 * fallback pool (the external stub block shared by every function in the
	 * run) for what does not fit — or for everything, in partial mode, where the
	 * dispatcher stays live and owns no spare byte.
	 */
	private static final class StubAllocator {
		private final List<long[]> free = new ArrayList<long[]>(); // [start, end) offsets
		private final Address base;
		private final int align;
		private int used;
		private long capacity;
		private StubAllocator fallback;
		private final long lo;
		private final long hi;

		StubAllocator(AddressSetView region, int align) {
			this.align = align;
			Address b = null;
			long l = Long.MAX_VALUE;
			long h = Long.MIN_VALUE;
			AddressRangeIterator it = region.getAddressRanges();
			while (it.hasNext()) {
				AddressRange ar = it.next();
				if (b == null) {
					b = ar.getMinAddress();
				}
				free.add(new long[] { ar.getMinAddress().getOffset(), ar.getMaxAddress().getOffset() + 1 });
				capacity += ar.getLength();
				l = Math.min(l, ar.getMinAddress().getOffset());
				h = Math.max(h, ar.getMaxAddress().getOffset() + 1);
			}
			base = b;
			lo = l;
			hi = h;
		}

		long capacity() {
			return capacity;
		}

		void setFallback(StubAllocator f) {
			fallback = f;
		}

		/** Does this allocator's own span cover {@code at}? */
		boolean contains(Address at) {
			if (base == null || !at.getAddressSpace().equals(base.getAddressSpace())) {
				return false;
			}
			long o = at.getOffset();
			return o >= lo && o < hi;
		}

		private StubAllocator(StubAllocator o) {
			this.align = o.align;
			this.base = o.base;
			this.lo = o.lo;
			this.hi = o.hi;
			this.capacity = o.capacity;
			this.fallback = o.fallback;
			for (long[] r : o.free) {
				free.add(new long[] { r[0], r[1] });
			}
			used = o.used;
		}

		StubAllocator copy() {
			return new StubAllocator(this);
		}

		/** Roll this allocator back to an earlier {@link #copy()} (a plan that was abandoned). */
		void restore(StubAllocator snapshot) {
			free.clear();
			for (long[] r : snapshot.free) {
				free.add(new long[] { r[0], r[1] });
			}
			used = snapshot.used;
		}

		int used() {
			return used;
		}

		void reserve(Address at, int len) {
			long s = at.getOffset();
			long e = s + len;
			List<long[]> next = new ArrayList<long[]>();
			for (long[] r : free) {
				if (e <= r[0] || s >= r[1]) {
					next.add(r);
					continue;
				}
				if (r[0] < s) {
					next.add(new long[] { r[0], s });
				}
				if (e < r[1]) {
					next.add(new long[] { e, r[1] });
				}
			}
			free.clear();
			free.addAll(next);
		}

		boolean canAllocate(int len) {
			for (long[] r : free) {
				long s = (r[0] + align - 1) / align * align;
				if (s + len <= r[1]) {
					return true;
				}
			}
			return false;
		}

		Address allocate(int len) {
			for (long[] r : free) {
				long s = (r[0] + align - 1) / align * align;
				if (s + len <= r[1]) {
					Address at = base.getNewAddress(s);
					r[0] = s + len;
					used += len;
					return at;
				}
			}
			if (fallback != null) {
				return fallback.allocate(len);
			}
			throw new IllegalStateException((base == null ? "no code cave available (dispatcher live, external stubs off)"
					: "dispatcher code cave exhausted") + " (" + len + " bytes)");
		}
	}

	// -------------------------------------------------------------- apply ----

	/**
	 * First page-aligned address after the last block of the default address
	 * space, one guard page further. Deterministic, so dryRun and the real run
	 * plan against the same base.
	 */
	private Address chooseExternalBase() {
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address max = null;
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (b.isOverlay() || !b.getStart().getAddressSpace().equals(space)) {
				continue;
			}
			if (max == null || b.getEnd().compareTo(max) > 0) {
				max = b.getEnd();
			}
		}
		if (max == null) {
			return null;
		}
		long page = 0x1000;
		long off = (Long.divideUnsigned(max.getOffset(), page) + 2) * page;
		long top = space.getMaxAddress().getOffset(); // may be 0xffff_ffff_ffff_ffff: compare unsigned
		if (Long.compareUnsigned(off, max.getOffset()) <= 0 || Long.compareUnsigned(off + EXTERNAL_RESERVE, top) >= 0
				|| Long.compareUnsigned(off + EXTERNAL_RESERVE, off) < 0) {
			return null;
		}
		return space.getAddress(off);
	}

	private static long externalBlockSize(int used) {
		return (used + 0xfffL) & ~0xfffL;
	}

	private void createExternalBlock(int used) throws Exception {
		Memory mem = currentProgram.getMemory();
		String name = EXTERNAL_BLOCK_NAME;
		for (int n = 2; mem.getBlock(name) != null; n++) {
			name = EXTERNAL_BLOCK_NAME + "_" + n;
		}
		long size = externalBlockSize(used);
		externalBlock = mem.createInitializedBlock(name, externalBase, size, (byte) 0, monitor, false);
		externalBlock.setRead(true);
		externalBlock.setWrite(false);
		externalBlock.setExecute(true);
		externalBlock.setComment("CffDeflatten trampoline stubs (synthetic; undo= removes this block)");
		println("created memory block " + name + " @" + externalBase + " (" + size + " bytes) for " + used + " bytes of trampolines");
	}

	private boolean externalBlockInUse() {
		for (FnPlan p : plans) {
			if (!p.applied) {
				continue;
			}
			for (Patch pt : p.patches) {
				if (isExternal(pt.at)) {
					return true;
				}
			}
		}
		return false;
	}

	private int apply(FnPlan p) {
		int ok = 0;
		for (Patch pt : p.patches) {
			try {
				// bytes are defined as instructions; clear the code units first
				clearListing(pt.at, pt.at.add(pt.repl.length - 1));
				currentProgram.getMemory().setBytes(pt.at, pt.repl);
				if (arch == Arch.ARM32 && tmodeReg != null && isExternal(pt.at)) {
					// the stub block has no ISA context of its own: give the stub the mode of its function
					currentProgram.getProgramContext().setValue(tmodeReg, pt.at, pt.at.add(pt.repl.length - 1),
							p.thumb ? BigInteger.ONE : BigInteger.ZERO);
				}
				ok++;
			}
			catch (Exception e) {
				printerr("  write failed @" + pt.at + ": " + e.getMessage());
			}
		}
		p.applied = ok > 0;
		return ok;
	}

	private void revert(FnPlan p) {
		for (int i = p.patches.size() - 1; i >= 0; i--) {
			Patch pt = p.patches.get(i);
			try {
				clearListing(pt.at, pt.at.add(pt.orig.length - 1));
				currentProgram.getMemory().setBytes(pt.at, pt.orig);
				if (!isExternal(pt.at)) {
					disassemble(pt.at);
				}
			}
			catch (Exception e) {
				printerr("  revert failed @" + pt.at + ": " + e.getMessage());
			}
		}
		p.applied = false;
		p.patches.clear();
	}

	// --------------------------------------------------------------- verify --

	private Trace trace(FnPlan p) {
		Trace t = new Trace();
		for (int i = 0; i < SEEDS.length; i++) {
			t.perSeed.add(CffCore.traceRun(currentProgram, p.f, p.f.getEntryPoint(), p.r.watch, TRACE_MAX_HEADS,
					TRACE_MAX_STEPS, monitor, SEEDS[i]));
		}
		return t;
	}

	/** null when equal under every seed, otherwise a description of the first divergence. */
	private String compareTraces(FnPlan p, Trace before, Trace after) {
		if (before == null || after == null) {
			return "trace unavailable";
		}
		boolean any = false;
		for (int s = 0; s < before.perSeed.size() && s < after.perSeed.size(); s++) {
			List<CffCore.TraceEvent> a = before.perSeed.get(s);
			List<CffCore.TraceEvent> b = after.perSeed.get(s);
			if (a.isEmpty()) {
				continue; // this input never reached a real block; nothing to compare
			}
			any = true;
			String seed = "[seed " + SEEDS[s].name + "] ";
			int n = Math.min(a.size(), b.size());
			List<Register> regs = CffCore.traceRegisters(currentProgram);
			for (int i = 0; i < n; i++) {
				CffCore.TraceEvent x = a.get(i);
				CffCore.TraceEvent y = b.get(i);
				if (!x.head.equals(y.head)) {
					return seed + "head #" + i + ": original " + x.head + " vs patched " + y.head;
				}
				Set<String> ignore = ignoredAt(p, x.head);
				for (int k = 0; k < regs.size(); k++) {
					String reg = regs.get(k).getName();
					if (ignore.contains(reg)) {
						continue;
					}
					if (x.regs[k] != y.regs[k]) {
						if (garbageCopy(p, x, y, k, regs)) {
							continue;
						}
						return seed + "head #" + i + " @" + x.head + ": register " + reg + " original=0x"
								+ Long.toHexString(x.regs[k]) + " patched=0x" + Long.toHexString(y.regs[k]);
					}
				}
			}
			if (b.size() < a.size()) {
				return seed + "patched trace stops after " + b.size() + " head visits, original had " + a.size();
			}
		}
		if (!any) {
			return "original trace reached no real block under any seed";
		}
		return null;
	}

	/**
	 * A differing register is still harmless when, in BOTH traces, its value is
	 * a plain copy (through real-code `mov`s, e.g. -O2 PHI resolution
	 * `mov x26,x24`) of a register the whole function ignores because the
	 * dispatcher fills it with state-derived garbage: a copy of garbage is
	 * garbage. Only the function-wide ignore sets qualify as roots — a register
	 * merely killed at this head says nothing about the value it held earlier.
	 */
	private boolean garbageCopy(FnPlan p, CffCore.TraceEvent x, CffCore.TraceEvent y, int k, List<Register> regs) {
		if (x.prov == null || y.prov == null) {
			return false;
		}
		int root = x.prov[k];
		if (root < 0 || root != y.prov[k] || root >= regs.size()) {
			return false;
		}
		String src = regs.get(root).getName();
		return p.deadRegs.contains(src) || p.stateScratch.contains(src);
	}

	/**
	 * Registers whose value at {@code head} cannot matter: the state registers
	 * (nothing outside the dispatcher reads them) and whatever the block at
	 * {@code head} overwrites before reading. Everything else is compared.
	 */
	private Set<String> ignoredAt(FnPlan p, Address head) {
		Set<String> s = p.ignoreAt.get(head);
		if (s == null) {
			s = new HashSet<String>(p.deadRegs);
			// state copies / compare temporaries the dispatcher leaves behind: they
			// stay garbage across direct edges too, so they are ignored function-wide
			s.addAll(p.stateScratch);
			s.addAll(CffCore.killedOnEntry(currentProgram, head));
			p.ignoreAt.put(head, s);
		}
		return s;
	}

	/** Remember which registers the dispatcher fills with state-derived values on the way to a head. */
	private void noteStateDerived(FnPlan p, Address head, CffCore.PathEffects eff) {
		if (eff != null) {
			p.stateScratch.addAll(eff.stateDerivedAtEnd);
		}
	}

	/** Diagnostic: head sequences of both traces per seed and every register that differs at the first divergence. */
	private void dumpTraces(FnPlan p, Trace before, Trace after) {
		for (int s = 0; s < before.perSeed.size() && s < after.perSeed.size(); s++) {
			List<CffCore.TraceEvent> a = before.perSeed.get(s);
			List<CffCore.TraceEvent> b = after.perSeed.get(s);
			StringBuilder sa = new StringBuilder();
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < a.size() && i < 40; i++) {
				sa.append(a.get(i).head).append(' ');
			}
			for (int i = 0; i < b.size() && i < 40; i++) {
				sb.append(b.get(i).head).append(' ');
			}
			println("    [seed " + SEEDS[s].name + "] original(" + a.size() + "): " + sa);
			println("    [seed " + SEEDS[s].name + "] patched (" + b.size() + "): " + sb);
			int n = Math.min(a.size(), b.size());
			List<Register> names = CffCore.traceRegisters(currentProgram);
			for (int i = 0; i < n; i++) {
				CffCore.TraceEvent x = a.get(i);
				CffCore.TraceEvent y = b.get(i);
				boolean diff = !x.head.equals(y.head);
				StringBuilder regs = new StringBuilder();
				Set<String> ignore = ignoredAt(p, x.head);
				for (int k = 0; k < names.size(); k++) {
					String reg = names.get(k).getName();
					if (x.regs[k] != y.regs[k]) {
						boolean skip = ignore.contains(reg);
						String why = skip ? "(ignored)" : garbageCopy(p, x, y, k, names) ? "(copy of ignored " + names.get(x.prov[k]).getName() + ")" : "";
						skip = skip || why.length() > 0;
						regs.append(' ').append(reg).append(why).append("=0x")
								.append(Long.toHexString(x.regs[k])).append("/0x").append(Long.toHexString(y.regs[k]));
						if (!skip) {
							diff = true;
						}
					}
				}
				if (diff) {
					println("    [seed " + SEEDS[s].name + "] first divergence at head #" + i + " " + x.head + " vs " + y.head
							+ (regs.length() > 0 ? "; registers original/patched:" + regs : ""));
					break;
				}
			}
		}
	}

	/**
	 * Full-mode structural oracle, evaluated on the re-disassembled function:
	 * (1) no block reachable from the entry may overlap dispatcher bytes we did
	 * not overwrite ourselves (a tail still jumping into the dead compare tree
	 * would be exactly the corruption the trace might miss), and (2) every
	 * real block that was reachable before must still be reachable.
	 */
	private String checkFullModeCfg(FnPlan p) {
		try {
			CffCore.Cfg g = CffCore.buildCfg(currentProgram, p.f, monitor);
			AddressSet patched = new AddressSet();
			for (Patch pt : p.patches) {
				patched.add(pt.at, pt.at.add(pt.repl.length - 1));
			}
			AddressSet forbidden = new AddressSet(p.r.dispatchRegion);
			forbidden.delete(patched);
			BasicBlockModel bbm = new BasicBlockModel(currentProgram);
			for (int i = 0; i < g.size(); i++) {
				if (!g.isReachable(i)) {
					continue;
				}
				CodeBlock cb = bbm.getCodeBlockAt(g.addr(i), monitor);
				if (cb != null && forbidden.intersects(cb)) {
					return "patched CFG still reaches unpatched dispatcher code in block " + g.addr(i);
				}
			}
			CffCore.Cfg old = p.d.cfg;
			for (Address h : p.r.nodes.keySet()) {
				Integer oi = old.id.get(h);
				if (oi == null || !old.isReachable(oi.intValue())) {
					continue;
				}
				Integer ni = g.id.get(h);
				if (ni == null || !g.isReachable(ni.intValue())) {
					return "real block " + h + " is no longer reachable from the entry";
				}
			}
			return null;
		}
		catch (Exception e) {
			return "structural check failed: " + e.getMessage();
		}
	}

	// ----------------------------------------------------------- reanalyze ---

	/**
	 * Re-disassemble exactly the patched byte ranges (tails, stubs, entry
	 * slots) and recompute the function body from the entry, so the listing,
	 * the verify trace and the decompiler see the now-direct CFG; dead
	 * dispatcher blocks drop out of the body because nothing flows to them.
	 * Only the patched ranges are cleared: wiping the whole body would also
	 * throw away analysis-derived flow (switch-table references) and shrink the
	 * function on the next fix-up, which would make verify fail for the wrong
	 * reason and leave an undo worse than the original.
	 */
	private void reflow(FnPlan p) {
		reflowRanges(p.f, p.patches);
	}

	private void reflowRanges(Function f, List<Patch> patches) {
		try {
			for (Patch pt : patches) {
				clearListing(pt.at, pt.at.add(pt.repl.length - 1));
			}
			for (Patch pt : patches) {
				disassemble(pt.at);
			}
			disassemble(f.getEntryPoint());
			CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
		}
		catch (Exception e) {
			printerr("  reflow " + f.getName() + ": " + e.getMessage());
		}
	}

	// ----------------------------------------------------------------- undo --

	private void undo(String path) throws Exception {
		File f = new File(path);
		if (!f.isFile()) {
			printerr("undo: no log at " + path);
			return;
		}
		JsonObject root;
		FileReader reader = new FileReader(f);
		try {
			root = JsonParser.parseReader(reader).getAsJsonObject();
		}
		finally {
			reader.close();
		}
		JsonArray arr = root.getAsJsonArray("patches");
		// synthetic stub blocks this run created: their bytes need no restoring, the block goes away
		List<MemoryBlock> blocks = new ArrayList<MemoryBlock>();
		AddressSet blockRanges = new AddressSet();
		if (root.has("blocks")) {
			JsonArray ba = root.getAsJsonArray("blocks");
			for (int i = 0; i < ba.size(); i++) {
				JsonObject o = ba.get(i).getAsJsonObject();
				Address start = parseAddr(o.get("start").getAsString());
				MemoryBlock b = start == null ? null : currentProgram.getMemory().getBlock(start);
				if (b == null) {
					printerr("  undo: stub block " + o.get("name").getAsString() + " @" + o.get("start").getAsString() + " no longer exists");
					continue;
				}
				if (!b.getName().equals(o.get("name").getAsString())) {
					printerr("  undo: block @" + start + " is " + b.getName() + ", not " + o.get("name").getAsString() + "; left alone");
					continue;
				}
				blocks.add(b);
				blockRanges.add(b.getStart(), b.getEnd());
			}
		}
		int restored = 0;
		Set<Address> fns = new LinkedHashSet<Address>();
		List<Address> restoredAt = new ArrayList<Address>();
		// restore in reverse order so overlapping writes unwind correctly
		for (int i = arr.size() - 1; i >= 0; i--) {
			JsonObject o = arr.get(i).getAsJsonObject();
			Address at = parseAddr(o.get("at").getAsString());
			byte[] orig = hexToBytes(o.get("orig").getAsString());
			if (at == null || orig == null) {
				continue;
			}
			if (blockRanges.contains(at)) {
				if (o.has("fn")) {
					Address fn = parseAddr(o.get("fn").getAsString());
					if (fn != null) {
						fns.add(fn);
					}
				}
				restored++;
				continue;
			}
			try {
				clearListing(at, at.add(orig.length - 1));
				currentProgram.getMemory().setBytes(at, orig);
				restoredAt.add(at);
				restored++;
				if (o.has("fn")) {
					Address fn = parseAddr(o.get("fn").getAsString());
					if (fn != null) {
						fns.add(fn);
					}
				}
			}
			catch (Exception e) {
				printerr("  undo failed @" + at + ": " + e.getMessage());
			}
		}
		for (Address fn : fns) {
			Function fun = getFunctionAt(fn);
			if (fun == null) {
				continue;
			}
			try {
				for (Address at : restoredAt) {
					disassemble(at);
				}
				disassemble(fn);
				CreateFunctionCmd.fixupFunctionBody(currentProgram, fun, monitor);
			}
			catch (Exception e) {
				printerr("  undo: re-disassemble " + fun.getName() + ": " + e.getMessage());
			}
		}
		// after the bodies were recomputed (no branch leads into the block any more)
		for (MemoryBlock b : blocks) {
			String name = b.getName();
			if (removeStubBlock(b)) {
				println("  undo: removed stub block " + name);
			}
		}
		println("undo: restored " + restored + " patches from " + path + " (" + fns.size() + " function(s) re-disassembled"
				+ (blocks.isEmpty() ? "" : ", " + blocks.size() + " stub block(s) removed") + ")");
	}

	/**
	 * Remove a synthetic stub block. Ghidra deletes every function whose body
	 * overlaps a removed range, so first take the block out of any body that
	 * still lists it (a function keeps stub ranges in its body until it is
	 * re-fixed-up after the stubs are unreachable).
	 */
	private boolean removeStubBlock(MemoryBlock b) {
		AddressSet range = new AddressSet(b.getStart(), b.getEnd());
		try {
			java.util.Iterator<Function> it = currentProgram.getFunctionManager().getFunctionsOverlapping(range);
			List<Function> touching = new ArrayList<Function>();
			while (it.hasNext()) {
				touching.add(it.next());
			}
			for (Function fun : touching) {
				if (range.contains(fun.getEntryPoint())) {
					continue; // a function that starts inside the block goes away with it
				}
				AddressSetView body = fun.getBody();
				if (body.intersects(range)) {
					fun.setBody(body.subtract(range));
				}
			}
			currentProgram.getMemory().removeBlock(b, monitor);
			return true;
		}
		catch (Exception e) {
			printerr("  could not remove stub block " + b.getName() + ": " + e.getMessage());
			return false;
		}
	}

	private void writeLog(String path, int applied) throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("{\n  \"program\": \"").append(esc(currentProgram.getName())).append("\",\n  \"applied\": ")
				.append(applied).append(",\n  \"functions\": [\n");
		int k = 0;
		for (FnPlan p : plans) {
			if (!p.applied) {
				continue;
			}
			sb.append(k++ > 0 ? ",\n" : "").append("    {\"entry\": \"").append(p.f.getEntryPoint()).append("\", \"name\": \"")
					.append(esc(p.f.getName())).append("\", \"mode\": \"").append(p.full ? "full" : "partial")
					.append("\", \"patches\": ").append(p.patches.size()).append(", \"verify\": \"")
					.append(esc(p.verifyResult == null ? "skipped" : p.verifyResult)).append("\"}");
		}
		sb.append("\n  ],\n  \"blocks\": [");
		if (externalBlock != null) {
			sb.append("\n    {\"name\": \"").append(esc(externalBlock.getName())).append("\", \"start\": \"")
					.append(externalBlock.getStart()).append("\", \"size\": ").append(externalBlock.getSize()).append("}\n  ");
		}
		sb.append("],\n  \"patches\": [\n");
		List<Patch> all = new ArrayList<Patch>();
		for (FnPlan p : plans) {
			if (p.applied) {
				all.addAll(p.patches);
			}
		}
		for (int i = 0; i < all.size(); i++) {
			Patch p = all.get(i);
			sb.append("    {\"at\": \"").append(p.at).append("\", \"fn\": \"").append(p.fn).append("\", \"kind\": \"")
					.append(p.kind).append("\", \"orig\": \"").append(bytesToHex(p.orig)).append("\", \"repl\": \"")
					.append(bytesToHex(p.repl)).append("\", \"desc\": \"").append(esc(p.desc)).append("\"}");
			sb.append(i + 1 < all.size() ? ",\n" : "\n");
		}
		sb.append("  ]\n}\n");
		FileWriter w = new FileWriter(path);
		try {
			w.write(sb.toString());
		}
		finally {
			w.close();
		}
	}

	// ---------------------------------------------------------- encoders -----

	private Arch archOf() {
		String id = currentProgram.getLanguageID().toString().toUpperCase();
		if (id.startsWith("AARCH64")) {
			return Arch.ARM64;
		}
		if (id.startsWith("ARM:")) {
			return Arch.ARM32; // ARM:LE:32:v7 / v8 etc. (ARM + Thumb-2, TMode context decides per address)
		}
		if (id.startsWith("X86")) {
			return Arch.X86;
		}
		return Arch.OTHER;
	}

	private int a64B(Address at, Address target) {
		long disp = target.subtract(at);
		if ((disp & 3) != 0 || disp < -(1L << 27) || disp >= (1L << 27)) {
			return 0;
		}
		return 0x14000000 | (int) ((disp >> 2) & 0x03FFFFFF);
	}

	private int a64Bcond(Address at, Address target, String cc) {
		int c = a64Cond(cc);
		if (c < 0) {
			return 0;
		}
		long disp = target.subtract(at);
		if ((disp & 3) != 0 || disp < -(1L << 20) || disp >= (1L << 20)) {
			return 0;
		}
		return 0x54000000 | (((int) ((disp >> 2) & 0x7FFFF)) << 5) | c;
	}

	/**
	 * Re-encode an existing AArch64 conditional branch (B.cond / CBZ / CBNZ /
	 * TBZ / TBNZ) with a new target, keeping condition, register and bit
	 * number bits untouched. Returns 0 when the instruction is not one of
	 * those or the displacement does not fit.
	 */
	private int a64Retarget(int insn, Address at, Address target) {
		long disp = target.subtract(at);
		if ((disp & 3) != 0) {
			return 0;
		}
		long words = disp >> 2;
		if ((insn & 0xFF000010) == 0x54000000 || (insn & 0x7E000000) == 0x34000000) {
			// B.cond / CBZ / CBNZ: imm19 at [23:5]
			if (words < -(1L << 18) || words >= (1L << 18)) {
				return 0;
			}
			return (insn & ~(0x7FFFF << 5)) | (((int) words & 0x7FFFF) << 5);
		}
		if ((insn & 0x7E000000) == 0x36000000) {
			// TBZ / TBNZ: imm14 at [18:5]
			if (words < -(1L << 13) || words >= (1L << 13)) {
				return 0;
			}
			return (insn & ~(0x3FFF << 5)) | (((int) words & 0x3FFF) << 5);
		}
		return 0;
	}

	/** Re-encode an x86 `jcc rel32` (0F 8x) with a new target; short forms are refused. */
	private byte[] x86RetargetJcc(Instruction insn, Address at, Address target) throws Exception {
		byte[] orig = new byte[insn.getLength()];
		currentProgram.getMemory().getBytes(at, orig);
		if (orig.length != 6 || (orig[0] & 0xFF) != 0x0F || (orig[1] & 0xF0) != 0x80) {
			throw new IllegalStateException("conditional jump @" + at + " is not a jcc rel32; cannot retarget in place");
		}
		long rel = target.subtract(at.add(6));
		if (rel < Integer.MIN_VALUE || rel > Integer.MAX_VALUE) {
			throw new IllegalStateException("jcc rel32 out of range " + at + " -> " + target);
		}
		byte[] b = new byte[6];
		b[0] = orig[0];
		b[1] = orig[1];
		putLE(b, 2, (int) rel, 4);
		return b;
	}

	private int a64Cond(String cc) {
		switch (cc) {
		case "eq": return 0;
		case "ne": return 1;
		case "cs": case "hs": return 2;
		case "cc": case "lo": return 3;
		case "mi": return 4;
		case "pl": return 5;
		case "vs": return 6;
		case "vc": return 7;
		case "hi": return 8;
		case "ls": return 9;
		case "ge": return 10;
		case "lt": return 11;
		case "gt": return 12;
		case "le": return 13;
		case "al": return 14;
		default: return -1;
		}
	}

	private byte[] x86JmpBytes(Address at, Address target) {
		long rel = target.subtract(at.add(5));
		if (rel < Integer.MIN_VALUE || rel > Integer.MAX_VALUE) {
			throw new IllegalStateException("jmp rel32 out of range " + at + " -> " + target);
		}
		byte[] b = new byte[5];
		b[0] = (byte) 0xE9;
		putLE(b, 1, (int) rel, 4);
		return b;
	}

	private byte[] x86Jcc(Address at, Address target, String cc) {
		int op = x86CondOp(cc);
		if (op < 0) {
			throw new IllegalStateException("bad x86 condition " + cc);
		}
		long rel = target.subtract(at.add(6));
		if (rel < Integer.MIN_VALUE || rel > Integer.MAX_VALUE) {
			throw new IllegalStateException("jcc rel32 out of range " + at + " -> " + target);
		}
		byte[] b = new byte[6];
		b[0] = 0x0F;
		b[1] = (byte) op;
		putLE(b, 2, (int) rel, 4);
		return b;
	}

	private int x86CondOp(String cc) {
		switch (cc) {
		case "o": return 0x80;
		case "no": return 0x81;
		case "b": case "c": case "nae": return 0x82;
		case "ae": case "nb": case "nc": return 0x83;
		case "e": case "z": return 0x84;
		case "ne": case "nz": return 0x85;
		case "be": case "na": return 0x86;
		case "a": case "nbe": return 0x87;
		case "s": return 0x88;
		case "ns": return 0x89;
		case "p": case "pe": return 0x8A;
		case "np": case "po": return 0x8B;
		case "l": case "nge": return 0x8C;
		case "ge": case "nl": return 0x8D;
		case "le": case "ng": return 0x8E;
		case "g": case "nle": return 0x8F;
		default: return -1;
		}
	}

	/** Normalise a select's condition mnemonic to a bare code (eq, ne, g, l ...). */
	private String normCond(String c) {
		if (c == null) {
			return "?";
		}
		c = c.trim().toLowerCase();
		if (c.startsWith("cmov")) {
			c = c.substring(4);
		}
		return c;
	}

	private byte[] enc(int insn) {
		byte[] b = new byte[4];
		putLE(b, 0, insn, 4);
		return b;
	}

	private byte[] pad(byte[] src, int slot, boolean arm) {
		if (src.length == slot) {
			return src;
		}
		byte[] out = new byte[slot];
		System.arraycopy(src, 0, out, 0, Math.min(src.length, slot));
		if (arm) {
			for (int i = src.length; i < slot; i += 4) {
				putLE(out, i, 0xD503201F, 4);
			}
		}
		else {
			for (int i = src.length; i < slot; i++) {
				out[i] = (byte) 0x90;
			}
		}
		return out;
	}

	private static void putLE(byte[] b, int off, int val, int n) {
		for (int i = 0; i < n; i++) {
			b[off + i] = (byte) ((val >>> (8 * i)) & 0xFF);
		}
	}

	private static String bytesToHex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < b.length; i++) {
			sb.append(String.format("%02x", b[i] & 0xFF));
		}
		return sb.toString();
	}

	private static byte[] hexToBytes(String s) {
		if (s == null || (s.length() & 1) != 0) {
			return null;
		}
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return b;
	}

	private File defaultDir() {
		String p = currentProgram.getExecutablePath();
		if (p != null) {
			File f = new File(p);
			if (f.getParentFile() != null && f.getParentFile().isDirectory()) {
				return f.getParentFile();
			}
		}
		return new File(System.getProperty("java.io.tmpdir"));
	}

	private Address parseAddr(String s) {
		if (s == null) {
			return null;
		}
		s = s.trim();
		if (s.startsWith("0x") || s.startsWith("0X")) {
			s = s.substring(2);
		}
		try {
			return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(s, 16));
		}
		catch (Exception e) {
			return null;
		}
	}

	private String esc(String s) {
		return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
	}
}
