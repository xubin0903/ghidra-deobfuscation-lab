// BcfClean — fold opaque predicates whose outcome is a compile-time constant.
//
// Obfuscator-LLVM's "bogus control flow" (-bcf) guards every real block with a
// branch on a predicate such as `x*(x-1) % 2 == 0 || y < 10`, where x and y are
// global variables the program never writes. The predicate is always true, the
// "false" arm is a garbage clone of the block. This script finds conditional
// branches whose condition depends only on immediates, on such never-written
// globals and on frame slots filled from them, evaluates the branch once by
// concrete emulation, and rewrites it: always taken -> unconditional branch,
// never taken -> NOP. The bogus arm becomes unreachable and the decompiler
// drops it. Every patched function is re-emulated before/after under four
// input seeds (same harness as CffDeflatten); a mismatch reverts it. An undo
// log (CffDeflatten format) is written.
//
// @category Deobfuscation
// @menupath Tools.Deobfuscation.BCF Clean (fold constant predicates)
// @description Fold conditional branches whose predicate only depends on never-written globals (OLLVM bogus control flow); verify by emulation; undo log
//
// Args (headless: after -postScript BcfClean.java):
//   func=0x…        one function (default: function at the cursor)
//   all             every function of the program
//   dryRun          plan only, write nothing
//   noVerify        skip the before/after trace comparison
//   keepOnMismatch  keep patches even when verification fails
//   log=PATH        undo log location (default <program>.bcf-patch.json next to the program)
//   undo=PATH       restore bytes from a log, then exit
//   maxPath=256     instructions followed per straight-line path
//   crt             do not skip C runtime scaffolding (frame_dummy, register_tm_clones, ...) in an all-run
//   debugPlan       print the constness state after every analysed instruction

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
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

@SuppressWarnings("removal") // EmulatorHelper: deprecated for removal in Ghidra 12, still the only emulator with tracked memory faults (see docs/emulator-migration.md)
public class BcfClean extends GhidraScript {

	private enum Arch { ARM64, ARM32, X86, OTHER }

	private static final int TRACE_MAX_HEADS = 4000;
	private static final int TRACE_MAX_STEPS = 200000;

	private static final class Patch {
		Address at;
		byte[] orig;
		byte[] repl;
		String kind;
		String desc;
		Address fn;
	}

	/** One conditional branch with a constant outcome. */
	private static final class Fold {
		Instruction br;
		boolean taken;
		Address target;
		Address fall;
		String why; // what made the condition constant
	}

	private static final class FnPlan {
		Function f;
		final List<Fold> folds = new ArrayList<Fold>();
		final List<Patch> patches = new ArrayList<Patch>();
		final List<String> skips = new ArrayList<String>();
		final Set<Address> heads = new HashSet<Address>(); // block starts, watched by the verify trace
		final Map<Address, Set<String>> ignoreAt = new HashMap<Address, Set<String>>();
		boolean applied;
		String verifyResult;
	}

	private Arch arch;
	private boolean dryRun;
	private boolean verify = true;
	private boolean keepOnMismatch;
	private int maxPath = 256;
	private boolean debugPlan;
	private boolean crt; // also touch C runtime scaffolding functions in an ll run
	private Register tmodeReg;
	private final List<FnPlan> plans = new ArrayList<FnPlan>();
	private final Map<Address, Boolean> frozenCache = new HashMap<Address, Boolean>();

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		CffCore.Args a = CffCore.parseArgs(getScriptArgs(), new String[] { "func", "log", "undo", "maxPath" });
		boolean all = a.flag("all");
		dryRun = a.flag("dryRun");
		verify = !a.flag("noVerify");
		keepOnMismatch = a.flag("keepOnMismatch");
		maxPath = a.getInt("maxPath", maxPath);
		debugPlan = a.flag("debugPlan");
		crt = a.flag("crt");
		if (a.get("undo") != null) {
			undo(a.get("undo"));
			return;
		}
		arch = archOf();
		println("=== BcfClean ===");
		println("program=" + currentProgram.getName() + " language=" + currentProgram.getLanguageID() + " arch=" + arch
				+ " dryRun=" + dryRun + " verify=" + verify);
		if (arch == Arch.OTHER) {
			printerr("patching not supported for this architecture (AArch64, ARM32, x86/x64 only)");
			return;
		}
		if (arch == Arch.ARM32) {
			tmodeReg = currentProgram.getRegister("TMode");
		}

		List<Function> targets = new ArrayList<Function>();
		Address single = a.get("func") != null ? parseAddr(a.get("func")) : null;
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

		int totalFolds = 0;
		for (Function f : targets) {
			if (monitor.isCancelled()) {
				break;
			}
			if (all && !crt && isCrtScaffolding(f)) {
				continue; // frame_dummy & co. really do branch on link-time constants; nobody wants them rewritten
			}
			monitor.setMessage("BcfClean " + f.getName());
			FnPlan p = plan(f);
			if (p.folds.isEmpty() && p.skips.isEmpty()) {
				continue;
			}
			if (p.folds.isEmpty() && all) {
				continue; // only skips: not worth a line in an all-run
			}
			plans.add(p);
			println("");
			println("--- " + f.getName() + " @" + f.getEntryPoint() + ": " + p.folds.size() + " constant predicate(s) -> "
					+ p.patches.size() + " patch(es) ---");
			for (Fold fo : p.folds) {
				println("    " + fo.br.getMinAddress() + "  " + fo.br + "   " + (fo.taken ? "always taken -> " + fo.target
						: "never taken (falls through to " + fo.fall + ")") + "   [" + fo.why + "]");
			}
			for (String s : p.skips) {
				println("    (skip " + s + ")");
			}
			totalFolds += p.folds.size();
		}
		println("");
		if (dryRun) {
			println("dryRun: " + totalFolds + " constant predicate(s) in " + plans.size() + " function(s); nothing written.");
			return;
		}
		int applied = 0;
		int reverted = 0;
		for (FnPlan p : plans) {
			if (p.patches.isEmpty()) {
				continue;
			}
			for (Address h : p.heads) {
				ignoredAt(p, h); // from the original listing
			}
			List<List<CffCore.TraceEvent>> before = verify ? trace(p) : null;
			applied += apply(p);
			reflow(p);
			if (!verify) {
				continue;
			}
			List<List<CffCore.TraceEvent>> after = trace(p);
			String res = compare(p, before, after);
			if (res == null) {
				p.verifyResult = "OK (" + visits(before) + " block visits over " + before.size() + " input seeds)";
				println("  verify " + p.f.getName() + ": " + p.verifyResult);
			}
			else {
				p.verifyResult = "MISMATCH " + res;
				printerr("  verify " + p.f.getName() + ": " + p.verifyResult);
				if (!keepOnMismatch) {
					revert(p);
					reflow(p);
					reverted++;
					printerr("    -> patches of " + p.f.getName() + " reverted (use keepOnMismatch to keep them)");
				}
			}
		}
		println("applied " + applied + " patches across " + plans.size() + " function(s)");
		String logPath = a.get("log");
		if (logPath == null) {
			logPath = new File(defaultDir(), currentProgram.getName() + ".bcf-patch.json").getAbsolutePath();
		}
		writeLog(logPath, applied);
		println("patch log: " + logPath + "   (undo: -postScript BcfClean.java undo=" + logPath + ")");
		if (reverted > 0) {
			println("verify reverted " + reverted + " function(s); the rest are clean.");
		}
		println("done. re-run auto-analysis (or press F5) for the cleanest decompilation. see docs/scripts/BcfClean.md");
	}

	// ------------------------------------------------------------- planning --

	private FnPlan plan(Function f) throws Exception {
		FnPlan p = new FnPlan();
		p.f = f;
		BasicBlockModel bbm = new BasicBlockModel(currentProgram);
		List<Address> starts = new ArrayList<Address>();
		CodeBlockIterator it = bbm.getCodeBlocksContaining(f.getBody(), monitor);
		while (it.hasNext()) {
			CodeBlock cb = it.next();
			starts.add(cb.getFirstStartAddress());
		}
		Collections.sort(starts);
		p.heads.addAll(starts);
		if (arch == Arch.ARM32 && tmodeReg != null) {
			BigInteger tm = currentProgram.getProgramContext().getValue(tmodeReg, f.getEntryPoint(), false);
			if (tm != null && tm.signum() != 0) {
				p.skips.add("Thumb function: not supported yet");
				return p;
			}
		}
		Set<Address> done = new HashSet<Address>();
		for (Address s : starts) {
			if (done.contains(s)) {
				continue;
			}
			analyzePath(p, bbm, s, done);
		}
		for (Fold fo : p.folds) {
			try {
				emitFold(p, fo);
			}
			catch (Exception e) {
				p.skips.add(fo.br.getMinAddress() + ": " + e.getMessage());
			}
		}
		return p;
	}

	/**
	 * Follow one straight-line path from a block start, tracking which
	 * registers / frame slots hold values derived only from immediates and
	 * never-written globals, while an emulator computes the concrete values.
	 * A conditional branch whose inputs are all constant is a fold; the path
	 * continues along the arm the emulator took when that arm's block has no
	 * other predecessor (its state is then fully inherited).
	 */
	private void analyzePath(FnPlan p, BasicBlockModel bbm, Address start, Set<Address> done) throws Exception {
		// constness per register-space BYTE (so `setz bl ; setl bh ; or bl,bh` is tracked
		// exactly while the rest of EBX stays unknown) and per frame slot:
		// IMM = from immediates / read-only memory only, DATA = involves a never-written data global
		Map<Long, Integer> constRegs = new HashMap<Long, Integer>();
		Map<String, Integer> constSlots = new HashMap<String, Integer>();
		EmulatorHelper emu = null;
		try {
			emu = CffCore.newEmulator(currentProgram, false, (byte) 0);
			Register pc = emu.getPCRegister();
			emu.writeRegister(pc, start.getOffset());
			done.add(start);
			for (int n = 0; n < maxPath; n++) {
				Address cur = emu.getExecutionAddress();
				if (cur == null || !p.f.getBody().contains(cur)) {
					return;
				}
				Instruction in = getInstructionAt(cur);
				if (in == null) {
					return;
				}
				FlowType ft = in.getFlowType();
				if (ft == null || ft.isCall() || ft.isTerminal() || ft.isComputed()) {
					return; // a predicate never spans a call / return / indirect jump
				}
				boolean condBr = ft.isJump() && ft.isConditional();
				// p-code level: every op's output is constant iff all its inputs are,
				// so `sub r2,r0,#1` stays constant although the sleigh shifter code reads
				// CY, and `tst` makes ZR constant without caring about the old CY/OV
				Integer condLevel = propagate(in, constRegs, constSlots);
				if (debugPlan) {
					println("      " + cur + "  " + in + "   const=" + describeRegs(constRegs) + " slots=" + constSlots
							+ (condBr ? " cond=" + condLevel : ""));
				}
				if (condBr) {
					Address[] flows = in.getFlows();
					Address tgt = flows != null && flows.length == 1 ? flows[0] : null;
					Address fall = in.getFallThrough();
					// an all-immediate condition is the compiler's / linker's business (CRT scaffolding
					// compares link-time constants); an opaque predicate always involves a data global
					if (tgt == null || fall == null || condLevel == null || condLevel.intValue() != DATA) {
						return;
					}
					if (!emu.step(monitor)) {
						return;
					}
					Address after = emu.getExecutionAddress();
					if (after == null || (!after.equals(tgt) && !after.equals(fall))) {
						return;
					}
					Fold fo = new Fold();
					fo.br = in;
					fo.target = tgt;
					fo.fall = fall;
					fo.taken = after.equals(tgt);
					fo.why = "condition depends only on immediates and never-written globals";
					p.folds.add(fo);
					// continue only into a block nobody else enters
					CodeBlock nb = bbm.getCodeBlockAt(after, monitor);
					if (nb == null || predecessors(nb) != 1) {
						return;
					}
					done.add(after);
					continue;
				}
				if (ft.isJump()) {
					// unconditional: follow it when the target block is ours alone
					if (!emu.step(monitor)) {
						return;
					}
					Address after = emu.getExecutionAddress();
					CodeBlock nb = after == null ? null : bbm.getCodeBlockAt(after, monitor);
					if (nb == null || predecessors(nb) != 1) {
						return;
					}
					done.add(after);
					continue;
				}
				if (!emu.step(monitor)) {
					return;
				}
				Address next = emu.getExecutionAddress();
				if (next != null && p.heads.contains(next) && !next.equals(in.getFallThrough())) {
					return; // landed somewhere unexpected
				}
				if (next != null && p.heads.contains(next)) {
					// fell into the next block: inherit only when it has no other predecessor
					CodeBlock nb = bbm.getCodeBlockAt(next, monitor);
					if (nb == null || predecessors(nb) != 1) {
						return;
					}
					done.add(next);
				}
			}
		}
		finally {
			if (emu != null) {
				emu.dispose();
			}
		}
	}

	/**
	 * Run one instruction's p-code through the constness state. Returns the
	 * constness of the condition of its (architectural) CBRANCH, or null when
	 * the instruction has none.
	 * <ul>
	 * <li>constants are constant; a register is constant when tracked so; a
	 * unique is constant when the op that produced it in this instruction had
	 * only constant inputs;</li>
	 * <li>LOAD: constant when the instruction reads a never-written global
	 * (Ghidra resolved the address) or a frame slot filled from constants;</li>
	 * <li>STORE: records / forgets the frame slot it writes; a store through an
	 * unknown pointer forgets every slot;</li>
	 * <li>an internal CBRANCH (predicated ARM instruction) with a non-constant
	 * condition makes every later output of the instruction non-constant.</li>
	 * </ul>
	 */
	/** Constness levels: not constant / constant from immediates and read-only memory / involves a never-written data global. */
	private static final int VAR = 0;
	private static final int IMM = 1;
	private static final int DATA = 2;

	private Integer propagate(Instruction in, Map<Long, Integer> constRegs, Map<String, Integer> constSlots) {
		PcodeOp[] ops = in.getPcode();
		Map<Long, Integer> uniq = new HashMap<Long, Integer>();
		Integer condLevel = null;
		boolean predicatedUnknown = false;
		int frozenLoad = VAR;
		if (CffCore.hasLoad(in)) {
			Address g = frozenGlobalRead(in);
			frozenLoad = g == null ? VAR : levelOf(g);
		}
		String slot = CffCore.hasLoad(in) || CffCore.hasStore(in) ? slotKey(in) : null;
		for (int i = 0; ops != null && i < ops.length; i++) {
			PcodeOp op = ops[i];
			int oc = op.getOpcode();
			if (oc == PcodeOp.CBRANCH) {
				int c = level(op.getInput(1), constRegs, uniq);
				if (op.getInput(0).isConstant()) {
					// p-code-relative branch inside the instruction: ARM predication
					if (c == VAR) {
						predicatedUnknown = true;
					}
				}
				else {
					condLevel = Integer.valueOf(predicatedUnknown ? VAR : c);
				}
				continue;
			}
			if (oc == PcodeOp.BRANCH || oc == PcodeOp.BRANCHIND || oc == PcodeOp.CALL || oc == PcodeOp.CALLIND
					|| oc == PcodeOp.RETURN) {
				continue;
			}
			if (oc == PcodeOp.STORE) {
				int v = predicatedUnknown ? VAR : level(op.getInput(2), constRegs, uniq);
				if (slot == null) {
					constSlots.clear();
				}
				else if (v != VAR) {
					constSlots.put(slot, Integer.valueOf(v));
				}
				else {
					constSlots.remove(slot);
				}
				continue;
			}
			Varnode out = op.getOutput();
			if (out == null) {
				continue;
			}
			int c;
			if (oc == PcodeOp.LOAD) {
				Integer sl = slot == null ? null : constSlots.get(slot);
				c = frozenLoad != VAR ? frozenLoad : sl == null ? VAR : sl.intValue();
			}
			else {
				c = IMM;
				for (int k = 0; k < op.getNumInputs(); k++) {
					int l = level(op.getInput(k), constRegs, uniq);
					if (l == VAR) {
						c = VAR;
						break;
					}
					c = Math.max(c, l);
				}
			}
			if (predicatedUnknown) {
				c = VAR;
			}
			if (out.isUnique()) {
				uniq.put(Long.valueOf(out.getOffset()), Integer.valueOf(c));
			}
			else if (out.isRegister()) {
				Register r = currentProgram.getRegister(out.getAddress(), out.getSize());
				if (r == null || !r.isProgramCounter()) {
					for (int b = 0; b < out.getSize(); b++) {
						Long key = Long.valueOf(out.getOffset() + b);
						if (c != VAR) {
							constRegs.put(key, Integer.valueOf(c));
						}
						else {
							constRegs.remove(key);
						}
					}
				}
			}
		}
		return condLevel;
	}

	private int level(Varnode vn, Map<Long, Integer> constRegs, Map<Long, Integer> uniq) {
		if (vn == null) {
			return VAR;
		}
		if (vn.isConstant()) {
			return IMM;
		}
		if (vn.isUnique()) {
			Integer l = uniq.get(Long.valueOf(vn.getOffset()));
			return l == null ? VAR : l.intValue();
		}
		if (vn.isRegister()) {
			// every byte of the read must be constant; the read is DATA if any byte is
			int lvl = IMM;
			for (int b = 0; b < vn.getSize(); b++) {
				Integer l = constRegs.get(Long.valueOf(vn.getOffset() + b));
				if (l == null) {
					return VAR;
				}
				lvl = Math.max(lvl, l.intValue());
			}
			return lvl;
		}
		if (vn.isAddress() && vn.getAddress().isMemoryAddress()) {
			// x86 `MOV ECX,[0x8049e4c]` is a direct memory varnode, not a LOAD op
			return isFrozen(vn.getAddress()) ? levelOf(vn.getAddress()) : VAR;
		}
		return VAR;
	}

	/** Debug: register names whose every byte is currently constant, with the level. */
	private String describeRegs(Map<Long, Integer> constRegs) {
		Map<String, Integer> named = new java.util.TreeMap<String, Integer>();
		for (Map.Entry<Long, Integer> e : constRegs.entrySet()) {
			Register r = currentProgram.getRegister(
					currentProgram.getAddressFactory().getRegisterSpace().getAddress(e.getKey().longValue()));
			String n = r == null ? "reg@" + Long.toHexString(e.getKey().longValue()) : r.getName();
			Integer old = named.get(n);
			named.put(n, Integer.valueOf(old == null ? e.getValue().intValue() : Math.min(old.intValue(), e.getValue().intValue())));
		}
		return named.toString();
	}

	/** Frozen read-only memory (literal pools, .rodata) is IMM; a frozen writable global (OLLVM's x, y) is DATA. */
	private int levelOf(Address a) {
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		return b != null && b.isWrite() ? DATA : IMM;
	}

	private static final Set<String> CRT_NAMES = new HashSet<String>(java.util.Arrays.asList("_init", "_fini", "_start",
		"frame_dummy", "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux", "__do_global_ctors_aux",
		"__libc_csu_init", "__libc_csu_fini", "call_weak_fn", "__libc_start_main", "_dl_relocate_static_pie"));

	/** C runtime start-up files compare link-time constants; an `all` run leaves them alone unless `crt` is given. */
	private boolean isCrtScaffolding(Function f) {
		String n = f.getName();
		if (CRT_NAMES.contains(n)) {
			return true;
		}
		return n.startsWith("__libc_csu") || n.startsWith("_GLOBAL__sub_I_") || n.startsWith("__cxx_global_var_init");
	}

	private int predecessors(CodeBlock cb) throws Exception {
		int n = 0;
		CodeBlockReferenceIterator it = cb.getSources(monitor);
		while (it.hasNext()) {
			it.next();
			n++;
		}
		return n;
	}

	private String describeConst(Set<String> cond) {
		List<String> l = new ArrayList<String>(cond);
		Collections.sort(l);
		return "constants/never-written globals (via " + l + ")";
	}

	/**
	 * The global a load reads, if Ghidra resolved the address and nothing in the
	 * program writes it (no WRITE reference; read-only memory always qualifies).
	 */
	private Address frozenGlobalRead(Instruction in) {
		Reference[] refs = in.getReferencesFrom();
		for (int i = 0; refs != null && i < refs.length; i++) {
			Reference r = refs[i];
			if (!r.isMemoryReference() || r.getReferenceType().isFlow() || r.getReferenceType().isWrite()) {
				continue;
			}
			Address a = r.getToAddress();
			if (a != null && isFrozen(a)) {
				return a;
			}
		}
		return null;
	}

	private boolean isFrozen(Address a) {
		Boolean c = frozenCache.get(a);
		if (c != null) {
			return c.booleanValue();
		}
		boolean frozen = false;
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		if (b != null && !b.isExternalBlock() && !b.isOverlay()) {
			String bn = b.getName().toLowerCase();
			boolean loaderWritten = bn.contains("got") || bn.contains("plt") || bn.startsWith(".tbss") || bn.startsWith(".tdata")
					|| !currentProgram.getRelocationTable().getRelocations(a).isEmpty();
			if (loaderWritten) {
				frozen = false; // filled by the dynamic linker (weak symbols, GOT slots): a runtime value
			}
			else if (!b.isWrite()) {
				frozen = true; // literal pools, .rodata
			}
			else {
				frozen = true;
				ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(a);
				while (it.hasNext()) {
					Reference r = it.next();
					if (r.getReferenceType().isWrite()) {
						frozen = false;
						break;
					}
				}
			}
		}
		frozenCache.put(a, Boolean.valueOf(frozen));
		return frozen;
	}

	private static boolean isFrameRegName(String n) {
		String s = n.toLowerCase();
		return s.equals("sp") || s.equals("x29") || s.equals("fp") || s.equals("r11") || s.equals("rbp") || s.equals("rsp")
				|| s.equals("ebp") || s.equals("esp") || s.equals("r7");
	}

	/** Frame-slot key of a `[base,#imm]` memory operand (base must be a register), else null. */
	private String slotKey(Instruction in) {
		Set<String> keys = CffCore.memOperandKeys(in);
		if (keys.size() != 1) {
			return null;
		}
		String k = keys.iterator().next();
		if (!k.matches("^\\[[a-z][a-z0-9]*(?:[,+]#?-?(0x[0-9a-f]+|[0-9]+))?\\]$")) {
			return null;
		}
		return k;
	}

	// -------------------------------------------------------------- patches --

	private void emitFold(FnPlan p, Fold fo) throws Exception {
		Address at = fo.br.getMinAddress();
		int len = fo.br.getLength();
		byte[] repl;
		if (fo.taken) {
			switch (arch) {
			case ARM64:
				repl = enc(a64B(at, fo.target));
				break;
			case ARM32:
				repl = enc(armB(at, fo.target));
				break;
			default:
				repl = x86Jmp(at, fo.target, len);
				break;
			}
		}
		else {
			repl = nops(len);
		}
		if (repl.length != len) {
			throw new IllegalStateException("replacement length " + repl.length + " != branch length " + len);
		}
		Patch pt = new Patch();
		pt.at = at;
		pt.orig = new byte[len];
		currentProgram.getMemory().getBytes(at, pt.orig);
		pt.repl = repl;
		pt.kind = fo.taken ? "always" : "never";
		pt.desc = fo.taken ? "always taken -> " + fo.target : "never taken; falls through to " + fo.fall;
		pt.fn = p.f.getEntryPoint();
		p.patches.add(pt);
	}

	private int a64B(Address at, Address target) {
		long d = target.subtract(at);
		if ((d & 3) != 0 || d >= (1L << 27) || d < -(1L << 27)) {
			throw new IllegalStateException("B out of range " + at + " -> " + target);
		}
		return 0x14000000 | (int) ((d >> 2) & 0x3ffffff);
	}

	private int armB(Address at, Address target) {
		long d = target.subtract(at) - 8;
		if ((d & 3) != 0 || d >= (1L << 25) || d < -(1L << 25)) {
			throw new IllegalStateException("B out of range " + at + " -> " + target);
		}
		return 0xEA000000 | (int) ((d >> 2) & 0xffffff);
	}

	private byte[] x86Jmp(Address at, Address target, int len) {
		long d8 = target.subtract(at.add(2));
		if (len == 2) {
			if (d8 < -128 || d8 > 127) {
				throw new IllegalStateException("jmp rel8 out of range " + at + " -> " + target);
			}
			return new byte[] { (byte) 0xEB, (byte) d8 };
		}
		long d32 = target.subtract(at.add(5));
		if (d32 < Integer.MIN_VALUE || d32 > Integer.MAX_VALUE || len < 5) {
			throw new IllegalStateException("jmp rel32 does not fit in " + len + " bytes @" + at);
		}
		byte[] out = new byte[len];
		out[0] = (byte) 0xE9;
		out[1] = (byte) d32;
		out[2] = (byte) (d32 >> 8);
		out[3] = (byte) (d32 >> 16);
		out[4] = (byte) (d32 >> 24);
		for (int i = 5; i < len; i++) {
			out[i] = (byte) 0x90;
		}
		return out;
	}

	private byte[] nops(int len) {
		byte[] out = new byte[len];
		switch (arch) {
		case ARM64:
			for (int i = 0; i + 4 <= len; i += 4) {
				System.arraycopy(enc(0xD503201F), 0, out, i, 4);
			}
			break;
		case ARM32:
			for (int i = 0; i + 4 <= len; i += 4) {
				System.arraycopy(enc(0xE1A00000), 0, out, i, 4); // mov r0,r0: a NOP on every ARM
			}
			break;
		default:
			for (int i = 0; i < len; i++) {
				out[i] = (byte) 0x90;
			}
		}
		return out;
	}

	private static byte[] enc(int insn) {
		return new byte[] { (byte) insn, (byte) (insn >> 8), (byte) (insn >> 16), (byte) (insn >> 24) };
	}

	private Arch archOf() {
		String id = currentProgram.getLanguageID().toString().toUpperCase();
		if (id.startsWith("AARCH64")) {
			return Arch.ARM64;
		}
		if (id.startsWith("ARM:")) {
			return Arch.ARM32;
		}
		if (id.startsWith("X86")) {
			return Arch.X86;
		}
		return Arch.OTHER;
	}

	// ---------------------------------------------------------------- apply --

	private int apply(FnPlan p) {
		int ok = 0;
		for (Patch pt : p.patches) {
			try {
				clearListing(pt.at, pt.at.add(pt.repl.length - 1));
				currentProgram.getMemory().setBytes(pt.at, pt.repl);
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
				disassemble(pt.at); // before the patch list is dropped: reflow() would not see these sites any more
			}
			catch (Exception e) {
				printerr("  revert failed @" + pt.at + ": " + e.getMessage());
			}
		}
		p.applied = false;
		p.patches.clear();
	}

	private void reflow(FnPlan p) {
		try {
			for (Patch pt : p.patches) {
				disassemble(pt.at);
			}
			Function f = getFunctionAt(p.f.getEntryPoint());
			if (f != null) {
				CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
			}
		}
		catch (Exception e) {
			printerr("  reflow " + p.f.getName() + ": " + e.getMessage());
		}
	}

	// --------------------------------------------------------------- verify --

	private List<List<CffCore.TraceEvent>> trace(FnPlan p) {
		List<List<CffCore.TraceEvent>> out = new ArrayList<List<CffCore.TraceEvent>>();
		Function f = getFunctionAt(p.f.getEntryPoint());
		for (CffCore.TraceSeed seed : CffCore.VERIFY_SEEDS) {
			out.add(CffCore.traceRun(currentProgram, f, f.getEntryPoint(), p.heads, TRACE_MAX_HEADS, TRACE_MAX_STEPS, monitor, seed));
		}
		return out;
	}

	private static int visits(List<List<CffCore.TraceEvent>> t) {
		int n = 0;
		for (List<CffCore.TraceEvent> l : t) {
			n += l.size();
		}
		return n;
	}

	private Set<String> ignoredAt(FnPlan p, Address head) {
		Set<String> s = p.ignoreAt.get(head);
		if (s == null) {
			s = new HashSet<String>(CffCore.killedOnEntry(currentProgram, head));
			p.ignoreAt.put(head, s);
		}
		return s;
	}

	private String compare(FnPlan p, List<List<CffCore.TraceEvent>> before, List<List<CffCore.TraceEvent>> after) {
		boolean any = false;
		List<Register> regs = CffCore.traceRegisters(currentProgram);
		for (int s = 0; s < before.size() && s < after.size(); s++) {
			List<CffCore.TraceEvent> a = before.get(s);
			List<CffCore.TraceEvent> b = after.get(s);
			if (a.isEmpty()) {
				continue;
			}
			any = true;
			String seed = "[seed " + CffCore.VERIFY_SEEDS[s].name + "] ";
			int n = Math.min(a.size(), b.size());
			for (int i = 0; i < n; i++) {
				CffCore.TraceEvent x = a.get(i);
				CffCore.TraceEvent y = b.get(i);
				if (!x.head.equals(y.head)) {
					return seed + "block #" + i + ": original " + x.head + " vs patched " + y.head;
				}
				Set<String> ignore = ignoredAt(p, x.head);
				for (int k = 0; k < regs.size(); k++) {
					String reg = regs.get(k).getName();
					if (!ignore.contains(reg) && x.regs[k] != y.regs[k]) {
						return seed + "block #" + i + " @" + x.head + ": register " + reg + " original=0x"
								+ Long.toHexString(x.regs[k]) + " patched=0x" + Long.toHexString(y.regs[k]);
					}
				}
			}
			if (b.size() != a.size()) {
				return seed + "patched trace has " + b.size() + " block visits, original " + a.size();
			}
		}
		return any ? null : "original trace reached no block under any seed";
	}

	// ------------------------------------------------------------ log / undo --

	private File defaultDir() {
		String path = currentProgram.getExecutablePath();
		File f = path == null ? null : new File(path).getParentFile();
		return f != null && f.isDirectory() ? f : new File(System.getProperty("user.home"));
	}

	private void writeLog(String path, int applied) throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("{\n  \"program\": \"").append(esc(currentProgram.getName())).append("\",\n  \"tool\": \"BcfClean\",\n  \"applied\": ")
				.append(applied).append(",\n  \"functions\": [\n");
		int k = 0;
		for (FnPlan p : plans) {
			if (!p.applied) {
				continue;
			}
			sb.append(k++ > 0 ? ",\n" : "").append("    {\"entry\": \"").append(p.f.getEntryPoint()).append("\", \"name\": \"")
					.append(esc(p.f.getName())).append("\", \"patches\": ").append(p.patches.size()).append(", \"verify\": \"")
					.append(esc(p.verifyResult == null ? "skipped" : p.verifyResult)).append("\"}");
		}
		sb.append("\n  ],\n  \"blocks\": [],\n  \"patches\": [\n");
		List<Patch> all = new ArrayList<Patch>();
		for (FnPlan p : plans) {
			if (p.applied) {
				all.addAll(p.patches);
			}
		}
		for (int i = 0; i < all.size(); i++) {
			Patch pt = all.get(i);
			sb.append("    {\"at\": \"").append(pt.at).append("\", \"fn\": \"").append(pt.fn).append("\", \"kind\": \"").append(pt.kind)
					.append("\", \"orig\": \"").append(hex(pt.orig)).append("\", \"repl\": \"").append(hex(pt.repl)).append("\", \"desc\": \"")
					.append(esc(pt.desc)).append("\"}").append(i + 1 < all.size() ? ",\n" : "\n");
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
		Set<Address> fns = new LinkedHashSet<Address>();
		List<Address> restored = new ArrayList<Address>();
		for (int i = arr.size() - 1; i >= 0; i--) {
			JsonObject o = arr.get(i).getAsJsonObject();
			Address at = parseAddr(o.get("at").getAsString());
			byte[] orig = unhex(o.get("orig").getAsString());
			if (at == null || orig == null) {
				continue;
			}
			try {
				clearListing(at, at.add(orig.length - 1));
				currentProgram.getMemory().setBytes(at, orig);
				restored.add(at);
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
		for (Address at : restored) {
			disassemble(at);
		}
		for (Address fn : fns) {
			Function fun = getFunctionAt(fn);
			if (fun != null) {
				CreateFunctionCmd.fixupFunctionBody(currentProgram, fun, monitor);
			}
		}
		println("undo: restored " + restored.size() + " patches from " + path + " (" + fns.size() + " function(s) re-disassembled)");
	}

	private Address parseAddr(String s) {
		try {
			String t = s.trim();
			if (t.toLowerCase().startsWith("0x")) {
				t = t.substring(2);
			}
			return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(t, 16));
		}
		catch (Exception e) {
			try {
				return currentProgram.getAddressFactory().getAddress(s.trim());
			}
			catch (Exception e2) {
				return null;
			}
		}
	}

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < b.length; i++) {
			sb.append(String.format("%02x", b[i] & 0xff));
		}
		return sb.toString();
	}

	private static byte[] unhex(String s) {
		if (s == null || (s.length() & 1) != 0) {
			return null;
		}
		byte[] out = new byte[s.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return out;
	}

	private static String esc(String s) {
		return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ");
	}
}
