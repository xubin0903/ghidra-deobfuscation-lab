// CffCore — shared engine for the CFF (control-flow-flattening) script suite.
//
// NOT a runnable GhidraScript. It is a plain helper class compiled into the
// same script bundle and used by CffScan / CffRecover / CffDeflatten.
//
// It provides, architecture-independently (works on whatever Ghidra can
// disassemble + emulate: AArch64, ARM, x86, x86-64, ...):
//   * intra-function CFG construction from Ghidra basic blocks
//   * dominator tree (Cooper-Harvey-Kennedy) with O(1) dominance queries and
//     the mrphrazer "flattening score" (low false positive), no size cap
//   * structural identification of the OLLVM/Hikari/Arkari CFF scaffold
//       prologue -> pre-dispatcher (max fan-in) -> dispatcher (compare tree)
//       -> relevant/real blocks -> return blocks
//   * concrete p-code emulation of each real block to recover the *true*
//     successor(s). Every fork point met before the block hands control to the
//     dispatcher (csel/cmov/cset family, and real conditional branches) is
//     forced both ways *individually*; the fork whose outcome changes the
//     landing head is the one that decides the edge. This defeats the XOR
//     encoded state of Arkari/goron (switchVar ^ switchXorVar), 64-bit state
//     variants, register-resident state (-O2 builds) and cset->csel chains
//     without pattern matching any of them: the emulator just computes.
//   * a side-effect analysis of the dispatcher path actually executed between
//     a case tail and its successor (PathEffects). Optimised (-O2) flattened
//     code carries real PHI copies (mov x19,x10 ...) inside the compare tree;
//     those must be replicated by any patch that bypasses the dispatcher.
//   * traceRun(): a concrete whole-function trace used by CffDeflatten to
//     prove that the patched function visits the same real blocks with the
//     same live registers as the original one.
//
// Why emulation and not static dataflow: modern Hikari-lineage (Arkari) CFF
// stores the next state as   nextEnc = nextCase ^ newXor   into *two* volatile
// stack slots, and the dispatcher compares   switchVar ^ switchXorVar   after a
// rolling delta. Static "find the constant" passes miss this; a concrete
// emulator that just runs the block reads the real next state for free.
//
// Emulator note: EmulatorHelper is @Deprecated(forRemoval) since 12.1 in favour
// of ghidra.pcode.emu.PcodeEmulator (EmulatorHelper is itself an adapter over
// it). All emulator access is confined to runPath()/traceRun()/Snapshot so the
// swap is a local change.

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.util.task.TaskMonitor;

@SuppressWarnings("removal") // EmulatorHelper / MemoryFaultHandler are deprecated-for-removal in 12.x but fully functional in 12.1.3
public final class CffCore {

	private CffCore() {
	}

	// ---------------------------------------------------------------- CFG ----

	/** Intra-function control-flow graph built from Ghidra basic blocks. */
	public static final class Cfg {
		public final Function func;
		public final List<Address> nodes = new ArrayList<Address>();
		public final Map<Address, Integer> id = new HashMap<Address, Integer>();
		public List<List<Integer>> succ;
		public List<List<Integer>> pred;
		public int entry;
		public int[] idom;     // Cooper-Harvey-Kennedy immediate dominators (-1 = unreachable)
		public int[] post;     // DFS postorder number from entry (-1 = unreachable)
		public int[] domSize;  // size of the dominator-tree subtree rooted at each node
		public int reachable;  // nodes reachable from entry
		int[] domIn;           // dominator-tree DFS interval (O(1) dominance)
		int[] domOut;

		Cfg(Function f) {
			this.func = f;
		}

		public int size() {
			return nodes.size();
		}

		public Address addr(int i) {
			return nodes.get(i);
		}

		public boolean isReachable(int i) {
			return i >= 0 && i < post.length && post[i] >= 0;
		}
	}

	public static Cfg buildCfg(Program program, Function f, TaskMonitor monitor) throws Exception {
		Cfg g = new Cfg(f);
		AddressSetView body = f.getBody();
		BasicBlockModel bbm = new BasicBlockModel(program);
		CodeBlockIterator it = bbm.getCodeBlocksContaining(body, monitor);
		while (it.hasNext()) {
			CodeBlock b = it.next();
			Address s = b.getFirstStartAddress();
			if (s != null && body.contains(s) && !g.id.containsKey(s)) {
				g.id.put(s, Integer.valueOf(g.nodes.size()));
				g.nodes.add(s);
			}
		}
		int n = g.nodes.size();
		g.succ = new ArrayList<List<Integer>>(n);
		g.pred = new ArrayList<List<Integer>>(n);
		for (int i = 0; i < n; i++) {
			g.succ.add(new ArrayList<Integer>());
			g.pred.add(new ArrayList<Integer>());
		}
		for (int i = 0; i < n && !monitor.isCancelled(); i++) {
			Address a = g.nodes.get(i);
			CodeBlock cb = bbm.getCodeBlockAt(a, monitor);
			if (cb == null) {
				continue;
			}
			CodeBlockReferenceIterator di = cb.getDestinations(monitor);
			while (di.hasNext()) {
				CodeBlockReference ref = di.next();
				FlowType ft = ref.getFlowType();
				if (ft != null && ft.isCall()) {
					continue; // stay intra-procedural: ignore call edges
				}
				CodeBlock db = ref.getDestinationBlock();
				if (db == null) {
					continue;
				}
				Address ds = db.getFirstStartAddress();
				Integer j = ds == null ? null : g.id.get(ds);
				if (j == null) {
					continue; // leaves the function
				}
				int jj = j.intValue();
				if (!g.succ.get(i).contains(Integer.valueOf(jj))) {
					g.succ.get(i).add(Integer.valueOf(jj));
					g.pred.get(jj).add(Integer.valueOf(i));
				}
			}
		}
		Integer e = g.id.get(f.getEntryPoint());
		g.entry = e == null ? 0 : e.intValue();
		computeDominators(g);
		return g;
	}

	// ------------------------------------------------------- dominators ------

	private static void computeDominators(Cfg g) {
		int n = g.size();
		g.idom = new int[n];
		g.post = new int[n];
		g.domIn = new int[n];
		g.domOut = new int[n];
		g.domSize = new int[n];
		Arrays.fill(g.idom, -1);
		Arrays.fill(g.post, -1);
		if (n == 0) {
			return;
		}
		// postorder via iterative DFS from entry
		int[] order = new int[n];
		boolean[] seen = new boolean[n];
		int[] stack = new int[n + 1];
		int[] nextChild = new int[n];
		int sp = 0;
		stack[sp] = g.entry;
		seen[g.entry] = true;
		int pc = 0;
		while (sp >= 0) {
			int u = stack[sp];
			List<Integer> ss = g.succ.get(u);
			if (nextChild[u] < ss.size()) {
				int v = ss.get(nextChild[u]++).intValue();
				if (!seen[v]) {
					seen[v] = true;
					stack[++sp] = v;
				}
			}
			else {
				g.post[u] = pc;
				order[pc] = u;
				pc++;
				sp--;
			}
		}
		g.reachable = pc;
		// Cooper-Harvey-Kennedy fixpoint in reverse postorder; only processed
		// (idom != -1) predecessors take part in the intersection.
		g.idom[g.entry] = g.entry;
		boolean changed = true;
		while (changed) {
			changed = false;
			for (int idx = pc - 1; idx >= 0; idx--) {
				int b = order[idx];
				if (b == g.entry) {
					continue;
				}
				int newIdom = -1;
				List<Integer> ps = g.pred.get(b);
				for (int k = 0; k < ps.size(); k++) {
					int p = ps.get(k).intValue();
					if (g.post[p] < 0 || g.idom[p] == -1) {
						continue;
					}
					newIdom = (newIdom == -1) ? p : intersect(g, p, newIdom);
				}
				if (newIdom != -1 && g.idom[b] != newIdom) {
					g.idom[b] = newIdom;
					changed = true;
				}
			}
		}
		// dominator tree: children lists, DFS intervals, subtree sizes
		List<List<Integer>> kids = new ArrayList<List<Integer>>(n);
		for (int i = 0; i < n; i++) {
			kids.add(new ArrayList<Integer>());
		}
		for (int i = 0; i < n; i++) {
			if (i != g.entry && g.idom[i] != -1) {
				kids.get(g.idom[i]).add(Integer.valueOf(i));
			}
		}
		int[] kidIdx = new int[n];
		int counter = 0;
		sp = 0;
		stack[0] = g.entry;
		g.domIn[g.entry] = counter++;
		while (sp >= 0) {
			int u = stack[sp];
			List<Integer> ks = kids.get(u);
			if (kidIdx[u] < ks.size()) {
				int v = ks.get(kidIdx[u]++).intValue();
				g.domIn[v] = counter++;
				stack[++sp] = v;
			}
			else {
				g.domOut[u] = counter;
				sp--;
			}
		}
		for (int idx = 0; idx < pc; idx++) {
			g.domSize[order[idx]] += 1;
		}
		// children finish before their dominator in postorder, so a single
		// increasing-postorder sweep accumulates subtree sizes.
		for (int idx = 0; idx < pc; idx++) {
			int u = order[idx];
			if (u != g.entry) {
				g.domSize[g.idom[u]] += g.domSize[u];
			}
		}
	}

	private static int intersect(Cfg g, int a, int b) {
		while (a != b) {
			while (g.post[a] < g.post[b]) {
				a = g.idom[a];
			}
			while (g.post[b] < g.post[a]) {
				b = g.idom[b];
			}
		}
		return a;
	}

	/** O(1): does block a dominate block b? */
	public static boolean dominates(Cfg g, int a, int b) {
		if (a == b) {
			return true;
		}
		if (!g.isReachable(a) || !g.isReachable(b)) {
			return false;
		}
		return g.domIn[a] <= g.domIn[b] && g.domOut[b] <= g.domOut[a];
	}

	// ---------------------------------------------------- flattening score ---

	/**
	 * mrphrazer's flattening heuristic: the max over blocks B that sit on a back
	 * edge of |dominated(B)| / |reachable|. A flattened function has one
	 * dispatcher region dominating almost the whole body -> score near 1.0.
	 * Normal code with small loops -> low score. Very low false-positive rate.
	 * O(V + E) thanks to dominator subtree sizes; no function-size cap.
	 */
	public static double flatteningScore(Cfg g) {
		return flatteningScore(g, null);
	}

	/**
	 * @param hubOut if non-null, hubOut[0] receives the block index that
	 *               achieves the score (the dispatcher / loop head).
	 */
	public static double flatteningScore(Cfg g, int[] hubOut) {
		int n = g.size();
		if (hubOut != null) {
			hubOut[0] = -1;
		}
		if (n == 0 || g.reachable <= 1) {
			return 0.0;
		}
		double best = 0.0;
		int bestNode = -1;
		for (int b = 0; b < n; b++) {
			if (!g.isReachable(b)) {
				continue;
			}
			boolean backEdge = false;
			List<Integer> ps = g.pred.get(b);
			for (int k = 0; k < ps.size(); k++) {
				if (dominates(g, b, ps.get(k).intValue())) {
					backEdge = true;
					break;
				}
			}
			if (!backEdge) {
				continue;
			}
			double s = (double) g.domSize[b] / (double) g.reachable;
			if (s > best) {
				best = s;
				bestNode = b;
			}
		}
		if (hubOut != null) {
			hubOut[0] = bestNode;
		}
		return best;
	}

	// ------------------------------------------------- structural detect -----

	public static final class Detect {
		public Function func;
		public int nodeCount;
		public double score;
		public Address predispatcher;
		public Address dispatcher;
		public int fanIn;          // predecessors of the hub (convergence block)
		public int preOutDeg;      // successors of the hub
		public int dispatcherFanOut;
		public double cleanRatio;  // fraction of relevant blocks whose sole successor is the hub
		public double hubDomFrac;  // fraction of reachable nodes the hub dominates (loop head => ~1.0)
		public int relevantCount;
		public int returnCount;
		public String stateHint = "?";
		public boolean isCff;
		public String tier = "no"; // no | suspect | cff
		public List<Address> relevantHeads = new ArrayList<Address>();
		public Set<Address> returnBlocks = new HashSet<Address>();
		public Address entry;
		public Cfg cfg;
	}

	/** Detection thresholds; conservative to avoid flagging real loops. */
	public static double SCORE_CFF = 0.90;
	public static double SCORE_SUSPECT = 0.60;
	public static int MIN_NODES = 6;
	public static int MIN_FANIN = 3; // small flattened leaf functions really do have 3-4 cases; hubDom+cleanRatio carry precision
	public static double CLEAN_RATIO = 0.60;
	public static double HUB_DOM = 0.85;

	public static Detect detect(Program program, Function f, TaskMonitor monitor) throws Exception {
		Detect d = new Detect();
		d.func = f;
		d.entry = f.getEntryPoint();
		Cfg g = buildCfg(program, f, monitor);
		d.cfg = g;
		d.nodeCount = g.size();
		if (g.size() == 0) {
			return d;
		}
		// dispatcher / loop head = the block that achieves the flattening score
		// (dominates the largest fraction of the body AND sits on a back edge).
		// This is more robust than "max fan-in" alone, which can land on a
		// shared epilogue when every case returns through one block.
		int[] hub = new int[] { -1 };
		d.score = flatteningScore(g, hub);
		int di = hub[0];
		if (di < 0) {
			// fall back to max fan-in if scoring found no back edge
			int bf = -1;
			for (int i = 0; i < g.size(); i++) {
				if (g.pred.get(i).size() > bf) {
					bf = g.pred.get(i).size();
					di = i;
				}
			}
		}
		if (di >= 0) {
			// pre-dispatcher = the convergence block: whichever of {dispatcher}
			// U preds(dispatcher) has the most predecessors. Merged builds =>
			// pre-dispatcher == dispatcher; split builds => the loopEnd block.
			int pdi = di;
			int bestFan = g.pred.get(di).size();
			List<Integer> dps = g.pred.get(di);
			for (int k = 0; k < dps.size(); k++) {
				int c = dps.get(k).intValue();
				if (g.pred.get(c).size() > bestFan) {
					bestFan = g.pred.get(c).size();
					pdi = c;
				}
			}

			d.dispatcher = g.addr(di);
			d.dispatcherFanOut = g.succ.get(di).size();
			d.predispatcher = g.addr(pdi);
			d.fanIn = g.pred.get(pdi).size();
			d.preOutDeg = g.succ.get(pdi).size();
			d.hubDomFrac = g.reachable == 0 ? 0.0 : (double) g.domSize[di] / (double) g.reachable;

			// relevant blocks = predecessors of the pre-dispatcher; count the
			// ones whose ONLY successor is the pre-dispatcher (OLLVM emits an
			// unconditional back edge at the tail of every real block => high
			// clean-convergence ratio; natural loops converge with far fewer /
			// conditional back edges).
			List<Integer> ps = g.pred.get(pdi);
			int clean = 0;
			for (int k = 0; k < ps.size(); k++) {
				int p = ps.get(k).intValue();
				d.relevantHeads.add(g.addr(p));
				List<Integer> sp2 = g.succ.get(p);
				if (sp2.size() == 1 && sp2.get(0).intValue() == pdi) {
					clean++;
				}
			}
			d.relevantCount = ps.size();
			d.cleanRatio = ps.isEmpty() ? 0.0 : (double) clean / (double) ps.size();
		}
		// return blocks = intra-function sinks (end in ret / no successor)
		for (int i = 0; i < g.size(); i++) {
			if (g.succ.get(i).isEmpty()) {
				d.returnBlocks.add(g.addr(i));
				d.returnCount++;
			}
		}
		d.stateHint = guessStateVar(program, d.dispatcher);

		// A real OLLVM/Hikari/Arkari flattening loop:
		//   * high flattening score (one region dominates the body)
		//   * the hub dominates almost the whole function (it IS the loop head)
		//   * the dispatcher branches (compare tree => fan-out >= 2)
		//   * many real blocks (fan-in) converge cleanly onto the hub
		// The fan-in floor is what separates a state machine (O(#blocks) back
		// edges) from a natural loop (O(1) back edges), keeping false positives
		// on hand-written loops (libgcc unwinder, refcount loops, ...) out.
		boolean shape = d.predispatcher != null && d.dispatcher != null && d.dispatcherFanOut >= 2
				&& d.hubDomFrac >= HUB_DOM;
		boolean sized = d.nodeCount >= MIN_NODES && d.fanIn >= MIN_FANIN;
		// A moderate clean-convergence ratio is normal for modified/64-bit
		// variants (Ghidra splits the two state stores differently), so a very
		// strong score + hub-domination + fan-in may stand in for it.
		boolean strong = d.score >= 0.97 && d.hubDomFrac >= 0.95 && d.fanIn >= 8;
		if (d.score >= SCORE_CFF && shape && sized && (d.cleanRatio >= CLEAN_RATIO || strong)) {
			d.isCff = true;
			d.tier = "cff";
		}
		else if (d.score >= SCORE_SUSPECT && d.fanIn >= MIN_FANIN && d.dispatcherFanOut >= 2) {
			d.tier = "suspect";
		}
		return d;
	}

	/** Best-effort: name the register/slot the dispatcher compares. */
	private static String guessStateVar(Program program, Address dispatcher) {
		if (dispatcher == null) {
			return "?";
		}
		Listing listing = program.getListing();
		Instruction in = listing.getInstructionAt(dispatcher);
		int steps = 0;
		String loaded = null;
		while (in != null && steps < 16) {
			String m = in.getMnemonicString().toLowerCase();
			if (m.startsWith("ldr") || m.equals("mov") || m.equals("ldur")) {
				Register r0 = in.getRegister(0);
				if (r0 != null && loaded == null) {
					loaded = r0.getName();
				}
			}
			if (m.equals("cmp") || m.equals("subs") || m.equals("cmn") || m.equals("tst")
					|| m.equals("test") || m.startsWith("sub")) {
				Register r0 = in.getRegister(0);
				if (r0 != null) {
					return r0.getName();
				}
			}
			FlowType ft = in.getFlowType();
			if (ft != null && (ft.isJump() || ft.isTerminal())) {
				break;
			}
			in = in.getNext();
			steps++;
		}
		return loaded == null ? "?" : loaded;
	}

	// ------------------------------------------------ case-head discovery ----

	/**
	 * What the compare tree is known to work with: the state register (from the
	 * dispatcher's own compare), the frame slots the dispatcher loads / spills
	 * it through, and the scratch registers tree nodes materialise case
	 * constants into. Grows as tree nodes are accepted (-O0 x86 spills the state
	 * copy into a fresh slot in every node; -O2 AArch64 builds every 64-bit case
	 * constant with mov/movk into one or two scratch registers).
	 */
	private static final class TreeCtx {
		String stateBase;                                     // register the dispatcher COMPARES (base name), or null when unknown
		/**
		 * Register the cases WRITE their next state into: the source of the
		 * dispatcher's first copy into the compare register (`mov x8,x9` -> x9),
		 * or the compare register itself when the dispatcher does not copy it.
		 * Null when the state lives in memory (-O0 spills).
		 */
		String stateIncoming;
		final Set<String> stateSlots = new HashSet<String>();
		final Set<String> constRegs = new HashSet<String>();  // registers tree nodes load immediates into
	}

	/** Cap on instructions in one compare-tree node when the state register is known. */
	public static int TREE_NODE_MAX_INSNS = 128;

	private static boolean isCompareLike(String m) {
		// LowerSwitch emits cmp on ARM and `sub reg, imm` on x86 (-O0 keeps the
		// sub; the flags feed the je/jl/jg that follows)
		return m.startsWith("cmp") || m.startsWith("sub") || m.equals("cmn") || m.startsWith("ccmp")
				|| m.startsWith("test") || m.startsWith("tst");
	}

	/**
	 * Is this block part of the lowered switch (compare tree)? Such blocks only
	 * load/compare/branch (plus register shuffles and rematerialised constants
	 * in optimised builds): no memory STORE other than frame spills, no CALL,
	 * ends in a conditional jump, and contains a compare.
	 * <p>
	 * When the state register is known the compare must read a value derived
	 * from it — the state register itself, a copy made earlier in the tree
	 * ({@code entryDerived} carries the set down from the parent node), or a
	 * reload from a known state slot — so a real block that happens to end in
	 * {@code cmp w11,#0x64 ; b.gt} is not a tree node. -O2 64-bit trees
	 * materialise every case constant with mov/movk (14–70 instructions per
	 * node), so the size cap is generous in that mode.
	 *
	 * @return the derived-register set at the block's exit, or null if the block
	 *         is not a tree node
	 */
	private static Set<String> treeNodeExit(Program program, BasicBlockModel bbm, Address start, TaskMonitor monitor,
			TreeCtx ctx, Set<String> entryDerived) throws Exception {
		CodeBlock cb = bbm.getCodeBlockAt(start, monitor);
		if (cb == null) {
			return null;
		}
		Listing listing = program.getListing();
		boolean stateKnown = ctx.stateBase != null;
		int cap = stateKnown ? TREE_NODE_MAX_INSNS : 12;
		int count = 0;
		boolean hasCmp = false;
		boolean hasStateCmp = false;
		Instruction last = null;
		Set<String> derived = new HashSet<String>(entryDerived);
		Set<String> slotStores = new LinkedHashSet<String>();
		Set<String> constWrites = new HashSet<String>();
		for (Instruction in : listing.getInstructions(cb, true)) {
			count++;
			if (count > cap) {
				return null;
			}
			String m = in.getMnemonicString().toLowerCase();
			PcodeOp[] ops = in.getPcode();
			boolean load = false;
			boolean store = false;
			for (int i = 0; ops != null && i < ops.length; i++) {
				int oc = ops[i].getOpcode();
				if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND || oc == PcodeOp.RETURN) {
					return null;
				}
				if (oc == PcodeOp.STORE) {
					if (!isStackStore(in)) {
						return null; // a real block writes memory; the tree only spills the state copy
					}
					store = true;
				}
				if (oc == PcodeOp.LOAD) {
					load = true;
				}
			}
			Set<String> ins = regNames(in.getInputObjects());
			Set<String> outs = regNames(in.getResultObjects());
			if (isCompareLike(m) && writesFlags(in)) {
				hasCmp = true;
				boolean fromState = !Collections.disjoint(ins, derived);
				if (!fromState && load) {
					fromState = !Collections.disjoint(memOperandKeys(in), ctx.stateSlots);
				}
				if (fromState) {
					hasStateCmp = true;
				}
			}
			if (stateKnown) {
				boolean srcDerived = !Collections.disjoint(ins, derived);
				if (load && !Collections.disjoint(memOperandKeys(in), ctx.stateSlots)) {
					srcDerived = true; // reload of the spilled state
				}
				if (!outs.isEmpty()) {
					if (srcDerived) {
						derived.addAll(outs);
					}
					else {
						derived.removeAll(outs); // overwritten with an unrelated value
						if (ins.isEmpty() && !load) {
							constWrites.addAll(outs); // immediate materialisation (mov/movk #imm)
						}
					}
				}
				if (store && srcDerived) {
					slotStores.addAll(memOperandKeys(in)); // a spill OF THE STATE; spills of real PHI values are not state slots
				}
			}
			last = in;
		}
		if (last == null || !hasCmp || (stateKnown && !hasStateCmp)) {
			return null;
		}
		FlowType ft = last.getFlowType();
		if (ft == null || !ft.isJump() || !ft.isConditional()) {
			return null;
		}
		if (stateKnown) {
			ctx.stateSlots.addAll(slotStores); // the node's spills are state copies too
			ctx.constRegs.addAll(constWrites);
		}
		return derived;
	}

	/** -O0 x86 spills the state copy to the frame inside the tree: allow that. */
	public static boolean isStackStore(Instruction in) {
		String s = in.toString().toLowerCase().replace(" ", "");
		return s.contains("[rbp") || s.contains("[rsp") || s.contains("[ebp") || s.contains("[esp") || s.contains("[sp")
				|| s.contains("[x29") || s.contains("[fp");
	}

	/**
	 * A "stub" block: zero or more register-only instructions (constant
	 * materialisation `mov/movk`, register moves — no memory, no calls, no
	 * flags) followed by one unconditional direct jump inside the function, or
	 * by a plain fall-through into the next block (tail merging splits the
	 * constant off the compare it feeds). Returns the target, or null if the
	 * block is anything else. {@code writesOut[0]} reports whether the block
	 * writes any register: a bare `b loopEnd` is OLLVM's dead switchDefault,
	 * `mov w8,#K ; b loopEnd` is an empty real block (state = K), `mov w8,#K ;
	 * b treeNode` is a compare-tree node split by tail merging (-O2).
	 * <p>
	 * When the state register is known a stub may only write the state
	 * register or the tree's own constant scratch registers: a register-only
	 * block that sets up anything else ({@code mov w8,#0x240 ; mov w9,#1 ;
	 * mov x10,x19 ; b loop}) is a real block and must stay a case head.
	 * {@code derived} is updated in place (register moves propagate, immediate
	 * loads kill).
	 */
	private static Address stubTarget(Program program, BasicBlockModel bbm, Address start, AddressSetView body,
			TaskMonitor monitor, boolean[] writesOut, TreeCtx ctx, Set<String> derived) throws Exception {
		CodeBlock cb = bbm.getCodeBlockAt(start, monitor);
		if (cb == null) {
			return null;
		}
		Listing listing = program.getListing();
		Instruction last = null;
		int n = 0;
		boolean writes = false;
		Set<String> localDerived = new HashSet<String>(derived);
		for (Instruction in : listing.getInstructions(cb, true)) {
			n++;
			if (n > 8) {
				return null;
			}
			last = in;
			FlowType ft = in.getFlowType();
			if (ft != null && (ft.isJump() || ft.isCall() || ft.isTerminal())) {
				continue; // must be the last one; checked below
			}
			PcodeOp[] ops = in.getPcode();
			for (int i = 0; ops != null && i < ops.length; i++) {
				int oc = ops[i].getOpcode();
				if (oc == PcodeOp.LOAD || oc == PcodeOp.STORE || oc == PcodeOp.CALL || oc == PcodeOp.CALLIND
						|| oc == PcodeOp.CALLOTHER) {
					return null;
				}
			}
			if (writesFlags(in)) {
				return null;
			}
			Set<String> ins = regNames(in.getInputObjects());
			Set<String> outs = regNames(in.getResultObjects());
			if (!outs.isEmpty()) {
				writes = true;
				if (ctx.stateBase != null) {
					// only the next-state register and the tree's own constant scratch
					// registers may be written by a stub; the compare register is NOT
					// on that list when the dispatcher merely copies into it
					// (`mov x8,x9`): real code is free to use it as a scratch
					for (String o : outs) {
						boolean ok = ctx.constRegs.contains(o) || (ctx.stateIncoming != null && o.equals(ctx.stateIncoming))
								|| (ctx.stateIncoming == null && o.equals(ctx.stateBase));
						if (!ok) {
							return null;
						}
					}
					if (!Collections.disjoint(ins, localDerived)) {
						localDerived.addAll(outs);
					}
					else {
						localDerived.removeAll(outs);
					}
				}
			}
		}
		if (last == null) {
			return null;
		}
		Address target;
		FlowType ft = last.getFlowType();
		if (ft != null && ft.isJump()) {
			if (ft.isConditional() || ft.isComputed()) {
				return null;
			}
			Address[] flows = last.getFlows();
			if (flows == null || flows.length != 1) {
				return null;
			}
			target = flows[0];
		}
		else if (ft != null && ft.isFallthrough() && !ft.isCall() && !ft.isTerminal()) {
			target = last.getFallThrough(); // split constant that falls into its compare
		}
		else {
			return null;
		}
		if (target == null || !body.contains(target)) {
			return null;
		}
		if (writesOut != null) {
			writesOut[0] = writes;
		}
		derived.clear();
		derived.addAll(localDerived);
		return target;
	}

	public static final class Heads {
		public Set<Address> tree = new HashSet<Address>();      // dispatcher compare-tree blocks
		public Set<Address> tramps = new HashSet<Address>();    // one-jump stubs between tree nodes / onto heads
		public List<Address> caseHeads = new ArrayList<Address>(); // real case entry blocks (deduped, trampolines folded)
		public Set<Address> defaults = new HashSet<Address>();  // swDefault-like dead heads
		public String stateBase;                                // base register the compare tree reads, or null
		public String stateIncoming;                            // base register the cases write the next state into, or null (memory)
		/** Frame slots that hold the state or a spill of it (memory operand keys, see {@link #memOperandKeys}). */
		public Set<String> stateSlots = new HashSet<String>();
	}

	/**
	 * Walk the compare tree from the dispatcher. A successor is a tree node if it
	 * is dominated by the dispatcher, is not a case tail (predecessor of the
	 * pre-dispatcher) and looks like compare+branch on the state; jump / split
	 * constant stubs are followed (x86 -O0 chains tree nodes with `jmp`, -O2
	 * splits `mov w8,#K` off its `cmp`). Everything else the tree branches to
	 * is a case head. `jmp loopEnd` stubs are the switch default (dead) and are
	 * dropped. The set of registers holding the state is propagated node to
	 * node so a tree that copies the state (`mov w9,w8`) and compares the copy
	 * is still recognised.
	 */
	public static Heads discoverHeads(Program program, Detect d, TaskMonitor monitor) throws Exception {
		Heads h = new Heads();
		if (d.dispatcher == null) {
			return h;
		}
		Cfg g = d.cfg != null ? d.cfg : buildCfg(program, d.func, monitor);
		Integer diObj = g.id.get(d.dispatcher);
		int di = diObj == null ? -1 : diObj.intValue();
		AddressSetView body = d.func.getBody();
		BasicBlockModel bbm = new BasicBlockModel(program);
		TreeCtx ctx = treeContext(program, bbm, d, monitor);
		Map<Address, Set<String>> exitDerived = new HashMap<Address, Set<String>>();
		Set<Address> visited = new HashSet<Address>();
		List<Address> work = new ArrayList<Address>();
		work.add(d.dispatcher);
		h.tree.add(d.dispatcher);
		Set<String> seed = new HashSet<String>();
		if (ctx.stateBase != null) {
			seed.add(ctx.stateBase);
		}
		// the dispatcher block itself is a tree node by definition; still run it
		// through the filter to learn the copies / scratch registers it creates
		Set<String> dispExit = treeNodeExit(program, bbm, d.dispatcher, monitor, ctx, seed);
		exitDerived.put(d.dispatcher, dispExit != null ? dispExit : seed);
		if (d.predispatcher != null && !d.predispatcher.equals(d.dispatcher)) {
			exitDerived.put(d.predispatcher, seed);
		}
		Set<Address> rawHeads = new HashSet<Address>();
		// where a chain of jump stubs finally lands, per stub (so a later chain
		// that runs into an already folded stub knows the end without re-walking it)
		Map<Address, Address> stubDest = new HashMap<Address, Address>();
		while (!work.isEmpty() && !monitor.isCancelled()) {
			Address b = work.remove(work.size() - 1);
			if (!visited.add(b)) {
				continue;
			}
			CodeBlock cb = bbm.getCodeBlockAt(b, monitor);
			if (cb == null) {
				continue;
			}
			Set<String> bExit = exitDerived.containsKey(b) ? exitDerived.get(b) : seed;
			CodeBlockReferenceIterator it = cb.getDestinations(monitor);
			while (it.hasNext()) {
				CodeBlockReference ref = it.next();
				FlowType ft = ref.getFlowType();
				if (ft != null && ft.isCall()) {
					continue;
				}
				CodeBlock db = ref.getDestinationBlock();
				Address s = db == null ? null : db.getFirstStartAddress();
				if (s == null || !body.contains(s)) {
					continue;
				}
				if (h.tree.contains(s) || h.tramps.contains(s) || s.equals(d.predispatcher)) {
					continue;
				}
				// follow jump stubs (bare `b`, or register-only constant stubs + `b` / fall-through)
				Address cur = s;
				List<Address> chain = new ArrayList<Address>();
				boolean chainWrites = false;
				Set<String> derived = new HashSet<String>(bExit);
				for (int i = 0; i < 6; i++) {
					boolean[] w = new boolean[1];
					Address t = stubTarget(program, bbm, cur, body, monitor, w, ctx, derived);
					if (t == null) {
						break;
					}
					if (w[0] && (t.equals(d.predispatcher) || t.equals(d.dispatcher))) {
						// `mov w8,#K ; b loopEnd` is an EMPTY REAL BLOCK (state = K):
						// stop here, it is a case head, not a stub
						chainWrites = true;
						break;
					}
					if (stubDest.containsKey(t) && !w[0]) {
						// runs into a stub another chain already folded (-O0 ARM: every tree
						// leaf's `b loopEnd` shares the same `loopEnd: b dispatcher` stub):
						// this block is a stub too and ends where that one ends
						chain.add(cur);
						cur = stubDest.get(t);
						break;
					}
					if (h.tramps.contains(t) || chain.contains(t) || t.equals(cur)) {
						break; // stub cycle
					}
					chain.add(cur);
					cur = t;
				}
				if (!chainWrites && (cur.equals(d.predispatcher) || cur.equals(d.dispatcher) || h.tree.contains(cur))) {
					h.tramps.addAll(chain);
					for (Address c : chain) {
						stubDest.put(c, cur);
					}
					if (!chain.isEmpty() && (cur.equals(d.predispatcher) || cur.equals(d.dispatcher))) {
						h.defaults.add(s); // bare `jmp loopEnd` = switchDefault (never writes the state)
					}
					continue;
				}
				// NB: in the merged layout (dispatcher == hub) tree leaves end in
				// `b.ne dispatcher`, so they ARE hub predecessors; do not exclude
				// hub predecessors here. Real case tails end unconditionally and
				// already fail the conditional-branch test.
				Integer ci = g.id.get(cur);
				boolean dominated = di >= 0 && ci != null && dominates(g, di, ci.intValue());
				Set<String> ex = dominated ? treeNodeExit(program, bbm, cur, monitor, ctx, derived) : null;
				for (Address c : chain) {
					stubDest.put(c, cur);
				}
				if (ex != null) {
					h.tree.add(cur);
					h.tramps.addAll(chain);
					exitDerived.put(cur, ex);
					work.add(cur);
					continue;
				}
				h.tramps.addAll(chain);
				rawHeads.add(cur);
			}
		}
		h.caseHeads.addAll(rawHeads);
		Collections.sort(h.caseHeads);
		h.stateBase = ctx.stateBase;
		h.stateIncoming = ctx.stateIncoming;
		h.stateSlots.addAll(ctx.stateSlots);
		return h;
	}

	/**
	 * Seed the tree-node filter: the dispatcher's compare names the state
	 * register; the frame slots the dispatcher (and pre-dispatcher) touch are
	 * where the state lives / is spilled.
	 */
	private static TreeCtx treeContext(Program program, BasicBlockModel bbm, Detect d, TaskMonitor monitor)
			throws Exception {
		TreeCtx ctx = new TreeCtx();
		if (d.stateHint != null && !d.stateHint.equals("?")) {
			Register r = program.getRegister(d.stateHint);
			if (r != null) {
				ctx.stateBase = r.getBaseRegister().getName();
			}
		}
		if (ctx.stateBase != null) {
			// which register do the cases hand the state over in? Follow the first
			// write of the compare register inside the dispatcher block: a plain
			// copy from a register nothing in the block wrote before = that
			// register; a load / arithmetic result = memory-resident state (null);
			// no write at all = the compare register itself.
			ctx.stateIncoming = ctx.stateBase;
			CodeBlock db = d.dispatcher == null ? null : bbm.getCodeBlockAt(d.dispatcher, monitor);
			if (db != null) {
				Set<String> writtenBefore = new HashSet<String>();
				for (Instruction in : program.getListing().getInstructions(db, true)) {
					Set<String> outs = regNames(in.getResultObjects());
					if (outs.contains(ctx.stateBase)) {
						Set<String> ins = regNames(in.getInputObjects());
						String m = in.getMnemonicString().toLowerCase();
						boolean plainMove = m.equals("mov") && !hasLoad(in) && ins.size() == 1 && outs.size() == 1;
						if (plainMove && !writtenBefore.contains(ins.iterator().next())) {
							ctx.stateIncoming = ins.iterator().next();
						}
						else {
							ctx.stateIncoming = null;
						}
						break;
					}
					writtenBefore.addAll(outs);
				}
			}
		}
		// Which frame slots hold the state? Only the ones the dispatcher /
		// pre-dispatcher LOAD into the compare chain (-O0: `ldr x8,[sp,#0xd0] ;
		// cmp x8,#K`) or STORE a state-derived value into. An -O2 dispatcher
		// block also reloads a dozen real PHI values from the frame; those slots
		// are real data and must not be treated as state (a case's `stur wzr,
		// [x29,#-0x18]` initialising one would be dropped as dead otherwise).
		Address[] blocks = { d.predispatcher, d.dispatcher };
		for (int k = 0; k < blocks.length; k++) {
			if (blocks[k] == null) {
				continue;
			}
			CodeBlock cb = bbm.getCodeBlockAt(blocks[k], monitor);
			if (cb == null) {
				continue;
			}
			List<Instruction> list = new ArrayList<Instruction>();
			for (Instruction in : program.getListing().getInstructions(cb, true)) {
				list.add(in);
			}
			if (ctx.stateBase == null) {
				// unknown state register: every slot the block touches may be it (old behaviour)
				for (Instruction in : list) {
					if (hasLoad(in) || hasStore(in)) {
						ctx.stateSlots.addAll(memOperandKeys(in));
					}
				}
				continue;
			}
			// backward: registers the compare(s) read, followed to the loads that produced them
			Set<String> needed = new HashSet<String>();
			for (int i = list.size() - 1; i >= 0; i--) {
				Instruction in = list.get(i);
				Set<String> outs = regNames(in.getResultObjects());
				Set<String> ins = regNames(in.getInputObjects());
				String m = in.getMnemonicString().toLowerCase();
				if (isCompareLike(m) && writesFlags(in)) {
					for (String s : ins) {
						if (!isFrameReg(s)) {
							needed.add(s);
						}
					}
					continue;
				}
				if (Collections.disjoint(outs, needed)) {
					continue;
				}
				needed.removeAll(outs);
				if (hasLoad(in)) {
					ctx.stateSlots.addAll(memOperandKeys(in)); // the state is reloaded from here
				}
				for (String s : ins) {
					if (!isFrameReg(s)) {
						needed.add(s);
					}
				}
			}
			// forward: stores of state-derived values are state spills
			Set<String> derived = new HashSet<String>();
			derived.add(ctx.stateBase);
			if (ctx.stateIncoming != null) {
				derived.add(ctx.stateIncoming);
			}
			for (Instruction in : list) {
				Set<String> outs = regNames(in.getResultObjects());
				Set<String> ins = regNames(in.getInputObjects());
				boolean load = hasLoad(in);
				boolean srcDerived = !Collections.disjoint(ins, derived)
						|| (load && !Collections.disjoint(memOperandKeys(in), ctx.stateSlots));
				if (hasStore(in) && srcDerived) {
					ctx.stateSlots.addAll(memOperandKeys(in));
				}
				if (!outs.isEmpty()) {
					if (srcDerived) {
						derived.addAll(outs);
					}
					else {
						derived.removeAll(outs);
					}
				}
			}
		}
		return ctx;
	}

	// ------------------------------------------------ emulation recovery -----

	public static final class Node {
		public Address head;
		public List<Address> succs = new ArrayList<Address>();
		public Address selectAddr;    // conditional: the fork point (csel/cmov/cset or b.cond) that decides the edge
		public String deciderKind;    // "select" | "branch"
		public String cond;           // condition mnemonic of that fork (eq, ne, cmovz, ...)
		public Address succTrue;      // conditional: successor when cond holds
		public Address succFalse;     // conditional: successor when cond fails
		public Boolean concreteTake;  // outcome of the decider when the block is simply run (zeroed inputs); null if unknown
		public String status = "unresolved"; // uncond | cond | multi | ret | exit | unresolved
		public boolean pure = true;   // every path from this case to its successor(s) crossed ONLY dispatcher blocks
		public boolean selfLoop;      // one successor is the block itself (single-block loop)
		public int runs;
		public String note = "";
		/** Dispatcher instructions executed on the way to each successor (in order); first run that landed there. */
		public Map<Address, List<Address>> pathTo = new HashMap<Address, List<Address>>();
		/** Last case instruction executed before the dispatcher on the way to each successor (the tail branch); first run. */
		public Map<Address, Address> tailTo = new HashMap<Address, Address>();
		/** Successors reached without crossing the dispatcher at all (edge already direct). */
		public Set<Address> directTo = new HashSet<Address>();
		/**
		 * EVERY tail (last case instruction before the dispatcher) observed on
		 * any explored path to each successor. A case whose two arms (`b.cc`
		 * lowered select) each end in their own `mov state ; b dispatcher` has two
		 * tails per node; every one of them must be redirected.
		 */
		public Map<Address, Set<Address>> tailsTo = new HashMap<Address, Set<Address>>();
		/** Dispatcher instructions executed on the edge (tail, successor); key = {@link #edgeKey}. */
		public Map<String, List<Address>> pathByEdge = new HashMap<String, List<Address>>();
		/**
		 * Case instructions executed on the edge (tail, successor), in order, up to
		 * and including the tail; null when the run exceeded the trace cap. Lets a
		 * patch find the last instruction the case OWNS before it enters a
		 * tail-merged block shared with other cases.
		 */
		public Map<String, List<Address>> caseTraceByEdge = new HashMap<String, List<Address>>();
		/** Tails through which more than one successor was reached (the state was decided before the tail). */
		public Set<Address> convergingTails = new HashSet<Address>();
		/**
		 * false when some explored path could not be followed to a head / return
		 * (step cap, emulator fault) or when the fork exploration hit its cap: the
		 * successor / tail sets may be missing entries and no patch may rely on them.
		 */
		public boolean complete = true;

		public static String edgeKey(Address tail, Address succ) {
			return tail + ">" + succ;
		}
	}

	public static final class Recovery {
		public Detect d;
		public Heads heads;
		public AddressSet dispatchRegion = new AddressSet(); // tree + stubs + hub: the only code a patch may skip
		public Set<Address> watch = new HashSet<Address>();
		public Map<Address, Node> nodes = new HashMap<Address, Node>();
		public Address firstHead; // successor of the prologue
		public Snapshot snap;     // post-prologue context (fallback for heads no explored path reached)
		/**
		 * Machine state captured the first time an explored path landed on each
		 * head. Cases are emulated from this context rather than from the
		 * post-prologue snapshot: -O2 trees copy PHI values and even hoist a
		 * case's `state = NEXT` into the tree path leading to it, so the
		 * dispatcher snapshot alone makes such a case look like `-> itself`.
		 */
		public Map<Address, List<Snapshot>> contexts = new HashMap<Address, List<Snapshot>>();
		public int resolved;
		public int conditional;
		public int unresolved;
		public List<String> log = new ArrayList<String>();
		/**
		 * The recovered graph contradicts what a flattened function can look
		 * like (a cycle made only of unconditional edges: real code would be an
		 * infinite loop, far more likely a dispatcher block was taken for a case
		 * head). Nothing in such a recovery should be patched.
		 */
		public boolean lowConfidence;
		public String confidenceNote = "";

		/**
		 * Drop the per-path detail (landing contexts, instruction lists per
		 * edge, tail sets) once a consumer has finished planning with it. A
		 * 200+ function run keeps every Recovery alive until verification is
		 * over; the detail is the bulk of that memory and nothing after planning
		 * reads it. Heads, successors, statuses and the dispatcher region stay.
		 */
		public void trim() {
			contexts = Collections.emptyMap();
			snap = null;
			log = Collections.emptyList();
			for (Node n : nodes.values()) {
				n.pathTo = Collections.emptyMap();
				n.tailTo = Collections.emptyMap();
				n.tailsTo = Collections.emptyMap();
				n.pathByEdge = Collections.emptyMap();
				n.caseTraceByEdge = Collections.emptyMap();
				n.convergingTails = Collections.emptySet();
				n.directTo = Collections.emptySet();
			}
		}
	}

	public static int MAX_STEPS = 20000;
	public static int MAX_FORK_POINTS = 16; // fork points examined per case (each costs two extra runs); beyond this the case is left unresolved
	public static int MAX_RUNS = 64;        // emulation runs per case including nested fork contexts
	public static int MAX_CONTEXTS = 4;     // distinct landing contexts kept per head

	/**
	 * Register file + tracked memory writes captured when the prologue first
	 * reaches the dispatcher. OLLVM on AArch64 hoists the case constants into
	 * callee-saved registers in the prologue and the compare tree does
	 * `cmp w8, w24` against them, so every case must be emulated from this
	 * post-prologue context, not from zeroed registers.
	 */
	public static final class Snapshot {
		final Map<Register, BigInteger> regs = new HashMap<Register, BigInteger>();
		final List<Address> memAddr = new ArrayList<Address>();
		final List<byte[]> memBytes = new ArrayList<byte[]>();

		void take(EmulatorHelper emu, Program p) {
			take(emu, p, null);
		}

		/**
		 * Capture registers plus every memory range written so far. The write
		 * tracker also sees {@link #restore} writes, so a snapshot taken after
		 * restoring {@code base} already includes its memory; {@code base} is
		 * merged explicitly anyway so the capture cannot lose ranges if tracking
		 * was enabled late.
		 */
		void take(EmulatorHelper emu, Program p, Snapshot base) {
			Register[] all = p.getLanguage().getRegisters().toArray(new Register[0]);
			for (int i = 0; i < all.length; i++) {
				Register r = all[i];
				if (!r.isBaseRegister() || r.isProcessorContext() || r.isProgramCounter() || r.isHidden()) {
					continue;
				}
				try {
					regs.put(r, emu.readRegister(r));
				}
				catch (Exception e) {
					// not readable on this language
				}
			}
			try {
				AddressSet union = new AddressSet();
				AddressSetView w = emu.getTrackedMemoryWriteSet();
				if (w != null) {
					union.add(w);
				}
				if (base != null) {
					for (int i = 0; i < base.memAddr.size(); i++) {
						Address a = base.memAddr.get(i);
						union.add(a, a.add(base.memBytes.get(i).length - 1));
					}
				}
				for (AddressRange ar : union.getAddressRanges()) {
					long len = ar.getLength();
					if (len <= 0 || len > 65536) {
						continue;
					}
					byte[] bytes = emu.readMemory(ar.getMinAddress(), (int) len);
					if (bytes != null) {
						memAddr.add(ar.getMinAddress());
						memBytes.add(bytes);
					}
				}
			}
			catch (Exception e) {
				// tracking unavailable
			}
		}

		void restore(EmulatorHelper emu) {
			for (Map.Entry<Register, BigInteger> e : regs.entrySet()) {
				try {
					emu.writeRegister(e.getKey(), e.getValue());
				}
				catch (Exception ex) {
					// skip
				}
			}
			for (int i = 0; i < memAddr.size(); i++) {
				try {
					emu.writeMemory(memAddr.get(i), memBytes.get(i));
				}
				catch (Exception ex) {
					// skip
				}
			}
		}
	}

	/**
	 * Script-argument parser that survives cmd.exe splitting: analyzeHeadless.bat
	 * is a batch file, so "func=0x1000" arrives as two tokens "func" "0x1000".
	 * Accepts both "key=value" and "key value" for the given value keys; every
	 * other token is a flag.
	 */
	public static final class Args {
		public final Map<String, String> kv = new HashMap<String, String>();
		public final Set<String> flags = new HashSet<String>();

		public boolean flag(String f) {
			return flags.contains(f);
		}

		public String get(String k) {
			return kv.get(k);
		}

		public int getInt(String k, int def) {
			String v = kv.get(k);
			if (v == null) {
				return def;
			}
			try {
				return Integer.parseInt(v.trim());
			}
			catch (Exception e) {
				return def;
			}
		}

		public double getDouble(String k, double def) {
			String v = kv.get(k);
			if (v == null) {
				return def;
			}
			try {
				return Double.parseDouble(v.trim());
			}
			catch (Exception e) {
				return def;
			}
		}
	}

	public static Args parseArgs(String[] args, String[] valueKeys) {
		Args a = new Args();
		Set<String> keys = new HashSet<String>(Arrays.asList(valueKeys));
		for (int i = 0; args != null && i < args.length; i++) {
			String t = args[i];
			if (t == null || t.length() == 0) {
				continue;
			}
			int eq = t.indexOf('=');
			if (eq > 0) {
				a.kv.put(t.substring(0, eq), t.substring(eq + 1));
				continue;
			}
			if (keys.contains(t) && i + 1 < args.length) {
				a.kv.put(t, args[i + 1]);
				i++;
				continue;
			}
			a.flags.add(t);
		}
		return a;
	}

	private static final class PathResult {
		Address landed;         // watch-set head reached, or null
		boolean selfLanding;    // landed == start (single-block loop through the dispatcher)
		String stop;            // head | ret | exit | steps | fault | error | cancel
		String note = "";
		int steps;
		boolean impure;         // executed non-dispatcher code after leaving the case
		Address impureAt;
		boolean forceFailed;    // a fork point could not be forced (memory-source cmov ...)
		int faultsSkipped;      // data-dependent faults (divide by zero) stepped over
		final List<Address> forks = new ArrayList<Address>();            // fork points met before the dispatcher, first-seen order
		final Map<Address, String> forkKind = new HashMap<Address, String>();
		final Map<Address, Boolean> concrete = new HashMap<Address, Boolean>(); // observed outcome when not forced
		final List<Address> regionTrace = new ArrayList<Address>();      // dispatcher instructions executed, in order
		final List<Address> caseTrace = new ArrayList<Address>();        // case (non-dispatcher) instructions executed, in order (capped)
		boolean caseTraceOverflow;
		Address tail;           // last case instruction executed before the dispatcher (or before landing when the edge is direct)
		boolean enteredRegion;
	}

	public static int CASE_TRACE_CAP = 8192;

	private static boolean isSelectInsn(Instruction in) {
		String m = in.getMnemonicString().toLowerCase();
		return m.equals("csel") || m.equals("csinc") || m.equals("csinv") || m.equals("csneg") || m.equals("cset")
				|| m.equals("csetm") || m.equals("cinc") || m.equals("cinv") || m.equals("cneg") || m.startsWith("cmov");
	}

	/**
	 * ARM32 predicated (conditionally executed) non-branch instruction:
	 * `moveq r4,#K` and friends. Ghidra lowers the predicate to an internal
	 * CBRANCH. These are how a 32-bit ARM build expresses the select that
	 * picks the next state; the engine does not force them yet (it would have
	 * to synthesise CPSR flags per condition), so a case containing one before
	 * the dispatcher is reported as incomplete instead of being guessed.
	 */
	private static boolean isPredicated(Program program, Instruction in) {
		if (!"ARM".equals(program.getLanguage().getProcessor().toString())) {
			return false;
		}
		FlowType ft = in.getFlowType();
		if (ft == null || ft.isJump() || ft.isCall() || ft.isTerminal()) {
			return false;
		}
		String m = in.getMnemonicString().toLowerCase();
		if (m.startsWith("it")) {
			return true; // Thumb IT block opener: everything it covers is predicated
		}
		PcodeOp[] ops = in.getPcode();
		for (int i = 0; ops != null && i < ops.length; i++) {
			if (ops[i].getOpcode() == PcodeOp.CBRANCH) {
				return true;
			}
		}
		return false;
	}

	private static final String[] ARM_CONDS = { "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge",
		"lt", "gt", "le" };

	/**
	 * Condition suffix of an ARM32 predicated non-branch instruction (`cpyne`
	 * -> ne, `addgt` -> gt), or null when the mnemonic carries none we know
	 * (an IT-block opener, an `s`-suffixed form we would misread, ...).
	 */
	public static String armPredicate(Instruction in) {
		String m = in.getMnemonicString().toLowerCase();
		if (m.startsWith("it") || m.length() < 3) {
			return null;
		}
		String tail = m.substring(m.length() - 2);
		for (int i = 0; i < ARM_CONDS.length; i++) {
			if (ARM_CONDS[i].equals(tail)) {
				return tail.equals("hs") ? "cs" : tail.equals("lo") ? "cc" : tail;
			}
		}
		return null;
	}

	/** N, Z, C, V that make the ARM condition hold (a full assignment, so a whole predicated group stays consistent). */
	private static int[] armFlagsFor(String cc) {
		switch (cc) {
		case "eq": return new int[] { 0, 1, 0, 0 };
		case "ne": return new int[] { 0, 0, 0, 0 };
		case "cs": return new int[] { 0, 0, 1, 0 };
		case "cc": return new int[] { 0, 0, 0, 0 };
		case "mi": return new int[] { 1, 0, 0, 0 };
		case "pl": return new int[] { 0, 0, 0, 0 };
		case "vs": return new int[] { 0, 0, 0, 1 };
		case "vc": return new int[] { 0, 0, 0, 0 };
		case "hi": return new int[] { 0, 0, 1, 0 };
		case "ls": return new int[] { 0, 1, 0, 0 };
		case "ge": return new int[] { 0, 0, 0, 0 };
		case "lt": return new int[] { 1, 0, 0, 0 };
		case "gt": return new int[] { 0, 0, 0, 0 };
		case "le": return new int[] { 0, 1, 0, 0 };
		default: return null;
		}
	}

	private static String armInverse(String cc) {
		switch (cc) {
		case "eq": return "ne";
		case "ne": return "eq";
		case "cs": return "cc";
		case "cc": return "cs";
		case "mi": return "pl";
		case "pl": return "mi";
		case "vs": return "vc";
		case "vc": return "vs";
		case "hi": return "ls";
		case "ls": return "hi";
		case "ge": return "lt";
		case "lt": return "ge";
		case "gt": return "le";
		case "le": return "gt";
		default: return null;
		}
	}

	/**
	 * Force an ARM predicate by writing CPSR flags (Ghidra's NG/ZR/CY/OV) so that
	 * {@code cc} holds or fails; the instruction is then executed normally,
	 * and every further predicated instruction of the same group (until the
	 * next flag-setting instruction) sees the same, consistent flags.
	 */
	private static boolean forceArmPredicate(EmulatorHelper emu, Program program, String cc, boolean hold) throws Exception {
		int[] f = armFlagsFor(hold ? cc : armInverse(cc));
		if (f == null) {
			return false;
		}
		String[] names = { "NG", "ZR", "CY", "OV" };
		for (int i = 0; i < names.length; i++) {
			Register r = program.getRegister(names[i]);
			if (r == null) {
				return false;
			}
			emu.writeRegister(r, BigInteger.valueOf(f[i]));
		}
		return true;
	}

	/** Evaluate an ARM condition against the emulator's current flags (null when the flags are unavailable). */
	private static Boolean evalArmPredicate(EmulatorHelper emu, Program program, String cc) throws Exception {
		Register ng = program.getRegister("NG");
		Register zr = program.getRegister("ZR");
		Register cy = program.getRegister("CY");
		Register ov = program.getRegister("OV");
		if (ng == null || zr == null || cy == null || ov == null) {
			return null;
		}
		boolean n = emu.readRegister(ng).signum() != 0;
		boolean z = emu.readRegister(zr).signum() != 0;
		boolean c = emu.readRegister(cy).signum() != 0;
		boolean v = emu.readRegister(ov).signum() != 0;
		switch (cc) {
		case "eq": return Boolean.valueOf(z);
		case "ne": return Boolean.valueOf(!z);
		case "cs": return Boolean.valueOf(c);
		case "cc": return Boolean.valueOf(!c);
		case "mi": return Boolean.valueOf(n);
		case "pl": return Boolean.valueOf(!n);
		case "vs": return Boolean.valueOf(v);
		case "vc": return Boolean.valueOf(!v);
		case "hi": return Boolean.valueOf(c && !z);
		case "ls": return Boolean.valueOf(!c || z);
		case "ge": return Boolean.valueOf(n == v);
		case "lt": return Boolean.valueOf(n != v);
		case "gt": return Boolean.valueOf(!z && n == v);
		case "le": return Boolean.valueOf(z || n != v);
		default: return null;
		}
	}

	/** Condition code of a select or conditional branch, normalised (eq, ne, g, nz, ...). */
	public static String condOf(Instruction in) {
		String m = in.getMnemonicString().toLowerCase();
		if (m.startsWith("cmov")) {
			return m.substring(4);
		}
		if ("ARM".equals(in.getProgram().getLanguage().getProcessor().toString())) {
			FlowType ft0 = in.getFlowType();
			if (ft0 != null && !ft0.isJump() && !ft0.isCall() && !ft0.isTerminal()) {
				String cc = armPredicate(in);
				if (cc != null) {
					return cc; // predicated `cpyne r0,r1`: the select of a 32-bit ARM build
				}
			}
		}
		FlowType ft = in.getFlowType();
		if (ft != null && ft.isJump() && ft.isConditional()) {
			if (m.startsWith("b.")) {
				return m.substring(2);          // AArch64 b.eq
			}
			if (m.startsWith("j")) {
				return m.substring(1);          // x86 jnz
			}
			if (m.startsWith("b") && m.length() >= 3) {
				return m.substring(1);          // ARM32 beq
			}
			return m;
		}
		int n = in.getNumOperands();
		if (n <= 0) {
			return "?";
		}
		String s = in.getDefaultOperandRepresentation(n - 1);
		return s == null ? "?" : s.trim().toLowerCase();
	}

	/** Force the select outcome instead of trusting garbage flags. */
	private static boolean applySelect(EmulatorHelper emu, Instruction in, boolean takeTrue) throws Exception {
		String m = in.getMnemonicString().toLowerCase();
		Register rd = in.getRegister(0);
		if (rd == null) {
			return false;
		}
		int bits = rd.getBitLength();
		BigInteger mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
		if (m.startsWith("cmov")) {
			Register rs = in.getRegister(1);
			if (rs == null) {
				return false; // memory source: cannot fork safely
			}
			if (takeTrue) {
				emu.writeRegister(rd, emu.readRegister(rs).and(mask));
			}
			return true;
		}
		Register rn = in.getRegister(1);
		Register rm = in.getRegister(2);
		BigInteger vn = rn == null ? BigInteger.ZERO : emu.readRegister(rn).and(mask);
		BigInteger vm = rm == null ? BigInteger.ZERO : emu.readRegister(rm).and(mask);
		BigInteger res;
		if (m.equals("csel")) {
			res = takeTrue ? vn : vm;
		}
		else if (m.equals("csinc")) {
			res = takeTrue ? vn : vm.add(BigInteger.ONE);
		}
		else if (m.equals("csinv")) {
			res = takeTrue ? vn : vm.not();
		}
		else if (m.equals("csneg")) {
			res = takeTrue ? vn : vm.negate();
		}
		else if (m.equals("cset")) {
			res = takeTrue ? BigInteger.ONE : BigInteger.ZERO;
		}
		else if (m.equals("csetm")) {
			res = takeTrue ? mask : BigInteger.ZERO;
		}
		else if (m.equals("cinc")) {
			res = takeTrue ? vn.add(BigInteger.ONE) : vn;
		}
		else if (m.equals("cinv")) {
			res = takeTrue ? vn.not() : vn;
		}
		else if (m.equals("cneg")) {
			res = takeTrue ? vn.negate() : vn;
		}
		else {
			return false;
		}
		emu.writeRegister(rd, res.and(mask));
		return true;
	}

	/**
	 * Run a select normally and report which way it went (by comparing the
	 * destination with the candidate sources). null = could not tell.
	 */
	private static Boolean stepSelectConcrete(EmulatorHelper emu, Instruction in, TaskMonitor monitor) throws Exception {
		String m = in.getMnemonicString().toLowerCase();
		Register rd = in.getRegister(0);
		if (rd == null) {
			return emu.step(monitor) ? null : Boolean.FALSE;
		}
		int bits = rd.getBitLength();
		BigInteger mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
		BigInteger before = emu.readRegister(rd).and(mask);
		Register rn = in.getRegister(1);
		Register rm = in.getRegister(2);
		BigInteger vn = rn == null ? null : emu.readRegister(rn).and(mask);
		BigInteger vm = rm == null ? null : emu.readRegister(rm).and(mask);
		if (!emu.step(monitor)) {
			throw new IllegalStateException("step failed: " + emu.getLastError());
		}
		BigInteger after = emu.readRegister(rd).and(mask);
		if (m.startsWith("cmov")) {
			if (vn == null || vn.equals(before)) {
				return null;
			}
			return Boolean.valueOf(after.equals(vn));
		}
		if (m.equals("cset")) {
			return Boolean.valueOf(after.signum() != 0);
		}
		if (m.equals("csetm")) {
			return Boolean.valueOf(after.signum() != 0);
		}
		if (vn == null) {
			return null;
		}
		BigInteger tVal;
		BigInteger fVal;
		if (m.equals("csel")) {
			tVal = vn;
			fVal = vm;
		}
		else if (m.equals("csinc")) {
			tVal = vn;
			fVal = vm == null ? null : vm.add(BigInteger.ONE).and(mask);
		}
		else if (m.equals("csinv")) {
			tVal = vn;
			fVal = vm == null ? null : vm.not().and(mask);
		}
		else if (m.equals("csneg")) {
			tVal = vn;
			fVal = vm == null ? null : vm.negate().and(mask);
		}
		else if (m.equals("cinc")) {
			tVal = vn.add(BigInteger.ONE).and(mask);
			fVal = vn;
		}
		else if (m.equals("cinv")) {
			tVal = vn.not().and(mask);
			fVal = vn;
		}
		else if (m.equals("cneg")) {
			tVal = vn.negate().and(mask);
			fVal = vn;
		}
		else {
			return null;
		}
		if (fVal == null || tVal.equals(fVal)) {
			return null;
		}
		if (after.equals(tVal)) {
			return Boolean.TRUE;
		}
		if (after.equals(fVal)) {
			return Boolean.FALSE;
		}
		return null;
	}

	private static long scratchBase(Program program) {
		int ps = program.getDefaultPointerSize();
		return ps >= 8 ? 0x7ff000000000L : 0x7ff00000L;
	}

	public static EmulatorHelper newEmulator(Program program, boolean trackWrites, final byte fill) {
		EmulatorHelper emu = new EmulatorHelper(program);
		if (trackWrites) {
			emu.enableMemoryWriteTracking(true);
		}
		emu.setMemoryFaultHandler(new MemoryFaultHandler() {
			@Override
			public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
				Arrays.fill(buf, bufOffset, bufOffset + size, fill);
				return true;
			}

			@Override
			public boolean unknownAddress(Address address, boolean write) {
				return true;
			}
		});
		Register sp = emu.getStackPointerRegister();
		long base = scratchBase(program);
		long spVal = base + 0x10000;
		if (sp != null) {
			emu.writeRegister(sp, spVal);
		}
		String[] fps = { "x29", "rbp", "ebp", "fp", "r11" };
		for (int i = 0; i < fps.length; i++) {
			Register fp = program.getRegister(fps[i]);
			if (fp != null && (sp == null || !fp.equals(sp))) {
				try {
					emu.writeRegister(fp, spVal + 0x800);
				}
				catch (Exception e) {
					// unsupported register on this language
				}
			}
		}
		return emu;
	}

	public static void advancePast(EmulatorHelper emu, Register pc, Instruction in) {
		Address next = in.getFallThrough();
		if (next == null) {
			next = in.getMaxAddress().add(1);
		}
		emu.writeRegister(pc, next.getOffset());
	}

	private static void noteFork(PathResult pr, Address at, String kind) {
		if (!pr.forkKind.containsKey(at)) {
			pr.forkKind.put(at, kind);
			pr.forks.add(at);
		}
	}

	/**
	 * Concretely emulate from {@code start} until a watch-set head (other than
	 * start, unless the dispatcher was crossed: single-block loops) is reached.
	 * Calls are stepped over, uninitialised memory reads zero, data-dependent
	 * divide faults are stepped over, fork points listed in {@code forceAt} are
	 * forced the FIRST time they execute (a loop's back-branch forced every
	 * iteration would never terminate; forcing once explores "the other arm"),
	 * every other fork point runs concretely and its outcome is noted.
	 */
	private static PathResult runPath(Program program, Recovery r, Address start, Map<Address, Boolean> forceAt,
			TaskMonitor monitor, Address stopAt, Snapshot base, Snapshot capture) {
		PathResult pr = new PathResult();
		Listing listing = program.getListing();
		AddressSetView body = r.d.func.getBody();
		EmulatorHelper emu = null;
		Set<Address> forcedOnce = new HashSet<Address>();
		boolean predGroupDecided = false; // ARM32: a predicated group's first member decided the flags; the rest are not forks
		boolean captureLandings = r.contexts != null;
		try {
			// write tracking is what lets a landing snapshot carry the memory the
			// restored base snapshot brought along (restore() writes are tracked too)
			emu = newEmulator(program, capture != null || captureLandings, (byte) 0);
			Register pc = emu.getPCRegister();
			if (base != null) {
				base.restore(emu);
			}
			emu.writeRegister(pc, start.getOffset());

			boolean inDispatch = false;
			for (int step = 0; step < MAX_STEPS; step++) {
				if (monitor.isCancelled()) {
					pr.stop = "cancel";
					return pr;
				}
				Address cur = emu.getExecutionAddress();
				if (cur == null) {
					pr.stop = "fault";
					return pr;
				}
				boolean atStop = stopAt != null && cur.equals(stopAt);
				if (step > 0 && (atStop || r.watch.contains(cur)) && (!cur.equals(start) || inDispatch)) {
					pr.landed = cur;
					pr.selfLanding = cur.equals(start);
					pr.stop = "head";
					pr.steps = step;
					if (capture != null) {
						capture.take(emu, program);
					}
					if (captureLandings) {
						// the machine state the successor is really entered with:
						// includes PHI copies and speculative state materialisation
						// the compare tree performed on the way in. Distinct contexts
						// (the two arms of a forced fork landing on the same head with
						// different registers) are all kept: a hoisted select decides the
						// head's OWN successor through such a register.
						List<Snapshot> list = r.contexts.get(cur);
						if (list == null) {
							list = new ArrayList<Snapshot>();
							r.contexts.put(cur, list);
						}
						if (list.size() < MAX_CONTEXTS) {
							Snapshot s = new Snapshot();
							s.take(emu, program, base);
							boolean dup = false;
							for (Snapshot o : list) {
								if (o.regs.equals(s.regs)) {
									dup = true;
									break;
								}
							}
							if (!dup) {
								list.add(s);
							}
						}
					}
					return pr;
				}
				if (!body.contains(cur)) {
					pr.stop = "exit";
					pr.steps = step;
					return pr;
				}
				// purity: once the case has handed control to the dispatcher, the
				// only code allowed before the next head is the dispatcher itself
				if (r.dispatchRegion.contains(cur)) {
					inDispatch = true;
					pr.enteredRegion = true;
					pr.regionTrace.add(cur);
				}
				else if (inDispatch && !pr.impure) {
					pr.impure = true;
					pr.impureAt = cur;
				}
				else if (!inDispatch) {
					pr.tail = cur; // last case instruction so far
					if (pr.caseTrace.size() < CASE_TRACE_CAP) {
						pr.caseTrace.add(cur);
					}
					else {
						pr.caseTraceOverflow = true;
					}
				}
				Instruction in = listing.getInstructionAt(cur);
				if (in == null) {
					pr.stop = "fault:no instruction";
					pr.steps = step;
					return pr;
				}
				FlowType ft = in.getFlowType();
				if (writesFlags(in) && !isPredicated(program, in)) {
					predGroupDecided = false; // a new compare: the next predicated instruction is a new fork point
				}
				if (ft != null && ft.isCall()) {
					if (ft.isTerminal()) {
						pr.stop = "ret";
						pr.note = "noreturn call";
						pr.steps = step;
						return pr;
					}
					// step over the call; the state update never lives in the callee
					advancePast(emu, pc, in);
					continue;
				}
				if (ft != null && ft.isTerminal()) {
					pr.stop = "ret";
					pr.steps = step;
					return pr;
				}
				boolean handled = false;
				if (!inDispatch) {
					if (isPredicated(program, in)) {
						// ARM32 lowers the state select to predicated moves (`moveq r0,#A ;
						// movne r0,#B`). The FIRST predicated instruction after a flag write
						// is the fork point; it is forced by synthesising the CPSR flags, so
						// the rest of the group executes consistently with the same predicate.
						String cc = armPredicate(in);
						if (cc == null) {
							pr.forceFailed = true;
							pr.note = "predicated instruction not modelled: " + in.getMnemonicString() + " @" + cur;
						}
						else if (!predGroupDecided) {
							noteFork(pr, cur, "select");
							Boolean force = forceAt.get(cur);
							if (force != null && !forcedOnce.add(cur)) {
								force = null;
							}
							if (force != null) {
								if (forceArmPredicate(emu, program, cc, force.booleanValue())) {
									predGroupDecided = true;
								}
								else {
									pr.forceFailed = true;
									pr.note = "cannot force predicate " + cc + " @" + cur;
								}
							}
							else {
								Boolean took = evalArmPredicate(emu, program, cc);
								if (took != null && !pr.concrete.containsKey(cur)) {
									pr.concrete.put(cur, took);
								}
								predGroupDecided = true; // the group is decided; later members are not forks
							}
						}
					}
					if (isSelectInsn(in)) {
						noteFork(pr, cur, "select");
						Boolean force = forceAt.get(cur);
						if (force != null && !forcedOnce.add(cur)) {
							force = null; // already forced once on this run
						}
						if (force != null) {
							if (applySelect(emu, in, force.booleanValue())) {
								advancePast(emu, pc, in);
								handled = true;
							}
							else {
								pr.forceFailed = true;
								pr.note = "cannot force " + in.getMnemonicString() + " @" + cur;
							}
						}
						else {
							Boolean took = stepSelectConcrete(emu, in, monitor);
							if (took != null && !pr.concrete.containsKey(cur)) {
								pr.concrete.put(cur, took);
							}
							handled = true;
						}
					}
					else if (ft != null && ft.isJump() && ft.isConditional() && !ft.isComputed()) {
						Address[] flows = in.getFlows();
						Address tgt = flows != null && flows.length == 1 ? flows[0] : null;
						Address fall = in.getFallThrough();
						if (tgt != null && fall != null) {
							noteFork(pr, cur, "branch");
							Boolean force = forceAt.get(cur);
							if (force != null && !forcedOnce.add(cur)) {
								force = null;
							}
							if (force != null) {
								emu.writeRegister(pc, (force.booleanValue() ? tgt : fall).getOffset());
								handled = true;
							}
							else {
								if (!emu.step(monitor)) {
									pr.stop = "fault:" + emu.getLastError();
									pr.steps = step;
									return pr;
								}
								Address after = emu.getExecutionAddress();
								if (!pr.concrete.containsKey(cur)) {
									pr.concrete.put(cur, Boolean.valueOf(after != null && after.equals(tgt)));
								}
								handled = true;
							}
						}
					}
				}
				if (handled) {
					continue;
				}
				if (!emu.step(monitor)) {
					String err = String.valueOf(emu.getLastError());
					if (err.toLowerCase().contains("divide")) {
						// data-dependent fault on zeroed inputs; the state update does not depend on it
						pr.faultsSkipped++;
						advancePast(emu, pc, in);
						continue;
					}
					pr.stop = "fault:" + err;
					pr.steps = step;
					return pr;
				}
			}
			pr.stop = "steps";
			pr.steps = MAX_STEPS;
			return pr;
		}
		catch (Exception e) {
			pr.stop = "error:" + e.getMessage();
			return pr;
		}
		finally {
			if (emu != null) {
				try {
					emu.dispose();
				}
				catch (Exception e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Resolve every real successor of one case head. Every fork point met by
	 * the unforced probe run is then forced true and false on its own; a fork
	 * whose two outcomes land on different heads decides the edge. Forcing one
	 * fork at a time keeps cset->csel data dependencies intact (the concrete
	 * machine evaluates everything else), which forcing all selects by index
	 * did not.
	 */
	private static void resolveNode(Program program, Recovery r, Node node, Snapshot base, TaskMonitor monitor) {
		Map<Address, Boolean> none = Collections.emptyMap();
		PathResult probe = runPath(program, r, node.head, none, monitor, null, base, null);
		node.runs = 1;
		Map<Address, PathResult> landings = new LinkedHashMap<Address, PathResult>();
		if (probe.landed != null) {
			landings.put(probe.landed, probe);
		}
		absorbFlags(node, probe);
		observe(node, probe);

		List<Address> forks = new ArrayList<Address>(probe.forks);
		if (forks.size() > MAX_FORK_POINTS) {
			// never guess "unconditional" because the deciding select was not examined
			node.status = "unresolved";
			node.note = appendNote(node.note, forks.size() + " fork points before the dispatcher (cap " + MAX_FORK_POINTS + ")");
			return;
		}
		// Every fork the probe met is forced true and false on its own (this is
		// what decides the edge). Forks that only exist on a forced path (the
		// "other arm" of a real branch may contain further branches) are then
		// explored under that forcing context, so a hidden third state store is
		// found instead of silently left pointing at the dispatcher.
		List<Address> deciders = new ArrayList<Address>();
		Map<Address, PathResult> trueRun = new HashMap<Address, PathResult>();
		Map<Address, PathResult> falseRun = new HashMap<Address, PathResult>();
		List<Map<Address, Boolean>> work = new ArrayList<Map<Address, Boolean>>();
		Set<String> scheduled = new HashSet<String>();
		for (int i = 0; i < forks.size(); i++) {
			schedule(work, scheduled, none, forks.get(i), true);
			schedule(work, scheduled, none, forks.get(i), false);
		}
		int wi = 0;
		while (wi < work.size() && !monitor.isCancelled()) {
			if (node.runs >= MAX_RUNS) {
				node.complete = false;
				node.note = appendNote(node.note, "fork exploration capped at " + MAX_RUNS + " runs");
				break;
			}
			Map<Address, Boolean> ctx = work.get(wi++);
			PathResult pr = runPath(program, r, node.head, ctx, monitor, null, base, null);
			node.runs++;
			absorbFlags(node, pr);
			observe(node, pr);
			if (pr.landed != null && !landings.containsKey(pr.landed)) {
				landings.put(pr.landed, pr);
			}
			if (ctx.size() == 1) {
				Map.Entry<Address, Boolean> e = ctx.entrySet().iterator().next();
				(e.getValue().booleanValue() ? trueRun : falseRun).put(e.getKey(), pr);
			}
			for (int k = 0; k < pr.forks.size(); k++) {
				Address g = pr.forks.get(k);
				if (ctx.containsKey(g) || probe.forkKind.containsKey(g)) {
					continue; // part of this context, or already explored on its own
				}
				schedule(work, scheduled, ctx, g, true);
				schedule(work, scheduled, ctx, g, false);
			}
		}
		for (int i = 0; i < forks.size(); i++) {
			Address f = forks.get(i);
			PathResult pt = trueRun.get(f);
			PathResult pf = falseRun.get(f);
			if (pt != null && pf != null && pt.landed != null && pf.landed != null && !pt.landed.equals(pf.landed)) {
				deciders.add(f);
			}
		}
		node.succs.clear();
		node.succs.addAll(landings.keySet());
		Collections.sort(node.succs);
		for (Map.Entry<Address, PathResult> e : landings.entrySet()) {
			recordPath(node, e.getKey(), e.getValue());
		}
		if (node.succs.isEmpty()) {
			if ("ret".equals(probe.stop)) {
				node.status = "ret";
				node.note = appendNote(node.note, probe.note);
			}
			else if ("exit".equals(probe.stop)) {
				node.status = "exit";
			}
			else {
				node.status = "unresolved";
				node.note = appendNote(node.note, probe.stop == null ? "" : probe.stop);
			}
			return;
		}
		// Several deciders that all toggle between the SAME two heads are one
		// decision expressed as a dependency chain (cset -> tst -> csel): the
		// last one in execution order is the state select and carries the
		// condition the patch must use.
		if (!deciders.isEmpty() && node.succs.size() == 2) {
			Address f = deciders.get(deciders.size() - 1);
			boolean samePair = true;
			for (Address g : deciders) {
				Set<Address> pg = new HashSet<Address>(Arrays.asList(trueRun.get(g).landed, falseRun.get(g).landed));
				Set<Address> pf = new HashSet<Address>(Arrays.asList(trueRun.get(f).landed, falseRun.get(f).landed));
				if (!pg.equals(pf)) {
					samePair = false;
					break;
				}
			}
			if (samePair) {
				node.status = "cond";
				node.selectAddr = f;
				node.deciderKind = probe.forkKind.get(f);
				Instruction fin = program.getListing().getInstructionAt(f);
				node.cond = fin == null ? "?" : condOf(fin);
				node.succTrue = trueRun.get(f).landed;
				node.succFalse = falseRun.get(f).landed;
				recordPath(node, node.succTrue, trueRun.get(f));
				recordPath(node, node.succFalse, falseRun.get(f));
				node.concreteTake = probe.concrete.get(f);
				if (deciders.size() > 1) {
					node.note = appendNote(node.note, deciders.size() + " dependent fork points");
				}
				return;
			}
		}
		if (node.succs.size() == 1) {
			node.status = "uncond";
			return;
		}
		node.status = "multi";
		if (deciders.size() > 1) {
			node.note = appendNote(node.note, deciders.size() + " independent fork points");
		}
	}

	private static void schedule(List<Map<Address, Boolean>> work, Set<String> scheduled, Map<Address, Boolean> base,
			Address fork, boolean take) {
		Map<Address, Boolean> ctx = new LinkedHashMap<Address, Boolean>(base);
		ctx.put(fork, Boolean.valueOf(take));
		StringBuilder key = new StringBuilder();
		for (Map.Entry<Address, Boolean> e : new TreeMap<Address, Boolean>(ctx).entrySet()) {
			key.append(e.getKey()).append(e.getValue().booleanValue() ? "T" : "F").append(';');
		}
		if (scheduled.add(key.toString())) {
			work.add(ctx);
		}
	}

	/**
	 * Per-tail bookkeeping for one explored path, plus the completeness flag:
	 * a path that ended in neither a head nor a return / tail call means the
	 * exploration could not see where that arm goes.
	 */
	private static void observe(Node node, PathResult pr) {
		if ("head".equals(pr.stop) && pr.landed != null) {
			if (pr.enteredRegion && pr.tail != null) {
				Set<Address> tails = node.tailsTo.get(pr.landed);
				if (tails == null) {
					tails = new LinkedHashSet<Address>();
					node.tailsTo.put(pr.landed, tails);
				}
				tails.add(pr.tail);
				String key = Node.edgeKey(pr.tail, pr.landed);
				if (!node.pathByEdge.containsKey(key)) {
					node.pathByEdge.put(key, new ArrayList<Address>(pr.regionTrace));
					node.caseTraceByEdge.put(key, pr.caseTraceOverflow ? null : new ArrayList<Address>(pr.caseTrace));
				}
				for (Map.Entry<Address, Set<Address>> e : node.tailsTo.entrySet()) {
					if (!e.getKey().equals(pr.landed) && e.getValue().contains(pr.tail)) {
						node.convergingTails.add(pr.tail);
					}
				}
			}
			return;
		}
		if ("ret".equals(pr.stop) || "exit".equals(pr.stop)) {
			return; // an arm that returns / tail-calls needs no dispatcher
		}
		if (node.complete) {
			node.complete = false;
			node.note = appendNote(node.note, "an explored arm stopped without reaching a head (" + pr.stop + ")");
		}
	}

	private static void recordPath(Node node, Address succ, PathResult pr) {
		node.pathTo.put(succ, new ArrayList<Address>(pr.regionTrace));
		if (pr.tail != null) {
			node.tailTo.put(succ, pr.tail);
		}
		if (!pr.enteredRegion) {
			node.directTo.add(succ);
		}
		else {
			node.directTo.remove(succ);
		}
		if (pr.selfLanding) {
			node.selfLoop = true;
		}
	}

	private static void absorbFlags(Node node, PathResult pr) {
		if (pr.impure && node.pure) {
			node.pure = false;
			node.note = appendNote(node.note, "impure@" + pr.impureAt);
		}
		if (pr.forceFailed) {
			node.pure = false; // one outcome could not be explored; never patch
			node.note = appendNote(node.note, pr.note);
		}
		if (pr.faultsSkipped > 0) {
			node.note = appendNote(node.note, "skipped " + pr.faultsSkipped + " divide fault(s)");
		}
	}

	private static String appendNote(String base, String add) {
		if (add == null || add.length() == 0) {
			return base == null ? "" : base;
		}
		if (base == null || base.length() == 0) {
			return add;
		}
		return base.contains(add) ? base : base + "; " + add;
	}

	/**
	 * Full recovery for one detected function: discover case heads, then
	 * emulate each head (and the prologue) to its true successor(s).
	 */
	public static Recovery recover(Program program, Detect d, TaskMonitor monitor) throws Exception {
		Recovery r = new Recovery();
		r.d = d;
		r.heads = discoverHeads(program, d, monitor);
		r.watch.addAll(r.heads.caseHeads);
		r.watch.addAll(d.returnBlocks);
		// the dispatcher region = every block a patch is allowed to skip
		BasicBlockModel bbm = new BasicBlockModel(program);
		Set<Address> region = new HashSet<Address>(r.heads.tree);
		region.addAll(r.heads.tramps);
		if (d.predispatcher != null) {
			region.add(d.predispatcher);
		}
		if (d.dispatcher != null) {
			region.add(d.dispatcher);
		}
		for (Address a : region) {
			CodeBlock cb = bbm.getCodeBlockAt(a, monitor);
			if (cb != null) {
				r.dispatchRegion.add(cb);
			}
		}
		r.log.add("caseHeads=" + r.heads.caseHeads.size() + " treeBlocks=" + r.heads.tree.size() + " stubs="
				+ r.heads.tramps.size() + " defaults=" + r.heads.defaults.size() + " returnBlocks="
				+ d.returnBlocks.size() + " regionBytes=" + r.dispatchRegion.getNumAddresses());

		// 1) run the prologue up to the dispatcher and snapshot the machine
		//    context (hoisted case constants, frame/base registers, stack init);
		//    this is the fallback context for heads no explored path lands on
		if (d.dispatcher != null) {
			Map<Address, List<Snapshot>> saved = r.contexts;
			r.contexts = null; // the dispatcher itself is not a head: no landing capture here
			Snapshot s = new Snapshot();
			PathResult pr = runPath(program, r, d.entry, Collections.<Address, Boolean> emptyMap(), monitor, d.dispatcher,
					null, s);
			r.contexts = saved;
			if (pr.landed != null && pr.landed.equals(d.dispatcher)) {
				r.snap = s;
				r.log.add("prologue snapshot @" + d.dispatcher + ": regs=" + s.regs.size() + " memRanges="
						+ s.memAddr.size() + " steps=" + pr.steps);
			}
			else {
				r.log.add("WARN prologue did not reach dispatcher (" + pr.stop
						+ "); cases emulated from zeroed registers, expect unresolved edges");
			}
		}

		// 2) prologue -> first real block; every landing captures the successor's
		//    entry context, and heads are then emulated from their own captured
		//    context in discovery order (a forward propagation over the real CFG)
		Node entry = new Node();
		entry.head = d.entry;
		resolveNode(program, r, entry, null, monitor);
		if (entry.succs.size() == 1) {
			r.firstHead = entry.succs.get(0);
		}
		r.nodes.put(d.entry, entry);

		Set<Address> headSet = new HashSet<Address>(r.heads.caseHeads);
		List<Address> queue = new ArrayList<Address>();
		Set<Address> queued = new HashSet<Address>();
		for (Address s : entry.succs) {
			if (headSet.contains(s) && queued.add(s)) {
				queue.add(s);
			}
		}
		int qi = 0;
		int fallback = 0;
		while (!monitor.isCancelled()) {
			Address h;
			Snapshot base;
			List<Snapshot> ctxs = null;
			boolean fromQueue;
			if (qi < queue.size()) {
				h = queue.get(qi++);
				ctxs = r.contexts.get(h);
				base = ctxs == null || ctxs.isEmpty() ? null : ctxs.get(0);
				fromQueue = true;
			}
			else {
				fromQueue = false;
				// heads no explored path reached (dead cases, or only reachable through
				// unresolved nodes): fall back to the post-prologue snapshot
				h = null;
				for (int i = 0; i < r.heads.caseHeads.size(); i++) {
					Address c = r.heads.caseHeads.get(i);
					if (!c.equals(d.entry) && !r.nodes.containsKey(c)) {
						h = c;
						break;
					}
				}
				if (h == null) {
					break;
				}
				base = r.snap;
			}
			if (h.equals(d.entry) || r.nodes.containsKey(h)) {
				continue;
			}
			monitor.setMessage("CFF emulate " + h);
			Node n = new Node();
			n.head = h;
			if (d.returnBlocks.contains(h)) {
				n.status = "ret";
				r.nodes.put(h, n);
				continue;
			}
			if (!fromQueue) {
				fallback++;
				n.note = appendNote(n.note, "no predecessor context (dispatcher snapshot used)");
			}
			resolveNode(program, r, n, base, monitor);
			// A hoisted select (`csel x23,K1,K2` in the prologue, `mov x8,x23 ; b
			// dispatcher` in the case) decides this case's successor through a
			// register it merely copies: no fork inside the case, but the landing
			// contexts of the two arms differ. Probe every other captured context;
			// a successor outside the recovered set means the edge is
			// data-dependent and must not be treated as unconditional.
			if (ctxs != null && ctxs.size() > 1 && (n.status.equals("uncond") || n.status.equals("cond"))) {
				for (int c = 1; c < ctxs.size() && !monitor.isCancelled(); c++) {
					PathResult pr = runPath(program, r, h, Collections.<Address, Boolean> emptyMap(), monitor, null, ctxs.get(c),
							null);
					n.runs++;
					if (pr.landed != null && !n.succs.contains(pr.landed)) {
						n.status = "unresolved";
						n.complete = false;
						n.note = appendNote(n.note, "successor depends on the incoming context (state chosen before this block, e.g. a hoisted select): "
								+ pr.landed + " not among " + n.succs);
						break;
					}
				}
			}
			r.nodes.put(h, n);
			for (Address s : n.succs) {
				if (headSet.contains(s) && !r.nodes.containsKey(s) && queued.add(s)) {
					queue.add(s);
				}
			}
		}
		if (fallback > 0) {
			r.log.add(fallback + " head(s) had no predecessor context; emulated from the dispatcher snapshot");
		}
		for (Node n : r.nodes.values()) {
			if (n.status.equals("uncond") || n.status.equals("cond") || n.status.equals("multi")) {
				r.resolved++;
			}
			if (n.status.equals("cond")) {
				r.conditional++;
			}
			if (n.status.equals("unresolved")) {
				r.unresolved++;
			}
		}
		checkConsistency(program, r);
		return r;
	}

	/**
	 * A recovered graph in which a cycle consists solely of unconditional edges
	 * describes an infinite loop with no exit. Real code almost never does
	 * that; -O2 tail merging occasionally makes a dispatcher-internal block
	 * look like a case head, and the emulator then "recovers" A -> B -> A.
	 * Flag it so nothing gets patched on that basis.
	 */
	private static void checkConsistency(Program program, Recovery r) {
		// The state registers (the one cases write the next state into, and the
		// copy the dispatcher compares) are read only by the dispatcher. A case
		// head that reads one before writing it is either not a real head (a
		// mid-case block mistaken for one) or the "state" is a real variable
		// (an interpreter loop that merely looks flattened): nothing may be
		// patched. (A hoisted select's head `mov x8,x23 ; b dispatcher` WRITES the
		// state register and is fine; the landing contexts handle it.) With a
		// memory-resident state (-O0) the compare register is an ordinary
		// scratch register and is not checked.
		Set<String> stateRegs = new HashSet<String>();
		if (r.heads.stateIncoming != null) {
			stateRegs.add(r.heads.stateIncoming);
		}
		if (r.heads.stateBase != null && r.heads.stateIncoming != null) {
			stateRegs.add(r.heads.stateBase);
		}
		for (Address h : r.heads.caseHeads) {
			if (stateRegs.isEmpty() || r.d.returnBlocks.contains(h)) {
				continue;
			}
			Instruction in = program.getListing().getInstructionAt(h);
			Set<String> written = new HashSet<String>();
			for (int i = 0; in != null && i < 64; i++) {
				Set<String> ins = regNames(in.getInputObjects());
				Set<String> outs = regNames(in.getResultObjects());
				for (String s : stateRegs) {
					if (ins.contains(s) && !written.contains(s) && !isSelectInsn(in)) {
						r.lowConfidence = true;
						r.confidenceNote = "case head " + h + " reads the state register " + s + " @" + in.getMinAddress()
								+ " (" + in + "): not a flattened case head, or the state is a real variable";
						r.log.add("WARN low confidence: " + r.confidenceNote);
						return;
					}
				}
				written.addAll(outs);
				if (written.containsAll(stateRegs)) {
					break;
				}
				FlowType ft = in.getFlowType();
				if (ft != null && (ft.isJump() || ft.isCall() || ft.isTerminal())) {
					break;
				}
				Address next = in.getFallThrough();
				in = next == null ? null : program.getListing().getInstructionAt(next);
			}
		}
		for (Node start : r.nodes.values()) {
			if (!start.status.equals("uncond")) {
				continue;
			}
			List<Address> path = new ArrayList<Address>();
			Set<Address> seen = new HashSet<Address>();
			Node cur = start;
			while (cur != null && cur.status.equals("uncond") && cur.succs.size() == 1) {
				if (!seen.add(cur.head)) {
					int at = path.indexOf(cur.head);
					StringBuilder sb = new StringBuilder();
					for (int i = at; i < path.size(); i++) {
						sb.append(path.get(i)).append(" -> ");
					}
					sb.append(cur.head);
					r.lowConfidence = true;
					r.confidenceNote = "cycle of unconditional edges " + sb
							+ " (infinite loop or a dispatcher block mistaken for a case head)";
					r.log.add("WARN low confidence: " + r.confidenceNote);
					return;
				}
				path.add(cur.head);
				cur = r.nodes.get(cur.succs.get(0));
			}
		}
		// Every case head must be somebody's successor: the flattening pass gave
		// every original block a state and every original block had a
		// predecessor, i.e. a state store somewhere. A head nothing leads to
		// means a decision the exploration never saw — typically a select
		// hoisted several cases before the node whose successor it decides, so
		// the alternative value never reached that node's landing contexts.
		// Patching ANY edge of such a recovery is unsafe (the node with the
		// missing successor is unknown) unless some node is still unresolved
		// and may simply own the missing edge.
		Set<Address> targeted = new HashSet<Address>();
		boolean allResolved = true;
		for (Node n : r.nodes.values()) {
			targeted.addAll(n.succs);
			targeted.addAll(n.directTo);
			boolean settled = n.status.equals("uncond") || n.status.equals("cond") || n.status.equals("ret")
					|| n.status.equals("exit");
			if (!settled || !n.complete) {
				allResolved = false;
			}
		}
		if (allResolved) {
			for (Address h : r.heads.caseHeads) {
				if (h.equals(r.d.entry) || r.heads.defaults.contains(h) || targeted.contains(h)) {
					continue;
				}
				r.lowConfidence = true;
				r.confidenceNote = "case head " + h + " is reached by no recovered edge although every case resolved:"
						+ " a decision the exploration never saw (hoisted select?) or dead code; nothing patched";
				r.log.add("WARN low confidence: " + r.confidenceNote);
				return;
			}
		}
	}

	// ------------------------------------------- dispatcher path effects ----

	/**
	 * What the dispatcher did to the machine on one recovered edge, beyond
	 * reading the state. -O0 trees are side-effect free; -O2 trees interleave
	 * register copies (PHI resolution, rematerialised constants, spill reloads)
	 * that the successor block relies on. A patch that bypasses the dispatcher
	 * must replay {@link #live} in order; {@link #deadRegs} are the state /
	 * compare scratch registers whose values nobody downstream reads.
	 */
	public static final class PathEffects {
		public final List<Instruction> live = new ArrayList<Instruction>();
		public final List<Instruction> dropped = new ArrayList<Instruction>(); // region instructions judged dead (diagnostics)
		public final Set<String> deadRegs = new HashSet<String>();
		/**
		 * Registers that, when the original path lands on the successor, hold a
		 * value computed FROM the state (state copies, decoded states, compare
		 * temporaries). No real code reads them; a patched function may leave
		 * anything in them, so a before/after comparison must ignore them there.
		 */
		public final Set<String> stateDerivedAtEnd = new HashSet<String>();
		public boolean unsupported;
		public String note = "";
	}

	private static final Set<String> FLAG_NAMES = new HashSet<String>(Arrays.asList("NG", "ZR", "CY", "OV", "CF", "PF", "AF",
			"ZF", "SF", "TF", "IF", "DF", "OF", "AC", "ID", "NT", "RF", "VM", "F1", "F3", "F5", "shift_carry", "Q", "GE1",
			"GE2", "GE3", "GE4", "GE", "T"));

	public static boolean isFlagReg(Register r) {
		String n = r.getName();
		return FLAG_NAMES.contains(n) || n.startsWith("tmp") || n.equals("NZCV") || n.equals("flags") || n.equals("eflags")
				|| n.equals("rflags") || n.equals("cpsr") || n.equals("apsr");
	}

	private static boolean isFrameReg(String n) {
		return n.equals("sp") || n.equals("x29") || n.equals("fp") || n.equals("rsp") || n.equals("rbp")
				|| n.equals("esp") || n.equals("ebp") || n.equals("RSP") || n.equals("RBP") || n.equals("ESP")
				|| n.equals("EBP") || n.equals("SP") || n.equals("FP");
	}

	/** Base-register names read/written by an instruction, flags excluded. */
	public static Set<String> regNames(Object[] objs) {
		Set<String> out = new LinkedHashSet<String>();
		for (int i = 0; objs != null && i < objs.length; i++) {
			if (objs[i] instanceof Register) {
				Register r = (Register) objs[i];
				if (isFlagReg(r) || r.isProcessorContext() || r.isProgramCounter()) {
					continue;
				}
				out.add(r.getBaseRegister().getName());
			}
		}
		return out;
	}

	public static boolean writesFlags(Instruction in) {
		Object[] outs = in.getResultObjects();
		for (int i = 0; outs != null && i < outs.length; i++) {
			if (outs[i] instanceof Register && isFlagReg((Register) outs[i])) {
				return true;
			}
		}
		return false;
	}

	public static boolean hasStore(Instruction in) {
		PcodeOp[] ops = in.getPcode();
		for (int i = 0; ops != null && i < ops.length; i++) {
			if (ops[i].getOpcode() == PcodeOp.STORE) {
				return true;
			}
		}
		return false;
	}

	public static boolean hasLoad(Instruction in) {
		PcodeOp[] ops = in.getPcode();
		for (int i = 0; ops != null && i < ops.length; i++) {
			if (ops[i].getOpcode() == PcodeOp.LOAD) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Normalised text of the memory operand(s) of an instruction
	 * (`[sp,#0x1c]`, `[rbp+-0x18]`), used to match a case's state store with
	 * the dispatcher's state load without knowing the frame layout.
	 */
	public static Set<String> memOperandKeys(Instruction in) {
		Set<String> keys = new LinkedHashSet<String>();
		int n = in.getNumOperands();
		for (int i = 0; i < n; i++) {
			String rep = in.getDefaultOperandRepresentation(i);
			if (rep == null) {
				continue;
			}
			int a = rep.indexOf('[');
			int b = rep.lastIndexOf(']');
			if (a >= 0 && b > a) {
				keys.add(rep.substring(a, b + 1).replace(" ", "").toLowerCase());
			}
		}
		return keys;
	}

	/** A frame slot: base register + byte range, for store/load overlap questions on one path. */
	static final class Slot {
		final String base;
		final long lo;
		final long hi; // exclusive

		Slot(String base, long lo, long hi) {
			this.base = base;
			this.lo = lo;
			this.hi = hi;
		}

		boolean overlaps(Slot o) {
			return base.equals(o.base) && lo < o.hi && o.lo < hi;
		}

		/** Does this slot write every byte of {@code o}? */
		boolean covers(Slot o) {
			return base.equals(o.base) && lo <= o.lo && hi >= o.hi;
		}
	}

	private static final java.util.regex.Pattern SLOT_KEY =
		java.util.regex.Pattern.compile("^\\[([a-z][a-z0-9]*)(?:[,+]#?(-?0x[0-9a-f]+|-?[0-9]+))?\\]$");
	private static final java.util.regex.Pattern LITERAL_KEY = java.util.regex.Pattern.compile("^\\[(0x[0-9a-f]+|[0-9]+)\\]$");
	/** A read of the literal pool: aliases no frame slot (empty range under a base no register has). */
	private static final Slot LITERAL = new Slot("<literal>", 0, 0);

	/**
	 * The frame slot a `[base, #imm]` load/store touches, or null when the
	 * operand is not of that simple shape (register-indexed, several memory
	 * operands, no register data) — callers treat null as "could be anything".
	 */
	static Slot slotOf(Instruction in, boolean isStore) {
		Set<String> keys = memOperandKeys(in);
		if (keys.size() != 1) {
			return null;
		}
		String key = keys.iterator().next();
		if (LITERAL_KEY.matcher(key).matches()) {
			// ARM literal-pool load `ldr r1,[0x87d8]`: a constant in read-only code, never a frame slot
			return LITERAL;
		}
		// AArch64 `[x29,#-0xdc]` / `[sp]`, x86 `[rbp+-0x1c]` / `[rsp+0x10]` (keys are lower-case, space-free)
		java.util.regex.Matcher mt = SLOT_KEY.matcher(key);
		if (!mt.matches()) {
			return null;
		}
		String base = mt.group(1);
		long off = 0;
		if (mt.group(2) != null) {
			String o = mt.group(2);
			try {
				boolean neg = o.startsWith("-");
				if (neg) {
					o = o.substring(1);
				}
				off = o.startsWith("0x") ? Long.parseLong(o.substring(2), 16) : Long.parseLong(o);
				if (neg) {
					off = -off;
				}
			}
			catch (NumberFormatException e) {
				return null;
			}
		}
		Register baseReg = in.getProgram().getRegister(base);
		if (baseReg == null) {
			return null;
		}
		base = baseReg.getBaseRegister().getName();
		// bytes moved = widths of the data registers (stp x25,x30 -> 16, stur w26 -> 4)
		Object[] objs = isStore ? in.getInputObjects() : in.getResultObjects();
		long size = 0;
		for (int i = 0; objs != null && i < objs.length; i++) {
			if (objs[i] instanceof Register) {
				Register r = (Register) objs[i];
				if (r.getBaseRegister().getName().equals(base) || isFrameReg(r.getName())) {
					continue;
				}
				size += Math.max(1, r.getBitLength() / 8);
			}
		}
		if (size == 0) {
			return null;
		}
		return new Slot(base, off, off + size);
	}

	/**
	 * Can the instruction be copied byte-for-byte to another address? No flow,
	 * no PC-relative or absolute memory operand (Ghidra resolves those to an
	 * Address input/result object; register-relative operands do not produce
	 * one and stay valid wherever the bytes live).
	 */
	public static boolean isRelocatable(Instruction in) {
		FlowType ft = in.getFlowType();
		if (ft == null || !ft.isFallthrough() || ft.isJump() || ft.isCall() || ft.isTerminal()) {
			return false;
		}
		String m = in.getMnemonicString().toLowerCase();
		if (m.equals("adrp") || m.equals("adr") || m.equals("auipc") || m.startsWith("prfm")) {
			return false;
		}
		Object[] ins = in.getInputObjects();
		for (int i = 0; ins != null && i < ins.length; i++) {
			if (ins[i] instanceof Address && ((Address) ins[i]).isMemoryAddress()) {
				return false;
			}
			if (ins[i] instanceof Register && ((Register) ins[i]).isProgramCounter()) {
				return false;
			}
		}
		Object[] outs = in.getResultObjects();
		for (int i = 0; outs != null && i < outs.length; i++) {
			// unnamed register-space lanes (fmov zeroing the upper vector lanes) are fine
			if (outs[i] instanceof Address && ((Address) outs[i]).isMemoryAddress()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Registers the successor block overwrites before reading them: a value the
	 * dispatcher left in such a register is dead on arrival (-O0 code kills
	 * every scratch register at block entry; -O2 code may carry values through).
	 */
	public static Set<String> killedOnEntry(Program program, Address head) {
		Set<String> killed = new HashSet<String>();
		Set<String> seen = new HashSet<String>();
		if (head == null) {
			return killed;
		}
		Instruction in = program.getListing().getInstructionAt(head);
		for (int i = 0; in != null && i < 64; i++) {
			FlowType ft = in.getFlowType();
			boolean call = ft != null && ft.isCall();
			if (call) {
				// the callee may read every argument register still standing ...
				for (Register r : argRegisters(program)) {
					seen.add(r.getBaseRegister().getName());
				}
				// ... and clobbers every caller-saved register, so a value the
				// dispatcher left there is dead unless something read it first
				for (String r : killedByCall(program)) {
					if (seen.add(r)) {
						killed.add(r);
					}
				}
				if (ft.isTerminal()) {
					break;
				}
			}
			else {
				for (String r : regNames(in.getInputObjects())) {
					seen.add(r);
				}
				for (String r : regNames(in.getResultObjects())) {
					if (seen.add(r)) {
						killed.add(r);
					}
				}
			}
			if (ft != null && !call && (ft.isJump() || ft.isTerminal())) {
				break;
			}
			Address next = in.getFallThrough();
			in = next == null ? null : program.getListing().getInstructionAt(next);
		}
		return killed;
	}

	private static Map<Program, Set<String>> killedByCallCache = new HashMap<Program, Set<String>>();

	/** Base names of the registers the default calling convention lets a callee clobber. */
	public static Set<String> killedByCall(Program program) {
		Set<String> out = killedByCallCache.get(program);
		if (out != null) {
			return out;
		}
		out = new HashSet<String>();
		try {
			ghidra.program.model.lang.PrototypeModel model = program.getCompilerSpec().getDefaultCallingConvention();
			ghidra.program.model.pcode.Varnode[] kill = model == null ? null : model.getKilledByCallList();
			for (int i = 0; kill != null && i < kill.length; i++) {
				Register r = program.getRegister(kill[i].getAddress(), kill[i].getSize());
				if (r == null) {
					r = program.getRegister(kill[i].getAddress());
				}
				if (r != null && !isFlagReg(r)) {
					out.add(r.getBaseRegister().getName());
				}
			}
			// the link register is rewritten by the call itself
			Register lr = program.getRegister("lr");
			if (lr == null) {
				lr = program.getRegister("x30");
			}
			if (lr != null) {
				out.add(lr.getBaseRegister().getName());
			}
		}
		catch (Exception e) {
			// no convention information: nothing is assumed clobbered
		}
		killedByCallCache.put(program, out);
		return out;
	}

	/**
	 * Classify the dispatcher instructions executed on one edge (see
	 * {@link Node#pathTo}). {@code successor} is the head the edge lands on;
	 * registers it overwrites before reading are dead at the end of the path.
	 */
	public static PathEffects analyzeRegionPath(Program program, List<Address> trace, Address successor) {
		return analyzeRegionPath(program, trace, successor, Collections.<String> emptySet());
	}

	/**
	 * @param alwaysDead base names of registers nobody outside the dispatcher
	 *                   ever reads (the state register): writes to them are dead
	 *                   wherever they occur
	 */
	public static PathEffects analyzeRegionPath(Program program, List<Address> trace, Address successor,
			Set<String> alwaysDead) {
		return analyzeRegionPath(program, trace, successor, alwaysDead, alwaysDead, Collections.<String> emptySet());
	}

	/**
	 * @param derivedSeed registers holding the state when the path starts: a value
	 *                    computed FROM one of them (copy, xor-decode, compare
	 *                    temporary) is dispatcher-internal and dead. A write INTO
	 *                    one of them from elsewhere (an immediate: a hoisted
	 *                    `state = NEXT`) is NOT dead — the successor may rely on it
	 * @param stateSlots  frame slots the dispatcher keeps the state / its spills in
	 *                    (see {@link #regionLoadSlots}); a reload from one of them
	 *                    is a state-derived value
	 */
	public static PathEffects analyzeRegionPath(Program program, List<Address> trace, Address successor,
			Set<String> alwaysDead, Set<String> derivedSeed, Set<String> stateSlots) {
		PathEffects pe = new PathEffects();
		if (trace == null || trace.isEmpty()) {
			return pe;
		}
		Set<String> killed = killedOnEntry(program, successor);
		Listing listing = program.getListing();
		int n = trace.size();
		Instruction[] ins = new Instruction[n];
		List<Set<String>> reads = new ArrayList<Set<String>>(n);
		List<Set<String>> writes = new ArrayList<Set<String>>(n);
		boolean[] flow = new boolean[n];
		boolean[] pureCmp = new boolean[n];
		boolean[] store = new boolean[n];
		boolean[] flags = new boolean[n];
		for (int i = 0; i < n; i++) {
			Instruction in = listing.getInstructionAt(trace.get(i));
			if (in == null) {
				pe.unsupported = true;
				pe.note = "no instruction @" + trace.get(i);
				return pe;
			}
			ins[i] = in;
			FlowType ft = in.getFlowType();
			flow[i] = ft != null && (ft.isJump() || ft.isCall() || ft.isTerminal());
			reads.add(regNames(in.getInputObjects()));
			writes.add(regNames(in.getResultObjects()));
			flags[i] = writesFlags(in);
			store[i] = hasStore(in);
			pureCmp[i] = !flow[i] && !store[i] && flags[i] && writes.get(i).isEmpty();
			if (store[i] && !isStackStore(in)) {
				pe.unsupported = true;
				pe.note = "memory store inside dispatcher @" + in.getMinAddress() + " (" + in + ")";
				return pe;
			}
		}
		// Liveness is decided per WRITE, never per register: an -O2 tree path
		// loops through the dispatcher several times, and the copy `mov w28,w8`
		// of pass 1 is dead (overwritten in pass 2) while the same instruction
		// in the last pass is what the successor relies on. The only registers
		// dead everywhere are the state register(s) the caller names.
		// (`sub eax,K ; je` style compares-in-disguise need no special case: the
		// per-write analysis below finds their GPR result unread and killed.)
		Set<String> dead = new HashSet<String>(alwaysDead);
		boolean[] deadInsn = new boolean[n];
		// values computed from the state are as dead as the state itself: a copy
		// of it (`mov w8,w9`), an xor-decoded state, a `sub`/compare temporary.
		// Track them forward; a register stops being state-derived as soon as
		// something unrelated is written into it.
		boolean[] stateDerived = new boolean[n];
		boolean[] stateSpill = new boolean[n]; // store whose every stored value is state-derived at that point
		Set<String> derivedRegs = new HashSet<String>(derivedSeed);
		derivedRegs.addAll(alwaysDead);
		for (int i = 0; i < n; i++) {
			boolean load = hasLoad(ins[i]);
			boolean fromStateReg = !load && !Collections.disjoint(reads.get(i), derivedRegs);
			boolean fromStateSlot = load && !stateSlots.isEmpty()
					&& !Collections.disjoint(memOperandKeys(ins[i]), stateSlots); // reload of the (spilled) state
			if (store[i]) {
				Set<String> vals = new HashSet<String>(reads.get(i));
				for (java.util.Iterator<String> it = vals.iterator(); it.hasNext();) {
					if (isFrameReg(it.next())) {
						it.remove();
					}
				}
				stateSpill[i] = !vals.isEmpty() && derivedRegs.containsAll(vals);
			}
			if ((fromStateReg || fromStateSlot) && !store[i] && !writes.get(i).isEmpty()) {
				stateDerived[i] = true;
				derivedRegs.addAll(writes.get(i));
			}
			else {
				// written from something unrelated to the state (an immediate, a real
				// value): no longer state-derived — even for the state register itself
				for (String w : writes.get(i)) {
					if (!alwaysDead.contains(w)) {
						derivedRegs.remove(w);
					}
				}
			}
		}
		pe.stateDerivedAtEnd.addAll(derivedRegs);
		pe.stateDerivedAtEnd.removeAll(alwaysDead);
		pe.stateDerivedAtEnd.removeAll(derivedSeed);
		// copy propagation: the -O2 PHI dance copies stable -> in-flight registers
		// and back (`mov x19,x10 ... mov x10,x19`); a register move whose source
		// already equals its destination is a no-op and need not be replayed.
		// A no-op does not count as an overwrite either: the equality it relies on
		// was established by the earlier copy, which must therefore stay live.
		boolean[] noop = new boolean[n];
		markNoopCopies(ins, reads, writes, store, flags, noop);
		for (int i = 0; i < n; i++) {
			deadInsn[i] |= noop[i];
		}
		// Stack stores. The successor may reload any frame slot the dispatcher
		// wrote (-O2 spills real values through the tree: `ldp w13,w20,[x29,#-0x18]
		// ... stur w13,[x29,#-0xdc]` and real code reloads -0xdc later), so a store
		// is live unless
		//  (a) it spills a state-derived value (only the dispatcher reads those), or
		//  (b) a later store on this path overwrites the very same slot before
		//      anything reads it,
		// and in both cases only when no later load on the path can read the slot
		// — a dropped store followed by a replayed load of its slot would read
		// stale memory. Whether the STORED register was produced inside the
		// region says nothing: a value loaded from a real slot is real.
		// The loads that may read each store's slot are collected once; whether
		// they keep the store alive depends on whether they are live themselves
		// (a reload of a spilled state copy is dropped, and then so is the
		// spill), so the store verdict is recomputed inside the fixpoint below.
		boolean[] liveStore = new boolean[n];
		boolean[] storeUnknown = new boolean[n];   // slot not understood / base changes: assume read
		boolean[] overwritten = new boolean[n];
		List<List<Integer>> readers = new ArrayList<List<Integer>>(n);
		for (int i = 0; i < n; i++) {
			readers.add(null);
			if (!store[i]) {
				continue;
			}
			List<Integer> rd = new ArrayList<Integer>();
			readers.set(i, rd);
			Slot s = slotOf(ins[i], true);
			if (s == null) {
				storeUnknown[i] = true;
				continue;
			}
			for (int j = i + 1; j < n; j++) {
				if (writes.get(j).contains(s.base)) {
					storeUnknown[i] = true; // base register changes: slot identity lost
					break;
				}
				if (hasLoad(ins[j])) {
					Slot l = slotOf(ins[j], false);
					if (l == null) {
						storeUnknown[i] = true;
						break;
					}
					if (l.overlaps(s)) {
						rd.add(Integer.valueOf(j));
					}
				}
				if (store[j]) {
					Slot t = slotOf(ins[j], true);
					if (t == null) {
						storeUnknown[i] = true;
						break;
					}
					if (t.covers(s)) {
						overwritten[i] = true;
						break;
					}
				}
			}
		}
		boolean changed = true;
		while (changed) {
			changed = false;
			for (int i = 0; i < n; i++) {
				if (!store[i]) {
					continue;
				}
				boolean readLive = storeUnknown[i];
				for (Integer j : readers.get(i)) {
					if (!deadInsn[j.intValue()]) {
						readLive = true;
					}
				}
				liveStore[i] = readLive || !(stateSpill[i] || overwritten[i]);
			}
			for (int i = 0; i < n; i++) {
				if (deadInsn[i]) {
					continue;
				}
				if (flow[i] || pureCmp[i] || stateDerived[i] || (store[i] && !liveStore[i])) {
					deadInsn[i] = true;
					changed = true;
					continue;
				}
				if (store[i]) {
					continue; // live spill: replicated
				}
				Set<String> wr = writes.get(i);
				if (wr.isEmpty()) {
					deadInsn[i] = true; // nop / hint / flag-only
					changed = true;
					continue;
				}
				boolean all = true;
				for (String reg : wr) {
					if (alwaysDead.contains(reg)) {
						continue;
					}
					if (!regDeadAfter(i, reg, n, reads, writes, deadInsn, noop, store, liveStore, killed)) {
						all = false;
					}
				}
				if (all) {
					deadInsn[i] = true;
					changed = true;
				}
			}
		}
		for (int i = 0; i < n; i++) {
			if (deadInsn[i]) {
				pe.dropped.add(ins[i]);
				continue;
			}
			if (!isRelocatable(ins[i])) {
				pe.unsupported = true;
				pe.note = "live dispatcher instruction cannot be relocated: " + ins[i].getMinAddress() + "  " + ins[i];
				return pe;
			}
			pe.live.add(ins[i]);
		}
		// registers whose every write on this path is dead AND that the
		// successor kills on entry carry nothing across the patch; they are the
		// only ones a before/after register comparison may ignore
		for (int i = 0; i < n; i++) {
			if (!deadInsn[i]) {
				continue;
			}
			for (String reg : writes.get(i)) {
				if (alwaysDead.contains(reg) || killed.contains(reg)) {
					dead.add(reg);
				}
			}
		}
		pe.deadRegs.addAll(dead);
		return pe;
	}

	/** A plain full-width register-to-register move (`mov x19,x10`, `mov rax,rcx`): [dst, src] or null. */
	private static String[] plainMove(Instruction in, Set<String> reads, Set<String> writes, boolean store, boolean flags) {
		if (store || flags || reads.size() != 1 || writes.size() != 1 || hasLoad(in)) {
			return null;
		}
		String m = in.getMnemonicString().toLowerCase();
		if (!m.equals("mov") || in.getNumOperands() != 2) {
			return null;
		}
		Register rd = in.getRegister(0);
		Register rs = in.getRegister(1);
		if (rd == null || rs == null || rd.getBitLength() != rs.getBitLength()) {
			return null;
		}
		// `mov w8,w28` writes only the low half of x8 (the upper half is zeroed):
		// equivalence is therefore tracked per exact view (w8 ~ w28), never per base
		String dstBase = rd.getBaseRegister().getName();
		String srcBase = rs.getBaseRegister().getName();
		viewBase.put(rd.getName(), dstBase);
		viewBase.put(rs.getName(), srcBase);
		return new String[] { dstBase, srcBase, rd.getName(), rs.getName() };
	}

	/**
	 * Mark register moves that copy a value onto itself. Equivalence is tracked
	 * per exact register view (x19 vs w19) and killed by any other write to
	 * either base register, so a 32-bit copy never masks a 64-bit difference.
	 */
	private static void markNoopCopies(Instruction[] ins, List<Set<String>> reads, List<Set<String>> writes,
			boolean[] store, boolean[] flags, boolean[] deadInsn) {
		// eq[view] = the view it currently mirrors (canonical representative)
		Map<String, String> eq = new HashMap<String, String>();
		// bases whose upper half is known to be zero (last written by a sub-width move in this trace)
		Set<String> upperZero = new HashSet<String>();
		for (int i = 0; i < ins.length; i++) {
			String[] mv = plainMove(ins[i], reads.get(i), writes.get(i), store[i], flags[i]);
			if (mv != null) {
				String dstBase = mv[0];
				String dstView = mv[2];
				String srcView = mv[3];
				Register rd = ins[i].getRegister(0);
				boolean fullWidth = rd != null && rd.getBitLength() == rd.getBaseRegister().getBitLength();
				String srcRep = eq.containsKey(srcView) ? eq.get(srcView) : srcView;
				String dstRep = eq.containsKey(dstView) ? eq.get(dstView) : dstView;
				// a sub-width move also zeroes the upper half of dst: only a no-op when
				// that half is already known to be zero
				if (srcRep.equals(dstRep) && (fullWidth || upperZero.contains(dstBase))) {
					deadInsn[i] = true; // dst already holds src
					continue;
				}
				dropBase(eq, dstBase);
				eq.put(dstView, srcRep);
				if (fullWidth) {
					upperZero.remove(dstBase);
				}
				else {
					upperZero.add(dstBase);
				}
				continue;
			}
			for (String w : writes.get(i)) {
				dropBase(eq, w);
				upperZero.remove(w);
			}
		}
	}

	private static void dropBase(Map<String, String> eq, String base) {
		java.util.Iterator<Map.Entry<String, String>> it = eq.entrySet().iterator();
		Set<String> victims = new HashSet<String>();
		while (it.hasNext()) {
			Map.Entry<String, String> e = it.next();
			if (baseOf(e.getKey()).equals(base) || baseOf(e.getValue()).equals(base)) {
				victims.add(e.getKey());
				victims.add(e.getValue());
				it.remove();
			}
		}
		// views that mirrored a victim are no longer known to equal anything
		it = eq.entrySet().iterator();
		while (it.hasNext()) {
			if (victims.contains(it.next().getValue())) {
				it.remove();
			}
		}
	}

	/** Best-effort base name of a register view name (x19/w19 -> x19, rax/eax -> rax) for the equivalence bookkeeping. */
	private static Map<String, String> viewBase = new HashMap<String, String>();

	private static String baseOf(String view) {
		String b = viewBase.get(view);
		return b == null ? view : b;
	}

	/**
	 * Is the value written to {@code reg} at position i consumed only by dead
	 * instructions (compares, dead spills) before being overwritten? A value
	 * still standing when the trace lands on the successor is potentially live.
	 */
	private static boolean regDeadAfter(int i, String reg, int n, List<Set<String>> reads, List<Set<String>> writes,
			boolean[] deadInsn, boolean[] noop, boolean[] store, boolean[] liveStore, Set<String> killedOnEntry) {
		for (int j = i + 1; j < n; j++) {
			if (reads.get(j).contains(reg)) {
				boolean deadReader = deadInsn[j] || (store[j] && !liveStore[j]);
				if (!deadReader) {
					return false;
				}
			}
			if (writes.get(j).contains(reg) && !noop[j]) {
				return true; // really overwritten (a no-op copy only re-establishes the same value)
			}
		}
		// still standing when the successor is entered: dead only if the
		// successor overwrites it before reading it
		return killedOnEntry.contains(reg);
	}

	// ------------------------------------------------- whole-function trace --

	/**
	 * One head visit: which head, at which step, and the register file as a
	 * flat array (index i = {@link #traceRegisters}(program).get(i)). Kept
	 * flat on purpose: a whole-program verify keeps thousands of visits alive.
	 */
	public static final class TraceEvent {
		public Address head;
		public int step;
		public long[] regs;
		/**
		 * Copy provenance: {@code prov[i] = j} when register i currently holds a
		 * value that arrived through plain register moves from register j (the
		 * root of the copy chain), -1 when it was computed. Lets the comparison
		 * treat a real-code copy of dispatcher garbage (`mov x26,x24` where x24
		 * is a state copy) as garbage too.
		 */
		public int[] prov;
	}

	private static Map<Program, List<Register>> traceRegCache = new HashMap<Program, List<Register>>();

	/** Registers a verification trace records: base GPRs of 32..64 bits (vector/flag/context registers excluded). */
	public static List<Register> traceRegisters(Program program) {
		List<Register> gprs = traceRegCache.get(program);
		if (gprs != null) {
			return gprs;
		}
		gprs = new ArrayList<Register>();
		Register[] all = program.getLanguage().getRegisters().toArray(new Register[0]);
		for (int i = 0; i < all.length; i++) {
			Register r = all[i];
			if (r.isBaseRegister() && !r.isProcessorContext() && !r.isProgramCounter() && !r.isHidden() && !isFlagReg(r)
					&& r.getBitLength() >= 32 && r.getBitLength() <= 64) {
				gprs.add(r);
			}
		}
		traceRegCache.put(program, gprs);
		return gprs;
	}

	/**
	 * Run the function concretely from {@code entry} (zeroed inputs, calls
	 * stepped over, divide faults skipped) and record the register file each
	 * time a watched head is reached. Used to compare the original and the
	 * patched function: same heads in the same order with the same live
	 * registers means the patch preserved the real control flow.
	 */
	public static List<TraceEvent> traceRun(Program program, Function f, Address entry, Set<Address> watch, int maxHeads,
			int maxSteps, TaskMonitor monitor) {
		return traceRun(program, f, entry, watch, maxHeads, maxSteps, monitor, null);
	}

	/**
	 * Input vector for one verification trace: the value written to every
	 * potential argument register of the default calling convention (index i
	 * gets {@code args[i % args.length]}) and the byte every uninitialised
	 * memory read returns. Different seeds drive the function down different
	 * real branches, so the before/after comparison covers more than one path.
	 */
	public static final class TraceSeed {
		public final String name;
		public final long[] args;
		public final byte fill;

		public TraceSeed(String name, long[] args, byte fill) {
			this.name = name;
			this.args = args;
			this.fill = fill;
		}
	}

	/** The input vectors every verification trace is run under (CffDeflatten, BcfClean): different seeds drive different real branches. */
	public static final TraceSeed[] VERIFY_SEEDS = {
		new TraceSeed("zero", new long[] { 0 }, (byte) 0),
		new TraceSeed("small", new long[] { 1, 2, 3, 4, 5, 6, 7, 8 }, (byte) 0x01),
		new TraceSeed("ones", new long[] { -1L }, (byte) 0xFF),
		new TraceSeed("ptr", new long[] { 0x7ff000020000L, 0x7ff000030000L, 0x10, 0x7ff000040000L }, (byte) 0x41),
	};

	/** Argument registers of the program's default calling convention, in order. */
	public static List<Register> argRegisters(Program program) {
		List<Register> out = new ArrayList<Register>();
		try {
			ghidra.program.model.lang.PrototypeModel model = program.getCompilerSpec().getDefaultCallingConvention();
			if (model == null) {
				return out;
			}
			ghidra.program.model.listing.VariableStorage[] pot = model.getPotentialInputRegisterStorage(program);
			for (int i = 0; pot != null && i < pot.length; i++) {
				Register r = pot[i].getRegister();
				if (r != null && !out.contains(r) && !isFlagReg(r) && !r.isProgramCounter()) {
					out.add(r);
				}
			}
		}
		catch (Exception e) {
			// no convention information: unseeded trace
		}
		return out;
	}

	public static List<TraceEvent> traceRun(Program program, Function f, Address entry, Set<Address> watch, int maxHeads,
			int maxSteps, TaskMonitor monitor, TraceSeed seed) {
		List<TraceEvent> out = new ArrayList<TraceEvent>();
		Listing listing = program.getListing();
		AddressSetView body = f.getBody();
		List<Register> gprs = traceRegisters(program);
		Map<String, Integer> gprIndex = new HashMap<String, Integer>();
		for (int i = 0; i < gprs.size(); i++) {
			gprIndex.put(gprs.get(i).getName(), Integer.valueOf(i));
		}
		int[] prov = new int[gprs.size()];
		Arrays.fill(prov, -1);
		EmulatorHelper emu = null;
		try {
			emu = newEmulator(program, false, seed == null ? (byte) 0 : seed.fill);
			Register pc = emu.getPCRegister();
			if (seed != null && seed.args != null && seed.args.length > 0) {
				List<Register> argRegs = argRegisters(program);
				for (int i = 0; i < argRegs.size(); i++) {
					Register r = argRegs.get(i);
					BigInteger v = BigInteger.valueOf(seed.args[i % seed.args.length]);
					BigInteger mask = BigInteger.ONE.shiftLeft(r.getBitLength()).subtract(BigInteger.ONE);
					try {
						emu.writeRegister(r, v.and(mask));
					}
					catch (Exception e) {
						// not writable on this language
					}
				}
			}
			emu.writeRegister(pc, entry.getOffset());
			for (int step = 0; step < maxSteps && out.size() < maxHeads; step++) {
				if (monitor.isCancelled()) {
					break;
				}
				Address cur = emu.getExecutionAddress();
				if (cur == null || !body.contains(cur)) {
					break;
				}
				if (watch.contains(cur)) {
					TraceEvent ev = new TraceEvent();
					ev.head = cur;
					ev.step = step;
					ev.regs = new long[gprs.size()];
					for (int i = 0; i < gprs.size(); i++) {
						try {
							ev.regs[i] = emu.readRegister(gprs.get(i)).longValue();
						}
						catch (Exception e) {
							ev.regs[i] = 0; // unreadable on this language
						}
					}
					ev.prov = prov.clone();
					out.add(ev);
				}
				Instruction in = listing.getInstructionAt(cur);
				if (in == null) {
					break;
				}
				FlowType ft = in.getFlowType();
				if (ft != null && ft.isCall()) {
					if (ft.isTerminal()) {
						break;
					}
					// a real callee clobbers every caller-saved register; model that
					// deterministically so a value that only survives because the call
					// was skipped is the same garbage in the original and patched traces
					for (String name : killedByCall(program)) {
						Register r = program.getRegister(name);
						if (r != null && !r.equals(pc)) {
							try {
								emu.writeRegister(r, BigInteger.ZERO);
							}
							catch (Exception e) {
								// not writable
							}
							Integer k = gprIndex.get(r.getBaseRegister().getName());
							if (k != null) {
								prov[k.intValue()] = -1;
							}
						}
					}
					advancePast(emu, pc, in);
					continue;
				}
				if (ft != null && ft.isTerminal()) {
					break;
				}
				trackProvenance(in, gprIndex, prov);
				if (!emu.step(monitor)) {
					String err = String.valueOf(emu.getLastError());
					if (err.toLowerCase().contains("divide")) {
						advancePast(emu, pc, in);
						continue;
					}
					break;
				}
			}
		}
		catch (Exception e) {
			// return what we have
		}
		finally {
			if (emu != null) {
				try {
					emu.dispose();
				}
				catch (Exception e) {
					// ignore
				}
			}
		}
		return out;
	}

	/**
	 * Update copy provenance for one instruction about to execute: a plain
	 * full-width register move makes the destination mirror the source's root;
	 * every other write is a computed value (root = itself, encoded as -1).
	 */
	private static void trackProvenance(Instruction in, Map<String, Integer> gprIndex, int[] prov) {
		Object[] outs = in.getResultObjects();
		if (outs == null || outs.length == 0) {
			return;
		}
		String m = in.getMnemonicString().toLowerCase();
		boolean plain = m.equals("mov") && in.getNumOperands() == 2 && !hasLoad(in) && !hasStore(in) && !writesFlags(in);
		if (plain) {
			Register rd = in.getRegister(0);
			Register rs = in.getRegister(1);
			if (rd != null && rs != null && rd.getBitLength() == rs.getBitLength()
					&& rd.getBitLength() == rd.getBaseRegister().getBitLength()) {
				Integer d = gprIndex.get(rd.getBaseRegister().getName());
				Integer s = gprIndex.get(rs.getBaseRegister().getName());
				if (d != null && s != null) {
					int root = prov[s.intValue()] >= 0 ? prov[s.intValue()] : s.intValue();
					prov[d.intValue()] = root == d.intValue() ? -1 : root;
					return;
				}
			}
		}
		for (int i = 0; i < outs.length; i++) {
			if (outs[i] instanceof Register) {
				Integer d = gprIndex.get(((Register) outs[i]).getBaseRegister().getName());
				if (d != null) {
					prov[d.intValue()] = -1;
				}
			}
		}
	}

	// --------------------------------------------------- misc helpers --------

	public static boolean isExecutable(Program program, Address a) {
		if (a == null) {
			return false;
		}
		Memory mem = program.getMemory();
		MemoryBlock b = mem.getBlock(a);
		return b != null && b.isExecute();
	}

	public static String hex(long v) {
		return "0x" + Long.toHexString(v);
	}
}
