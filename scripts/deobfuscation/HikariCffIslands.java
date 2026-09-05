// HikariCffIslands — classify reloc-filled CFF table destinations into
// dispatcher vs work island, and bookmark the work ones.
//
// Companion to CFFDispatchTracer: that script finds/labels the pointer tables
// in .data/.bss; this one walks each unique destination, decodes a short
// window of instructions, and decides "just another dispatcher" vs "a basic
// block that does real work" (SVC, byte XOR, a BL into a primitive).
//
// The structural half (dispatcher vs work; svc / byte_xor / call) is generic
// AArch64 and works on any Hikari/OLLVM-flattened target.
//
// @category Deobfuscation
// @menupath Tools.Deobfuscation.Hikari CFF Islands
// @description Classify Hikari CFF dests: drop dispatchers, bookmark work islands

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class HikariCffIslands extends GhidraScript {

	private static final int DEFAULT_MIN_RUN = 32;
	private static final int MAX_ISLAND = 48;
	private static final String BOOKMARK_CATEGORY = "CFF";

	private int minRun;
	private long maxBlockBytes; // 0 = unlimited
	private boolean dryRun;
	private boolean doDisasm;

	private Memory mem;
	private Listing listing;
	private List<MemoryBlock> exec;
	private List<MemoryBlock> data;

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		parseArgs();
		int ptr = currentProgram.getDefaultPointerSize();
		if (ptr != 8) {
			printerr("HikariCffIslands wants a 64-bit program (AArch64); pointer size=" + ptr);
			return;
		}
		mem = currentProgram.getMemory();
		listing = currentProgram.getListing();
		collectLayout();
		if (exec.isEmpty() || data.isEmpty()) {
			printerr("need at least one executable block and one data block (exec=" + exec.size()
					+ " data=" + data.size() + ")");
			return;
		}

		println("=== HikariCffIslands ===");
		println("program=" + currentProgram.getName() + " language=" + currentProgram.getLanguageID());
		println("execBlocks=" + exec.size() + " dataBlocks=" + data.size() + " minRun=" + minRun
				+ " dryRun=" + dryRun + " disasm=" + doDisasm);

		if (doDisasm) {
			ensureDisassembled();
		}

		List<Run> runs = findRuns();
		println("runs=" + runs.size());
		for (int i = 0; i < runs.size(); i++) {
			Run r = runs.get(i);
			println("  run @ " + r.start + " n=" + r.dests.size());
		}

		Set<Address> uniq = new HashSet<Address>();
		for (int i = 0; i < runs.size(); i++) {
			uniq.addAll(runs.get(i).dests);
		}

		int disp = 0;
		int work = 0;
		int tagged = 0;
		int undecoded = 0;
		Map<String, Integer> byTag = new TreeMap<String, Integer>();
		for (Address dest : uniq) {
			if (monitor.isCancelled()) {
				break;
			}
			Island is = decodeIsland(dest);
			if (is.empty) {
				undecoded++;
				continue;
			}
			if (is.dispatcher) {
				disp++;
				continue;
			}
			work++;
			String tag = tagIsland(is);
			if (tag == null) {
				continue;
			}
			tagged++;
			bump(byTag, tag);
			if (!dryRun) {
				annotate(dest, tag);
			}
		}

		println("uniqueDests=" + uniq.size() + " dispatcher=" + disp + " work=" + work + " tagged=" + tagged
				+ " undecoded=" + undecoded);
		for (Map.Entry<String, Integer> e : byTag.entrySet()) {
			println("  tag " + e.getKey() + " = " + e.getValue());
		}
		if (undecoded > 0 && !doDisasm) {
			println("note: " + undecoded + " dests had no instructions and disasm was off; drop noDisasm to classify them");
		}
		println("done. See docs/scripts/HikariCffIslands.md");
	}

	private void parseArgs() {
		minRun = DEFAULT_MIN_RUN;
		maxBlockBytes = 0;
		dryRun = false;
		doDisasm = true;
		String[] args = getScriptArgs();
		if (args == null) {
			return;
		}
		for (int i = 0; i < args.length; i++) {
			String a = args[i];
			if (a == null) {
				continue;
			}
			if (a.equals("dryRun")) {
				dryRun = true;
			}
			else if (a.equals("noDisasm")) {
				doDisasm = false;
			}
			else if (a.startsWith("minRun=")) {
				try {
					minRun = Integer.parseInt(a.substring("minRun=".length()));
				}
				catch (Exception e) {
					printerr("bad minRun=, keeping " + minRun);
				}
			}
			else if (a.startsWith("maxBlockMiB=")) {
				try {
					maxBlockBytes = Long.parseLong(a.substring("maxBlockMiB=".length())) * 1024L * 1024L;
				}
				catch (Exception e) {
					printerr("bad maxBlockMiB=, keeping unlimited");
				}
			}
		}
		if (minRun < 1) {
			minRun = 1;
		}
	}

	private void collectLayout() {
		exec = new ArrayList<MemoryBlock>();
		data = new ArrayList<MemoryBlock>();
		MemoryBlock[] blocks = mem.getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			MemoryBlock b = blocks[i];
			if (b.isExecute()) {
				exec.add(b);
			}
			else if (isDataish(b)) {
				data.add(b);
			}
		}
	}

	// Mirrors CFFDispatchTracer.isDataish so const/RELRO pointer tables
	// (.data.rel.ro, mapped read-only after relocation) are not dropped.
	private boolean isDataish(MemoryBlock b) {
		if (b.isExecute()) {
			return false;
		}
		String n = b.getName().toLowerCase();
		if (n.contains("external") || n.equals("headers") || n.contains("overlay") || n.contains("got")
				|| n.contains("plt") || n.contains("extern") || n.contains("reloc") || n.contains("eh_frame")
				|| n.contains("gcc_except") || n.contains("mod_init") || n.contains("mod_term")
				|| n.contains("objc")) {
			return false;
		}
		if (n.contains(".data") || n.contains(".bss") || n.contains("__data") || n.contains("__bss")
				|| n.contains("data.") || n.equals("ram") || n.contains(".data.rel")) {
			return true;
		}
		return b.isWrite() || !b.isInitialized();
	}

	// The whole point of this script is that CFF dests are addresses, not
	// encrypted, so the destinations must already be instructions. On a
	// -noanalysis import .text is bytes, getInstructionAt() returns null, and
	// everything is silently "undecoded". Linear-disassemble first.
	private void ensureDisassembled() {
		long n = listing.getNumInstructions();
		long execBytes = 0;
		for (int i = 0; i < exec.size(); i++) {
			execBytes += exec.get(i).getSize();
		}
		long dense = execBytes / 8;
		if (n >= dense && n > 1000) {
			println("instructions already=" + n + " (execBytes=" + execBytes + ")");
			return;
		}
		println("sparse instructions (" + n + " / execBytes=" + execBytes + "); linear-disassembling exec blocks");
		for (int i = 0; i < exec.size() && !monitor.isCancelled(); i++) {
			MemoryBlock b = exec.get(i);
			if (!b.isInitialized()) {
				continue;
			}
			AddressSet set = new AddressSet(b.getStart(), b.getEnd());
			DisassembleCommand cmd = new DisassembleCommand(set, set, false);
			cmd.applyTo(currentProgram, monitor);
		}
		println("instructions now=" + listing.getNumInstructions());
	}

	private List<Run> findRuns() {
		List<Run> runs = new ArrayList<Run>();
		for (int bi = 0; bi < data.size() && !monitor.isCancelled(); bi++) {
			MemoryBlock b = data.get(bi);
			if (!b.isInitialized()) {
				continue;
			}
			if (maxBlockBytes > 0 && b.getSize() > maxBlockBytes) {
				println("skip large data block " + b.getName() + " size=" + b.getSize() + " (> maxBlockMiB)");
				continue;
			}
			monitor.setMessage("HikariCffIslands scan " + b.getName());
			Address a = alignUp(b.getStart(), 8);
			Address end = b.getEnd();
			Run cur = null;
			while (a != null && a.compareTo(end) <= 0 && !monitor.isCancelled()) {
				Address dest = readCodePtr(a);
				if (dest != null) {
					if (cur == null) {
						cur = new Run();
						cur.start = a;
					}
					cur.dests.add(dest);
					cur.end = a;
				}
				else {
					if (cur != null && cur.dests.size() >= minRun) {
						runs.add(cur);
					}
					cur = null;
				}
				a = addOrNull(a, 8);
			}
			if (cur != null && cur.dests.size() >= minRun) {
				runs.add(cur);
			}
		}
		return runs;
	}

	private Address readCodePtr(Address slot) {
		long raw;
		try {
			raw = mem.getLong(slot);
		}
		catch (MemoryAccessException e) {
			return null;
		}
		if (raw == 0) {
			return null;
		}
		try {
			Address a = slot.getAddressSpace().getAddress(raw);
			if (a != null && isExec(a)) {
				return a;
			}
		}
		catch (Exception e) {
			return null;
		}
		return null;
	}

	private boolean isExec(Address a) {
		for (int i = 0; i < exec.size(); i++) {
			if (exec.get(i).contains(a)) {
				return true;
			}
		}
		return false;
	}

	private Island decodeIsland(Address start) {
		Island is = new Island();
		is.addr = start;
		Instruction in = listing.getInstructionAt(start);
		if (in == null && doDisasm) {
			try {
				disassemble(start);
			}
			catch (Exception e) {
				// leave null; counted as undecoded
			}
			in = listing.getInstructionAt(start);
		}
		if (in == null) {
			is.empty = true;
			return is;
		}
		int n = 0;
		while (in != null && n < MAX_ISLAND) {
			String m = in.getMnemonicString().toLowerCase();
			is.mnems.add(m);
			collectScalars(in, is.imms);
			if ((m.equals("ldr") || m.equals("ldrsw"))) {
				String rep = in.toString().toLowerCase();
				if (rep.contains("uxtw") || rep.contains("sxtw") || rep.contains("lsl #3")) {
					is.hasIndexedLoad = true;
				}
			}
			if (isCall(m, in)) {
				is.hasCall = true;
				Address[] flows = in.getFlows();
				if (flows != null) {
					for (int f = 0; f < flows.length; f++) {
						is.callTargets.add(flows[f]);
					}
				}
			}
			n++;
			if (isTerminalBranch(m)) {
				break;
			}
			in = in.getNext();
		}
		is.dispatcher = looksDispatcher(is);
		return is;
	}

	private void collectScalars(Instruction in, Set<Long> out) {
		int nops = in.getNumOperands();
		for (int i = 0; i < nops; i++) {
			Scalar sc = in.getScalar(i);
			if (sc != null) {
				out.add(Long.valueOf(sc.getUnsignedValue()));
			}
		}
	}

	private boolean isCall(String m, Instruction in) {
		if (m.equals("bl") || m.equals("blr") || m.equals("blraa") || m.equals("blrab")) {
			return true;
		}
		try {
			return in.getFlowType().isCall();
		}
		catch (Exception e) {
			return false;
		}
	}

	private boolean isTerminalBranch(String m) {
		if (m.equals("ret") || m.equals("retaa") || m.equals("retab")) {
			return true;
		}
		if (isRegBranch(m)) {
			return true;
		}
		return m.equals("b") || m.startsWith("b.");
	}

	private boolean isRegBranch(String m) {
		return m.equals("br") || m.equals("braa") || m.equals("brab") || m.equals("braaz") || m.equals("brabz");
	}

	private boolean looksDispatcher(Island is) {
		if (is.mnems.isEmpty()) {
			return false;
		}
		String last = is.mnems.get(is.mnems.size() - 1);
		if (!isRegBranch(last)) {
			return false;
		}
		boolean heavy = false;
		boolean adrp = false;
		boolean cset = false;
		for (int i = 0; i < is.mnems.size(); i++) {
			String m = is.mnems.get(i);
			if (m.equals("ldrb") || m.equals("strb") || m.equals("bl") || m.equals("blr") || m.equals("svc")
					|| m.equals("madd") || m.equals("ldp") || m.equals("stp") || m.equals("stur")
					|| m.equals("ldur")) {
				heavy = true;
			}
			if (m.equals("adrp")) {
				adrp = true;
			}
			if (m.equals("cset")) {
				cset = true;
			}
		}
		if (heavy) {
			return false;
		}
		return is.hasIndexedLoad || (adrp && cset);
	}

	private String tagIsland(Island is) {
		if (is.mnems.contains("svc")) {
			return "svc";
		}
		if (is.mnems.contains("ldrb") && is.mnems.contains("strb")) {
			return "byte_xor";
		}
		if (is.hasCall) {
			return "call";
		}
		return null;
	}

	private void annotate(Address dest, String tag) {
		currentProgram.getBookmarkManager().setBookmark(dest, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY,
				"CFF work island: " + tag);
		String add = "CFF work " + tag;
		String old = listing.getComment(CommentType.EOL, dest);
		if (old == null) {
			listing.setComment(dest, CommentType.EOL, add);
		}
		else if (old.indexOf(add) < 0) {
			listing.setComment(dest, CommentType.EOL, old + " ; " + add);
		}
		createWorkLabel(dest, tag);
	}

	private void createWorkLabel(Address dest, String tag) {
		try {
			SymbolTable st = currentProgram.getSymbolTable();
			Symbol primary = st.getPrimarySymbol(dest);
			if (primary != null && !isDefaultName(primary.getName())) {
				return;
			}
			String nm = ("cff_work_" + tag + "_" + dest).replace(':', '_').replace('.', '_').replace(' ', '_');
			createLabel(dest, nm, false);
		}
		catch (Exception e) {
			// non-fatal
		}
	}

	private boolean isDefaultName(String n) {
		if (n == null) {
			return true;
		}
		return n.startsWith("FUN_") || n.startsWith("LAB_") || n.startsWith("SUB_") || n.startsWith("DAT_")
				|| n.startsWith("cff_");
	}

	private void bump(Map<String, Integer> m, String k) {
		Integer c = m.get(k);
		m.put(k, c == null ? Integer.valueOf(1) : Integer.valueOf(c.intValue() + 1));
	}

	private Address alignUp(Address a, int align) {
		long rem = a.getOffset() % align;
		if (rem == 0) {
			return a;
		}
		return addOrNull(a, (int) (align - rem));
	}

	private Address addOrNull(Address a, int delta) {
		try {
			return a.addNoWrap(delta);
		}
		catch (Exception e) {
			return null;
		}
	}

	private static class Run {
		Address start;
		Address end;
		List<Address> dests = new ArrayList<Address>();
	}

	private static class Island {
		Address addr;
		List<String> mnems = new ArrayList<String>();
		Set<Long> imms = new HashSet<Long>();
		Set<Address> callTargets = new HashSet<Address>();
		boolean hasCall;
		boolean hasIndexedLoad;
		boolean dispatcher;
		boolean empty;
	}
}
