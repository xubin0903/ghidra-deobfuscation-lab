// CFFDispatchTracer — static recovery of OLLVM/Hikari control-flow-flattening
// dispatch tables. Algorithm follows xkilldash9x gist (CFFDispatchTracer):
//   https://gist.github.com/xkilldash9x/e8ee393a5c681677b38c58f178e203a4
//
// @category Deobfuscation
// @menupath Tools.Deobfuscation.CFF Dispatch Tracer
// @description Recover OLLVM/Hikari CFF dispatch tables (ref scan / ASLR slide / trampolines)

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class CFFDispatchTracer extends GhidraScript {

	private static final int DEFAULT_MIN_TABLE = 6;
	private static final int DEFAULT_MAX_SWITCH = 96;
	private static final int TRAMPOLINE_MAX_BYTES = 160;
	private static final int LOOKBACK_INSNS = 14;
	private static final int MBA_WINDOW = 6;

	private int ptrSize;
	private int minTable;
	private int maxSwitch;
	private boolean applySwitch;
	private boolean dryRun;
	private boolean doMba;
	private File kbFile;
	private File kbInFile;
	private File dotFile;

	private Memory mem;
	private Listing listing;
	private List<MemoryBlock> execBlocks;
	private List<MemoryBlock> dataBlocks;
	private long imageBaseOff;
	private long slide;
	private boolean slideKnown;

	private TreeMap<Address, Address> entries = new TreeMap<Address, Address>();
	private Map<Address, String> entryHow = new HashMap<Address, String>();
	private List<TableRun> tables = new ArrayList<TableRun>();
	private Map<Address, TableRun> dispatcherToTable = new HashMap<Address, TableRun>();
	private Map<Address, Address> encryptedDispatchers = new HashMap<Address, Address>();
	private List<MbaHit> mbaHits = new ArrayList<MbaHit>();

	private static class TableRun {
		Address start;
		Address end;
		List<Address> dests = new ArrayList<Address>();
		int interior;
		int fromDispatcher;
		int score;
		boolean likelyCff;
	}

	private static class MbaHit {
		Address addr;
		long value;
		String how;
	}

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		parseArgs();
		ptrSize = currentProgram.getDefaultPointerSize();
		if (ptrSize != 4 && ptrSize != 8) {
			printerr("pointer size " + ptrSize + " not supported (want 4 or 8)");
			return;
		}
		mem = currentProgram.getMemory();
		listing = currentProgram.getListing();
		imageBaseOff = currentProgram.getImageBase().getOffset();
		collectLayout();
		if (execBlocks.isEmpty() || dataBlocks.isEmpty()) {
			printerr("need at least one executable block and one data/bss block");
			return;
		}

		println("=== CFFDispatchTracer ===");
		println("program=" + currentProgram.getName());
		println("language=" + currentProgram.getLanguageID());
		println("ptrSize=" + ptrSize + " imageBase=" + currentProgram.getImageBase());
		println("execBlocks=" + execBlocks.size() + " dataBlocks=" + dataBlocks.size());
		println("minTable=" + minTable + " applySwitch=" + applySwitch + " dryRun=" + dryRun);
		ensureDisassembled();

		loadKnowledgeBaseFromBookmarks();
		if (kbInFile != null) {
			loadKbJson(kbInFile);
			println("kbIn loaded: " + kbInFile.getAbsolutePath() + " entries=" + entries.size());
		}
		int kbPrior = entries.size();

		monitor.setMessage("CFF strategy A: reference scan");
		int refHits = strategyA_referenceScan();
		println("Phase A (ref scan): +" + refHits + " entries");

		monitor.setMessage("CFF discover ASLR slide");
		discoverSlide();
		println("slide=" + hex(slide) + " known=" + slideKnown);

		monitor.setMessage("CFF strategy B: ASLR / raw data scan");
		int bssHits = strategyB_aslrScan();
		println("Phase B (aslr/raw): +" + bssHits + " entries");

		monitor.setMessage("CFF strategy C: trampoline BR/JMP");
		int trampHits = strategyC_trampolineScan();
		println("Phase C (trampoline): +" + trampHits + " entries");

		clusterTables();
		scoreTables();
		findDispatchers();
		findEncryptedDispatchers();

		int cffTables = 0;
		int cffSlots = 0;
		for (int i = 0; i < tables.size(); i++) {
			TableRun t = tables.get(i);
			if (t.likelyCff) {
				cffTables++;
				cffSlots += t.dests.size();
			}
		}
		println("Phase cluster: tables=" + tables.size() + " cffTables=" + cffTables + " cffSlots=" + cffSlots
				+ " dispatchers=" + dispatcherToTable.size() + " encryptedDispatchers=" + encryptedDispatchers.size()
				+ " (ref=" + refHits + " bss=" + bssHits + " kb=" + kbPrior + ")");

		if (doMba) {
			monitor.setMessage("CFF MBA immediates");
			scanMba();
			println("Phase MBA: " + mbaHits.size() + " immediates annotated");
		}

		if (!dryRun) {
			monitor.setMessage("CFF apply annotations");
			applyAnnotations();
			if (applySwitch) {
				applySwitchOverrides();
			}
		}
		else {
			println("dryRun: no DB writes");
		}

		dumpSummary();
		if (kbFile != null) {
			writeKnowledgeBase(kbFile);
			println("kb written: " + kbFile.getAbsolutePath());
		}
		if (dotFile != null) {
			writeDot(dotFile);
			println("dot written: " + dotFile.getAbsolutePath());
		}
		println("done. see docs/scripts/CFFDispatchTracer.md");
	}

	private void parseArgs() throws Exception {
		minTable = DEFAULT_MIN_TABLE;
		maxSwitch = DEFAULT_MAX_SWITCH;
		applySwitch = false;
		dryRun = false;
		doMba = true;
		kbFile = null;
		kbInFile = null;
		dotFile = null;

		String[] args = getScriptArgs();
		boolean hasArgs = args != null && args.length > 0;
		if (hasArgs) {
			for (int i = 0; i < args.length; i++) {
				String a = args[i];
				if (a == null) {
					continue;
				}
				if (a.equals("applySwitch")) {
					applySwitch = true;
				}
				else if (a.equals("dryRun")) {
					dryRun = true;
				}
				else if (a.equals("noMba")) {
					doMba = false;
				}
				else if (a.startsWith("minTable=")) {
					minTable = Integer.parseInt(a.substring("minTable=".length()));
				}
				else if (a.startsWith("maxSwitch=")) {
					maxSwitch = Integer.parseInt(a.substring("maxSwitch=".length()));
				}
				else if (a.startsWith("kb=")) {
					kbFile = new File(a.substring("kb=".length()));
				}
				else if (a.startsWith("kbIn=")) {
					kbInFile = new File(a.substring("kbIn=".length()));
				}
				else if (a.startsWith("dot=")) {
					dotFile = new File(a.substring("dot=".length()));
				}
			}
		}
		else if (!isRunningHeadless()) {
			applySwitch = askYesNo("CFFDispatchTracer",
					"Apply JumpTable override on SMALL local tables (<= " + maxSwitch + " dests)?\n"
							+ "Leave NO for shared mega-tables (JNI_OnLoad with thousands of slots).\n"
							+ "Annotations / pointer xrefs are always written.");
			try {
				File defKb = defaultSidecar(".cff-kb.json");
				if (defKb != null && askYesNo("CFFDispatchTracer", "Write knowledge-base JSON next to the binary?")) {
					kbFile = defKb;
				}
			}
			catch (Exception e) {
				// cancelled
			}
		}
	}

	private void ensureDisassembled() {
		long n = listing.getNumInstructions();
		long execBytes = 0;
		for (int i = 0; i < execBlocks.size(); i++) {
			execBytes += execBlocks.get(i).getSize();
		}
		// ARM64 fully-disassembled ~ 1 insn / 4 bytes. CRT+PLT alone is ~80
		// insns; a 32-insn cutoff skips linear disasm and leaves dispatchers=0.
		long dense = execBytes / 8;
		if (n >= dense && n > 1000) {
			println("instructions already=" + n + " execBytes=" + execBytes);
			return;
		}
		println("sparse instructions (" + n + " / execBytes=" + execBytes
				+ "), linear-disassembling executable blocks (no flow follow)");
		for (int i = 0; i < execBlocks.size() && !monitor.isCancelled(); i++) {
			MemoryBlock b = execBlocks.get(i);
			if (!b.isInitialized()) {
				continue;
			}
			AddressSet set = new AddressSet(b.getStart(), b.getEnd());
			DisassembleCommand cmd = new DisassembleCommand(set, set, false);
			cmd.applyTo(currentProgram, monitor);
		}
		println("instructions now=" + listing.getNumInstructions());
	}

	private File defaultSidecar(String suffix) {
		String path = currentProgram.getExecutablePath();
		if (path == null || path.length() == 0) {
			return null;
		}
		return new File(path + suffix);
	}

	private void collectLayout() {
		execBlocks = new ArrayList<MemoryBlock>();
		dataBlocks = new ArrayList<MemoryBlock>();
		MemoryBlock[] blocks = mem.getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			MemoryBlock b = blocks[i];
			String n = b.getName().toLowerCase();
			if (n.contains("external") || n.equals("headers") || n.contains("overlay")) {
				continue;
			}
			if (b.isExecute()) {
				execBlocks.add(b);
			}
			else if (isDataish(b)) {
				dataBlocks.add(b);
			}
		}
	}

	private boolean isDataish(MemoryBlock b) {
		if (b.isExecute()) {
			return false;
		}
		String n = b.getName().toLowerCase();
		if (n.contains("got") || n.contains("plt") || n.contains("extern") || n.contains("reloc")
				|| n.contains("eh_frame") || n.contains("gcc_except") || n.contains("mod_init")
				|| n.contains("mod_term") || n.contains("objc")) {
			return false;
		}
		if (n.contains(".data") || n.contains(".bss") || n.contains("__data") || n.contains("__bss")
				|| n.contains("data.") || n.equals("ram") || n.contains(".data.rel")) {
			return true;
		}
		return b.isWrite() || !b.isInitialized();
	}

	private boolean isExec(Address a) {
		for (int i = 0; i < execBlocks.size(); i++) {
			if (execBlocks.get(i).contains(a)) {
				return true;
			}
		}
		return false;
	}

	private boolean isDataAddr(Address a) {
		for (int i = 0; i < dataBlocks.size(); i++) {
			if (dataBlocks.get(i).contains(a)) {
				return true;
			}
		}
		return false;
	}

	private void loadKnowledgeBaseFromBookmarks() {
		Iterator<Bookmark> it = currentProgram.getBookmarkManager().getBookmarksIterator("Analysis");
		while (it.hasNext()) {
			Bookmark bm = it.next();
			if (!"CFF".equals(bm.getCategory())) {
				continue;
			}
			String c = bm.getComment();
			if (c == null) {
				continue;
			}
			if (c.startsWith("CFF slot")) {
				Address dest = parseArrowDest(c);
				if (dest != null && isExec(dest)) {
					putEntry(bm.getAddress(), dest, "kb");
				}
			}
		}
	}

	private void loadKbJson(File file) {
		if (file == null || !file.isFile()) {
			printerr("kbIn missing: " + file);
			return;
		}
		FileReader reader = null;
		try {
			reader = new FileReader(file);
			JsonElement rootEl = JsonParser.parseReader(reader);
			if (!rootEl.isJsonObject()) {
				return;
			}
			JsonObject root = rootEl.getAsJsonObject();
			if (root.has("slide")) {
				try {
					slide = parseHex(root.get("slide").getAsString());
					slideKnown = true;
				}
				catch (Exception e) {
					// ignore
				}
			}
			if (!root.has("tables")) {
				return;
			}
			JsonArray tarr = root.getAsJsonArray("tables");
			for (int i = 0; i < tarr.size(); i++) {
				JsonObject t = tarr.get(i).getAsJsonObject();
				if (!t.has("entries")) {
					continue;
				}
				JsonArray ents = t.getAsJsonArray("entries");
				for (int j = 0; j < ents.size(); j++) {
					JsonObject e = ents.get(j).getAsJsonObject();
					if (!e.has("slot") || !e.has("dest")) {
						continue;
					}
					Address slot = currentProgram.getAddressFactory().getAddress(e.get("slot").getAsString());
					Address dest = currentProgram.getAddressFactory().getAddress(e.get("dest").getAsString());
					if (slot != null && dest != null && isExec(dest)) {
						putEntry(slot, dest, "kb");
					}
				}
			}
		}
		catch (Exception e) {
			printerr("kbIn parse failed: " + e.getMessage());
		}
		finally {
			if (reader != null) {
				try {
					reader.close();
				}
				catch (Exception e) {
					// ignore
				}
			}
		}
	}

	private Address parseArrowDest(String c) {
		int i = c.lastIndexOf("->");
		if (i < 0) {
			return null;
		}
		String s = c.substring(i + 2).trim();
		int sp = s.indexOf(' ');
		if (sp > 0) {
			s = s.substring(0, sp);
		}
		try {
			return currentProgram.getAddressFactory().getAddress(s);
		}
		catch (Exception e) {
			return toCodeAddress(parseHex(s));
		}
	}

	private long parseHex(String s) {
		if (s.startsWith("0x") || s.startsWith("0X")) {
			s = s.substring(2);
		}
		s = s.replace(":", "");
		return Long.parseUnsignedLong(s, 16);
	}

	private int strategyA_referenceScan() {
		int before = entries.size();
		InstructionIterator ii = listing.getInstructions(true);
		while (ii.hasNext() && !monitor.isCancelled()) {
			Instruction in = ii.next();
			Address ia = in.getMinAddress();
			if (!isExec(ia)) {
				continue;
			}
			Reference[] refs = in.getReferencesFrom();
			for (int r = 0; r < refs.length; r++) {
				Address to = refs[r].getToAddress();
				if (!isDataAddr(to)) {
					continue;
				}
				Address dest = readPointerAsCode(to);
				if (dest != null) {
					boolean fresh = !entries.containsKey(to);
					putEntry(to, dest, "ref");
					if (fresh) {
						growTable(to, "ref");
					}
				}
			}
		}
		return entries.size() - before;
	}

	private int strategyB_aslrScan() {
		int before = entries.size();
		for (int bi = 0; bi < dataBlocks.size() && !monitor.isCancelled(); bi++) {
			MemoryBlock b = dataBlocks.get(bi);
			if (!b.isInitialized()) {
				continue;
			}
			if (b.getSize() > 16L * 1024 * 1024) {
				continue;
			}
			Address a = b.getStart();
			Address end = b.getEnd();
			monitor.setMessage("CFF B scan " + b.getName());
			while (a != null && a.compareTo(end) <= 0 && !monitor.isCancelled()) {
				if ((a.getOffset() % ptrSize) == 0) {
					Address dest = readPointerAsCode(a);
					if (dest != null) {
						putEntry(a, dest, "bss");
					}
				}
				try {
					a = a.addNoWrap(ptrSize);
				}
				catch (Exception e) {
					break;
				}
			}
		}
		return entries.size() - before;
	}

	private int strategyC_trampolineScan() {
		int before = entries.size();
		FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
		while (fit.hasNext() && !monitor.isCancelled()) {
			Function f = fit.next();
			long naddr = f.getBody().getNumAddresses();
			if (naddr == 0 || naddr > TRAMPOLINE_MAX_BYTES) {
				continue;
			}
			boolean hasComputed = false;
			List<Address> dataRefs = new ArrayList<Address>();
			InstructionIterator ii = listing.getInstructions(f.getBody(), true);
			while (ii.hasNext()) {
				Instruction in = ii.next();
				if (isComputedBranch(in)) {
					hasComputed = true;
				}
				Reference[] refs = in.getReferencesFrom();
				for (int r = 0; r < refs.length; r++) {
					Address to = refs[r].getToAddress();
					if (isDataAddr(to)) {
						dataRefs.add(to);
					}
				}
			}
			if (!hasComputed || dataRefs.isEmpty()) {
				continue;
			}
			for (int i = 0; i < dataRefs.size(); i++) {
				Address to = dataRefs.get(i);
				Address dest = readPointerAsCode(to);
				if (dest != null) {
					boolean fresh = !entries.containsKey(to);
					putEntry(to, dest, "tramp");
					if (fresh) {
						growTable(to, "tramp");
					}
				}
			}
		}
		return entries.size() - before;
	}

	private void growTable(Address seed, String how) {
		Address cur = seed;
		for (int i = 0; i < 8192; i++) {
			try {
				cur = cur.addNoWrap(ptrSize);
			}
			catch (Exception e) {
				break;
			}
			if (!isDataAddr(cur)) {
				break;
			}
			Address dest = readPointerAsCode(cur);
			if (dest == null) {
				break;
			}
			putEntry(cur, dest, how);
		}
		cur = seed;
		for (int i = 0; i < 8192; i++) {
			try {
				cur = cur.subtractNoWrap(ptrSize);
			}
				catch (Exception e) {
				break;
			}
			if (!isDataAddr(cur)) {
				break;
			}
			Address dest = readPointerAsCode(cur);
			if (dest == null) {
				break;
			}
			putEntry(cur, dest, how);
		}
	}

	private void putEntry(Address slot, Address dest, String how) {
		if (slot == null || dest == null) {
			return;
		}
		if (!entries.containsKey(slot)) {
			entries.put(slot, dest);
			entryHow.put(slot, how);
		}
	}

	private Address readPointerAsCode(Address slot) {
		long raw;
		try {
			if (ptrSize == 8) {
				raw = mem.getLong(slot);
			}
			else {
				raw = mem.getInt(slot) & 0xffffffffL;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		if (raw == 0) {
			return null;
		}
		long[] cands = candidateOffsets(raw);
		for (int i = 0; i < cands.length; i++) {
			Address a = toCodeAddress(cands[i]);
			if (a != null) {
				return a;
			}
		}
		return null;
	}

	private long[] candidateOffsets(long raw) {
		HashSet<Long> s = new HashSet<Long>();
		s.add(Long.valueOf(raw));
		if (slideKnown && slide != 0) {
			s.add(Long.valueOf(raw + slide));
		}
		if (imageBaseOff != 0) {
			s.add(Long.valueOf(raw + imageBaseOff));
			s.add(Long.valueOf(raw - imageBaseOff));
		}
		long[] out = new long[s.size()];
		int i = 0;
		for (Long v : s) {
			out[i++] = v.longValue();
		}
		return out;
	}

	private Address toCodeAddress(long offset) {
		for (int i = 0; i < execBlocks.size(); i++) {
			MemoryBlock b = execBlocks.get(i);
			try {
				Address a = b.getStart().getAddressSpace().getAddress(offset);
				if (b.contains(a)) {
					return a;
				}
				if ((offset & 1L) == 1L) {
					Address t = b.getStart().getAddressSpace().getAddress(offset & ~1L);
					if (b.contains(t)) {
						return t;
					}
				}
			}
			catch (Exception e) {
				// skip
			}
		}
		return null;
	}

	private void discoverSlide() {
		Map<Long, Integer> votes = new HashMap<Long, Integer>();
		int already = 0;
		int n = 0;
		for (Map.Entry<Address, Address> e : entries.entrySet()) {
			long raw;
			try {
				if (ptrSize == 8) {
					raw = mem.getLong(e.getKey());
				}
				else {
					raw = mem.getInt(e.getKey()) & 0xffffffffL;
				}
			}
			catch (MemoryAccessException ex) {
				continue;
			}
			n++;
			long destOff = e.getValue().getOffset();
			if (raw == destOff || toCodeAddress(raw) != null) {
				already++;
				continue;
			}
			long s = destOff - raw;
			Integer c = votes.get(Long.valueOf(s));
			votes.put(Long.valueOf(s), c == null ? 1 : c.intValue() + 1);
		}
		if (n > 0 && already * 2 >= n) {
			slide = 0;
			slideKnown = true;
			return;
		}
		long best = 0;
		int bestC = 0;
		for (Map.Entry<Long, Integer> v : votes.entrySet()) {
			if (v.getValue().intValue() > bestC) {
				bestC = v.getValue().intValue();
				best = v.getKey().longValue();
			}
		}
		if (bestC >= 3) {
			slide = best;
			slideKnown = true;
			return;
		}
		voteSlideFromRawSample();
	}

	private void voteSlideFromRawSample() {
		List<Long> raws = new ArrayList<Long>();
		int sampled = 0;
		for (int bi = 0; bi < dataBlocks.size() && sampled < 4000; bi++) {
			MemoryBlock b = dataBlocks.get(bi);
			if (!b.isInitialized() || b.getSize() > 8L * 1024 * 1024) {
				continue;
			}
			Address a = b.getStart();
			Address end = b.getEnd();
			while (a != null && a.compareTo(end) <= 0 && sampled < 4000) {
				if ((a.getOffset() % ptrSize) == 0) {
					try {
						long raw = ptrSize == 8 ? mem.getLong(a) : (mem.getInt(a) & 0xffffffffL);
						if (raw > 0x10000L) {
							raws.add(Long.valueOf(raw));
							sampled++;
						}
					}
					catch (MemoryAccessException e) {
						// skip
					}
				}
				try {
					a = a.addNoWrap(ptrSize * 4);
				}
				catch (Exception e) {
					break;
				}
			}
		}
		if (raws.isEmpty() || execBlocks.isEmpty()) {
			slide = 0;
			slideKnown = false;
			return;
		}
		Map<Long, Integer> votes = new HashMap<Long, Integer>();
		for (int i = 0; i < execBlocks.size(); i++) {
			long execPage = execBlocks.get(i).getStart().getOffset() & ~0xfffL;
			int limit = Math.min(raws.size(), 800);
			for (int r = 0; r < limit; r++) {
				long rawPage = raws.get(r).longValue() & ~0xfffL;
				long s = execPage - rawPage;
				Integer c = votes.get(Long.valueOf(s));
				votes.put(Long.valueOf(s), c == null ? 1 : c.intValue() + 1);
			}
		}
		long best = 0;
		int bestC = 0;
		for (Map.Entry<Long, Integer> v : votes.entrySet()) {
			if (v.getValue().intValue() > bestC) {
				bestC = v.getValue().intValue();
				best = v.getKey().longValue();
			}
		}
		int hits = 0;
		int check = Math.min(raws.size(), 500);
		for (int r = 0; r < check; r++) {
			if (toCodeAddress(raws.get(r).longValue() + best) != null) {
				hits++;
			}
		}
		if (hits >= 8) {
			slide = best;
			slideKnown = true;
		}
		else {
			slide = 0;
			slideKnown = false;
		}
	}

	private void clusterTables() {
		tables.clear();
		if (entries.isEmpty()) {
			return;
		}
		List<Address> slots = new ArrayList<Address>(entries.keySet());
		Collections.sort(slots);
		TableRun cur = null;
		Address prev = null;
		for (int i = 0; i < slots.size(); i++) {
			Address slot = slots.get(i);
			boolean cont = prev != null && isDataAddr(slot) && isDataAddr(prev);
			if (cont) {
				try {
					cont = slot.subtract(prev) == ptrSize;
				}
				catch (Exception e) {
					cont = false;
				}
			}
			if (!cont) {
				if (cur != null && cur.dests.size() >= minTable) {
					tables.add(cur);
				}
				cur = new TableRun();
				cur.start = slot;
				cur.dests = new ArrayList<Address>();
			}
			cur.dests.add(entries.get(slot));
			cur.end = nextSlot(slot);
			prev = slot;
		}
		if (cur != null && cur.dests.size() >= minTable) {
			tables.add(cur);
		}
	}

	private Address nextSlot(Address slot) {
		try {
			return slot.addNoWrap(ptrSize);
		}
		catch (Exception e) {
			return slot;
		}
	}

	private void scoreTables() {
		for (int i = 0; i < tables.size(); i++) {
			TableRun t = tables.get(i);
			int interior = 0;
			for (int d = 0; d < t.dests.size(); d++) {
				Address dest = t.dests.get(d);
				Function f = getFunctionContaining(dest);
				if (f == null || !f.getEntryPoint().equals(dest)) {
					interior++;
				}
				else if (f.getBody().getNumAddresses() > 0x400) {
					interior++;
				}
			}
			t.interior = interior;
			t.fromDispatcher = 0;
			t.score = interior * 3 + t.dests.size();
			double ratio = t.dests.isEmpty() ? 0.0 : (double) interior / (double) t.dests.size();
			int uniq = uniqueDests(t);
			double uniqRatio = t.dests.isEmpty() ? 0.0 : (double) uniq / (double) t.dests.size();
			// GOT/IAT: every slot the same dest. vtable: unique FUN_* entries, interior ~ 0.
			boolean notGot = uniq > 1;
			boolean notVtable = ratio >= 0.40 || uniqRatio < 0.55;
			t.likelyCff = t.dests.size() >= minTable && notGot && notVtable;
		}
	}

	private int uniqueDests(TableRun t) {
		HashSet<Address> s = new HashSet<Address>();
		for (int i = 0; i < t.dests.size(); i++) {
			s.add(t.dests.get(i));
		}
		return s.size();
	}

	private void findDispatchers() {
		dispatcherToTable.clear();
		InstructionIterator ii = listing.getInstructions(true);
		while (ii.hasNext() && !monitor.isCancelled()) {
			Instruction in = ii.next();
			if (!isComputedBranch(in)) {
				continue;
			}
			TableRun t = tableReferencedNear(in);
			if (t == null) {
				continue;
			}
			t.fromDispatcher++;
			t.likelyCff = true;
			dispatcherToTable.put(in.getMinAddress(), t);
		}
		for (int i = 0; i < tables.size(); i++) {
			TableRun t = tables.get(i);
			if (t.fromDispatcher > 0 && uniqueDests(t) > 1) {
				t.score += 50 * t.fromDispatcher;
				t.likelyCff = true;
			}
		}
	}

	/**
	 * Packed OLLVM (packed loader): dispatcher is
	 *   ADRP+ADD Xn, table
	 *   LDR Xt, [Xn, Wm, UXTW#3]
	 *   BR Xt
	 * but table slots are still ciphertext, so strategies A/B find nothing.
	 * Still bookmark the BR and the table base Ghidra already xref'd.
	 */
	private void findEncryptedDispatchers() {
		encryptedDispatchers.clear();
		InstructionIterator ii = listing.getInstructions(true);
		while (ii.hasNext() && !monitor.isCancelled()) {
			Instruction br = ii.next();
			if (!isComputedBranch(br)) {
				continue;
			}
			if (dispatcherToTable.containsKey(br.getMinAddress())) {
				continue;
			}
			if (!isIndexedLoadThenBranch(br)) {
				continue;
			}
			Address table = dataXrefInLookback(br);
			if (table == null) {
				table = br.getMinAddress();
			}
			encryptedDispatchers.put(br.getMinAddress(), table);
		}
	}

	private boolean isIndexedLoadThenBranch(Instruction br) {
		Instruction prev = br.getPrevious();
		if (prev == null) {
			return false;
		}
		String m = prev.getMnemonicString().toLowerCase();
		if (!m.equals("ldr") && !m.equals("ldrsw")) {
			return false;
		}
		String op = prev.toString().toLowerCase();
		// ARM64: ldr xN, [xM, wK, uxtw #3]  or lsl #3
		if (op.indexOf("uxtw") >= 0 || op.indexOf("lsl") >= 0 || op.indexOf("sxtw") >= 0) {
			return true;
		}
		ghidra.program.model.symbol.FlowType ft = br.getFlowType();
		return ft.isJump() && ft.isComputed();
	}

	private Address dataXrefInLookback(Instruction br) {
		Instruction cur = br;
		for (int i = 0; i < LOOKBACK_INSNS && cur != null; i++) {
			Reference[] refs = cur.getReferencesFrom();
			for (int r = 0; r < refs.length; r++) {
				Address to = refs[r].getToAddress();
				if (isDataAddr(to)) {
					return to;
				}
			}
			cur = cur.getPrevious();
			if (cur != null && (isComputedBranch(cur) || cur.getFlowType().isCall())) {
				break;
			}
		}
		return null;
	}

	private TableRun tableReferencedNear(Instruction br) {
		Set<Address> refs = new HashSet<Address>();
		collectDataRefs(br, refs);
		Instruction cur = br;
		for (int i = 0; i < LOOKBACK_INSNS && cur != null; i++) {
			cur = cur.getPrevious();
			if (cur == null) {
				break;
			}
			if (isComputedBranch(cur) || cur.getFlowType().isCall()) {
				break;
			}
			collectDataRefs(cur, refs);
		}
		TableRun best = null;
		int bestScore = -1;
		for (Address to : refs) {
			TableRun t = tableContainingSlot(to);
			if (t == null) {
				t = tableStartingAt(to);
			}
			if (t == null) {
				continue;
			}
			if (t.dests.size() > bestScore) {
				bestScore = t.dests.size();
				best = t;
			}
		}
		return best;
	}

	private void collectDataRefs(Instruction in, Set<Address> out) {
		Reference[] refs = in.getReferencesFrom();
		for (int i = 0; i < refs.length; i++) {
			Address to = refs[i].getToAddress();
			if (isDataAddr(to)) {
				out.add(to);
			}
		}
	}

	private TableRun tableContainingSlot(Address slot) {
		for (int i = 0; i < tables.size(); i++) {
			TableRun t = tables.get(i);
			if (slot.compareTo(t.start) >= 0 && slot.compareTo(t.end) < 0) {
				return t;
			}
		}
		return null;
	}

	private TableRun tableStartingAt(Address a) {
		for (int i = 0; i < tables.size(); i++) {
			if (tables.get(i).start.equals(a)) {
				return tables.get(i);
			}
		}
		return null;
	}

	private boolean isComputedBranch(Instruction in) {
		if (in == null) {
			return false;
		}
		FlowType ft = in.getFlowType();
		if (ft.isJump() && ft.isComputed()) {
			return true;
		}
		String m = in.getMnemonicString().toLowerCase();
		if (m.equals("br") || m.equals("braa") || m.equals("brab") || m.equals("braaz") || m.equals("brabz")) {
			return true;
		}
		if (m.equals("bx") || m.equals("bxj")) {
			return true;
		}
		if (m.startsWith("jmp") && ft.isComputed()) {
			return true;
		}
		return false;
	}

	private void scanMba() {
		InstructionIterator ii = listing.getInstructions(true);
		while (ii.hasNext() && !monitor.isCancelled()) {
			Instruction in = ii.next();
			if (!isExec(in.getMinAddress())) {
				continue;
			}
			String m = in.getMnemonicString().toLowerCase();
			if (m.equals("movz") || m.equals("movk") || m.equals("movn")) {
				MbaHit hit = reconstructArm64MovzMovk(in);
				if (hit != null) {
					mbaHits.add(hit);
				}
			}
			else if (m.equals("mov") || m.equals("movi")) {
				Scalar sc = in.getScalar(in.getNumOperands() > 1 ? 1 : 0);
				if (sc != null) {
					long v = sc.getUnsignedValue();
					if (isInterestingImm(v)) {
						MbaHit hit = new MbaHit();
						hit.addr = in.getMinAddress();
						hit.value = v;
						hit.how = "mov";
						mbaHits.add(hit);
					}
				}
			}
		}
	}

	private MbaHit reconstructArm64MovzMovk(Instruction start) {
		ghidra.program.model.lang.Register reg = start.getRegister(0);
		if (reg == null) {
			return null;
		}
		long value = 0;
		boolean saw = false;
		Instruction in = start;
		String startReg = reg.getName();
		for (int step = 0; step < MBA_WINDOW && in != null; step++) {
			String m = in.getMnemonicString().toLowerCase();
			ghidra.program.model.lang.Register r0 = in.getRegister(0);
			if (r0 == null || !r0.getName().equals(startReg)) {
				if (saw) {
					break;
				}
				in = in.getNext();
				continue;
			}
			Scalar imm = in.getScalar(1);
			if (imm == null) {
				in = in.getNext();
				continue;
			}
			long piece = imm.getUnsignedValue() & 0xffffL;
			int shift = 0;
			if (in.getNumOperands() > 2) {
				Scalar sh = in.getScalar(2);
				if (sh != null) {
					shift = (int) sh.getUnsignedValue();
				}
				else {
					shift = parseLsl(in.getDefaultOperandRepresentation(2));
				}
			}
			if (m.equals("movz")) {
				value = piece << shift;
				saw = true;
			}
			else if (m.equals("movk")) {
				long mask = 0xffffL << shift;
				value = (value & ~mask) | (piece << shift);
				saw = true;
			}
			else if (m.equals("movn")) {
				value = ~(piece << shift);
				saw = true;
			}
			else if (saw) {
				break;
			}
			in = in.getNext();
		}
		if (!saw || !isInterestingImm(value)) {
			return null;
		}
		MbaHit hit = new MbaHit();
		hit.addr = start.getMinAddress();
		hit.value = value & 0xffffffffL;
		hit.how = "movz/movk";
		return hit;
	}

	private int parseLsl(String op) {
		if (op == null) {
			return 0;
		}
		String s = op.toLowerCase().replace(" ", "");
		int i = s.indexOf("#");
		if (s.contains("lsl") && i >= 0) {
			try {
				return Integer.parseInt(s.substring(i + 1).replaceAll("[^0-9]", ""));
			}
			catch (Exception e) {
				return 0;
			}
		}
		return 0;
	}

	private boolean isInterestingImm(long v) {
		v = v & 0xffffffffL;
		if (v == 0 || v == 0xffffffffL) {
			return false;
		}
		if (v > 0 && v < 0x2000) {
			return true;
		}
		long lo = v & 0xffffL;
		long hi = (v >>> 16) & 0xffffL;
		return lo != 0 && hi != 0;
	}

	private void applyAnnotations() throws Exception {
		int labeled = 0;
		int ptrs = 0;
		for (int ti = 0; ti < tables.size(); ti++) {
			TableRun t = tables.get(ti);
			if (!t.likelyCff) {
				continue;
			}
			createLabelQuiet(t.start, "cff_dispatch_table_" + t.start);
			Address slot = t.start;
			for (int i = 0; i < t.dests.size(); i++) {
				Address dest = t.dests.get(i);
				if (listing.getDefinedDataAt(slot) == null && listing.getInstructionAt(slot) == null) {
					try {
						if (ptrSize == 8) {
							createData(slot, new Pointer64DataType());
						}
						else {
							createData(slot, new Pointer32DataType());
						}
						ptrs++;
					}
					catch (Exception e) {
						// conflict
					}
				}
				try {
					currentProgram.getReferenceManager().addMemoryReference(slot, dest, RefType.DATA,
							SourceType.ANALYSIS, 0);
				}
				catch (Exception e) {
					// dup
				}
				setCommentQuiet(slot, "CFF[" + i + "] -> " + dest);
				currentProgram.getBookmarkManager().setBookmark(slot, BookmarkType.ANALYSIS, "CFF",
						"CFF slot -> " + dest);
				if (createLabelQuiet(dest, "cff_" + t.start + "_" + i)) {
					labeled++;
				}
				setCommentQuiet(dest, "CFF case table=" + t.start + " idx=" + i);
				try {
					slot = slot.addNoWrap(ptrSize);
				}
				catch (Exception e) {
					break;
				}
			}
		}
		for (Map.Entry<Address, TableRun> e : dispatcherToTable.entrySet()) {
			Address br = e.getKey();
			TableRun t = e.getValue();
			currentProgram.getBookmarkManager().setBookmark(br, BookmarkType.ANALYSIS, "CFF",
					"CFF dispatcher -> table " + t.start + " n=" + t.dests.size());
			setCommentQuiet(br, "CFF dispatcher table=" + t.start + " entries=" + t.dests.size());
		}
		int enc = 0;
		for (Map.Entry<Address, Address> e : encryptedDispatchers.entrySet()) {
			Address br = e.getKey();
			Address table = e.getValue();
			boolean unresolved = table.equals(br);
			String msg = unresolved
					? "CFF packed dispatcher (LDR idx + BR); table ciphertext / unresolved"
					: "CFF packed dispatcher (LDR idx + BR); table base " + table + " (slots still encrypted)";
			currentProgram.getBookmarkManager().setBookmark(br, BookmarkType.ANALYSIS, "CFF", msg);
			setCommentQuiet(br, msg);
			if (!unresolved) {
				setCommentQuiet(table, "CFF packed table base xref from dispatcher " + br);
			}
			enc++;
		}
		for (int i = 0; i < mbaHits.size(); i++) {
			MbaHit h = mbaHits.get(i);
			String idxHint = "";
			if (h.value >= 0 && h.value < 0x2000) {
				idxHint = " (possible state index)";
			}
			setCommentQuiet(h.addr, "CFF/MBA imm=" + hex(h.value) + " via " + h.how + idxHint);
		}
		println("annotated pointers=" + ptrs + " destLabels=" + labeled + " dispatchers=" + dispatcherToTable.size() + " packedDispatchers=" + encryptedDispatchers.size());
	}

	private void setCommentQuiet(Address addr, String add) {
		if (add == null) {
			return;
		}
		String old = listing.getComment(CommentType.EOL, addr);
		if (old != null && old.indexOf(add) >= 0) {
			return;
		}
		listing.setComment(addr, CommentType.EOL, old == null ? add : old + " ; " + add);
	}

	private boolean createLabelQuiet(Address addr, String name) {
		try {
			SymbolTable st = currentProgram.getSymbolTable();
			Symbol primary = st.getPrimarySymbol(addr);
			if (primary != null && !isDefaultName(primary.getName())) {
				return false;
			}
			createLabel(addr, sanitize(name), false);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	private String sanitize(String n) {
		return n.replace(':', '_').replace('.', '_').replace(' ', '_');
	}

	private boolean isDefaultName(String n) {
		if (n == null) {
			return true;
		}
		return n.startsWith("FUN_") || n.startsWith("LAB_") || n.startsWith("SUB_") || n.startsWith("DAT_")
				|| n.startsWith("unnamed_") || n.startsWith("thunk_") || n.startsWith("caseD_")
				|| n.startsWith("cff_");
	}

	private void applySwitchOverrides() {
		int applied = 0;
		int skipped = 0;
		for (Map.Entry<Address, TableRun> e : dispatcherToTable.entrySet()) {
			if (monitor.isCancelled()) {
				break;
			}
			Address br = e.getKey();
			TableRun t = e.getValue();
			if (t.dests.size() < 2 || t.dests.size() > maxSwitch) {
				skipped++;
				continue;
			}
			Function f = getFunctionContaining(br);
			if (f == null) {
				skipped++;
				continue;
			}
			Instruction instr = listing.getInstructionAt(br);
			if (instr == null) {
				continue;
			}
			try {
				ArrayList<Address> destlist = new ArrayList<Address>(t.dests);
				for (int i = 0; i < destlist.size(); i++) {
					instr.addOperandReference(0, destlist.get(i), RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
				}
				JumpTable jumpTab = new JumpTable(br, destlist, true, 0);
				jumpTab.writeOverride(f);
				CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
				applied++;
			}
			catch (Exception ex) {
				println("switch override failed at " + br + ": " + ex.getMessage());
			}
		}
		println("JumpTable overrides applied=" + applied + " skipped(large/no-fn)=" + skipped);
	}

	private void dumpSummary() {
		println("--- CFF tables (likely) ---");
		List<TableRun> show = new ArrayList<TableRun>();
		for (int i = 0; i < tables.size(); i++) {
			if (tables.get(i).likelyCff) {
				show.add(tables.get(i));
			}
		}
		Collections.sort(show, new Comparator<TableRun>() {
			@Override
			public int compare(TableRun a, TableRun b) {
				return b.score - a.score;
			}
		});
		int limit = Math.min(show.size(), 30);
		for (int i = 0; i < limit; i++) {
			TableRun t = show.get(i);
			int uniq = uniqueDests(t);
			println("  " + t.start + " n=" + t.dests.size() + " unique=" + uniq + " interior=" + t.interior
					+ " dispXref=" + t.fromDispatcher + " score=" + t.score);
		}
		if (show.size() > limit) {
			println("  ... " + (show.size() - limit) + " more tables");
		}
		println("--- dispatchers ---");
		int dlimit = 0;
		for (Map.Entry<Address, TableRun> e : dispatcherToTable.entrySet()) {
			if (dlimit++ >= 40) {
				println("  ... more");
				break;
			}
			Function f = getFunctionContaining(e.getKey());
			String fn = f == null ? "?" : f.getName();
			println("  BR " + e.getKey() + " in " + fn + " table=" + e.getValue().start + " n="
					+ e.getValue().dests.size());
		}
		println("--- packed/encrypted dispatchers (LDR idx + BR) ---");
		println("count=" + encryptedDispatchers.size());
		int elimit = 0;
		for (Map.Entry<Address, Address> e : encryptedDispatchers.entrySet()) {
			if (elimit++ >= 20) {
				println("  ... more");
				break;
			}
			Function f = getFunctionContaining(e.getKey());
			String fn = f == null ? "?" : f.getName();
			String tb = e.getKey().equals(e.getValue()) ? "unresolved" : e.getValue().toString();
			println("  BR " + e.getKey() + " in " + fn + " table=" + tb);
		}
	}

	private void writeKnowledgeBase(File file) throws Exception {
		JsonObject root = new JsonObject();
		root.addProperty("program", currentProgram.getName());
		root.addProperty("path", currentProgram.getExecutablePath());
		root.addProperty("language", currentProgram.getLanguageID().toString());
		root.addProperty("imageBase", currentProgram.getImageBase().toString());
		root.addProperty("slide", hex(slide));
		root.addProperty("ptrSize", ptrSize);
		JsonArray tarr = new JsonArray();
		for (int i = 0; i < tables.size(); i++) {
			TableRun t = tables.get(i);
			if (!t.likelyCff) {
				continue;
			}
			JsonObject o = new JsonObject();
			o.addProperty("start", t.start.toString());
			o.addProperty("count", t.dests.size());
			o.addProperty("interior", t.interior);
			o.addProperty("dispatchers", t.fromDispatcher);
			o.addProperty("score", t.score);
			JsonArray dests = new JsonArray();
			Address slot = t.start;
			for (int d = 0; d < t.dests.size(); d++) {
				JsonObject e = new JsonObject();
				e.addProperty("idx", d);
				e.addProperty("slot", slot.toString());
				e.addProperty("dest", t.dests.get(d).toString());
				dests.add(e);
				try {
					slot = slot.addNoWrap(ptrSize);
				}
				catch (Exception ex) {
					break;
				}
			}
			o.add("entries", dests);
			tarr.add(o);
		}
		root.add("tables", tarr);
		JsonArray darr = new JsonArray();
		for (Map.Entry<Address, TableRun> e : dispatcherToTable.entrySet()) {
			JsonObject o = new JsonObject();
			o.addProperty("br", e.getKey().toString());
			o.addProperty("table", e.getValue().start.toString());
			Function f = getFunctionContaining(e.getKey());
			if (f != null) {
				o.addProperty("function", f.getName());
			}
			darr.add(o);
		}
		root.add("dispatchers", darr);
		JsonArray mbaArr = new JsonArray();
		int mlim = Math.min(mbaHits.size(), 2000);
		for (int i = 0; i < mlim; i++) {
			MbaHit h = mbaHits.get(i);
			JsonObject o = new JsonObject();
			o.addProperty("addr", h.addr.toString());
			o.addProperty("value", hex(h.value));
			o.addProperty("how", h.how);
			mbaArr.add(o);
		}
		root.add("mba", mbaArr);
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		FileWriter w = new FileWriter(file);
		try {
			gson.toJson(root, w);
		}
		finally {
			w.close();
		}
	}

	private void writeDot(File file) throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("digraph cff {\n");
		sb.append("  rankdir=LR;\n");
		sb.append("  node [shape=box,fontname=monospace];\n");
		int edges = 0;
		for (Map.Entry<Address, TableRun> e : dispatcherToTable.entrySet()) {
			TableRun t = e.getValue();
			String src = "br_" + e.getKey();
			sb.append("  \"" + src + "\" [label=\"BR " + e.getKey() + "\"];\n");
			if (t.dests.size() > 32) {
				sb.append("  \"" + src + "\" -> \"table_" + t.start + "\";\n");
				sb.append("  \"table_" + t.start + "\" [label=\"table " + t.start + " n=" + t.dests.size()
						+ "\"];\n");
				edges++;
				continue;
			}
			for (int i = 0; i < t.dests.size(); i++) {
				sb.append("  \"" + src + "\" -> \"" + t.dests.get(i) + "\";\n");
				edges++;
			}
		}
		sb.append("}\n");
		FileWriter w = new FileWriter(file);
		try {
			w.write(sb.toString());
		}
		finally {
			w.close();
		}
		println("dot edges=" + edges);
	}

	private static String hex(long v) {
		return "0x" + Long.toHexString(v);
	}
}
