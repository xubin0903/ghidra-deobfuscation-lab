// CffRecover — recover the REAL control-flow graph of a flattened function by
// concrete p-code emulation. Non-destructive: comments + bookmarks + DOT/JSON,
// never touches bytes.
//
// @category Deobfuscation
// @menupath Tools.Deobfuscation.CFF Recover (emulate)
// @description Emulate each CFF case block to its true successor(s); annotate the recovered CFG (no patching).
//
// Scenario: CffScan said this function is flattened. You want to READ it:
// which real block follows which, where the real if/else are. Run this, then
// follow the `CFF next ->` comments / CFF bookmarks, or open the DOT graph.
//
// How: OLLVM/Hikari/Arkari replace every terminator with
//     state = NEXT (or select(cond, A, B));  br dispatcher
// The constant NEXT does not depend on function input, so each case block can
// be emulated in isolation: run it, let it fall into the dispatcher, and stop
// when execution lands on another case head — that head is the true successor.
// Arkari's XOR-encoded state (switchVar ^ switchXorVar, rolling delta) needs
// no special handling: the emulator simply computes it. Conditional blocks
// contain one csel/cmov selecting between two next states; both outcomes are
// forced, giving both successors plus the condition code.
//
// Args (headless: after -postScript CffRecover.java):
//   func=0x114400   target function (GUI default: function under cursor)
//   all             every function CffScan flags as CFF
//   force           run even if CffScan does not flag the function
//   dryRun          print only, no comments / bookmarks
//   labels          also label case heads cff_case_<addr> (default-named only)
//   dot=PATH        write Graphviz of the recovered CFG (one file per function; %s -> entry)
//   json=PATH       write JSON edge list
//   maxSteps=20000  per-path emulation step cap

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;

public class CffRecover extends GhidraScript {

	private boolean dryRun;
	private boolean labels;
	private String dotPath;
	private String jsonPath;

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		boolean all = false;
		boolean force = false;
		Address single = null;
		// cmd.exe splits "key=value" into two tokens; parseArgs accepts both forms
		CffCore.Args a = CffCore.parseArgs(getScriptArgs(), new String[] { "func", "dot", "json", "maxSteps" });
		all = a.flag("all");
		force = a.flag("force");
		dryRun = a.flag("dryRun");
		labels = a.flag("labels");
		if (a.get("func") != null) {
			single = parseAddr(a.get("func"));
		}
		dotPath = a.get("dot");
		jsonPath = a.get("json");
		CffCore.MAX_STEPS = a.getInt("maxSteps", CffCore.MAX_STEPS);

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

		println("=== CffRecover ===");
		println("program=" + currentProgram.getName() + " language=" + currentProgram.getLanguageID()
				+ " dryRun=" + dryRun + " targets=" + targets.size());

		int done = 0;
		int skipped = 0;
		List<String> jsonFuncs = new ArrayList<String>();
		for (int i = 0; i < targets.size(); i++) {
			if (monitor.isCancelled()) {
				break;
			}
			Function f = targets.get(i);
			CffCore.Detect d = CffCore.detect(currentProgram, f, monitor);
			if (!d.isCff && !force) {
				if (!all) {
					println("  " + f.getName() + " @" + f.getEntryPoint() + " not flagged as CFF (score="
							+ String.format("%.3f", d.score) + " fanIn=" + d.fanIn + "); use `force` to override");
				}
				skipped++;
				continue;
			}
			monitor.setMessage("CffRecover " + f.getName());
			CffCore.Recovery r = CffCore.recover(currentProgram, d, monitor);
			report(f, d, r);
			if (!dryRun) {
				annotate(r);
			}
			if (dotPath != null) {
				String p = dotPath.contains("%s") ? dotPath.replace("%s", f.getEntryPoint().toString()) : dotPath;
				writeDot(p, f, r);
				println("  dot: " + p);
			}
			if (jsonPath != null) {
				jsonFuncs.add(jsonFor(f, r));
			}
			done++;
		}
		if (jsonPath != null) {
			FileWriter w = new FileWriter(jsonPath);
			try {
				w.write("{\n  \"program\": \"" + esc(currentProgram.getName()) + "\",\n  \"functions\": [\n");
				for (int i = 0; i < jsonFuncs.size(); i++) {
					w.write(jsonFuncs.get(i));
					w.write(i + 1 < jsonFuncs.size() ? ",\n" : "\n");
				}
				w.write("  ]\n}\n");
			}
			finally {
				w.close();
			}
			println("json: " + jsonPath);
		}
		println("recovered=" + done + " skipped(not CFF)=" + skipped + ". see docs/scripts/CffRecover.md");
	}

	private void report(Function f, CffCore.Detect d, CffCore.Recovery r) {
		println("");
		println("--- " + f.getName() + " @" + f.getEntryPoint() + " score=" + String.format("%.3f", d.score)
				+ " dispatcher=" + d.dispatcher + " state=" + d.stateHint + " ---");
		for (int i = 0; i < r.log.size(); i++) {
			println("  " + r.log.get(i));
		}
		println("  prologue -> " + (r.firstHead == null ? "?" : r.firstHead.toString()));
		List<Address> heads = new ArrayList<Address>(r.nodes.keySet());
		Collections.sort(heads);
		for (int i = 0; i < heads.size(); i++) {
			Address h = heads.get(i);
			if (h.equals(d.entry)) {
				continue;
			}
			CffCore.Node n = r.nodes.get(h);
			println("  " + h + "  " + describe(n));
		}
		println("  nodes=" + (r.nodes.size() - 1) + " resolved=" + r.resolved + " conditional=" + r.conditional
				+ " unresolved=" + r.unresolved);
	}

	private String describe(CffCore.Node n) {
		String tag = n.pure ? "" : "  [IMPURE " + n.note + ": real code between case and successor, not patchable]";
		String copies = copiesTag(n);
		String loop = n.selfLoop ? " (self-loop)" : "";
		if (n.status.equals("uncond")) {
			return "-> " + n.succs.get(0) + loop + copies + tag;
		}
		if (n.status.equals("cond")) {
			String natural = n.concreteTake == null ? "" : (n.concreteTake.booleanValue() ? " natural=true" : " natural=false");
			return "if(" + n.cond + ") -> " + n.succTrue + " else -> " + n.succFalse + "   [" + n.deciderKind + "@" + n.selectAddr
					+ natural + "]" + loop + copies + tag;
		}
		if (n.status.equals("multi")) {
			return "-> " + n.succs + " (multi-way, review" + (n.note.length() > 0 ? ": " + n.note : "") + ")" + tag;
		}
		if (n.status.equals("ret")) {
			return "return" + (n.note.length() > 0 ? " (" + n.note + ")" : "");
		}
		if (n.status.equals("exit")) {
			return "leaves function (tail call)";
		}
		return "UNRESOLVED " + n.note;
	}

	/** How many live dispatcher instructions (register copies) each edge carries; -O0 trees carry none. */
	private String copiesTag(CffCore.Node n) {
		StringBuilder sb = new StringBuilder();
		for (Address s : n.succs) {
			List<Address> path = n.pathTo.get(s);
			if (path == null || path.isEmpty()) {
				continue;
			}
			CffCore.PathEffects pe = CffCore.analyzeRegionPath(currentProgram, path, s);
			if (pe.unsupported) {
				sb.append(" [dispatcher path to " + s + " has unsupported side effects: " + pe.note + "]");
			}
			else if (!pe.live.isEmpty()) {
				sb.append(" [+" + pe.live.size() + " dispatcher copies to " + s + "]");
			}
		}
		return sb.toString();
	}

	private void annotate(CffCore.Recovery r) throws Exception {
		int c = 0;
		for (Map.Entry<Address, CffCore.Node> e : r.nodes.entrySet()) {
			Address h = e.getKey();
			CffCore.Node n = e.getValue();
			String text;
			if (h.equals(r.d.entry)) {
				text = "CFF prologue; first real block -> " + r.firstHead;
			}
			else {
				text = "CFF " + describe(n);
			}
			String old = currentProgram.getListing().getComment(CommentType.PRE, h);
			if (old == null || !old.contains(text)) {
				currentProgram.getListing().setComment(h, CommentType.PRE, old == null ? text : old + "\n" + text);
			}
			currentProgram.getBookmarkManager().setBookmark(h, BookmarkType.ANALYSIS, "CFF", text);
			if (labels && !h.equals(r.d.entry)) {
				Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(h);
				if (s == null || s.getName().startsWith("LAB_") || s.getName().startsWith("FUN_")) {
					try {
						createLabel(h, "cff_case_" + h.toString().replace(':', '_'), false);
					}
					catch (Exception ex) {
						// conflict
					}
				}
			}
			c++;
		}
		if (r.d.dispatcher != null) {
			currentProgram.getBookmarkManager().setBookmark(r.d.dispatcher, BookmarkType.ANALYSIS, "CFF",
					"CFF dispatcher (state=" + r.d.stateHint + ", cases=" + r.heads.caseHeads.size() + ")");
		}
		println("  annotated " + c + " heads");
	}

	private void writeDot(String path, Function f, CffCore.Recovery r) throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("digraph cff_").append(f.getEntryPoint()).append(" {\n  node [shape=box,fontname=monospace];\n");
		sb.append("  \"").append(r.d.entry).append("\" [label=\"prologue\\n").append(r.d.entry).append("\",style=bold];\n");
		for (Map.Entry<Address, CffCore.Node> e : r.nodes.entrySet()) {
			CffCore.Node n = e.getValue();
			Address h = e.getKey();
			if (!h.equals(r.d.entry)) {
				String shape = n.status.equals("ret") ? ",shape=doublecircle" : "";
				sb.append("  \"").append(h).append("\" [label=\"").append(h).append("\"").append(shape).append("];\n");
			}
			if (n.status.equals("cond")) {
				sb.append("  \"").append(h).append("\" -> \"").append(n.succTrue).append("\" [label=\"").append(n.cond)
						.append("\",color=darkgreen];\n");
				sb.append("  \"").append(h).append("\" -> \"").append(n.succFalse).append("\" [label=\"!").append(n.cond)
						.append("\",color=red];\n");
			}
			else {
				for (int i = 0; i < n.succs.size(); i++) {
					sb.append("  \"").append(h).append("\" -> \"").append(n.succs.get(i)).append("\";\n");
				}
			}
		}
		sb.append("}\n");
		FileWriter w = new FileWriter(path);
		try {
			w.write(sb.toString());
		}
		finally {
			w.close();
		}
	}

	private String jsonFor(Function f, CffCore.Recovery r) {
		StringBuilder sb = new StringBuilder();
		sb.append("    {\"name\": \"").append(esc(f.getName())).append("\", \"entry\": \"").append(f.getEntryPoint())
				.append("\", \"dispatcher\": \"").append(String.valueOf(r.d.dispatcher)).append("\", \"state\": \"")
				.append(esc(r.d.stateHint)).append("\", \"firstHead\": \"").append(String.valueOf(r.firstHead))
				.append("\", \"nodes\": [\n");
		List<Address> heads = new ArrayList<Address>(r.nodes.keySet());
		Collections.sort(heads);
		int k = 0;
		for (int i = 0; i < heads.size(); i++) {
			Address h = heads.get(i);
			CffCore.Node n = r.nodes.get(h);
			if (k++ > 0) {
				sb.append(",\n");
			}
			sb.append("      {\"head\": \"").append(h).append("\", \"status\": \"").append(n.status).append("\", \"pure\": ")
					.append(n.pure).append(", \"selfLoop\": ").append(n.selfLoop).append(", \"succs\": [");
			for (int j = 0; j < n.succs.size(); j++) {
				sb.append(j > 0 ? ", " : "").append("\"").append(n.succs.get(j)).append("\"");
			}
			sb.append("]");
			if (n.status.equals("cond")) {
				sb.append(", \"select\": \"").append(n.selectAddr).append("\", \"decider\": \"").append(esc(n.deciderKind))
						.append("\", \"cond\": \"").append(esc(n.cond)).append("\", \"true\": \"").append(n.succTrue)
						.append("\", \"false\": \"").append(n.succFalse).append("\"");
				if (n.concreteTake != null) {
					sb.append(", \"natural\": ").append(n.concreteTake.booleanValue());
				}
			}
			if (n.note.length() > 0) {
				sb.append(", \"note\": \"").append(esc(n.note)).append("\"");
			}
			sb.append("}");
		}
		sb.append("\n    ]}");
		return sb.toString();
	}

	private Address parseAddr(String s) {
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
