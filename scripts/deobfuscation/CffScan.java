// CffScan — precise triage for OLLVM / Hikari / Arkari control-flow-flattening.
//
// @category Deobfuscation
// @menupath Tools.Deobfuscation.CFF Scan
// @description Detect control-flow-flattened functions (dominator flattening score + CFF scaffold), low false positive.
//
// Scenario: "which functions in this binary are CFF-flattened, and where is the
// dispatcher?" Run it first; it does NOT modify code. Feed the flagged function
// addresses to CffRecover / CffDeflatten.
//
// Detection = mrphrazer flattening score (>=0.90) corroborated by the OLLVM
// scaffold (a pre-dispatcher with high fan-in whose single successor is a
// high-fan-out dispatcher). Both must hold, so real loops are not flagged.
//
// Args (all optional, headless: "name=value" after -postScript CffScan.java):
//   all             scan every function (default when headless / no cursor)
//   func=0x14400    scan a single function at this address
//   min=0.90        flattening-score threshold to call something CFF
//   suspect=0.60    threshold for the weaker "suspect" tier
//   fanin=3         minimum pre-dispatcher fan-in
//   nodes=6         minimum basic-block count
//   top=100         max rows to print per tier
//   json=PATH       write a JSON report
//   noBookmark      do not drop CFF bookmarks

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.BookmarkType;

public class CffScan extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		double min = CffCore.SCORE_CFF;
		double suspect = CffCore.SCORE_SUSPECT;
		int fanin = CffCore.MIN_FANIN;
		int nodes = CffCore.MIN_NODES;
		int top = 100;
		boolean all = false;
		boolean bookmark = true;
		String jsonPath = null;
		Address single = null;

		// cmd.exe splits "key=value" into two tokens; parseArgs accepts both forms
		CffCore.Args a = CffCore.parseArgs(getScriptArgs(),
				new String[] { "func", "min", "suspect", "fanin", "nodes", "top", "json" });
		all = a.flag("all");
		bookmark = !a.flag("noBookmark");
		if (a.get("func") != null) {
			single = parseAddr(a.get("func"));
		}
		min = a.getDouble("min", min);
		suspect = a.getDouble("suspect", suspect);
		fanin = a.getInt("fanin", fanin);
		nodes = a.getInt("nodes", nodes);
		top = a.getInt("top", top);
		jsonPath = a.get("json");
		CffCore.SCORE_CFF = min;
		CffCore.SCORE_SUSPECT = suspect;
		CffCore.MIN_FANIN = fanin;
		CffCore.MIN_NODES = nodes;

		List<Function> targets = new ArrayList<Function>();
		if (single != null) {
			Function f = getFunctionContaining(single);
			if (f == null) {
				f = getFunctionAt(single);
			}
			if (f == null) {
				printerr("no function at " + single);
				return;
			}
			targets.add(f);
		}
		else if (all || currentAddress == null || getFunctionContaining(currentAddress) == null) {
			FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
			while (fit.hasNext()) {
				Function f = fit.next();
				if (f.isExternal() || f.isThunk()) {
					continue;
				}
				targets.add(f);
			}
		}
		else {
			targets.add(getFunctionContaining(currentAddress));
		}

		println("=== CffScan ===");
		println("program=" + currentProgram.getName() + " language=" + currentProgram.getLanguageID());
		println("thresholds: cff>=" + min + " suspect>=" + suspect + " fanin>=" + fanin + " nodes>=" + nodes);
		println("scanning " + targets.size() + " function(s)");

		List<CffCore.Detect> cff = new ArrayList<CffCore.Detect>();
		List<CffCore.Detect> suspects = new ArrayList<CffCore.Detect>();
		int scanned = 0;
		for (int i = 0; i < targets.size(); i++) {
			if (monitor.isCancelled()) {
				break;
			}
			Function f = targets.get(i);
			monitor.setMessage("CffScan " + f.getName());
			CffCore.Detect d;
			try {
				d = CffCore.detect(currentProgram, f, monitor);
			}
			catch (Exception e) {
				printerr("detect failed " + f.getName() + " @" + f.getEntryPoint() + ": " + e);
				continue;
			}
			scanned++;
			if (d.tier.equals("cff")) {
				cff.add(d);
			}
			else if (d.tier.equals("suspect")) {
				suspects.add(d);
			}
		}

		Comparator<CffCore.Detect> byScore = new Comparator<CffCore.Detect>() {
			@Override
			public int compare(CffCore.Detect a, CffCore.Detect b) {
				int c = Double.compare(b.score, a.score);
				return c != 0 ? c : Integer.compare(b.fanIn, a.fanIn);
			}
		};
		Collections.sort(cff, byScore);
		Collections.sort(suspects, byScore);

		println("");
		println("scanned=" + scanned + " CFF=" + cff.size() + " suspect=" + suspects.size());
		println("--- CFF (flattened) ---");
		printTier(cff, top);
		if (!suspects.isEmpty()) {
			println("--- suspect (high score, weak scaffold; inspect manually) ---");
			printTier(suspects, top);
		}

		if (bookmark) {
			for (int i = 0; i < cff.size(); i++) {
				CffCore.Detect d = cff.get(i);
				Address at = d.dispatcher != null ? d.dispatcher : d.entry;
				currentProgram.getBookmarkManager().setBookmark(at, BookmarkType.ANALYSIS, "CFF",
						"CFF flattened " + d.func.getName() + " score=" + fmt(d.score) + " fanIn=" + d.fanIn
								+ " relevant=" + d.relevantCount + " state=" + d.stateHint);
			}
		}

		if (jsonPath != null) {
			writeJson(jsonPath, cff, suspects);
			println("json written: " + jsonPath);
		}
		println("done. see docs/scripts/CffScan.md");
	}

	private void printTier(List<CffCore.Detect> list, int top) {
		int lim = Math.min(list.size(), top);
		for (int i = 0; i < lim; i++) {
			CffCore.Detect d = list.get(i);
			println(String.format("  %-24s @%s score=%s nodes=%d fanIn=%d preOut=%d dispOut=%d clean=%s hubDom=%s ret=%d disp=%s state=%s",
					d.func.getName(), d.entry, fmt(d.score), d.nodeCount, d.fanIn, d.preOutDeg, d.dispatcherFanOut,
					fmt(d.cleanRatio), fmt(d.hubDomFrac), d.returnCount, d.dispatcher, d.stateHint));
		}
		if (list.size() > lim) {
			println("  ... " + (list.size() - lim) + " more");
		}
	}

	private String fmt(double v) {
		// Locale-independent: a comma decimal separator (de/fr locales) would
		// corrupt the JSON report.
		return String.format(java.util.Locale.ROOT, "%.3f", v);
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

	private void writeJson(String path, List<CffCore.Detect> cff, List<CffCore.Detect> suspects) throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("{\n  \"program\": \"").append(esc(currentProgram.getName())).append("\",\n");
		sb.append("  \"cff\": [\n");
		appendJsonList(sb, cff);
		sb.append("  ],\n  \"suspect\": [\n");
		appendJsonList(sb, suspects);
		sb.append("  ]\n}\n");
		FileWriter w = new FileWriter(path);
		try {
			w.write(sb.toString());
		}
		finally {
			w.close();
		}
	}

	private void appendJsonList(StringBuilder sb, List<CffCore.Detect> list) {
		for (int i = 0; i < list.size(); i++) {
			CffCore.Detect d = list.get(i);
			sb.append("    {\"name\": \"").append(esc(d.func.getName())).append("\", \"entry\": \"").append(d.entry)
					.append("\", \"score\": ").append(fmt(d.score)).append(", \"nodes\": ").append(d.nodeCount)
					.append(", \"fanIn\": ").append(d.fanIn).append(", \"dispatcher\": \"")
					.append(String.valueOf(d.dispatcher)).append("\", \"relevant\": ").append(d.relevantCount)
					.append(", \"state\": \"").append(esc(d.stateHint)).append("\"}");
			sb.append(i + 1 < list.size() ? ",\n" : "\n");
		}
	}

	private String esc(String s) {
		return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
	}
}
