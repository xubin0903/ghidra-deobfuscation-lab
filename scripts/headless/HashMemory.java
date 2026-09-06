// HashMemory — SHA-256 over the program's initialized memory, block by block
// and in total. Headless-friendly oracle for "did this patch/undo round trip
// leave the bytes exactly as they were" (the CFF regression harness runs it
// before apply, after apply and after undo).
//
// @category Headless
// @description Print SHA-256 of every initialized memory block and of all of them together (byte-exact patch/undo oracle)
//
// Args (headless: after -postScript HashMemory.java):
//   exec            hash only executable blocks
//   block=NAME      hash only the block with this name (repeatable via "block=a block=b")
//   out=PATH        also append the TOTAL line to this file (one line per run)

import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class HashMemory extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		boolean execOnly = false;
		Set<String> only = new HashSet<String>();
		String out = null;
		String[] args = getScriptArgs();
		for (int i = 0; args != null && i < args.length; i++) {
			String t = args[i];
			if (t.equals("exec")) {
				execOnly = true;
			}
			else if (t.startsWith("block=")) {
				only.add(t.substring(6));
			}
			else if (t.startsWith("out=")) {
				out = t.substring(4);
			}
			else if ((t.equals("block") || t.equals("out")) && i + 1 < args.length) {
				// cmd.exe splits key=value into two tokens
				if (t.equals("block")) {
					only.add(args[++i]);
				}
				else {
					out = args[++i];
				}
			}
		}
		Memory mem = currentProgram.getMemory();
		MessageDigest total = MessageDigest.getInstance("SHA-256");
		long totalBytes = 0;
		int blocks = 0;
		List<String> lines = new ArrayList<String>();
		byte[] buf = new byte[65536];
		for (MemoryBlock b : mem.getBlocks()) {
			if (!b.isInitialized()) {
				continue;
			}
			if (execOnly && !b.isExecute()) {
				continue;
			}
			if (!only.isEmpty() && !only.contains(b.getName())) {
				continue;
			}
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			long off = 0;
			long size = b.getSize();
			while (off < size) {
				int n = (int) Math.min(buf.length, size - off);
				int got = b.getBytes(b.getStart().add(off), buf, 0, n);
				if (got <= 0) {
					break;
				}
				md.update(buf, 0, got);
				total.update(buf, 0, got);
				off += got;
			}
			blocks++;
			totalBytes += size;
			lines.add("BLOCK " + b.getName() + " " + b.getStart() + "-" + b.getEnd() + " bytes=" + size + " sha256=" + hex(md.digest()));
		}
		for (String l : lines) {
			println(l);
		}
		// function count rides along: a byte-exact round trip can still lose listing
		// state (e.g. a removed memory block deletes the functions whose body touched it)
		String totalLine = "TOTAL program=" + currentProgram.getName() + " blocks=" + blocks + " bytes=" + totalBytes
				+ " functions=" + currentProgram.getFunctionManager().getFunctionCount() + " sha256=" + hex(total.digest());
		println(totalLine);
		if (out != null) {
			FileWriter w = new FileWriter(out, true);
			try {
				w.write(totalLine + System.lineSeparator());
			}
			finally {
				w.close();
			}
		}
	}

	private static String hex(byte[] d) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < d.length; i++) {
			sb.append(String.format("%02x", d[i] & 0xff));
		}
		return sb.toString();
	}
}
