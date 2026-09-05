// Heuristic: functions that look like they decrypt/transform a byte buffer.
// @category Deobfuscation
// @menupath Tools.Deobfuscation.Find Encrypted String Refs
// @description Flag functions with xor/add/rol loops (string-decrypt candidates)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

public class FindEncryptedStringRefs extends GhidraScript {

	private static final int MIN_HITS = 4;

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}

		Listing listing = currentProgram.getListing();
		int flagged = 0;
		println("name\tentry\txor\tadd\trol/ror\tscore");
		FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
		while (fit.hasNext() && !monitor.isCancelled()) {
			Function f = fit.next();
			monitor.setMessage(f.getName());
			int xor = 0, add = 0, rot = 0;
			InstructionIterator ii = listing.getInstructions(f.getBody(), true);
			while (ii.hasNext()) {
				Instruction in = ii.next();
				String mnem = in.getMnemonicString().toLowerCase();
				// xor: x86 xor/pxor/xorps, ARM/AArch64 eor/eon/veor
				if (mnem.startsWith("xor") || mnem.equals("pxor") || mnem.startsWith("eor") || mnem.equals("eon")
						|| mnem.equals("veor")) {
					// skip xor r,r / eor r,r,r (zeroing)
					if (isSelfXor(in)) {
						continue;
					}
					xor++;
				}
				else if (mnem.startsWith("add") || mnem.startsWith("sub")) {
					add++;
				}
				// rotates: x86 rol/ror/rcl/rcr, ARM/AArch64 ror/extr (ror is the
				// AArch64 rotate; ARM shifts appear as an operand suffix, caught below)
				else if (mnem.startsWith("rol") || mnem.startsWith("ror") || mnem.startsWith("rcl")
						|| mnem.startsWith("rcr") || mnem.equals("extr")) {
					rot++;
				}
				else if (in.toString().toLowerCase().contains(", ror ") || in.toString().toLowerCase().contains(",ror ")) {
					rot++; // ARM barrel-shifter rotate as an operand modifier
				}
			}
			int score = xor * 3 + rot * 2 + Math.min(add, 8);
			if (xor >= MIN_HITS || rot >= MIN_HITS || score >= 16) {
				println(f.getName() + "\t" + f.getEntryPoint() + "\t" + xor + "\t" + add + "\t" + rot + "\t" + score);
				flagged++;
			}
		}
		println("flagged=" + flagged + " program=" + currentProgram.getName());
		println("this script does NOT decrypt. see docs/cookbook/string-encryption.md");
	}

	/** True for a zeroing idiom: xor eax,eax / eor w0,w0,w0 (all register operands identical). */
	private static boolean isSelfXor(Instruction in) {
		int n = in.getNumOperands();
		if (n < 2) {
			return false;
		}
		String first = in.getDefaultOperandRepresentation(0);
		if (first == null) {
			return false;
		}
		for (int i = 1; i < n; i++) {
			if (!first.equals(in.getDefaultOperandRepresentation(i))) {
				return false;
			}
		}
		return true;
	}
}
