// Headless-friendly summary: program + function/export counts.
// @category Headless
// @description Print program name, language, function count, export count (no GUI)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SymbolTable;

public class HeadlessSummary extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}
		FunctionManager fm = currentProgram.getFunctionManager();
		SymbolTable st = currentProgram.getSymbolTable();
		int exports = 0;
		AddressIterator eit = st.getExternalEntryPointIterator();
		while (eit.hasNext()) {
			eit.next();
			exports++;
		}
		println("program=" + currentProgram.getName());
		println("path=" + currentProgram.getExecutablePath());
		println("language=" + currentProgram.getLanguageID());
		println("compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID());
		println("imageBase=" + currentProgram.getImageBase());
		println("functions=" + fm.getFunctionCount());
		println("exports=" + exports);
	}
}
