// List every function in the current program: name, entry, body size.
// @category Analysis
// @menupath Tools.Analysis.List Functions
// @description Print function name, entry, and body size

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ListFunctions extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}

		int count = 0;
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		println("name\tentry\tsize");
		while (it.hasNext() && !monitor.isCancelled()) {
			Function f = it.next();
			long size = f.getBody().getNumAddresses();
			println(f.getName() + "\t" + f.getEntryPoint() + "\t" + size);
			count++;
		}
		println("total=" + count + " program=" + currentProgram.getName());
	}
}
