// Dump external entry points (PE/ELF exports) as a JSON array.
// @category Export
// @menupath Tools.Export.Dump Exports
// @description Dump exported symbols (name + address) as JSON

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class DumpExports extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("no currentProgram");
			return;
		}

		SymbolTable st = currentProgram.getSymbolTable();
		int count = 0;
		println("[");
		boolean first = true;
		AddressIterator it = st.getExternalEntryPointIterator();
		while (it.hasNext() && !monitor.isCancelled()) {
			Address addr = it.next();
			Symbol s = st.getPrimarySymbol(addr);
			String name = s != null ? s.getName() : addr.toString();
			Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
			String kind = f != null ? "function" : "symbol";
			if (!first) {
				println(",");
			}
			first = false;
			println("  {\"name\":\"" + escape(name) + "\",\"addr\":\"" + addr + "\",\"kind\":\"" + kind + "\"}");
			count++;
		}
		println("]");
		println("count=" + count + " program=" + currentProgram.getName());
	}

	private static String escape(String s) {
		return s.replace("\\", "\\\\").replace("\"", "\\\"");
	}
}
