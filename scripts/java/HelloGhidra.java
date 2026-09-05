// Tiny GUI/headless smoke test.
// @category Java
// @menupath Tools.Java.Hello Ghidra
// @description Print program name and image base

import ghidra.app.script.GhidraScript;

public class HelloGhidra extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			println("hello from Ghidra, no currentProgram");
			return;
		}
		println("program=" + currentProgram.getName());
		println("imageBase=" + currentProgram.getImageBase());
		println("language=" + currentProgram.getLanguageID());
	}
}
