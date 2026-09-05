# HelloPyGhidra
# @category Python
# @menupath Tools.Python.Hello PyGhidra
# @description Smoke-test that this script is running under CPython 3 (PyGhidra), not Jython 2.7

import sys

ver = sys.version.replace("\n", " ")
println("python=" + ver)
println("executable=" + getattr(sys, "executable", "?"))
if currentProgram is None:
    println("program=None")
else:
    println("program=" + currentProgram.getName())

if sys.version_info[0] < 3:
    printerr("this is Jython/Python2. relaunch with tools\\pyghidra.ps1")
else:
    println("ok: CPython3 / PyGhidra")
