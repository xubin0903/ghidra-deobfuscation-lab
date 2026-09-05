# HelloPyGhidra

**Path:** `scripts/python/HelloPyGhidra.py`  
**Lang:** PyGhidra (CPython 3)  
**Category:** Python

## Purpose

Smoke-test that Script Manager is executing `.py` files with **CPython 3 / PyGhidra**, not Jython 2.7. Prints `sys.version` and `currentProgram`.

## When

- First time you wire PyGhidra on this machine
- A Python script failed with `Ghidra was not started with PyGhidra` or printed a `2.7.4` Jython banner

## GUI

1. `.\tools\pyghidra.ps1`  (**not** `ghidra.ps1`)
2. Script Manager → Python → `HelloPyGhidra.py` → Run
3. Console should contain `ok: CPython3 / PyGhidra`

If you see `Python 2.7.4` / Jython, you launched the wrong wrapper.

## Headless

Do not assume Script Manager `.py` files run unchanged under `analyzeHeadless`. Prefer Java for unattended jobs, or use the `pyghidra` Python module (`pyghidra.ghidra_script(...)`) from CPython.

## Inputs / outputs

- Input: none required (`currentProgram` may be None)
- Output: console
- Does not mutate the DB
