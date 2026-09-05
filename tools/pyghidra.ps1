#requires -Version 5.1
<#
.SYNOPSIS
  Launch Ghidra via PyGhidra (native CPython 3, not Jython 2.7).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

$ready = Get-GhidraEnv
$bat = Join-Path $ready.GhidraInstall 'support\pyghidraRun.bat'
if (-not (Test-Path $bat)) {
    throw "pyghidraRun.bat missing: $bat"
}
Write-Host "PyGhidra: $bat"
Write-Host "JAVA    : $($ready.JdkHome)"
Write-Host "scripts : $($ready.ScriptsRoot)"
& $bat @args
