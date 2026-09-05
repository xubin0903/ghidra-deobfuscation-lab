#requires -Version 5.1
<#
.SYNOPSIS
  Launch Ghidra GUI with the bundled JDK 21 (never the system JDK 23).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

$ready = Get-GhidraEnv
$bat = Join-Path $ready.GhidraInstall 'ghidraRun.bat'
Write-Host "Ghidra : $($ready.GhidraInstall)"
Write-Host "JAVA   : $($ready.JdkHome)"
Write-Host "scripts: $($ready.ScriptsRoot)"
Write-Host "launch : $bat"
& $bat @args
