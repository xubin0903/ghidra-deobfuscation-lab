#requires -Version 5.1
<#
.SYNOPSIS
  Headless Ghidra wrapper. Always uses bundled JDK 21 + this lab's scripts dir.

.EXAMPLE
  .\tools\ghidra-headless.ps1 -ProjectDir E:\Projects\ghidra\projects\lab -ProjectName lab -Import C:\bins\a.exe

.EXAMPLE
  .\tools\ghidra-headless.ps1 -ProjectDir E:\Projects\ghidra\projects\lab -ProjectName lab -Process a.exe -PostScript DumpExports.java
#>
[CmdletBinding(DefaultParameterSetName='Raw', PositionalBinding=$false)]
param(
    [string]$ProjectDir,
    [string]$ProjectName,
    [string]$Import,
    [string]$Process,
    [switch]$Analysis,
    [string[]]$PreScript,
    [string[]]$PostScript,
    [string[]]$ScriptPath,
    [string]$ScriptsRoot,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Passthru
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

$ready = Get-GhidraEnv
$bat = Join-Path $ready.GhidraInstall 'support\analyzeHeadless.bat'
if (-not (Test-Path $bat)) {
    throw "analyzeHeadless.bat missing: $bat"
}

# Headless looks up -postScript by filename and does NOT recurse.
# analyzeHeadless takes ONE -scriptPath with semicolon-separated dirs
# (multiple -scriptPath flags overwrite; last one wins). Enumerate the scripts
# tree so a newly added scripts\<category>\ folder is found without editing this.
# -ScriptsRoot replaces the lab's scripts\ with another tree (the regression
# harness runs against a frozen copy so the working tree can keep changing).
$scriptsRoot = if ($ScriptsRoot) { $ScriptsRoot } else { $ready.ScriptsRoot }
$extraScriptPaths = @($scriptsRoot)
$extraScriptPaths += (Get-ChildItem -Path $scriptsRoot -Directory -Recurse -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName)
if ($ScriptPath) { $extraScriptPaths += $ScriptPath }
$extraScriptPaths = @($extraScriptPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)

$argv = @()
if ($ProjectDir -and $ProjectName) {
    if (-not (Test-Path $ProjectDir)) {
        New-Item -ItemType Directory -Force -Path $ProjectDir | Out-Null
    }
    $argv += @($ProjectDir, $ProjectName)
    if ($Import) { $argv += @('-import', $Import) }
    if ($Process) { $argv += @('-process', $Process) }
    if ($PSBoundParameters.ContainsKey('Analysis')) {
        # -Analysis  => let the default analyzers run (analyzeHeadless analyzes
        #               on import by default, so add nothing).
        # -Analysis:$false => reuse the saved analysis, do not re-run.
        # NB: -analysisTimeoutPerFile 0 means "cancel immediately" (0 s), not
        # "no timeout" (-1 is the no-timeout sentinel), so never pass 0 here.
        if (-not $Analysis) { $argv += '-noanalysis' }
    }
    $argv += @('-scriptPath', ($extraScriptPaths -join ';'))
    foreach ($s in $PreScript) { $argv += @('-preScript', $s) }
    foreach ($s in $PostScript) { $argv += @('-postScript', $s) }
}

# Script args for the last -postScript (Ghidra: -postScript Name [arg]*).
# Do NOT pass a bare "--" — PowerShell 5.1 can bind the next token to -Process.
if ($Passthru) {
    $argv += ($Passthru | Where-Object { $_ -ne '--' })
}
Write-Host "headless: $bat"
Write-Host "args    : $($argv -join ' ')"

# analyzeHeadless.bat forwards args through cmd.exe `%*`, which treats ';' (and
# ',') as token delimiters. PowerShell 5.1 will NOT quote a bare "a;b;c" arg, so
# the semicolon-joined -scriptPath would be split into several bogus positional
# args ("Bad argument: ...\scripts\deobfuscation"). Build an explicitly quoted
# command line and hand the whole thing to cmd.exe so the quotes survive.
$cmdline = '"' + $bat + '"'
foreach ($tok in $argv) {
    if ($null -eq $tok) { continue }
    if ($tok -eq '' -or $tok -match '[;,\s"]') {
        $cmdline += ' "' + ($tok -replace '"', '\"') + '"'
    }
    else {
        $cmdline += ' ' + $tok
    }
}
& $env:ComSpec /c $cmdline
exit $LASTEXITCODE
