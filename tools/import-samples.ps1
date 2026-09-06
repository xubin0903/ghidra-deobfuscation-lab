#requires -Version 5.1
<#
.SYNOPSIS
  Import the fetched test-suite binaries into the regression project (analysis on).

.DESCRIPTION
  Puts each file of samples\deflat-testsuite\ into a folder of the Ghidra
  project used by tools\cff-regress.ps1 (default projects\cfftest, project
  name "t"): arm32 / aarch64 / x64 / x86 by ELF machine. Programs that already
  exist in the project are skipped. Run tools\fetch-samples.ps1 first.

.EXAMPLE
  .\tools\import-samples.ps1
#>
[CmdletBinding()]
param(
    [string]$SamplesDir,
    [string]$ProjectDir,
    [string]$ProjectName = 't'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $SamplesDir) { $SamplesDir = Join-Path (Get-LabRoot) 'samples\deflat-testsuite' }
if (-not $ProjectDir) { $ProjectDir = Join-Path (Get-ProjectsRoot) 'cfftest' }
if (-not (Test-Path $SamplesDir)) { throw "no samples in $SamplesDir (run tools\fetch-samples.ps1)" }
$headless = Join-Path $PSScriptRoot 'ghidra-headless.ps1'

function Get-ElfFolder([string]$path) {
    $b = [IO.File]::ReadAllBytes($path)
    if ($b.Length -lt 20) { return $null }
    if ($b[0] -eq 0x7f -and $b[1] -eq 0x45) {
        $machine = [BitConverter]::ToUInt16($b, 18)
        switch ($machine) {
            0x28 { return 'arm32' }
            0xb7 { return 'aarch64' }
            0x3e { return 'x64' }
            0x03 { return 'x86' }
            default { return $null }
        }
    }
    if ($b[0] -eq 0xcf -and $b[1] -eq 0xfa -and $b[2] -eq 0xed -and $b[3] -eq 0xfe) {
        # Mach-O 64-bit little-endian: cputype at offset 4 (0x0100000c = arm64, 0x01000007 = x86_64)
        $cpu = [BitConverter]::ToUInt32($b, 4)
        switch ($cpu) {
            0x0100000c { return 'aarch64' }
            0x01000007 { return 'x64' }
            default { return $null }
        }
    }
    return $null
}

$existing = @()
if (Test-Path (Join-Path $ProjectDir "$ProjectName.rep")) {
    $existing = Get-ChildItem (Join-Path $ProjectDir "$ProjectName.rep\idata") -Recurse -Filter '*.prp' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $m = Select-String -Path $_.FullName -Pattern 'NAME="NAME" TYPE="string" VALUE="([^"]+)"' | Select-Object -First 1
            if ($m) { $m.Matches[0].Groups[1].Value }
        }
}
foreach ($f in Get-ChildItem $SamplesDir -File | Where-Object { $_.Extension -notin '.c', '.txt' }) {
    $folder = Get-ElfFolder $f.FullName
    if (-not $folder) { Write-Host "skip $($f.Name): not an ELF this lab handles"; continue }
    if ($existing -contains $f.Name) { Write-Host "skip $($f.Name): already in project"; continue }
    Write-Host "import $($f.Name) -> $ProjectName/$folder"
    & $headless -ProjectDir $ProjectDir -ProjectName "$ProjectName/$folder" -Import $f.FullName 6>$null 2>&1 |
        Select-String -Pattern 'REPORT: Import succeeded|Analysis succeeded|ERROR|Exception' | ForEach-Object { "    $($_.Line -replace '^INFO\s+','')" }
}
