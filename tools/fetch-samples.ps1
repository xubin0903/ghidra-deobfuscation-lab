#requires -Version 5.1
<#
.SYNOPSIS
  Download the public, purpose-built obfuscation test binaries this lab uses as fixtures.

.DESCRIPTION
  These are tiny test programs (a `check_password()` and a 20-line `target.c`,
  sources included) that the author of the open-source deobfuscation tool
  cq674350529/deflat compiled with Obfuscator-LLVM (-fla control-flow
  flattening, -bcf bogus control flow) specifically so that deobfuscation
  tools can be tested against them. They are not third-party software, contain
  no real functionality and are used here only to test this lab's scripts.
  Pinned to one upstream commit; SHA-256 of every file is checked.

  Files land in samples\deflat-testsuite\ (gitignored). Import them into the
  regression project with tools\import-samples.ps1.

.EXAMPLE
  .\tools\fetch-samples.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $OutDir) { $OutDir = Join-Path (Get-LabRoot) 'samples\deflat-testsuite' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$repo = 'cq674350529/deflat'
$commit = '34a43cbfc9ae5806f2cd6371e67551e51d681d3f'
$files = @(
    # control-flow flattening: original / flattened, per architecture (+ upstream's own recovered output for comparison)
    'flat_control_flow/samples/src/check_passwd.c',
    'flat_control_flow/samples/bin/check_passwd_arm',
    'flat_control_flow/samples/bin/check_passwd_arm_flat',
    'flat_control_flow/samples/bin/check_passwd_arm64',
    'flat_control_flow/samples/bin/check_passwd_arm64_flat',
    'flat_control_flow/samples/bin/check_passwd_x8664',
    'flat_control_flow/samples/bin/check_passwd_x8664_flat',
    # bogus control flow: original / obfuscated
    'bogus_control_flow/samples/src/target.c',
    'bogus_control_flow/samples/bin/target_arm',
    'bogus_control_flow/samples/bin/target_arm_bogus',
    'bogus_control_flow/samples/bin/target_x86',
    'bogus_control_flow/samples/bin/target_x86_bogus'
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$sha = [System.Security.Cryptography.SHA256]::Create()
$manifest = @()
foreach ($f in $files) {
    $name = Split-Path $f -Leaf
    $dest = Join-Path $OutDir $name
    $url = "https://raw.githubusercontent.com/$repo/$commit/$f"
    if (-not (Test-Path $dest)) {
        Write-Host "fetch $name"
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    }
    $hash = ($sha.ComputeHash([IO.File]::ReadAllBytes($dest)) | ForEach-Object { $_.ToString('x2') }) -join ''
    $manifest += "$hash  $name  <- $repo@$($commit.Substring(0,8)):$f"
}
$manifestPath = Join-Path $OutDir 'SHA256SUMS.txt'
$expected = Join-Path $PSScriptRoot 'fetch-samples.sha256'
if (Test-Path $expected) {
    $want = @{}
    foreach ($line in Get-Content $expected) {
        if ($line -match '^([0-9a-f]{64})\s+(\S+)') { $want[$Matches[2]] = $Matches[1] }
    }
    $bad = 0
    foreach ($m in $manifest) {
        $h, $n = ($m -split '\s+')[0, 1]
        if ($want.ContainsKey($n) -and $want[$n] -ne $h) { Write-Host "SHA-256 MISMATCH: $n" -ForegroundColor Red; $bad++ }
    }
    if ($bad) { throw "$bad file(s) do not match tools\fetch-samples.sha256" }
    Write-Host "all $($manifest.Count) files match tools\fetch-samples.sha256"
}
$manifest | Out-File $manifestPath -Encoding ascii
Write-Host "samples in $OutDir"
