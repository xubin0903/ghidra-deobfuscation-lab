#requires -Version 5.1
<#
.SYNOPSIS
  One-command regression for the CFF suite (CffScan / CffRecover / CffDeflatten).

.DESCRIPTION
  Copies the shared lab project to %TEMP% (the original is never written), then
  for every fixture listed in cff-regress.expected.json:
    1. HashMemory      -> pristine SHA-256 of every initialized block
    2. CffDeflatten all -> patch + 4-seed verify + structural oracle
    3. HashMemory      -> must differ when patches were applied
    4. CffDeflatten undo -> HashMemory must be back to the pristine value
  and compares the counts (functions patched / verified / reverted / full-mode /
  low-confidence) with the recorded baseline. Exit code 1 on any regression
  (fewer verified, more reverted, undo not byte-exact, script error).

.EXAMPLE
  .\tools\cff-regress.ps1                 # everything (the -O2 SDK takes ~5 min)
  .\tools\cff-regress.ps1 -Quick          # skip fixtures marked "slow"
  .\tools\cff-regress.ps1 -Only sample_cff,x64
  .\tools\cff-regress.ps1 -UpdateExpected # accept the current numbers as the new baseline
#>
[CmdletBinding()]
param(
    [string]$ProjectDir,
    [string]$ProjectName = 't',
    [string]$Expected = (Join-Path $PSScriptRoot 'cff-regress.expected.json'),
    [string[]]$Only,
    [switch]$Quick,
    [switch]$UpdateExpected,
    [switch]$KeepScratch
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $ProjectDir) { $ProjectDir = Join-Path (Get-ProjectsRoot) 'cfftest' }
if (-not (Test-Path $ProjectDir)) { throw "project dir not found: $ProjectDir" }
if (-not (Test-Path $Expected)) { throw "baseline not found: $Expected" }
$headless = Join-Path $PSScriptRoot 'ghidra-headless.ps1'

$baseline = Get-Content $Expected -Raw | ConvertFrom-Json
$fixtures = @($baseline.fixtures)
if ($Only) { $fixtures = @($fixtures | Where-Object { $Only -contains $_.id }) }
if ($Quick) { $fixtures = @($fixtures | Where-Object { -not $_.slow }) }
if ($fixtures.Count -eq 0) { throw 'no fixtures selected' }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$scratch = Join-Path $env:TEMP "cff-regress-$stamp"
Write-Host "scratch project: $scratch  (copy of $ProjectDir)"
Copy-Item $ProjectDir $scratch -Recurse
Get-ChildItem $scratch -Filter '*.lock*' -ErrorAction SilentlyContinue | Remove-Item -Force
# Freeze the scripts too: headless compiles them from source at every run, so
# editing scripts\ while the regression runs would otherwise test a moving target.
$scriptsSnap = Join-Path $scratch '_scripts'
Copy-Item (Get-ScriptsRoot) $scriptsSnap -Recurse
$rev = try { (& git -C (Get-LabRoot) describe --always --dirty 2>$null) } catch { $null }
if ($rev) { Write-Host "scripts snapshot: $rev" }

function Invoke-Headless([string]$folder, [string]$program, [string[]]$scriptArgs, [string]$logPath) {
    # The wrapper's banner goes to the information stream (Write-Host): drop it;
    # the script output (stdout + stderr) is what we parse and keep.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $headless -ProjectDir $scratch -ProjectName "$ProjectName/$folder" -Process $program -Analysis:$false -ScriptsRoot $scriptsSnap -PostScript @scriptArgs 6>$null 2>&1 |
            ForEach-Object { "$_" }
    }
    finally {
        $ErrorActionPreference = $prev
    }
    $raw | Out-File $logPath -Encoding utf8
    # strip the headless log decorations so the callers can match on plain script output
    $raw | ForEach-Object { $_ -replace '^(INFO|ERROR|WARN)\s+\S+\.java> ', '' -replace ' \(GhidraScript\)\s*$', '' }
}

function Get-Hash([string]$folder, [string]$program, [string]$tag) {
    $lines = Invoke-Headless $folder $program @('HashMemory.java') (Join-Path $scratch "$tag.hash.log")
    $m = $lines | Where-Object { $_ -match '^TOTAL program=.* sha256=([0-9a-f]{64})' } | Select-Object -Last 1
    if (-not $m) { throw "HashMemory produced no TOTAL line for $program ($tag)" }
    return ([regex]::Match($m, 'sha256=([0-9a-f]{64})')).Groups[1].Value
}

$results = @()
$failed = $false
$sw = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($fx in $fixtures) {
    $t0 = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "=== $($fx.id): $($fx.folder)/$($fx.program) ===" -ForegroundColor Cyan
    $r = [ordered]@{
        id = $fx.id; program = $fx.program; patched = 0; verified = 0; reverted = 0; lowConfidence = 0
        full = 0; partial = 0; caveExhausted = 0; patches = 0; undoExact = $false; errors = 0; seconds = 0; status = 'ok'; notes = @()
    }
    try {
        $h0 = Get-Hash $fx.folder $fx.program "$($fx.id).0-pristine"
        $patchLog = Join-Path $scratch "$($fx.id).patch.json"
        $out = Invoke-Headless $fx.folder $fx.program @('CffDeflatten.java', 'all', "log=$patchLog") (Join-Path $scratch "$($fx.id).deflatten.log")

        $r.full = @($out | Where-Object { $_ -match '^--- .* mode=full' }).Count
        $r.partial = @($out | Where-Object { $_ -match '^--- .* mode=partial' }).Count
        $r.verified = @($out | Where-Object { $_ -match '^\s*verify \S+: OK' }).Count
        $r.reverted = @($out | Where-Object { $_ -match '^\s*verify \S+: MISMATCH' }).Count
        $r.lowConfidence = @($out | Where-Object { $_ -match 'LOW CONFIDENCE' }).Count
        $r.caveExhausted = @($out | Where-Object { $_ -match 'code cave exhausted' }).Count
        $r.errors = @($out | Where-Object { $_ -match '^ERROR\s+REPORT|Exception|^ERROR .*CffDeflatten' -and $_ -notmatch 'Emulation failure' }).Count
        $applied = $out | Where-Object { $_ -match '^applied (\d+)/(\d+) patches' } | Select-Object -Last 1
        if ($applied) { $r.patches = [int]([regex]::Match($applied, '^applied (\d+)/')).Groups[1].Value }
        $r.patched = $r.verified + $r.reverted

        $h1 = Get-Hash $fx.folder $fx.program "$($fx.id).1-patched"
        if ($r.patches -gt 0 -and $h1 -eq $h0) { $r.notes += 'patches reported but bytes unchanged'; $r.status = 'FAIL' }

        if (Test-Path $patchLog) {
            $undo = Invoke-Headless $fx.folder $fx.program @('CffDeflatten.java', "undo=$patchLog") (Join-Path $scratch "$($fx.id).undo.log")
            if (-not ($undo | Where-Object { $_ -match '^undo: restored' })) { $r.notes += 'undo printed no summary'; $r.status = 'FAIL' }
        }
        $h2 = Get-Hash $fx.folder $fx.program "$($fx.id).2-undone"
        $r.undoExact = ($h2 -eq $h0)
        if (-not $r.undoExact) { $r.notes += "undo is not byte-exact (pristine $($h0.Substring(0,12)) vs undone $($h2.Substring(0,12)))"; $r.status = 'FAIL' }
        if ($r.errors -gt 0) { $r.notes += "$($r.errors) error line(s) in the deflatten log"; $r.status = 'FAIL' }

        # compare with the baseline
        $e = $fx.expect
        if ($e -and -not $UpdateExpected) {
            if ($r.verified -lt $e.verified) { $r.notes += "verified $($r.verified) < baseline $($e.verified)"; $r.status = 'FAIL' }
            if ($r.reverted -gt $e.reverted) { $r.notes += "reverted $($r.reverted) > baseline $($e.reverted)"; $r.status = 'FAIL' }
            if ($r.full -lt $e.full) { $r.notes += "full-mode $($r.full) < baseline $($e.full)"; if ($r.status -eq 'ok') { $r.status = 'WARN' } }
            if ($r.lowConfidence -ne $e.lowConfidence) { $r.notes += "low-confidence $($r.lowConfidence) != baseline $($e.lowConfidence)"; if ($r.status -eq 'ok') { $r.status = 'WARN' } }
            if ($r.verified -gt $e.verified -or $r.full -gt $e.full) { $r.notes += 'better than baseline; re-run with -UpdateExpected to record it' }
        }
    }
    catch {
        $r.status = 'FAIL'
        $r.notes += "exception: $($_.Exception.Message)"
    }
    $r.seconds = [int]$t0.Elapsed.TotalSeconds
    if ($r.status -eq 'FAIL') { $failed = $true }
    $color = switch ($r.status) { 'ok' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
    Write-Host ("  {0,-5} patched={1} verified={2} reverted={3} full={4} partial={5} lowconf={6} cave-exhausted={7} patches={8} undoExact={9} {10}s" -f `
        $r.status, $r.patched, $r.verified, $r.reverted, $r.full, $r.partial, $r.lowConfidence, $r.caveExhausted, $r.patches, $r.undoExact, $r.seconds) -ForegroundColor $color
    foreach ($n in $r.notes) { Write-Host "        - $n" -ForegroundColor $color }
    $results += [pscustomobject]$r
}

Write-Host ""
Write-Host ("total {0}s; results + logs in {1}" -f [int]$sw.Elapsed.TotalSeconds, $scratch)
$results | ConvertTo-Json -Depth 4 | Out-File (Join-Path $scratch 'results.json') -Encoding utf8

if ($UpdateExpected) {
    foreach ($fx in $baseline.fixtures) {
        $r = $results | Where-Object { $_.id -eq $fx.id } | Select-Object -First 1
        if ($r) {
            $fx.expect = [pscustomobject]@{ patched = $r.patched; verified = $r.verified; reverted = $r.reverted; full = $r.full; lowConfidence = $r.lowConfidence }
        }
    }
    $baseline.recorded = (Get-Date).ToString('yyyy-MM-dd')
    $baseline | ConvertTo-Json -Depth 5 | Out-File $Expected -Encoding utf8
    Write-Host "baseline updated: $Expected"
}

if (-not $failed -and -not $KeepScratch) {
    Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'scratch removed'
}
elseif ($failed) {
    Write-Host 'REGRESSION: scratch kept for inspection' -ForegroundColor Red
}
exit $(if ($failed) { 1 } else { 0 })
