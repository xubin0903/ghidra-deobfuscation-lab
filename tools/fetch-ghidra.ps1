#requires -Version 5.1
<#
.SYNOPSIS
  Download the latest (or pinned) Ghidra PUBLIC zip into dist\ and optionally extract to ghidra\.
#>
[CmdletBinding()]
param(
    [string]$Tag = 'Ghidra_12.1.3_build',
    [string]$Asset = 'ghidra_12.1.3_PUBLIC_20260817.zip',
    [string]$Sha256 = '93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54',
    [switch]$Extract
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

$dist = Get-DistRoot
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$zip = Join-Path $dist $Asset

function Test-Hash($path, $expect) {
    $actual = (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant()
    $expect = $expect.ToLowerInvariant()
    if ($actual -ne $expect) {
        throw "SHA-256 mismatch for $path`n  expected $expect`n  actual   $actual"
    }
    Write-Host "OK sha256 $actual"
}

$needDownload = $true
if (Test-Path $zip) {
    try {
        Test-Hash $zip $Sha256
        $needDownload = $false
        Write-Host "already have $zip"
    } catch {
        Write-Warning $_
        Remove-Item -Force $zip
    }
}

if ($needDownload) {
    $url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/$Tag/$Asset"
    Write-Host "downloading $url"
    # curl.exe follows GitHub redirects; gh often dies on release-assets CDN timeouts
    & curl.exe -L --retry 8 --retry-all-errors --retry-delay 4 --continue-at - -o $zip $url
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "curl failed ($LASTEXITCODE), falling back to gh"
        & gh release download $Tag --repo NationalSecurityAgency/ghidra --pattern $Asset --dir $dist --clobber
        if ($LASTEXITCODE -ne 0) { throw "ghidra download failed" }
    }
    Test-Hash $zip $Sha256
}

if ($Extract) {
    $ghidraRoot = Join-Path (Get-LabRoot) 'ghidra'
    if (Test-Path $ghidraRoot) {
        Write-Host "wiping $ghidraRoot (never extract on top of an old install)"
        Remove-Item -Recurse -Force $ghidraRoot
    }
    New-Item -ItemType Directory -Force -Path $ghidraRoot | Out-Null
    Write-Host "extracting $zip -> $ghidraRoot"
    # Windows tar handles large zips better than Expand-Archive.
    # Do NOT flatten ghidra_12.1.3_PUBLIC\ into ghidra\ — Move-Item on those
    # giant trees hits Access Denied on Windows. tools\_common.ps1 already
    # walks one extra directory to find ghidraRun.bat.
    & tar -xf $zip -C $ghidraRoot
    if ($LASTEXITCODE -ne 0) { throw "tar extract failed ($LASTEXITCODE)" }

    $install = $null
    if (Test-Path (Join-Path $ghidraRoot 'ghidraRun.bat')) {
        $install = $ghidraRoot
    } else {
        $nested = Get-ChildItem $ghidraRoot -Directory |
            Where-Object { Test-Path (Join-Path $_.FullName 'ghidraRun.bat') } |
            Select-Object -First 1
        if ($nested) { $install = $nested.FullName }
    }
    if (-not $install) {
        throw "extract succeeded but ghidraRun.bat not found under $ghidraRoot"
    }
    Write-Host "Ghidra ready: $install"
}
