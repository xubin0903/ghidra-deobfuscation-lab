#requires -Version 5.1
<#
.SYNOPSIS
  Download Eclipse Temurin JDK 21 (x64 Windows zip) into dist\ and extract to jdk\.
  Ghidra 12.1.3 PUBLIC wants JDK 21. Do not use the system JDK 23.
#>
[CmdletBinding()]
param(
    [string]$Release = 'jdk-21.0.11+10',
    [string]$Asset = 'OpenJDK21U-jdk_x64_windows_hotspot_21.0.11_10.zip',
    [string]$Sha256 = 'd3625e7cadf23787ea540229544b6e2ab494b3b54da1801879e583e1dfee0a64'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_common.ps1')

$dist = Get-DistRoot
$jdkRoot = Join-Path (Get-LabRoot) 'jdk'
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
    } catch {
        Write-Warning $_
        Remove-Item -Force $zip
    }
}

if ($needDownload) {
    $api = 'https://api.adoptium.net/v3/binary/version/{0}/windows/x64/jdk/hotspot/normal/eclipse?project=jdk' -f [uri]::EscapeDataString($Release)
    Write-Host "downloading JDK 21 from Adoptium API"
    Write-Host "  $api"
    # curl.exe follows redirects; gh often dies on githubusercontent CDN timeouts
    & curl.exe -L --retry 5 --retry-all-errors --retry-delay 3 -o $zip $api
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Adoptium API failed, falling back to gh"
        & gh release download $Release --repo adoptium/temurin21-binaries --pattern $Asset --dir $dist --clobber
        if ($LASTEXITCODE -ne 0) { throw "JDK download failed" }
    }
    Test-Hash $zip $Sha256
}

# Keep README.md; wipe everything else. Do NOT flatten jdk-21.x\ — Move-Item
# on bin/lib hits Access Denied on Windows. tools\_common.ps1 walks one extra dir.
if (Test-Path $jdkRoot) {
    Get-ChildItem $jdkRoot -Force | Where-Object { $_.Name -ne 'README.md' } | ForEach-Object {
        Remove-Item -Recurse -Force $_.FullName
    }
}
New-Item -ItemType Directory -Force -Path $jdkRoot | Out-Null
Write-Host "extracting $zip -> $jdkRoot"
& tar -xf $zip -C $jdkRoot
if ($LASTEXITCODE -ne 0) { throw "tar extract failed ($LASTEXITCODE)" }

$java = $null
$direct = Join-Path $jdkRoot 'bin\java.exe'
if (Test-Path $direct) {
    $java = $direct
} else {
    $nested = Get-ChildItem $jdkRoot -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName 'bin\java.exe') } |
        Select-Object -First 1
    if ($nested) { $java = Join-Path $nested.FullName 'bin\java.exe' }
}
if (-not $java) { throw "java.exe missing after extract under $jdkRoot" }
Write-Host "JDK 21 ready: $(Split-Path (Split-Path $java -Parent) -Parent)"
& $java -version
