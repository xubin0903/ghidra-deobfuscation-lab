#requires -Version 5.1
<#
.SYNOPSIS
  Resolve this lab's Ghidra install dir and bundled JDK 21.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LabRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:GhidraRoot = Join-Path $LabRoot 'ghidra'
$script:JdkRoot = Join-Path $LabRoot 'jdk'
$script:ScriptsRoot = Join-Path $LabRoot 'scripts'
$script:ProjectsRoot = Join-Path $LabRoot 'projects'
$script:DistRoot = Join-Path $LabRoot 'dist'

function Get-LabRoot { $script:LabRoot }
function Get-ScriptsRoot { $script:ScriptsRoot }
function Get-ProjectsRoot { $script:ProjectsRoot }
function Get-DistRoot { $script:DistRoot }

function Find-GhidraInstall {
    $direct = Join-Path $script:GhidraRoot 'ghidraRun.bat'
    if (Test-Path $direct) { return $script:GhidraRoot }

    if (Test-Path $script:GhidraRoot) {
        $nested = Get-ChildItem $script:GhidraRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName 'ghidraRun.bat') } |
            Select-Object -First 1
        if ($nested) { return $nested.FullName }
    }
    return $null
}

function Find-BundledJdk {
    $java = Join-Path $script:JdkRoot 'bin\java.exe'
    if (Test-Path $java) { return $script:JdkRoot }

    if (Test-Path $script:JdkRoot) {
        $nested = Get-ChildItem $script:JdkRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName 'bin\java.exe') } |
            Select-Object -First 1
        if ($nested) { return $nested.FullName }
    }
    return $null
}

function Get-JavaMajor([string]$javaExe) {
    # `java -version` prints to stderr; with $ErrorActionPreference='Stop' the
    # 2>&1 merge would turn that banner into a terminating error, so relax it
    # for this call only.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $javaExe -version 2>&1 | Out-String
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($out -match 'version "(\d+)') { return [int]$Matches[1] }
    return 0
}

function Find-FallbackJdk {
    # 12.1.3 application.java.min=21, application.java.max empty.
    # LaunchSupport on this machine accepted Oracle JDK 23. Official docs still pin 21.
    $candidates = @()
    if ($env:JAVA_HOME) {
        $candidates += (Join-Path $env:JAVA_HOME 'bin\java.exe')
    }
    $candidates += 'C:\Program Files\Java\jdk-23\bin\java.exe'
    $cmd = Get-Command java -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }

    foreach ($c in $candidates) {
        if (-not (Test-Path $c)) { continue }
        $major = Get-JavaMajor $c
        if ($major -ge 21) {
            return (Split-Path (Split-Path $c -Parent) -Parent)
        }
    }
    return $null
}

function Assert-GhidraReady {
    $install = Find-GhidraInstall
    if (-not $install) {
        throw "Ghidra is not extracted. Run tools\fetch-ghidra.ps1 -Extract  (expected under $script:GhidraRoot)"
    }
    $jdk = Find-BundledJdk
    $jdkSource = 'bundled-temurin-21'
    if (-not $jdk) {
        $jdk = Find-FallbackJdk
        $jdkSource = 'fallback-system-jdk>=21'
        if (-not $jdk) {
            throw "No JDK >= 21. Run tools\fetch-jdk21.ps1 (preferred) or install a JDK 21+."
        }
        Write-Warning "Bundled JDK 21 missing under $($script:JdkRoot). Using $jdk ($jdkSource). Official pin is Temurin 21 — run tools\fetch-jdk21.ps1 when the zip finishes."
    }
    [pscustomobject]@{
        LabRoot       = $script:LabRoot
        GhidraInstall = $install
        JdkHome       = $jdk
        JdkSource     = $jdkSource
        ScriptsRoot   = $script:ScriptsRoot
        ProjectsRoot  = $script:ProjectsRoot
    }
}

function Get-GhidraEnv {
    $ready = Assert-GhidraReady
    $env:JAVA_HOME = $ready.JdkHome
    $env:GHIDRA_INSTALL_DIR = $ready.GhidraInstall
    $env:GHIDRA_SCRIPTS_DIR = $ready.ScriptsRoot
    # Prepend bundled JDK so Ghidra launcher does not pick system JDK 23
    $env:PATH = (Join-Path $ready.JdkHome 'bin') + ';' + $env:PATH
    $ready
}
