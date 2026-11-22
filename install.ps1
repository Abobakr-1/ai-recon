<#
.SYNOPSIS
    AI RECON - Windows installer.
.DESCRIPTION
    Installs AI RECON (ai-recon) on Windows: creates a virtualenv, installs the
    package and its dependencies, and adds an `ai-recon` command to your PATH.

    Default is a per-user install (no administrator rights needed):
        %LOCALAPPDATA%\ai-recon\

.EXAMPLE
    # from a clone of the repo:
    powershell -ExecutionPolicy Bypass -File .\install.ps1

.EXAMPLE
    # one-liner (no clone needed):
    irm https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/install.ps1 | iex

.EXAMPLE
    # all-users install (needs an elevated PowerShell):
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -System
.NOTES
    Developed by: AboBakr Mohamed
#>
[CmdletBinding()]
param(
    [switch]$System,          # install for all users (needs admin)
    [switch]$NoPath,          # do not modify PATH
    [string]$Source           # path to source dir (auto-detected otherwise)
)

$ErrorActionPreference = 'Stop'
$RepoUrl = 'https://github.com/Abobakr-1/ai-recon.git'
$Version = '1.1.0'

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Die($msg)  { Write-Host "[!] $msg" -ForegroundColor Red; exit 1 }

Step "AI RECON installer (Windows, v$Version)"

# --- 1. locate Python ------------------------------------------------------ #
function Find-Python {
    $candidates = @(
        @{ exe = 'py';      pre = @('-3') },
        @{ exe = 'python';  pre = @() },
        @{ exe = 'python3'; pre = @() }
    )
    foreach ($c in $candidates) {
        $cmd = Get-Command $c.exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            # Use --version and parse stdout (keeps us clear of PowerShell's
            # -c quoting quirks on Windows).
            $out = & $c.exe @($c.pre) --version 2>&1
            if ($LASTEXITCODE -ne 0 -or -not $out) { continue }
            $m = [regex]::Match([string]$out, '(\d+)\.(\d+)')
            if (-not $m.Success) { continue }
            $maj = [int]$m.Groups[1].Value
            $min = [int]$m.Groups[2].Value
            if ($maj -ge 3 -and $min -ge 9) {
                return @{ exe = $cmd.Source; pre = $c.pre; version = "$maj.$min" }
            }
        } catch { }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Die "Python 3.9+ not found. Install it first:  winget install Python.Python.3.12   (or download from python.org, and tick 'Add python.exe to PATH')"
}
Ok "python: $($py.exe) ($($py.version))"

# --- 2. locate or fetch the source ---------------------------------------- #
function Test-Source($dir) {
    return (Test-Path (Join-Path $dir 'pyproject.toml')) -and (Test-Path (Join-Path $dir 'airecon'))
}

$src = $null
if ($Source -and (Test-Source $Source)) {
    $src = (Resolve-Path $Source).Path
} elseif (Test-Source (Get-Location).Path) {
    $src = (Get-Location).Path
} elseif ($PSScriptRoot -and (Test-Source $PSScriptRoot)) {
    $src = $PSScriptRoot
}

if (-not $src) {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        Die "Not running from the source folder and 'git' is not available. Either cd into the cloned repo and re-run, or install git:  winget install Git.Git"
    }
    $tmp = Join-Path $env:TEMP ("ai-recon-" + [guid]::NewGuid().ToString('N'))
    Step "Fetching source into $tmp"
    & git clone --depth 1 $RepoUrl $tmp | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "git clone failed" }
    $src = $tmp
}
Ok "source: $src"

# --- 3. install into a virtualenv ----------------------------------------- #
if ($System) {
    $root = Join-Path $env:ProgramData 'ai-recon'
    $admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { Die "A -System install needs an elevated (Administrator) PowerShell." }
} else {
    $root = Join-Path $env:LOCALAPPDATA 'ai-recon'
}
$venv = Join-Path $root 'venv'
$bin  = Join-Path $root 'bin'
New-Item -ItemType Directory -Force -Path $root, $bin | Out-Null

Step "Creating virtualenv: $venv"
$pyArgs = $py.pre + @('-m', 'venv', $venv)
& $py.exe @pyArgs
if ($LASTEXITCODE -ne 0) { Die "virtualenv creation failed" }

$vpy = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $vpy)) { Die "venv python not found at $vpy" }

Step "Installing AI RECON + dependencies (requests, PyYAML)"
& $vpy -m pip install --quiet --upgrade pip
& $vpy -m pip install --quiet $src
if ($LASTEXITCODE -ne 0) { Die "pip install failed" }

# --- 4. launchers ---------------------------------------------------------- #
$exe = Join-Path $venv 'Scripts\ai-recon.exe'
if (-not (Test-Path $exe)) { Die "console script not found at $exe" }

Step "Writing launchers into $bin"
foreach ($name in @('ai-recon', 'airecon')) {
    $cmdPath = Join-Path $bin "$name.cmd"
    $content = "@echo off`r`n`"$exe`" %*`r`n"
    Set-Content -Path $cmdPath -Value $content -Encoding ASCII
    Ok "installed: $cmdPath"
}

# --- 5. PATH --------------------------------------------------------------- #
if (-not $NoPath) {
    $scope = if ($System) { 'Machine' } else { 'User' }
    $cur = [Environment]::GetEnvironmentVariable('Path', $scope)
    if ($null -eq $cur) { $cur = '' }
    if (($cur -split ';') -notcontains $bin) {
        Step "Adding to $scope PATH: $bin"
        $new = ($cur.TrimEnd(';') + ';' + $bin).TrimStart(';')
        [Environment]::SetEnvironmentVariable('Path', $new, $scope)
        Ok "PATH updated (open a NEW terminal for it to take effect)"
    } else {
        Ok "$bin already on PATH"
    }
    # make it usable in this session too
    $env:Path = $env:Path.TrimEnd(';') + ';' + $bin
}

# --- 6. verify ------------------------------------------------------------- #
Step "Verifying installation"
& (Join-Path $bin 'ai-recon.cmd') --version
if ($LASTEXITCODE -ne 0) { Die "verification failed" }

Write-Host ""
Write-Host "[+] Done. AI RECON is installed (developed by AboBakr Mohamed)." -ForegroundColor Green
Write-Host "    Open a NEW terminal, then try:"
Write-Host "        ai-recon --help"
Write-Host "        ai-recon passive https://chatgpt.com"
Write-Host "    Active testing needs an authorization scope:"
Write-Host "        ai-recon active https://your-lab --scope authorized.txt"
