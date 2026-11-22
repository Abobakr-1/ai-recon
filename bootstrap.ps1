<#
.SYNOPSIS
    AI RECON - Windows bootstrap installer (fetched by the irm one-liner).
.EXAMPLE
    irm https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/bootstrap.ps1 | iex
.NOTES
    Developed by: AboBakr Mohamed
#>
$ErrorActionPreference = 'Stop'
$RepoUrl = 'https://github.com/Abobakr-1/ai-recon.git'

function Die($m) { Write-Host "[!] $m" -ForegroundColor Red; exit 1 }

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Die "git is required:  winget install Git.Git   (then reopen the terminal)"
}

$tmp = Join-Path $env:TEMP ("ai-recon-" + [guid]::NewGuid().ToString('N'))
Write-Host "[*] fetching AI RECON into $tmp"
git clone --depth 1 $RepoUrl $tmp
if ($LASTEXITCODE -ne 0) { Die "git clone failed" }

# Delegate to the repo's installer, forwarding any extra args (e.g. -System).
& (Join-Path $tmp 'install.ps1') @args
