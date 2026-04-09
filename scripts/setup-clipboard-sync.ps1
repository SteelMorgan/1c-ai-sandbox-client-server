<#
.SYNOPSIS
    Sets up Clipboard Sync: creates a desktop shortcut and adds
    the app to Windows Startup (auto-run on login).

.DESCRIPTION
    Clipboard Sync is a lightweight tray app that watches the Windows
    clipboard for images and writes them to a bind-mounted directory.
    A watcher inside each container picks up the file and loads it
    into X11 clipboard, so CLI tools (Claude Code, Codex CLI) can
    paste images via Ctrl+V.

    This script:
      1. Creates the sync temp directory (%TEMP%\cb-x11-sync)
      2. Adds a shortcut to the Desktop
      3. Adds a shortcut to Windows Startup (auto-run on login)

    Run once after cloning the repo.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .devcontainer\tools\setup-clipboard-sync.ps1
#>

$ErrorActionPreference = 'Stop'

$toolsDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$vbsPath    = Join-Path $toolsDir 'clipboard-image-tray.vbs'
$desktopDir = [Environment]::GetFolderPath('Desktop')
$startupDir = [Environment]::GetFolderPath('Startup')
$syncDir    = Join-Path $env:TEMP 'cb-x11-sync'

# Validate
if (-not (Test-Path $vbsPath)) {
    Write-Error "clipboard-image-tray.vbs not found at $vbsPath"
    exit 1
}

# 1. Sync directory
Write-Host "[1/3] Ensuring sync directory..." -ForegroundColor Cyan
if (-not (Test-Path $syncDir)) {
    New-Item -ItemType Directory -Path $syncDir | Out-Null
}
Write-Host "      $syncDir" -ForegroundColor Green

# 2. Desktop shortcut
Write-Host "[2/3] Creating desktop shortcut..." -ForegroundColor Cyan
$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut("$desktopDir\Clipboard Sync.lnk")
$lnk.TargetPath = 'wscript.exe'
$lnk.Arguments = "`"$vbsPath`""
$lnk.Description = 'Sync clipboard images to Docker containers'
$lnk.Save()
Write-Host "      $desktopDir\Clipboard Sync.lnk" -ForegroundColor Green

# 3. Startup shortcut
Write-Host "[3/3] Adding to Windows Startup..." -ForegroundColor Cyan
Copy-Item "$desktopDir\Clipboard Sync.lnk" "$startupDir\Clipboard Sync.lnk" -Force
Write-Host "      $startupDir\Clipboard Sync.lnk" -ForegroundColor Green

Write-Host ""
Write-Host "Done. Clipboard Sync will auto-start on login." -ForegroundColor Green
Write-Host "To start now: double-click 'Clipboard Sync' on desktop." -ForegroundColor DarkGray
