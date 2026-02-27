<#
.SYNOPSIS
  Бэкап docker volume agent-work-sandbox-1c в ./backups и добавление backups/ в .gitignore.

.USAGE
  Запусти из корня репозитория:
    powershell -ExecutionPolicy Bypass -File .\Скрипты\backup-sandbox-volume.ps1

  (опционально) другой volume:
    powershell -ExecutionPolicy Bypass -File .\Скрипты\backup-sandbox-volume.ps1 -VolumeName "agent-work-sandbox-1c"
#>

param(
  [string]$VolumeName = "agent-work-sandbox-1c",
  [string]$BackupsDirName = "backups"
)

$ErrorActionPreference = "Stop"

# Если есть кириллица в выводе — ставим UTF-8 кодовую страницу
chcp 65001 | Out-Null

$repoRoot = (Get-Location).Path
$backupsDir = Join-Path $repoRoot $BackupsDirName
$gitignorePath = Join-Path $repoRoot ".gitignore"

# 1) Создать папку backups
if (-not (Test-Path -LiteralPath $backupsDir)) {
  New-Item -ItemType Directory -Path $backupsDir | Out-Null
}

# 2) Добавить backups/ в .gitignore (если нет)
$ignoreLine = "backups/"
$needsAppend = $true

if (Test-Path -LiteralPath $gitignorePath) {
  $raw = Get-Content -LiteralPath $gitignorePath -Raw
  if ($raw -match "(?m)^\Q$ignoreLine\E\s*$") {
    $needsAppend = $false
  }
} else {
  $raw = ""
}

if ($needsAppend) {
  $nl = "`r`n"
  $textToAppend = ($nl + $ignoreLine + $nl)
  $utf8bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::AppendAllText($gitignorePath, $textToAppend, $utf8bom)
}

# 3) Проверить, что volume существует
& docker volume inspect $VolumeName *> $null
if ($LASTEXITCODE -ne 0) {
  throw "Docker volume '$VolumeName' не найден. Проверь имя: docker volume ls"
}

# 4) Сделать бэкап в tar.gz
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$archiveName = "${VolumeName}_${ts}.tar.gz"

# Docker на Windows нормально понимает bind-mount с путём вида D:\...\backups,
# но надёжнее отдать с '/'.
$backupsDirForDocker = $backupsDir.Replace("\", "/")

$dockerArgs = @(
  "run", "--rm",
  "-v", "${VolumeName}:/v:ro",
  "-v", "${backupsDirForDocker}:/backup",
  "busybox", "sh", "-lc",
  "tar -czf /backup/$archiveName -C /v ."
)

Write-Host "Делаю бэкап volume '$VolumeName' -> $BackupsDirName\$archiveName"
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) {
  throw "Бэкап не выполнен (docker run завершился с кодом $LASTEXITCODE)."
}

# 5) Проверка результата
$archivePath = Join-Path $backupsDir $archiveName
if (-not (Test-Path -LiteralPath $archivePath)) {
  throw "Архив не найден после бэкапа: $archivePath"
}

$item = Get-Item -LiteralPath $archivePath
Write-Host "Готово: $($item.FullName)"
Write-Host ("Размер: {0:N0} байт" -f $item.Length)
