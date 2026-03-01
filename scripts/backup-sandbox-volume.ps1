<#
.SYNOPSIS
  Бэкап docker volumes sandbox 1C в ./backups и добавление backups/ в .gitignore.
  По умолчанию бэкапит все volumes сразу: agent-work-sandbox-1c и agent-home-1c.

.USAGE
  Запусти из корня репозитория:
    powershell -ExecutionPolicy Bypass -File .\scripts\backup-sandbox-volume.ps1

  (опционально) только конкретные volumes:
    powershell -ExecutionPolicy Bypass -File .\scripts\backup-sandbox-volume.ps1 -VolumeNames "agent-work-sandbox-1c","agent-home-1c"
#>

param(
  [string[]]$VolumeNames = @("agent-work-sandbox-1c", "agent-home-1c"),
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

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$backupsDirForDocker = $backupsDir.Replace("\", "/")

$results = @()

foreach ($VolumeName in $VolumeNames) {
  Write-Host ""
  Write-Host "=== Volume: $VolumeName ===" -ForegroundColor Cyan

  # 3) Проверить, что volume существует
  & docker volume inspect $VolumeName *> $null
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Docker volume '$VolumeName' не найден — пропускаю. (docker volume ls)"
    $results += [PSCustomObject]@{ Volume = $VolumeName; Status = "SKIPPED (not found)"; File = "" }
    continue
  }

  # 4) Сделать бэкап в tar.gz
  $archiveName = "${VolumeName}_${ts}.tar.gz"

  $dockerArgs = @(
    "run", "--rm",
    "-v", "${VolumeName}:/v:ro",
    "-v", "${backupsDirForDocker}:/backup",
    "busybox", "sh", "-lc",
    "tar -czf /backup/$archiveName -C /v ."
  )

  Write-Host "Делаю бэкап -> $BackupsDirName\$archiveName"
  & docker @dockerArgs
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Бэкап volume '$VolumeName' не выполнен (docker run завершился с кодом $LASTEXITCODE)."
    $results += [PSCustomObject]@{ Volume = $VolumeName; Status = "FAILED"; File = "" }
    continue
  }

  # 5) Проверка результата
  $archivePath = Join-Path $backupsDir $archiveName
  if (-not (Test-Path -LiteralPath $archivePath)) {
    Write-Warning "Архив не найден после бэкапа: $archivePath"
    $results += [PSCustomObject]@{ Volume = $VolumeName; Status = "FAILED (archive missing)"; File = "" }
    continue
  }

  $item = Get-Item -LiteralPath $archivePath
  Write-Host "Готово: $($item.FullName)"
  Write-Host ("Размер: {0:N0} байт" -f $item.Length)
  $results += [PSCustomObject]@{ Volume = $VolumeName; Status = "OK"; File = $item.FullName }
}

# 6) Итоговая сводка
Write-Host ""
Write-Host "=== Итог ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$failed = $results | Where-Object { $_.Status -ne "OK" }
if ($failed) {
  throw "Один или несколько volumes не были забэкаплены. Подробности выше."
}
