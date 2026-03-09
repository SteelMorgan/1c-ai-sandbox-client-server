param(
  [string[]]$VolumeNames = @("agent-work-sandbox-1c")
)

$ErrorActionPreference = "Stop"

function Assert-DockerAvailable {
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) {
    throw "Команда 'docker' не найдена. Установи Docker Desktop/Engine и повтори."
  }
}

function Ensure-Volume([string]$Name) {
  & docker volume inspect $Name *> $null
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Docker volume '$Name' уже существует."
    return
  }

  Write-Host "Создаю Docker volume '$Name'..."
  & docker volume create $Name
  if ($LASTEXITCODE -ne 0) {
    throw "Не удалось создать Docker volume '$Name'."
  }
}

Assert-DockerAvailable

foreach ($volumeName in $VolumeNames) {
  Ensure-Volume $volumeName
}

Write-Host "Проверка external volume завершена."
