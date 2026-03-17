param(
  # External Docker volumes required by .devcontainer/docker-compose.yml.
  [string[]]$VolumeNames = @("agent-work-sandbox-1c", "onescript-cache-1c", "onec-licenses")
)

$ErrorActionPreference = "Stop"

function Assert-DockerAvailable {
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) {
    throw "Команда 'docker' не найдена. Установи Docker Desktop/Engine и повтори."
  }
}

function Ensure-Volume([string]$Name) {
  $existingVolumes = & docker volume ls --format "{{.Name}}"
  if ($LASTEXITCODE -ne 0) {
    throw "Не удалось получить список Docker volumes."
  }

  if ($existingVolumes -contains $Name) {
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

Write-Host ""
Write-Host "External volumes готовы:"
foreach ($volumeName in $VolumeNames) {
  Write-Host " - $volumeName"
}
Write-Host "Теперь можно делать Dev Containers: Rebuild Container."
