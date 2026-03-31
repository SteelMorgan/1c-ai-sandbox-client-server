param(
  # External Docker volumes required by .devcontainer/docker-compose.yml.
  [string[]]$VolumeNames = @("agent-work-sandbox-1c", "onescript-cache-1c", "onec-licenses"),
  # Must match .devcontainer/docker-compose.yml (service agent -> networks.infra.ipv4_address).
  [string]$InfraNetworkName = "infra",
  [string]$InfraSubnet = "192.168.0.0/24",
  [string]$InfraGateway = "192.168.0.1"
)

$ErrorActionPreference = "Stop"

function Assert-DockerAvailable {
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) {
    throw "Команда 'docker' не найдена. Установи Docker Desktop/Engine и повтори."
  }
}

function Ensure-InfraNetwork {
  $raw = & docker network inspect $InfraNetworkName 2>$null
  if ($LASTEXITCODE -eq 0) {
    $json = $raw | ConvertFrom-Json
    $actualSubnet = $json[0].IPAM.Config[0].Subnet
    if ($actualSubnet -and $actualSubnet -ne $InfraSubnet) {
      Write-Warning ("Docker network '$InfraNetworkName' существует, но подсеть '$actualSubnet' " +
        "не совпадает с ожидаемой '$InfraSubnet'. " +
        "Удали сеть (docker network rm $InfraNetworkName) и запусти скрипт снова.")
    } else {
      Write-Host "Docker network '$InfraNetworkName' уже существует (subnet=$actualSubnet)."
    }
    return
  }

  Write-Host "Создаю Docker network '$InfraNetworkName' (subnet=$InfraSubnet, gateway=$InfraGateway)..."
  & docker network create $InfraNetworkName --subnet=$InfraSubnet --gateway=$InfraGateway
  if ($LASTEXITCODE -ne 0) {
    throw "Не удалось создать Docker network '$InfraNetworkName'."
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

Ensure-InfraNetwork

foreach ($volumeName in $VolumeNames) {
  Ensure-Volume $volumeName
}

Write-Host ""
Write-Host "Готово:"
Write-Host " - network: $InfraNetworkName"
foreach ($volumeName in $VolumeNames) {
  Write-Host " - volume: $volumeName"
}
Write-Host "Теперь можно делать Dev Containers: Rebuild Container."
