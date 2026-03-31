param(
  # External Docker volumes required by .devcontainer/docker-compose.yml.
  [string[]]$VolumeNames = @("agent-work-sandbox-1c", "onescript-cache-1c", "onec-licenses"),
  # External Docker network required by .devcontainer/docker-compose.yml.
  [string]$NetworkName = "infra",
  [string]$NetworkSubnet = "192.168.0.0/24",
  [string]$NetworkGateway = "192.168.0.1"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$devcontainerEnvPath = Join-Path $repoRoot ".devcontainer\.env"

function Assert-DockerAvailable {
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) {
    throw "Команда 'docker' не найдена. Установи Docker Desktop/Engine и повтори."
  }
}

function Import-SimpleEnvFile([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return @{}
  }

  $values = @{}
  foreach ($line in Get-Content -LiteralPath $Path) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#")) {
      continue
    }

    $idx = $trimmed.IndexOf("=")
    if ($idx -lt 1) {
      continue
    }

    $key = $trimmed.Substring(0, $idx).Trim()
    $value = $trimmed.Substring($idx + 1).Trim()
    $values[$key] = $value
  }

  return $values
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
  & docker volume create $Name | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Не удалось создать Docker volume '$Name'."
  }
}

function Ensure-Network([string]$Name) {
  $existingNetworks = & docker network ls --format "{{.Name}}"
  if ($LASTEXITCODE -ne 0) {
    throw "Не удалось получить список Docker networks."
  }

  if ($existingNetworks -contains $Name) {
    $networkJson = & docker network inspect $Name
    if ($LASTEXITCODE -ne 0) {
      throw "Не удалось получить параметры Docker network '$Name'."
    }

    $network = $networkJson | ConvertFrom-Json
    $configuredSubnet = $null
    $configuredGateway = $null
    if ($network.IPAM -and $network.IPAM.Config -and $network.IPAM.Config.Count -gt 0) {
      $configuredSubnet = $network.IPAM.Config[0].Subnet
      $configuredGateway = $network.IPAM.Config[0].Gateway
    }

    if ($NetworkSubnet -and $configuredSubnet -and $configuredSubnet -ne $NetworkSubnet) {
      throw "Docker network '$Name' уже существует, но с другой подсетью: '$configuredSubnet'. Ожидалось '$NetworkSubnet'. Удали сеть и создай заново с правильной подсетью."
    }

    if ($NetworkSubnet -and -not $configuredSubnet) {
      throw "Docker network '$Name' уже существует, но у нее не настроена пользовательская подсеть. Ожидалось '$NetworkSubnet'. Удали сеть и создай заново."
    }

    if ($NetworkGateway -and $configuredGateway -and $configuredGateway -ne $NetworkGateway) {
      throw "Docker network '$Name' уже существует, но с другим gateway: '$configuredGateway'. Ожидалось '$NetworkGateway'. Удали сеть и создай заново с правильным gateway."
    }

    Write-Host "Docker network '$Name' уже существует и соответствует ожидаемой конфигурации."
    return
  }

  Write-Host "Создаю Docker network '$Name'..."
  & docker network create --driver bridge --subnet $NetworkSubnet --gateway $NetworkGateway $Name | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Не удалось создать Docker network '$Name'."
  }
}

Assert-DockerAvailable

$devcontainerEnv = Import-SimpleEnvFile $devcontainerEnvPath
if ($devcontainerEnv.ContainsKey("AGENT_INFRA_NETWORK")) {
  $NetworkName = $devcontainerEnv["AGENT_INFRA_NETWORK"]
}
if ($devcontainerEnv.ContainsKey("AGENT_INFRA_SUBNET")) {
  $NetworkSubnet = $devcontainerEnv["AGENT_INFRA_SUBNET"]
}
if ($devcontainerEnv.ContainsKey("AGENT_INFRA_GATEWAY")) {
  $NetworkGateway = $devcontainerEnv["AGENT_INFRA_GATEWAY"]
}

foreach ($volumeName in $VolumeNames) {
  Ensure-Volume $volumeName
}

Ensure-Network $NetworkName

Write-Host ""
Write-Host "Devcontainer prerequisites готовы:"
foreach ($volumeName in $VolumeNames) {
  Write-Host " - volume: $volumeName"
}
Write-Host " - network: $NetworkName ($NetworkSubnet, gateway $NetworkGateway)"
Write-Host "Теперь можно делать Dev Containers: Rebuild Container."
