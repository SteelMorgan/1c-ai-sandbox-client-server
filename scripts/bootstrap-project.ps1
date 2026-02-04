param(
  [Parameter(Mandatory = $false)]
  [string] $ProjectName,

  [Parameter(Mandatory = $false)]
  [string] $VolumeName,

  [Parameter(Mandatory = $false)]
  [string] $ContainerName,

  [Parameter(Mandatory = $false)]
  [switch] $CreateVolume
)

$ErrorActionPreference = 'Stop'

function Get-Slug([string] $name) {
  if ([string]::IsNullOrWhiteSpace($name)) { return "project" }
  $s = $name.Trim().ToLowerInvariant()
  # Normalize common separators
  $s = $s -replace '[\s_]+', '-'
  # Keep only [a-z0-9-]
  $s = $s -replace '[^a-z0-9-]', ''
  # Collapse multiple hyphens
  $s = $s -replace '-{2,}', '-'
  # Trim hyphens
  $s = $s.Trim('-')
  if ([string]::IsNullOrWhiteSpace($s)) { return "project" }
  return $s
}

function Read-Json([string] $path) {
  $raw = [System.IO.File]::ReadAllText($path)
  $cmd = Get-Command ConvertFrom-Json -ErrorAction Stop
  if ($cmd.Parameters.ContainsKey('Depth')) {
    return $raw | ConvertFrom-Json -Depth 100
  }
  # Windows PowerShell 5.1: no -Depth on ConvertFrom-Json
  return $raw | ConvertFrom-Json
}

function Write-Json([string] $path, $obj) {
  $json = $obj | ConvertTo-Json -Depth 100
  $json = ($json -replace "`r`n", "`n") + "`n"
  $utf8bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::WriteAllText($path, $json, $utf8bom)
}

function Write-TextUtf8Bom([string] $path, [string] $text) {
  $text = ($text -replace "`r`n", "`n")
  if (-not $text.EndsWith("`n")) { $text += "`n" }
  $utf8bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::WriteAllText($path, $text, $utf8bom)
}

function Ensure-Volume([string] $name) {
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) { return }
  $null = & docker volume inspect $name 2>$null
  if ($LASTEXITCODE -ne 0) {
    $null = & docker volume create $name
  }
}

$root = Split-Path -Parent $PSScriptRoot

if (-not $ProjectName) {
  $ProjectName = Split-Path -Leaf $root
}

$slug = Get-Slug $ProjectName

if (-not $VolumeName) {
  $VolumeName = "agent-work-$slug"
}

if (-not $ContainerName) {
  $ContainerName = "ai-agent-$slug"
}

$composeMain = Join-Path $root ".devcontainer\docker-compose.yml"
$composeOffline = Join-Path $root ".devcontainer\docker-compose.offline.yml"

if (-not (Test-Path $composeMain)) {
  throw "Missing compose file: $composeMain"
}

$yaml = [System.IO.File]::ReadAllText($composeMain)
$yaml = ($yaml -replace "`r`n", "`n")

# Update container_name
$yaml = [regex]::Replace($yaml, '(^\s*container_name:\s*).+$', ('$1' + $ContainerName), [System.Text.RegularExpressions.RegexOptions]::Multiline)

# Update volumes mapping "- <volume>:/workspaces/work"
$yaml = [regex]::Replace($yaml, '(^\s*-\s*)([^:\s]+)(:\s*/workspaces/work\s*)$', ('$1' + $VolumeName + '$3'), [System.Text.RegularExpressions.RegexOptions]::Multiline)

# Update volumes section name "  <volume>:"
$yaml = [regex]::Replace($yaml, '(^\s*volumes:\s*\n\s*)([A-Za-z0-9_.-]+)(:\s*\n\s*external:\s*true\s*)', ('$1' + $VolumeName + '$3'), [System.Text.RegularExpressions.RegexOptions]::Multiline)

Write-TextUtf8Bom $composeMain $yaml

if (Test-Path $composeOffline) {
  $yamlOff = [System.IO.File]::ReadAllText($composeOffline)
  $yamlOff = ($yamlOff -replace "`r`n", "`n")
  $yamlOff = [regex]::Replace($yamlOff, '(^\s*container_name:\s*).+$', ('$1' + ($ContainerName + '-offline')), [System.Text.RegularExpressions.RegexOptions]::Multiline)
  Write-TextUtf8Bom $composeOffline $yamlOff
}

if ($CreateVolume) {
  Ensure-Volume $VolumeName
}

Write-Host "OK"
Write-Host "ProjectName: $ProjectName"
Write-Host "Slug:        $slug"
Write-Host "VolumeName:  $VolumeName"
Write-Host "Container:   $ContainerName"
Write-Host "Offline:     $ContainerName-offline"

