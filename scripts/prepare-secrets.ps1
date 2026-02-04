param(
  [string]$EnvFile = "secrets/.env",
  [string]$SecretsDir = "secrets"
)

$ErrorActionPreference = "Stop"

function Repo-Root {
  $here = $PSScriptRoot
  if (-not $here) { $here = (Resolve-Path ".").Path }
  return (Resolve-Path (Join-Path $here "..")).Path
}

function Read-DotEnv([string]$path) {
  $map = @{}
  if (-not (Test-Path -LiteralPath $path)) { return $map }

  foreach ($line in Get-Content -LiteralPath $path) {
    if ($null -eq $line) { continue }
    $t = ($line -replace "`r$","").Trim()
    if ($t.Length -eq 0) { continue }
    if ($t.StartsWith("#")) { continue }
    $idx = $t.IndexOf("=")
    if ($idx -lt 1) { continue }
    $k = $t.Substring(0, $idx).Trim()
    $v = $t.Substring($idx + 1)  # keep as-is (can contain spaces)

    # Optional: unwrap simple quotes
    $v2 = $v.Trim()
    if (($v2.StartsWith('"') -and $v2.EndsWith('"')) -or ($v2.StartsWith("'") -and $v2.EndsWith("'"))) {
      $v2 = $v2.Substring(1, $v2.Length - 2)
    }
    $map[$k] = $v2
  }

  return $map
}

function Write-SecretFile([string]$path, [string]$value) {
  # Secrets MUST be raw bytes (no BOM, no newline).
  if ($null -eq $value) { $value = "" }
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  $bytes = $utf8NoBom.GetBytes([string]$value)
  [System.IO.File]::WriteAllBytes($path, $bytes)
}

function New-RandomSecret([int]$bytes = 24) {
  $buf = New-Object byte[] $bytes
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
  $b64 = [Convert]::ToBase64String($buf)
  # base64url (no padding) similar to token_urlsafe
  $b64 = $b64.TrimEnd("=") -replace "\+","-" -replace "/","_"
  return $b64
}

$repoRoot = Repo-Root
$secretsPath = $SecretsDir
if (-not [System.IO.Path]::IsPathRooted($secretsPath)) { $secretsPath = Join-Path $repoRoot $SecretsDir }
$envPath = $EnvFile
if (-not [System.IO.Path]::IsPathRooted($envPath)) { $envPath = Join-Path $repoRoot $EnvFile }

if (-not (Test-Path -LiteralPath $secretsPath)) {
  throw "Secrets dir not found: $secretsPath"
}
if (-not (Test-Path -LiteralPath $envPath)) {
  throw "Missing secrets env file: $envPath (copy secrets/.env.example -> secrets/.env and fill values)"
}

$m = Read-DotEnv $envPath

$onecUsername = $m["ONEC_USERNAME"]
$onecPassword = $m["ONEC_PASSWORD"]
$devLogin = $m["DEV_LOGIN"]
$devPassword = $m["DEV_PASSWORD"]
$pgPassword = $m["PG_PASSWORD"]
$forceOverwrite = $m["FORCE_OVERWRITE_PG_PASSWORD"]

Write-SecretFile (Join-Path $secretsPath "onec_username") $onecUsername
Write-SecretFile (Join-Path $secretsPath "onec_password") $onecPassword
Write-SecretFile (Join-Path $secretsPath "dev_login") $devLogin
Write-SecretFile (Join-Path $secretsPath "dev_password") $devPassword

# pg_password stability rules
$pgFile = Join-Path $secretsPath "pg_password"
$existing = ""
if (Test-Path -LiteralPath $pgFile) {
  # read as UTF-8 no-BOM bytes, keep raw (no newline expected)
  $existing = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($pgFile))
}

if ($pgPassword -and $pgPassword.Trim().Length -gt 0) {
  if ($existing -and ($existing -ne $pgPassword) -and ($forceOverwrite -ne "1")) {
    throw "Refusing to overwrite existing secrets/pg_password with a different PG_PASSWORD. Reset pgdata + set FORCE_OVERWRITE_PG_PASSWORD=1 if you really want to rotate."
  }
  Write-SecretFile $pgFile $pgPassword
} else {
  if ($existing -and $existing.Trim().Length -gt 0) {
    # keep existing
  } else {
    Write-SecretFile $pgFile (New-RandomSecret 24)
  }
}

Write-Host "[OK] Secrets written to $secretsPath"
Write-Host "     - onec_username/onec_password"
Write-Host "     - dev_login/dev_password"
Write-Host "     - pg_password"

