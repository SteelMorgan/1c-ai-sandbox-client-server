param(
  # Windows-host IP on the Hyper-V *internal* mgmt switch (onec-mgmt).
  # This is the address onec-infra dials. Defaults to infra/vm/.env MGMT_HOST_IP.
  [string]$MgmtHostIp = "",

  # mgmt subnet allowed to reach the published port (firewall scope).
  [string]$MgmtSubnet = "192.168.250.0/24",

  # Host listen port (Docker Desktop published port) -> forwarded to 127.0.0.1.
  # Keep in sync with .devcontainer/docker-compose.yml `ports:`.
  [int[]]$Ports = @(14000, 14001),

  # Remove the portproxy + firewall rules instead of creating them.
  [switch]$Remove
)

$ErrorActionPreference = "Stop"

function Require-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw "Run PowerShell as Administrator." }
}

function Get-RepoRoot {
  $here = $PSScriptRoot
  if (-not $here) { throw "Cannot determine script directory (PSScriptRoot is empty)." }
  return (Resolve-Path (Join-Path $here "..\..")).Path
}

function Read-EnvValue([string]$envFile, [string]$key) {
  if (-not (Test-Path $envFile)) { return "" }
  foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*#') { continue }
    if ($line -match ("^\s*" + [regex]::Escape($key) + "\s*=\s*(.+?)\s*$")) {
      return $matches[1].Trim()
    }
  }
  return ""
}

Require-Admin

$repoRoot = Get-RepoRoot
$envFile  = Join-Path $repoRoot "infra\vm\.env"

if (-not $MgmtHostIp) {
  $MgmtHostIp = Read-EnvValue $envFile "MGMT_HOST_IP"
  if (-not $MgmtHostIp) { $MgmtHostIp = "192.168.250.1" }
}

# iphlpsvc (IP Helper) must run for netsh portproxy to work.
if (-not $Remove) {
  $svc = Get-Service -Name iphlpsvc -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne "Running") {
    Set-Service -Name iphlpsvc -StartupType Automatic
    Start-Service -Name iphlpsvc
  }
}

foreach ($port in $Ports) {
  $ruleName = "GBIG v8-session-manager $port"

  # Always clear any prior portproxy for this listen endpoint (idempotent).
  & netsh interface portproxy delete v4tov4 listenaddress=$MgmtHostIp listenport=$port 2>$null | Out-Null

  if ($Remove) {
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
      Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host ("[REMOVED] {0}:{1} portproxy + firewall rule" -f $MgmtHostIp, $port)
    continue
  }

  # mgmt-host -> Docker Desktop published port (loopback is where the WSL2 relay listens).
  & netsh interface portproxy add v4tov4 `
      listenaddress=$MgmtHostIp listenport=$port `
      connectaddress=127.0.0.1 connectport=$port | Out-Null

  # Inbound firewall: allow only the mgmt subnet (matches the restart-svc ufw scope).
  Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
  New-NetFirewallRule `
    -DisplayName $ruleName `
    -Direction Inbound -Action Allow -Protocol TCP `
    -LocalAddress $MgmtHostIp -LocalPort $port `
    -RemoteAddress $MgmtSubnet -Profile Any | Out-Null

  Write-Host ("[OK] {0}:{1} -> 127.0.0.1:{1}  (allow from {2})" -f $MgmtHostIp, $port, $MgmtSubnet)
}

if (-not $Remove) {
  Write-Host ""
  Write-Host "Active portproxy table:"
  & netsh interface portproxy show v4tov4
  Write-Host ""
  Write-Host ("From onec-infra check:  timeout 3 bash -lc '</dev/tcp/{0}/{1}' && echo open" -f $MgmtHostIp, $Ports[0])
  Write-Host ("manager_url:            ws://{0}:{1}/sessions" -f $MgmtHostIp, $Ports[0])
}
