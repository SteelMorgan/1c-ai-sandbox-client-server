param(
  # VM management IP (preferred). If omitted, will be read from infra/vm/.env (MGMT_VM_IP).
  [string]$VmIp = "",

  [string]$SshUser = "sandbox",
  [string]$SshIdentityFile = "",

  # Uses same env file as smoke/deploy.
  [string]$EnvFile = "infra/vm/.env",

  # RAS endpoint inside VM (host-networked container). If omitted, built from env (ONEC_RAS_PORT_HOST / ONEC_RAS_PORT).
  [string]$RasEndpoint = "",

  # Optional non-interactive mode
  [string]$InfobaseName = "",
  [string]$PostgresDbName = "",

  # Defaults for new infobase
  # With host networking (docker network_mode: host), Postgres is on the VM host loopback.
  # Container names (e.g. "postgres") are NOT resolvable in host network mode.
  [string]$DbServer = "127.0.0.1",
  [string]$Locale = "ru_RU"
)

$ErrorActionPreference = "Stop"

function Require-Cmd($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Required command not found: $name"
  }
}

function Repo-Root {
  $here = $PSScriptRoot
  if (-not $here) { $here = (Resolve-Path ".").Path }
  return (Resolve-Path (Join-Path $here "..\\..")).Path
}

function Load-DotEnv([string]$path) {
  $map = @{}
  if (-not (Test-Path $path)) { return $map }
  foreach ($line in (Get-Content $path)) {
    if (-not $line) { continue }
    $t = $line.Trim()
    if ($t.Length -eq 0) { continue }
    if ($t.StartsWith("#")) { continue }
    $idx = $t.IndexOf("=")
    if ($idx -lt 1) { continue }
    $k = $t.Substring(0, $idx).Trim()
    $v = $t.Substring($idx + 1).Trim()
    $map[$k] = $v
  }
  return $map
}

function Validate-Name([string]$name, [string]$label) {
  $n = ""
  if ($null -ne $name) { $n = [string]$name }
  $n = $n.Trim()
  if ($n.Length -eq 0) { throw "$label is empty." }
  # Keep it strict to avoid shell injection over SSH.
  if ($n -notmatch "^[A-Za-z0-9_\\-\\.]{1,64}$") {
    throw ("{0} must match ^[A-Za-z0-9_\\-\\.]{{1,64}}$. Got: '{1}'" -f $label, $n)
  }
  return $n
}

function Validate-Port([string]$port, [string]$label) {
  $p = ""
  if ($null -ne $port) { $p = [string]$port }
  $p = $p.Trim()
  if ($p.Length -eq 0) { return "" }
  if ($p -notmatch "^[0-9]{1,5}$") { throw "$label must be a number (1-65535). Got: '$p'" }
  $v = [int]$p
  if ($v -lt 1 -or $v -gt 65535) { throw "$label must be in range 1-65535. Got: '$v'" }
  return $v.ToString()
}

function Validate-HostPort([string]$value, [string]$label) {
  $s = ""
  if ($null -ne $value) { $s = [string]$value }
  $s = $s.Trim()
  if ($s.Length -eq 0) { throw "$label is empty." }

  # Allowed:
  # - hostname / IPv4, optional :port  (e.g. 127.0.0.1 or db-srv-01:5432)
  # - bracketed IPv6, optional :port  (e.g. [::1]:5432)
  $re = "^(?:[A-Za-z0-9_\\-\\.]+(?::[0-9]{1,5})?|\\[[0-9A-Fa-f:]+\\](?::[0-9]{1,5})?)$"
  if ($s -notmatch $re) {
    throw ("{0} must be host[:port] or [ipv6][:port]. Got: '{1}'" -f $label, $s)
  }

  # If there is an explicit port, validate range.
  if ($s.StartsWith("[")) {
    $m = [Regex]::Match($s, "^(\\[[0-9A-Fa-f:]+\\])(?::([0-9]{1,5}))?$")
    if ($m.Success -and $m.Groups[2].Success) {
      [void](Validate-Port $m.Groups[2].Value "$label port")
    }
  } else {
    $m = [Regex]::Match($s, "^(?<h>[A-Za-z0-9_\\-\\.]+)(?::(?<p>[0-9]{1,5}))?$")
    if ($m.Success -and $m.Groups["p"].Success) {
      [void](Validate-Port $m.Groups["p"].Value "$label port")
    }
  }

  return $s
}

function HostOnly([string]$hostPort, [string]$label) {
  # rac infobase create expects --db-server=<host> (NO port).
  # Accept host:port / [ipv6]:port from user/env for convenience, but strip the port.
  $s = ""
  if ($null -ne $hostPort) { $s = [string]$hostPort }
  $s = $s.Trim()
  if ($s.Length -eq 0) { throw "$label is empty." }

  if ($s.StartsWith("[")) {
    $m = [Regex]::Match($s, "^(\\[(?<ip>[0-9A-Fa-f:]+)\\])(?::(?<p>[0-9]{1,5}))?$")
    if (-not $m.Success) { throw ("{0} has invalid ipv6 form: '{1}'" -f $label, $s) }
    return $m.Groups["ip"].Value
  }

  $m2 = [Regex]::Match($s, "^(?<h>[A-Za-z0-9_\\-\\.]+)(?::(?<p>[0-9]{1,5}))?$")
  if (-not $m2.Success) { throw ("{0} has invalid host form: '{1}'" -f $label, $s) }
  return $m2.Groups["h"].Value
}

Require-Cmd ssh

$repoRoot = Repo-Root
$envPath = $EnvFile
if (-not [System.IO.Path]::IsPathRooted($envPath)) { $envPath = Join-Path $repoRoot $EnvFile }
$envMap = Load-DotEnv $envPath

if (-not $VmIp -or $VmIp.Trim().Length -eq 0) {
  $VmIp = $envMap["MGMT_VM_IP"]
}
if (-not $VmIp -or $VmIp.Trim().Length -eq 0) {
  throw "VmIp is not set. Pass -VmIp or set MGMT_VM_IP in $EnvFile."
}

$vmName = $envMap["VM_NAME"]
if (-not $vmName) { $vmName = "onec-infra" }

if (-not $SshIdentityFile -or $SshIdentityFile.Trim().Length -eq 0) {
  $SshIdentityFile = Join-Path (Join-Path $repoRoot ".cache\\hyperv") ("_ssh\\{0}\\id_ed25519" -f $vmName)
}
if (-not (Test-Path $SshIdentityFile)) {
  throw "SSH identity file not found: $SshIdentityFile"
}

$ibName = $InfobaseName
if (-not $ibName -or $ibName.Trim().Length -eq 0) {
  $ibName = Read-Host "Infobase name (Ref), e.g. demo"
}
$ibName = Validate-Name $ibName "Infobase name"

$dbName = $PostgresDbName
if (-not $dbName -or $dbName.Trim().Length -eq 0) {
  # If user provided infobase name via parameter, don't block on a prompt.
  if ($InfobaseName -and $InfobaseName.Trim().Length -gt 0) {
    $dbName = $ibName
  } else {
    $dbNameInput = Read-Host "Postgres DB name (Enter = same as infobase name)"
    $dbName = $dbNameInput
    if (-not $dbName -or $dbName.Trim().Length -eq 0) { $dbName = $ibName }
  }
}
$dbName = Validate-Name $dbName "Postgres database name"

$rasPort = ""
if (-not $RasEndpoint -or $RasEndpoint.Trim().Length -eq 0) {
  $rasPort = $envMap["ONEC_RAS_PORT_HOST"]
  if (-not $rasPort) { $rasPort = $envMap["ONEC_RAS_PORT"] }
  if (-not $rasPort) { $rasPort = "1545" }
  $rasPort = Validate-Port $rasPort "RAS port"
  $RasEndpoint = "localhost:$rasPort"
}
$RasEndpoint = Validate-HostPort $RasEndpoint "RasEndpoint"

$pgPort = $envMap["PGPORT_HOST"]
if (-not $pgPort) { $pgPort = $envMap["PGPORT"] }
$pgPort = Validate-Port $pgPort "Postgres port"
if (-not $PSBoundParameters.ContainsKey("DbServer")) {
  # Default DB server: loopback. rac expects host only, no port here.
  $DbServer = "127.0.0.1"
}
$DbServer = Validate-HostPort $DbServer "DbServer"
$DbServerHost = HostOnly $DbServer "DbServer"
$DbServerPortIgnored = $false
if ($DbServerHost -ne $DbServer) {
  # host:port or [ipv6]:port or bracketed ipv6 was provided; port/brackets will not be passed to rac.
  $DbServerPortIgnored = $true
}
$Locale = Validate-Name $Locale "Locale"

Write-Host "[STEP] Creating infobase '$ibName' (db='$dbName') on VM $VmIp ..."
if ($DbServerPortIgnored) {
  Write-Host ("[WARN] DbServer contains port/brackets ('{0}'). rac expects host only; using '{1}'." -f $DbServer, $DbServerHost)
}

$sshOpts = @(
  "-o", "BatchMode=yes",
  "-o", "ConnectTimeout=10",
  "-o", "ConnectionAttempts=1",
  "-o", "StrictHostKeyChecking=no",
  "-o", "UserKnownHostsFile=/dev/null",
  "-o", "LogLevel=ERROR",
  "-o", "IdentitiesOnly=yes",
  "-i", $SshIdentityFile
)

# Use docker exec directly to avoid fragile nested quoting.
$remote = "$SshUser@$VmIp"

function Invoke-SshAny([string]$remoteHost, [string[]]$sshOptions, [string]$command, [ref]$exitCode) {
  # PowerShell 5.1 turns native stderr into error records. With $ErrorActionPreference=Stop
  # this becomes terminating and we lose the actual output. Temporarily downgrade to Continue.
  $oldEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $out = & ssh @sshOptions $remoteHost $command 2>&1
    $exitCode.Value = $LASTEXITCODE
    return $out
  } finally {
    $ErrorActionPreference = $oldEap
  }
}

function Invoke-Ssh([string]$remoteHost, [string[]]$sshOptions, [string]$command) {
  $ec = 0
  $out = Invoke-SshAny $remoteHost $sshOptions $command ([ref]$ec)
  if ($ec -ne 0) { return $null }
  return $out
}

# Ensure container is running
$ec = 0
$probe = Invoke-SshAny $remote $sshOpts 'bash -lc ''sudo -n docker ps --format "{{.Names}}" | grep -qx "onec-server"''' ([ref]$ec)
if ($ec -ne 0) { throw "Container onec-server is not running on VM. Run deploy/up.sh first." }

function Parse-ClusterId($racOutput) {
  if (-not $racOutput) { return $null }
  $id = ($racOutput | Select-String -Pattern '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | Select-Object -First 1).Matches.Value
  if (-not $id) { return $null }
  if ($id -eq "00000000-0000-0000-0000-000000000000") { return $null }
  return $id
}

# Get cluster id (fail fast if RAS/cluster is not ready).
$clusterOut = $null
$clusterId = $null
$ec = 0
$clusterOut = Invoke-SshAny $remote $sshOpts ("bash -lc 'sudo -n docker exec onec-server /opt/1cv8/current/rac cluster list {0} 2>&1'" -f $RasEndpoint) ([ref]$ec)
if ($ec -ne 0) {
  $txt = ""
  if ($clusterOut) { $txt = ($clusterOut | Out-String) }
  throw ("rac cluster list failed (endpoint={0}). Output:`n{1}" -f $RasEndpoint, $txt)
}
$clusterId = Parse-ClusterId $clusterOut
if (-not $clusterId) {
  $txt = ""
  if ($clusterOut) { $txt = ($clusterOut | Out-String) }
  throw ("RAS/cluster is not ready yet (endpoint={0}). rac output:`n{1}" -f $RasEndpoint, $txt)
}

# Check if infobase already exists
$ibsOut = Invoke-Ssh $remote $sshOpts ("bash -lc 'sudo -n docker exec onec-server /opt/1cv8/current/rac infobase summary list {0} --cluster={1} 2>/dev/null || true'" -f $RasEndpoint, $clusterId)
$ibNameLine = '(?im)^\s*name\s*:\s*"?'+[Regex]::Escape($ibName)+'"?\s*$'
if ($ibsOut -and ($ibsOut -match $ibNameLine)) {
  Write-Host ("[OK] Infobase '{0}' already exists. Nothing to do." -f $ibName)
  return
}

# Create infobase + database inside the container.
# Keep quoting simple: run a single docker exec with a single-quoted bash script.
$createCmdTemplate = @'
sudo -n docker exec onec-server bash -lc 'set -euo pipefail
test -f /run/secrets/pg_password
PGPWD="$(cat /run/secrets/pg_password)"
PGUSER="${PGUSER:-onec}"
RAC="/opt/1cv8/current/rac"
test -x "$RAC"
echo "[INFO] rac infobase create: name=__IB__ db=__DB_NAME__ db_server=__DB_SERVER__"
timeout 180s "$RAC" infobase create __RAS__ --cluster=__CLUSTER__ --name=__IB__ --dbms=PostgreSQL --db-server=__DB_SERVER__ --db-name=__DB_NAME__ --db-user="$PGUSER" --db-pwd="$PGPWD" --locale=__LOCALE__ --create-database
'
'@

$createCmd = $createCmdTemplate
$createCmd = $createCmd.Replace("__RAS__", $RasEndpoint)
$createCmd = $createCmd.Replace("__CLUSTER__", $clusterId)
$createCmd = $createCmd.Replace("__IB__", $ibName)
$createCmd = $createCmd.Replace("__DB_SERVER__", $DbServerHost)
$createCmd = $createCmd.Replace("__DB_NAME__", $dbName)
$createCmd = $createCmd.Replace("__LOCALE__", $Locale)

$ec = 0
$createOut = Invoke-SshAny $remote $sshOpts ($createCmd -replace "`r","") ([ref]$ec)
if ($ec -ne 0) {
  $tail = $createOut
  if ($tail -and $tail.Count -gt 40) { $tail = $tail[-40..-1] }
  throw ("Failed to create infobase (ssh exit={0}). Output:`n{1}" -f $ec, ($tail -join "`n"))
}

Write-Host ("[OK] Created infobase '{0}'. Connect: Srvr={1};Ref={0};" -f $ibName, $VmIp)

