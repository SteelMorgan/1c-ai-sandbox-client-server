param(
  # VM management IP (preferred). If omitted, will be read from infra/vm/.env (MGMT_VM_IP).
  [string]$VmIp = "",

  [string]$SshUser = "sandbox",
  [string]$SshIdentityFile = "",

  # Uses same env file as smoke/deploy.
  [string]$EnvFile = "infra/vm/.env",

  # Action: Publish / Unpublish / Update (Update is Publish again).
  [ValidateSet("Publish","Unpublish","Update")]
  [string]$Action = "Publish",

  # Infobase name (Ref). Alias defaults to the same value.
  [string]$InfobaseName = "",
  [string]$Alias = "",

  # 1C server endpoint (inside VM). With host networking, onec-web can reach it via 127.0.0.1.
  [string]$ServerHost = "127.0.0.1",
  [string]$ServerPort = "",

  # Web port on VM host (Apache in onec-web container). If omitted, uses ONEC_WEB_PORT_HOST from env or defaults to 8080.
  [string]$WebPort = ""
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
    if ($null -eq $line) { continue }
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

function Bash-SingleQuote([string]$s) {
  # Wrap string for safe use in bash -lc '...'
  if ($null -eq $s) { return "''" }
  # Replace single quote with the bash-safe sequence: '"'"'
  $sq = "'" + '"' + "'" + '"' + "'"
  return "'" + ($s -replace "'", $sq) + "'"
}

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

if (-not $Alias -or $Alias.Trim().Length -eq 0) { $Alias = $ibName }
$Alias = Validate-Name $Alias "Alias"

if (-not $ServerPort -or $ServerPort.Trim().Length -eq 0) {
  $ServerPort = $envMap["ONEC_REGPORT_HOST"]
  if (-not $ServerPort) { $ServerPort = $envMap["ONEC_REGPORT"] }
  if (-not $ServerPort) { $ServerPort = "1541" }
}
$ServerPort = Validate-Port $ServerPort "ServerPort"

if (-not $WebPort -or $WebPort.Trim().Length -eq 0) {
  $WebPort = $envMap["ONEC_WEB_PORT_HOST"]
  if (-not $WebPort) { $WebPort = "8080" }
}
$WebPort = Validate-Port $WebPort "WebPort"

$connStr = ("Srvr={0}:{1};Ref={2};" -f $ServerHost.Trim(), $ServerPort, $ibName)
$connB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($connStr))
if ($connB64 -notmatch "^[A-Za-z0-9+/=]+$") {
  throw "Internal error: connStr base64 contains unexpected characters."
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

$remote = "$SshUser@$VmIp"

# Ensure onec-web container is running
$ec = 0
$probeCmd = "bash -lc " + (Bash-SingleQuote 'sudo -n docker ps --format "{{.Names}}" | grep -qx "onec-web"')
$probeOut = Invoke-SshAny $remote $sshOpts $probeCmd ([ref]$ec)
if ($ec -ne 0) {
  throw "Container onec-web is not running on VM. Deploy infra first (Deploy-OnecInfra.ps1 / infra/vm/up.sh)."
}

$act = $Action.ToLowerInvariant()
if ($act -eq "update") { $act = "publish" }
if ($act -eq "unpublish") { $act = "unpublish" }

Write-Host ("[STEP] {0}: infobase='{1}' alias='{2}' vm={3}" -f $Action, $ibName, $Alias, $VmIp)

$inner = $null
if ($act -eq "publish") {
  $inner = "sudo -n docker exec -e ONEC_ALIAS=$Alias -e ONEC_CONNSTR_B64=$connB64 onec-web /usr/local/bin/onec-webinst.sh publish"
} elseif ($act -eq "unpublish") {
  $inner = "sudo -n docker exec -e ONEC_ALIAS=$Alias onec-web /usr/local/bin/onec-webinst.sh unpublish"
} else {
  throw "Unexpected action resolved: '$act'"
}

$cmd = "bash -lc " + (Bash-SingleQuote $inner)
$ec = 0
$out = Invoke-SshAny $remote $sshOpts $cmd ([ref]$ec)
if ($ec -ne 0) {
  $txt = ""
  if ($out) { $txt = ($out | Out-String) }
  throw ("Failed to {0} publication (ssh exit={1}). Output:`n{2}" -f $Action, $ec, $txt)
}

$url = "http://$VmIp`:$WebPort/$Alias/"
Write-Host ("[OK] Action '{0}' completed. URL: {1}" -f $Action, $url)
Write-Host ("     HTTP services: {0}hs/<service>" -f $url)

