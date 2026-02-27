param(
  # VM management IP (preferred). If omitted, will be read from infra/vm/.env (MGMT_VM_IP).
  [string]$VmIp = "",

  [string]$SshUser = "sandbox",
  [string]$SshIdentityFile = "",

  # Uses same env file as smoke/deploy.
  [string]$EnvFile = "infra/vm/.env",

  # Publication alias (and wsdir). Defaults to InfobaseName.
  [string]$Alias = "",
  [string]$InfobaseName = "",

  # Optional: explicit list of HTTP services to publish (names as in конфигуратор).
  # Used only for Action=EnableHttpServicesExplicit.
  [string[]]$HttpServiceNames = @("mcp_APIBackend","mcp"),

  # What to do.
  [ValidateSet("Inspect","EnableHttpServices","EnableHttpServicesExplicit")]
  [string]$Action = "Inspect"
)

$ErrorActionPreference = "Stop"
try { chcp 65001 | Out-Null } catch {}

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

if (-not $InfobaseName -or $InfobaseName.Trim().Length -eq 0) {
  $InfobaseName = Read-Host "Infobase name (Ref), e.g. demo"
}
$InfobaseName = Validate-Name $InfobaseName "Infobase name"

if (-not $Alias -or $Alias.Trim().Length -eq 0) { $Alias = $InfobaseName }
$Alias = Validate-Name $Alias "Alias"

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

$pubPath = "/var/lib/onec-web/www/$Alias/default.vrd"

if ($Action -eq "Inspect") {
  $inner = "sudo -n docker exec onec-web bash -lc " + (Bash-SingleQuote ("set -euo pipefail; test -f ""$pubPath""; echo ""[VRD] $pubPath""; sed -n '1,220p' ""$pubPath"""))
  $cmd = "bash -lc " + (Bash-SingleQuote $inner)
  $ec = 0
  $out = Invoke-SshAny $remote $sshOpts $cmd ([ref]$ec)
  if ($ec -ne 0) { throw ("Inspect failed (ssh exit={0}). Output:`n{1}" -f $ec, ($out | Out-String)) }
  $out | Out-Host
  exit 0
}

if ($Action -eq "EnableHttpServices") {
  $patch = @"
set -euo pipefail
test -f "$pubPath"
if grep -qF "<httpServices" "$pubPath"; then
  perl -0777 -i -pe 's#\s+rootUrl="[^"]*"# #g' "$pubPath"
  perl -0777 -i -pe 's#(<httpServices[^>]*")(?=publishExtensionsByDefault)#$1 #g' "$pubPath"
  if ! grep -qE '<httpServices[^>]*\bpublishExtensionsByDefault="' "$pubPath"; then
    perl -0777 -i -pe 's#<httpServices([^>]*)/>#<httpServices$1 publishExtensionsByDefault="true"/>#g' "$pubPath"
  fi
else
  perl -0777 -i -pe 's#</point>\s*$#\t<httpServices publishExtensionsByDefault="true"/>\n</point>#s' "$pubPath"
fi

if ! grep -qF "<rest" "$pubPath"; then
  perl -0777 -i -pe 's#</point>\s*$#\t<rest publishExtensionsByDefault="true"/>\n</point>#s' "$pubPath"
fi
apache2ctl -k graceful >/dev/null 2>&1 || true
echo OK
"@
  $patch = ($patch -replace "`r","")
  $inner = "sudo -n docker exec onec-web bash -lc " + (Bash-SingleQuote $patch)
  $cmd = "bash -lc " + (Bash-SingleQuote $inner)
  $ec = 0
  $out = Invoke-SshAny $remote $sshOpts $cmd ([ref]$ec)
  if ($ec -ne 0) { throw ("Patch failed (ssh exit={0}). Output:`n{1}" -f $ec, ($out | Out-String)) }
  Write-Host ("[OK] Enabled HTTP/REST services in VRD: {0}" -f $pubPath)
  exit 0
}

if ($Action -eq "EnableHttpServicesExplicit") {
  # Publish only selected HTTP services explicitly (avoids relying on publish-by-default semantics).
  $names = @()
  foreach ($n in @($HttpServiceNames)) {
    if (-not $n) { continue }
    $t = ("$n").Trim()
    if (-not $t) { continue }
    $names += (Validate-Name $t "HttpService name")
  }
  if (-not $names -or $names.Count -eq 0) { throw "HttpServiceNames is empty." }

  $json = ($names | ConvertTo-Json -Compress)

  $patch = @"
set -euo pipefail
test -f "$pubPath"
export HTTP_SVC_NAMES_JSON='$json'
python3 - <<'PY'
import json, os, re
from pathlib import Path

p = Path(os.environ["VRD_PATH"])
t = p.read_text(encoding="utf-8")

names = json.loads(os.environ["HTTP_SVC_NAMES_JSON"])
services_xml = "\n".join([f'\t\t<service name="{n}" enable="true"/>' for n in names])
block = f'\t<httpServices publishExtensionsByDefault="true">\n{services_xml}\n\t</httpServices>'

# Remove invalid legacy attributes if present.
t = re.sub(r'\s+rootUrl="[^"]*"', " ", t)

# Replace existing httpServices (self-closing or expanded) with explicit block.
t2 = re.sub(r'\t<httpServices[^>]*/>\s*', block + "\n", t)
t2 = re.sub(r'\t<httpServices[^>]*>.*?</httpServices>\s*', block + "\n", t2, flags=re.S)
if t2 == t:
    # Insert before </point>
    t2 = re.sub(r'</point>\s*$', block + "\n</point>", t2)

p.write_text(t2, encoding="utf-8")
PY
apache2ctl -k graceful >/dev/null 2>&1 || true
echo OK
"@
  $patch = ($patch -replace "`r","")
  $inner = "sudo -n docker exec -e VRD_PATH=$pubPath onec-web bash -lc " + (Bash-SingleQuote $patch)
  $cmd = "bash -lc " + (Bash-SingleQuote $inner)
  $ec2 = 0
  $out2 = Invoke-SshAny $remote $sshOpts $cmd ([ref]$ec2)
  if ($ec2 -ne 0) { throw ("Patch failed (ssh exit={0}). Output:`n{1}" -f $ec2, ($out2 | Out-String)) }
  Write-Host ("[OK] Enabled explicit HTTP services in VRD: {0}" -f $pubPath)
  exit 0
}

throw "Unexpected Action: $Action"

