param(
  [Parameter(Mandatory=$true)]
  [string]$VmIp,

  [string]$SshUser = "sandbox",
  # Optional: explicit identity file (private key). Recommended for automation.
  [string]$SshIdentityFile = "",
  [string]$RemoteDir = "/opt/onec-sandbox",
  [string]$LocalRepoPath = "",

  # Can be relative to repo root or absolute path.
  # If file does not exist, deployment will proceed without creating infobases.
  # Format: one infobase name per line (comments with '#').
  [string]$InfobasesTxtPath = "infra/vm/infobases.txt",

  # Dangerous: removes 1C cluster state volume (vm_onec-data) before start.
  # Use when the cluster state is broken and you want a clean re-init.
  [switch]$ResetOnecData,

  # Dangerous: removes Postgres data volume (vm_pgdata) before start.
  # Use when you want to fully reset Postgres data (DBs/users/etc).
  # NOTE: Postgres password changes (secrets/pg_password) do NOT require wiping pgdata anymore:
  # the Postgres container entrypoint applies POSTGRES_PASSWORD(_FILE) on each start.
  [switch]$ResetPgData
)

$ErrorActionPreference = "Stop"
try { chcp 65001 | Out-Null } catch {}

function Write-DebugNdjson([string]$repoRoot, [string]$runId, [string]$hypothesisId, [string]$location, [string]$message, $data) {
  try {
    $logPath = Join-Path $repoRoot ".cursor\\debug.log"
    $utf8bom = New-Object System.Text.UTF8Encoding($true)
    $obj = [ordered]@{
      sessionId = "debug-session"
      runId = $runId
      hypothesisId = $hypothesisId
      location = $location
      message = $message
      data = $data
      timestamp = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    }
    $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
    [System.IO.File]::AppendAllText($logPath, $json + "`n", $utf8bom)
  } catch {}
}

function Get-RepoRoot {
  if ($LocalRepoPath -and (Test-Path $LocalRepoPath)) {
    return (Resolve-Path $LocalRepoPath).Path
  }
  $runId = "run1"
  # Prefer $PSScriptRoot; $MyInvocation.MyCommand.Path can be $null under pwsh -File in some setups.
  $here = $PSScriptRoot
  $invPath = $MyInvocation.MyCommand.Path
  if (-not $here) {
    try { $here = Split-Path -Parent $invPath } catch {}
  }
  $root = $null
  try { $root = (Resolve-Path (Join-Path $here "..\\..")).Path } catch {}

  #region agent log D
  Write-DebugNdjson (Resolve-Path ".").Path $runId "D" "Deploy-OnecInfra.ps1:Get-RepoRoot" "repo root resolution" @{
    LocalRepoPath = $LocalRepoPath
    MyInvocationPath = $invPath
    Here = $here
    ResolvedRoot = $root
    PSScriptRoot = $PSScriptRoot
  }
  #endregion

  return $root
}

function Require-Cmd($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Required command not found: $name"
  }
}

function Parse-InfobasesTxt([string]$path) {
  $names = @()
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $names }
  foreach ($line in (Get-Content -LiteralPath $path)) {
    if ($null -eq $line) { continue }
    $t = [string]$line
    # Strip inline comment (simple '#', no escaping; good enough for names).
    $hash = $t.IndexOf("#")
    if ($hash -ge 0) { $t = $t.Substring(0, $hash) }
    $t = $t.Trim()
    if ($t.Length -eq 0) { continue }
    if ($t -notmatch "^[A-Za-z0-9_\\-\\.]{1,64}$") {
      throw ("Invalid infobase name in {0}: '{1}'. Expected ^[A-Za-z0-9_\\-\\.]{{1,64}}$" -f $path, $t)
    }
    $names += $t
  }
  # De-dup but preserve order
  $seen = @{}
  $out = @()
  foreach ($n in $names) {
    if (-not $seen.ContainsKey($n)) { $seen[$n] = $true; $out += $n }
  }
  return $out
}

function Wait-OnecServerHealthy([string]$remote, [string[]]$sshOpts, [int]$timeoutSeconds = 360, [int]$pollSeconds = 5) {
  $cmd = 'bash -lc ''sudo -n docker inspect -f "{{.State.Health.Status}}" onec-server 2>/dev/null || echo unknown'''
  $started = Get-Date
  while ($true) {
    $raw = & ssh @sshOpts $remote $cmd 2>$null
    $ec = $LASTEXITCODE
    $status = ""
    if ($raw) {
      $s = ""
      if ($raw -is [array]) { $s = ($raw -join "`n") } else { $s = ("" + $raw) }
      $s = $s.Trim()
      if ($s) { $status = ($s -split "\r?\n")[0].Trim() }
    }
    if ($ec -eq 0 -and $status -eq "healthy") { return }
    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    if ($elapsed -ge $timeoutSeconds) {
      throw ("onec-server is not healthy after {0}s (last='{1}', ssh_exit={2})." -f $elapsed, $status, $ec)
    }
    $shown = $status
    if (-not $shown) { $shown = "n/a" }
    Write-Host ("[WAIT] onec-server health='{0}' (elapsed={1}s)..." -f $shown, $elapsed)
    Start-Sleep -Seconds $pollSeconds
  }
}

function Invoke-Remote([string]$remote, [string[]]$sshOpts, [string]$cmd, [string]$errPrefix) {
  # PowerShell 5.1 can turn native stderr into terminating errors when $ErrorActionPreference=Stop.
  # We still want the text, but we must not abort unless ssh exit code is non-zero.
  $oldEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $out = & ssh @sshOpts $remote $cmd 2>&1
    $ec = $LASTEXITCODE
    if ($ec -ne 0) {
      throw ("{0} (ssh exit={1}). Output:`n{2}" -f $errPrefix, $ec, ($out | Out-String))
    }
    return $out
  } finally {
    $ErrorActionPreference = $oldEap
  }
}

function Get-Remote-Stats([string]$remote, [string[]]$sshOpts) {
  # One-shot lightweight stats; keep it single SSH round-trip.
  # IMPORTANT: use single-quoted PowerShell string to avoid `$` interpolation (bash/awk uses `$` heavily).
  # Note: `free` output can be localized. Avoid matching the "Mem:" label and use row number instead.
  # Also force C locale for deterministic output.
  # IMPORTANT: run docker under sudo, because sandbox user may not be in docker group.
  $cmd = 'bash -lc ''set -e; export LANG=C LC_ALL=C; load=$(awk "{print \$1\" \"\$2\" \"\$3}" /proc/loadavg); mem=$(free -m | awk "NR==2{print $3\"/\"$2\"MB\"}"); root=$(df -Pm / | awk "NR==2{print $5\" used,\" $4\"MB free\"}"); dock=$(df -Pm /var/lib/docker 2>/dev/null | awk "NR==2{print $5\" used,\" $4\"MB free\"}" || echo n/a); c=$(sudo -n docker ps -q 2>/dev/null | wc -l || echo 0); echo "load=$load mem=$mem root=$root dockerfs=$dock containers=$c"'''
  $line = & ssh @sshOpts $remote $cmd 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $line) { return @{} }
  $h = @{}
  foreach ($kv in ($line -split "\s+")) {
    if (-not $kv) { continue }
    $p = $kv.Split('=',2)
    if ($p.Count -eq 2) { $h[$p[0]] = $p[1] }
  }
  return $h
}

function Get-Remote-LogTail([string]$remote, [string[]]$sshOpts, [string]$logPath, [int]$lines = 40) {
  $cmd = ('bash -lc ''test -f "{0}" && tail -n {1} "{0}" || true''' -f $logPath, $lines)
  return (& ssh @sshOpts $remote $cmd 2>$null)
}

function Invoke-Remote-LongStep(
  [string]$remote,
  [string[]]$sshOpts,
  [string]$activity,
  [string]$commandToRunAsRoot,
  [int]$pollSeconds = 15,
  [int]$logTailLinesOnError = 120
) {
  $tag = ([Guid]::NewGuid().ToString("N")).Substring(0,8)
  $logPath = "/tmp/onec-step-$tag.log"
  $exitPath = "/tmp/onec-step-$tag.exit"

  # Start in background and detach from SSH (nohup).
  # IMPORTANT: keep the template single-quoted to avoid PowerShell `$?` interpolation.
  $startCmd = ('bash -lc ''set -e; rm -f "{0}" "{1}"; nohup sudo -n bash -lc "set -euo pipefail; {2} ; echo $? > ''{1}''" > "{0}" 2>&1 & echo ok''' -f $logPath, $exitPath, $commandToRunAsRoot)
  Invoke-Remote $remote $sshOpts $startCmd "Failed to start '$activity'"

  $lastCheckpoint = Get-Date
  $started = Get-Date
  while ($true) {
    $exitRaw = & ssh @sshOpts $remote ("bash -lc 'test -f ""{0}"" && cat ""{0}"" || true'" -f $exitPath) 2>$null
    if ($LASTEXITCODE -eq 0 -and $exitRaw) {
      $exitCode = 0
      try { $exitCode = [int]("$exitRaw".Trim()) } catch { $exitCode = 1 }
      Write-Progress -Id 1 -Activity $activity -Completed
      if ($exitCode -ne 0) {
        $tail = Get-Remote-LogTail $remote $sshOpts $logPath $logTailLinesOnError
        throw ("{0} failed (exit={1}). Last log lines:`n{2}" -f $activity, $exitCode, ($tail -join "`n"))
      }
      return
    }

    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    $stats = Get-Remote-Stats $remote $sshOpts
    $lastLine = (& ssh @sshOpts $remote ("bash -lc 'test -f ""{0}"" && tail -n 1 ""{0}"" || true'" -f $logPath) 2>$null)
    if ($null -eq $lastLine) { $lastLine = "" }
    $lastLine = ("$lastLine".Trim() -replace "\s+", " ")
    if ($lastLine.Length -gt 120) { $lastLine = $lastLine.Substring(0,120) + "..." }

    $statusParts = @()
    if ($stats["load"]) { $statusParts += ("load={0}" -f $stats["load"]) }
    if ($stats["mem"]) { $statusParts += ("mem={0}" -f $stats["mem"]) }
    if ($stats["root"]) { $statusParts += ("disk={0}" -f $stats["root"]) }
    if ($stats["dockerfs"] -and $stats["dockerfs"] -ne "n/a") { $statusParts += ("dockerfs={0}" -f $stats["dockerfs"]) }
    if ($stats["containers"]) { $statusParts += ("containers={0}" -f $stats["containers"]) }
    $statusParts += ("elapsed={0}s" -f $elapsed)
    if ($lastLine) { $statusParts += ("last='{0}'" -f $lastLine) }
    $status = ($statusParts -join " | ")

    Write-Progress -Id 1 -Activity $activity -Status $status

    # Rare checkpoint line to keep scrollback meaningful (no spam).
    if (((Get-Date) - $lastCheckpoint).TotalSeconds -ge 60) {
      Write-Host ("[WAIT] {0}: {1}" -f $activity, $status)
      $lastCheckpoint = Get-Date
    }

    Start-Sleep -Seconds $pollSeconds
  }
}

Require-Cmd ssh
Require-Cmd scp
Require-Cmd tar

$repoRoot = Get-RepoRoot
$ibsPath = $InfobasesTxtPath
if (-not [System.IO.Path]::IsPathRooted($ibsPath)) {
  $ibsPath = Join-Path $repoRoot $InfobasesTxtPath
}
$infobases = @()
if (Test-Path -LiteralPath $ibsPath -PathType Leaf) {
  $infobases = Parse-InfobasesTxt $ibsPath
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("onec-sandbox-{0}.tar.gz" -f ([Guid]::NewGuid().ToString("N")))

Push-Location $repoRoot
try {
  # Create a minimal archive (allowlist include).
  #
  # Rationale: the repo can be large and contain transient tool directories (.cursor/.kiro/...)
  # that may be missing in other checkouts or cause tar failures.
  #
  # This archive must be sufficient to:
  # - run infra/vm/{up,down}.sh on the VM
  # - build images defined in infra/vm/docker-compose.yml (contexts are relative to repo root)
  # - prepare secrets (scripts/prepare-secrets.sh + secrets/.env)
  #
  # NOTE: Some paths are optional (e.g. secrets/.env). We include only if present.
  $include = @(
    ".devcontainer/.env",
    ".devcontainer/onec-activate-community.sh",
    ".devcontainer/distr",
    "infra/vm",
    "onec-client/ActivateCommunity.epf",
    "onec-client/scripts/onec-install.sh",
    "scripts/prepare-secrets.sh"
  )

  if (Test-Path "secrets/.env") { $include += "secrets/.env" }
  if (Test-Path "secrets/onec_username") { $include += "secrets/onec_username" }
  if (Test-Path "secrets/onec_password") { $include += "secrets/onec_password" }
  if (Test-Path "secrets/dev_login") { $include += "secrets/dev_login" }
  if (Test-Path "secrets/dev_password") { $include += "secrets/dev_password" }
  if (Test-Path "secrets/pg_password") { $include += "secrets/pg_password" }

  # Keep only existing paths (tar fails on missing inputs).
  $include = $include | Where-Object { Test-Path $_ }
  if (-not $include -or $include.Count -eq 0) { throw "Nothing to archive (include list is empty after filtering)." }

  # Use BSD tar (Windows bsdtar) with explicit file list.
  tar -czf $tmp @($include)
  if ($LASTEXITCODE -ne 0) { throw "Failed to create repo archive (tar exit=$LASTEXITCODE)." }
} finally {
  Pop-Location
}

$remote = "$SshUser@$VmIp"

$sshOpts = @(
  "-o", "BatchMode=yes",
  "-o", "ConnectTimeout=10",
  "-o", "ConnectionAttempts=1",
  "-o", "StrictHostKeyChecking=no",
  "-o", "UserKnownHostsFile=/dev/null",
  "-o", "LogLevel=ERROR"
)
if ($SshIdentityFile -and (Test-Path $SshIdentityFile)) {
  $sshOpts += @("-o","IdentitiesOnly=yes","-i",$SshIdentityFile)
}

# Preflight: ensure passwordless sudo (otherwise ssh can hang waiting for password).
& ssh @sshOpts $remote "sudo -n true" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Remote user '$SshUser' cannot run sudo without password. Fix: recreate VM with passwordless sudo (autoinstall late-command), or configure sudoers on the VM."
}

& ssh @sshOpts $remote "sudo -n mkdir -p '$RemoteDir' && sudo -n chown -R $SshUser '$RemoteDir'" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Remote mkdir/chown failed (ssh exit=$LASTEXITCODE)." }
& scp @sshOpts $tmp "${remote}:/tmp/onec-sandbox.tar.gz" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "SCP upload failed (exit=$LASTEXITCODE)." }
& ssh @sshOpts $remote "sudo -n rm -rf '$RemoteDir'/* && sudo -n tar --warning=no-unknown-keyword -xzf /tmp/onec-sandbox.tar.gz -C '$RemoteDir' && sudo -n chown -R $SshUser '$RemoteDir'" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Remote extract failed (ssh exit=$LASTEXITCODE)." }

# Normalize line endings for Linux shell scripts (Windows CRLF breaks shebang: /usr/bin/env: 'bash\r' ...).
# Also normalize secrets/.env because prepare-secrets uses `source` and CRLF breaks bash parsing.
# Keep it narrowly scoped to scripts we execute + secrets/.env.
$eolCmd = 'cd ''{0}'' && sudo -n perl -pi -e ''s/\r$//'' infra/vm/up.sh infra/vm/down.sh infra/vm/postgres/ensure-pg-user.sh scripts/prepare-secrets.sh && (test -f secrets/.env && perl -pi -e ''s/\r$//'' secrets/.env || true)' -f $RemoteDir
& ssh @sshOpts $remote $eolCmd 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Remote EOL normalization failed (ssh exit=$LASTEXITCODE)." }

# Ensure scripts are executable and Docker is available
& ssh @sshOpts $remote "cd '$RemoteDir' && chmod +x infra/vm/up.sh infra/vm/down.sh infra/vm/postgres/ensure-pg-user.sh scripts/prepare-secrets.sh && docker --version && docker compose version" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Remote preflight failed (ssh exit=$LASTEXITCODE)." }

# Prepare secrets on VM from secrets/.env (preferred) and harden permissions.
# This ensures DEV_LOGIN/DEV_PASSWORD (community activation) and PG_PASSWORD are available as Docker secrets files.
# Do NOT print secret values.
$prepSecretsCmd = ('bash -lc ''set -euo pipefail; cd "{0}"; mkdir -p secrets; if [ -f secrets/.env ]; then chmod 600 secrets/.env 2>/dev/null || true; ./scripts/prepare-secrets.sh; fi; chmod 600 secrets/onec_username secrets/onec_password secrets/dev_login secrets/dev_password secrets/pg_password 2>/dev/null || true; if [ ! -f secrets/pg_password ] || [ ! -s secrets/pg_password ]; then umask 077; python3 -c "import secrets; print(secrets.token_urlsafe(24))" > secrets/pg_password; chmod 600 secrets/pg_password; fi; echo ok''' -f $RemoteDir)
$prepOut = & ssh @sshOpts $remote $prepSecretsCmd 2>&1
if ($LASTEXITCODE -ne 0) {
  $prepText = ""
  try { $prepText = ($prepOut -join "`n") } catch { $prepText = ($prepOut | Out-String) }
  throw ("Failed to prepare secrets on VM (ssh exit={0}). Output:`n{1}" -f $LASTEXITCODE, $prepText)
}

# Bring infra up
if ($ResetOnecData -or $ResetPgData) {
  if ($ResetOnecData) { Write-Host "[STEP] Resetting 1C data volume (vm_onec-data)..." }
  if ($ResetPgData) { Write-Host "[STEP] Resetting Postgres data volume (vm_pgdata)..." }

  & ssh @sshOpts $remote ("cd '{0}' && ./infra/vm/down.sh" -f $RemoteDir) 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Failed to stop infra before reset (ssh exit=$LASTEXITCODE)." }

  if ($ResetOnecData) {
    # Volume name comes from compose project name 'vm' + declared volume 'onec-data' => vm_onec-data
    $rmOnec = "bash -lc 'set -euo pipefail; if sudo -n docker volume inspect vm_onec-data >/dev/null 2>&1; then sudo -n docker volume rm vm_onec-data; fi'"
    & ssh @sshOpts $remote $rmOnec 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to remove docker volume vm_onec-data (ssh exit=$LASTEXITCODE)." }
  }

  if ($ResetPgData) {
    # Volume name comes from compose project name 'vm' + declared volume 'pgdata' => vm_pgdata
    $rmPg = "bash -lc 'set -euo pipefail; if sudo -n docker volume inspect vm_pgdata >/dev/null 2>&1; then sudo -n docker volume rm vm_pgdata; fi'"
    & ssh @sshOpts $remote $rmPg 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to remove docker volume vm_pgdata (ssh exit=$LASTEXITCODE)." }
  }
}

Invoke-Remote-LongStep $remote $sshOpts "Starting infra (docker compose build+up)" ("cd '{0}'; ./infra/vm/up.sh" -f $RemoteDir) 15 140

Wait-OnecServerHealthy $remote $sshOpts 420 7

if ($infobases -and $infobases.Count -gt 0) {
  $createScript = Join-Path $repoRoot "scripts\\hyperv\\New-OnecInfobase.ps1"
  if (-not (Test-Path -LiteralPath $createScript -PathType Leaf)) { throw "Missing script: $createScript" }
  Write-Host ("[STEP] Creating infobases from {0} ({1} items)..." -f $ibsPath, $infobases.Count)
  foreach ($ib in $infobases) {
    Write-Host ("[STEP] Infobase: {0}" -f $ib)
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $createScript -VmIp $VmIp -SshUser $SshUser -SshIdentityFile $SshIdentityFile -InfobaseName $ib 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("Infobase creation failed for '{0}' (exit={1})." -f $ib, $LASTEXITCODE) }
  }
} else {
  if (Test-Path -LiteralPath $ibsPath -PathType Leaf) {
    Write-Host ("[INFO] No infobases listed in {0}. Skipping infobase creation." -f $ibsPath)
  } else {
    Write-Host ("[INFO] Infobases file not found: {0}. Skipping infobase creation." -f $ibsPath)
  }
}

try {
  $auto = & ssh @sshOpts $remote ("bash -lc 'systemctl is-enabled docker 2>/dev/null || true; systemctl is-enabled onec-infra.service 2>/dev/null || true; systemctl is-active docker 2>/dev/null || true; systemctl is-active onec-infra.service 2>/dev/null || true'") 2>$null
  if ($auto) {
    Write-Host "[INFO] Autostart status (docker / onec-infra.service):"
    foreach ($line in @($auto)) { if ($line) { Write-Host ("       " + $line) } }
  }
} catch {}

Write-Host "[OK] Deployed and started infra in VM."
Write-Host "     Repo: $RemoteDir"
Write-Host "     1C ports: 1540,1541,1545,1560-1591 (TCP)"
Write-Host "     Postgres: 5432 (TCP)"

Remove-Item -Force $tmp -ErrorAction SilentlyContinue

