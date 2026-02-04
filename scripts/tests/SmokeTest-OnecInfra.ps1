param(
  # Hyper-V / network
  # Load defaults from .env (recommended). CLI params override env file.
  [string]$EnvFile = "infra/vm/.env",

  [string]$NetAdapterName = "",

  [string]$VmName = "",
  [string]$SwitchName = "",

  # VM_IP is intentionally not part of the public contract anymore:
  # we use DHCP on LAN and a fixed mgmt IP on an internal Hyper-V switch.
  # Kept only as internal variable name later in the script (actual IP we connect to).
  [string]$VmIp = "",
  [string]$NetIface = "",

  # Content / infra
  [string]$InfobasesJsonPath = "infra/vm/infobases.json",
  [string]$RemoteDir = "/opt/onec-sandbox",

  # Behavior
  [switch]$KeepVm,
  [int]$SshWaitSeconds = 600,

  # Optional: require community license activation secrets (developer.1c.ru).
  # If false, DEV secrets may be empty and activation will be skipped.
  [switch]$EnableCommunityActivation
)

$ErrorActionPreference = "Stop"

# Ensure correct codepage for Cyrillic output (Hyper-V cmdlets may emit localized strings).
try { chcp 65001 | Out-Null } catch {}

# Ensure PowerShell decodes UTF-8 output from native commands correctly (ssh/docker output contains Cyrillic).
# Without this, UTF-8 bytes can be rendered as mojibake (e.g. "╨б╨╛╨╖...").
try {
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  [Console]::InputEncoding = $utf8
  [Console]::OutputEncoding = $utf8
  $global:OutputEncoding = $utf8
} catch {}

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

function Find-Ipv4ByMac([string]$macDashUpper) {
  try {
    if (-not $macDashUpper) { return $null }
    $mac = $macDashUpper.ToUpperInvariant()
    $n = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress.ToUpperInvariant() -eq $mac } | Select-Object -First 1
    if ($n -and $n.IPAddress) { return [string]$n.IPAddress }
  } catch {}
  # Fallback: parse arp output (best-effort).
  try {
    $lines = @(arp -a | Out-String -Width 4096).Split("`n")
    foreach ($l in $lines) {
      $t = $l.Trim()
      if (-not $t) { continue }
      if ($t -match "^(?<ip>\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(?<mac>(?:[0-9a-f]{2}-){5}[0-9a-f]{2})\\s+") {
        $ip = $Matches["ip"]
        $m = $Matches["mac"].ToUpperInvariant()
        if ($m -eq $macDashUpper.ToUpperInvariant()) { return $ip }
      }
    }
  } catch {}
  return $null
}

function Format-HyperVMacDash([string]$macRaw) {
  # Hyper-V may return MAC as "00155D63A5D8" (no separators) or already formatted.
  if (-not $macRaw) { return $null }
  $m = $macRaw.Trim()
  if ($m.Length -eq 12 -and ($m -match "^[0-9A-Fa-f]{12}$")) {
    return ($m.Substring(0,2)+"-"+$m.Substring(2,2)+"-"+$m.Substring(4,2)+"-"+$m.Substring(6,2)+"-"+$m.Substring(8,2)+"-"+$m.Substring(10,2)).ToUpperInvariant()
  }
  # If already dash-separated, normalize.
  if ($m -match "^(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$") { return $m.ToUpperInvariant() }
  return $m.ToUpperInvariant()
}

function Get-VmDhcpIpv4([string]$vmName) {
  try {
    if (-not (Get-Command Get-VMNetworkAdapter -ErrorAction SilentlyContinue)) { return $null }
    $ad = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $ad) { return $null }
    $macDash = Format-HyperVMacDash $ad.MacAddress
    if (-not $macDash) { return $null }
    return Find-Ipv4ByMac $macDash
  } catch {}
  return $null
}

function Require-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw "Run PowerShell as Administrator." }
}

function Require-Cmd($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Required command not found: $name"
  }
}

function Repo-Root {
  # $MyInvocation inside a function may not have MyCommand.Path (NULL).
  # $PSScriptRoot is stable for scripts.
  $here = $script:PSScriptRoot
  if (-not $here) { $here = $PSScriptRoot }
  if (-not $here) { throw "Cannot determine script directory (PSScriptRoot is empty)." }
  return (Resolve-Path (Join-Path $here "..\\..")).Path
}

function Load-DotEnv([string]$path) {
  if (-not (Test-Path $path)) { return @{} }
  $map = @{}
  foreach ($line in Get-Content $path) {
    $t = $line.Trim()
    if ($t.Length -eq 0) { continue }
    if ($t.StartsWith("#")) { continue }
    $idx = $t.IndexOf("=")
    if ($idx -lt 1) { continue }
    $k = $t.Substring(0,$idx).Trim()
    $v = $t.Substring($idx+1).Trim()
    if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
      $v = $v.Substring(1, $v.Length-2)
    }
    $map[$k] = $v
  }
  return $map
}

function Coalesce([string]$a, [string]$b) {
  if ($a -and $a.Trim().Length -gt 0) { return $a }
  return $b
}

function CoalesceInt([int]$a, [string]$b) {
  if ($a -gt 0) { return $a }
  if ($b) { return [int]$b }
  return 0
}

function Test-Port([string]$targetHost, [int]$port) {
  $r = Test-NetConnection -ComputerName $targetHost -Port $port -WarningAction SilentlyContinue
  return [bool]$r.TcpTestSucceeded
}

function New-SshArgs([string]$remote, [string]$identityFile) {
  $args = @(
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "ConnectionAttempts=1",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "PreferredAuthentications=publickey",
    "-o", "IdentitiesOnly=yes"
  )
  if ($identityFile -and (Test-Path $identityFile)) {
    $args += @("-i", $identityFile)
  }
  $args += @($remote)
  return $args
}

function Ssh-Run([string]$remote, [string]$identityFile, [string]$command) {
  $args = New-SshArgs $remote $identityFile
  $args += @($command)
  $out = & ssh @args 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return $out
}

function Ssh-RunAny([string]$remote, [string]$identityFile, [string]$command, [ref]$exitCode) {
  $args = New-SshArgs $remote $identityFile
  $args += @($command)
  $out = & ssh @args 2>&1
  $exitCode.Value = $LASTEXITCODE
  return $out
}

function Get-SshExePath() {
  try {
    $cmd = Get-Command ssh -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.CommandType -eq "Application" -and $cmd.Source) { return $cmd.Source }
  } catch {}
  return "ssh"
}

function Invoke-SshProbe([string[]]$sshArgs, [int]$timeoutMs = 5000) {
  # ssh.exe can sometimes hang even with ConnectTimeout (e.g. auth/IO edge cases).
  # Run it as a process and enforce a hard timeout so SmokeTest never "freezes".
  $exe = Get-SshExePath
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.Arguments = [string]::Join(" ", ($sshArgs | ForEach-Object { '"' + ($_ -replace '"','\"') + '"' }))
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $null = $p.Start()
  if (-not $p.WaitForExit($timeoutMs)) {
    try { $p.Kill() } catch {}
    return @{ ok = $false; timed_out = $true; exit_code = 124 }
  }
  return @{ ok = ($p.ExitCode -eq 0); timed_out = $false; exit_code = $p.ExitCode }
}

function Normalize-Lf([string]$text) {
  if ($null -eq $text) { return $null }
  # IMPORTANT: multi-line bash snippets are authored on Windows (CRLF).
  # When executed on Linux via `bash -lc`, stray '\r' breaks `set -euo pipefail` etc.
  return ($text -replace "`r", "")
}

function Wait-OnecServerHealthy([string]$remote, [string]$identityFile, [int]$timeoutSec = 240) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  $start = Get-Date
  $lastReport = Get-Date
  $lastStatus = ""
  while ((Get-Date) -lt $deadline) {
    $status = Ssh-Run $remote $identityFile 'sudo -n docker inspect --format "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}no-health{{end}}" onec-server 2>/dev/null || echo missing'
    if ($status) {
      $s = ("$status").Trim()
      $lastStatus = $s
      if ($s -match '\bhealthy\b') { return }
      if (((Get-Date) - $lastReport).TotalSeconds -ge 20) {
        $elapsed = [int]((Get-Date) - $start).TotalSeconds

        # Show one-line state for BOTH cluster and activation.
        $ec = 0

        # IMPORTANT: keep these as single-line strings to avoid CRLF/quoting issues across ssh->bash.
        $clusterCmd = 'sudo -n docker exec onec-server bash -lc ''ep="127.0.0.1:${RAS_PORT:-1545}"; out="$(/opt/1cv8/current/rac cluster list "$ep" 2>/dev/null || true)"; id="$(printf "%s" "$out" | grep -Eo "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" | head -n1 || true)"; if [[ -n "$id" && "$id" != "00000000-0000-0000-0000-000000000000" ]]; then echo OK; else echo WAIT; fi''' 
        $clusterStatus = Ssh-RunAny $remote $identityFile $clusterCmd ([ref]$ec)
        $clusterStatus = ("$clusterStatus").Trim()
        if (-not $clusterStatus) { $clusterStatus = "WAIT" }

        $actCmd = 'sudo -n docker exec onec-server bash -lc ''set -euo pipefail; if [[ -f /run/secrets/dev_login && -f /run/secrets/dev_password ]]; then if find /var/1C/licenses -maxdepth 1 -type f -size +0 2>/dev/null | grep -q .; then echo "OK"; elif [[ -f /var/log/onec/activation.done ]]; then state=""; rc=""; if [[ -f /var/log/onec/activation.status ]]; then state="$(grep -E "^state=" /var/log/onec/activation.status | head -n1 | cut -d= -f2- || true)"; rc="$(grep -E "^exit_code=" /var/log/onec/activation.status | head -n1 | cut -d= -f2- || true)"; fi; last="$(tail -n 1 /var/log/onec/activation.log 2>/dev/null || true)"; echo "FAIL:done state=${state:-?} rc=${rc:-?} ${last:-<no-log>}"; elif [[ -f /var/log/onec/activation.log ]]; then last="$(tail -n 1 /var/log/onec/activation.log 2>/dev/null || true)"; if grep -q "\[ERROR\]" /var/log/onec/activation.log 2>/dev/null; then echo "FAIL:${last}"; else echo "PROGRESS:${last}"; fi; else echo "PROGRESS:<no-log>"; fi; else echo "SKIP"; fi''' 
        $actRaw = Ssh-RunAny $remote $identityFile $actCmd ([ref]$ec)

        $actRaw = ("$actRaw").Trim()
        $actStatus = $actRaw
        $actLine = ""
        $idx = $actRaw.IndexOf(":")
        if ($idx -gt 0) {
          $actStatus = $actRaw.Substring(0, $idx)
          $actLine = $actRaw.Substring($idx + 1).Trim()
        }
        if ($actLine.Length -gt 140) { $actLine = $actLine.Substring(0, 140) + "..." }

        $msg = "[WAIT] CLUSTER={0} ACTIVATION={1} | health={2} | elapsed={3}s" -f $clusterStatus, $actStatus, $s, $elapsed
        if ($actLine) { $msg += (" | act=""{0}""" -f $actLine) }
        Write-Host $msg

        # Fail-fast: activation completed but no licenses -> error, don't wait full timeout.
        if ($actStatus -eq "FAIL" -and $actLine -match "\bdone\b") {
          Write-Host ""
          Write-Host "[FAIL] Activation script finished but license files were not created. This is an error."
          Write-Host "[DIAG] /var/log/onec/activation.status:"
          # Do NOT use "<missing>" here: in bash it is parsed as input redirection.
          (Ssh-RunAny $remote $identityFile 'sudo -n docker exec onec-server sh -c "cat /var/log/onec/activation.status 2>/dev/null || echo missing"' ([ref]$ec)) | Out-Host
          Write-Host "[DIAG] onec-server activation.log (tail 200):"
          (Ssh-RunAny $remote $identityFile 'sudo -n docker exec onec-server sh -c "test -f /var/log/onec/activation.log && tail -n 200 /var/log/onec/activation.log || echo missing"' ([ref]$ec)) | Out-Host
          throw "Activation finished but no license files were created. See diagnostics above."
        }

        $lastReport = Get-Date
      }
    }
    Start-Sleep -Seconds 2
  }
  $elapsed = [int]((Get-Date) - $start).TotalSeconds

  Write-Host ""
  $ls = $lastStatus
  if ($null -eq $ls -or ("$ls").Trim().Length -eq 0) { $ls = "<none>" }
  Write-Host ("[FAIL] onec-server did not become healthy in {0}s. Last status: {1}" -f $elapsed, $ls)
  Write-Host "[DIAG] VM docker status:"
  $ec = 0
  (Ssh-RunAny $remote $identityFile 'sudo -n docker ps --format "{{.Names}}\t{{.Status}}" | grep -E "onec-(server|postgres)" || true' ([ref]$ec)) | Out-Host

  Write-Host "[DIAG] onec-server health log (docker inspect):"
  (Ssh-RunAny $remote $identityFile 'sudo -n docker inspect --format "{{range .State.Health.Log}}{{.Start}} exit={{.ExitCode}} {{printf \"%.200s\" .Output}}{{\"\\n\"}}{{end}}" onec-server 2>/dev/null || true' ([ref]$ec)) | Out-Host

  Write-Host "[DIAG] onec-server logs (tail 200):"
  (Ssh-RunAny $remote $identityFile 'sudo -n docker logs --tail 200 onec-server 2>&1 || true' ([ref]$ec)) | Out-Host

  Write-Host "[DIAG] VM listening ports (1540/1541/1545):"
  (Ssh-RunAny $remote $identityFile 'sudo -n ss -ltnp | grep -E ":(1540|1541|1545)\\b" || true' ([ref]$ec)) | Out-Host

  throw "onec-server did not become healthy in ${elapsed}s. See diagnostics above."
}

function Test-TcpPortFast([string]$targetHost, [int]$port, [int]$timeoutMs = 700) {
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
      $ar = $client.BeginConnect($targetHost, $port, $null, $null)
      if (-not $ar.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
        return $false
      }
      $client.EndConnect($ar) | Out-Null
      return $true
    } finally {
      $client.Close()
    }
  } catch {
    return $false
  }
}

function Get-VmStatus([string]$vmName) {
  try {
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { return $null }
    return (Get-VM -Name $vmName -ErrorAction SilentlyContinue)
  } catch {
    return $null
  }
}

function Format-ObservedIps([string[]]$ips) {
  if (-not $ips -or $ips.Count -eq 0) { return "<none>" }
  return ($ips -join ",")
}

# Wait for SSH to become available.
# Returns the IP/host that actually responded (can differ from targetHost if VM got DHCP).
function Wait-Ssh([string]$vmName, [string]$targetHost, [int]$timeoutSec) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  $start = Get-Date
  $lastReport = Get-Date
  $lastState = ""
  $lastCheckpoint = Get-Date
  $progressId = 2
  $runId = "run1"
  while ((Get-Date) -lt $deadline) {
    try {
      # First wait for TCP/22 to be reachable to avoid ssh hanging on connect.
      # If targetHost is a placeholder, skip direct TCP check and rely on DHCP discovery.
      $tcpOk = $false
      if ($targetHost -and $targetHost -ne "0.0.0.0") {
        $tcpOk = Test-TcpPortFast $targetHost 22 700
      }
      if (-not $tcpOk) {
        # If target host isn't reachable yet, try to discover current DHCP IPv4 by MAC.
        $dhcpIp = Get-VmDhcpIpv4 $vmName
        $state = "tcp:down"
        $elapsed = [int]((Get-Date) - $start).TotalSeconds
        $obs = Format-ObservedIps (Get-ObservedVmIpv4s $vmName)
        $status = ("{0} | elapsed={1}s | target={2} | observed={3}" -f $state, $elapsed, $targetHost, $obs)
        Write-Progress -Id $progressId -Activity "Waiting for SSH" -Status $status
        if ($state -ne $lastState -or ((Get-Date) - $lastReport).TotalSeconds -ge 20) {
          # Rare line output; main status is Write-Progress to avoid spam.
          if (((Get-Date) - $lastCheckpoint).TotalSeconds -ge 60) {
            Write-Host ("[WAIT] Waiting for SSH: {0}" -f $status)
            $lastCheckpoint = Get-Date
          }
          #region agent log B
          Write-DebugNdjson $script:repoRoot $runId "B" "SmokeTest-OnecInfra.ps1:Wait-Ssh" "ssh wait tcp down" @{
            elapsed_s = $elapsed
            target = $targetHost
            observed = $obs
            dhcp_ip_by_mac = $dhcpIp
          }
          #endregion
          $lastReport = Get-Date
          $lastState = $state
        }

        $idFile = $env:ONEC_SSH_IDENTITY_FILE

        # If DHCP IP is known, try it as a fallback immediately.
        if ($dhcpIp -and ($dhcpIp -ne $targetHost)) {
          if (Test-TcpPortFast $dhcpIp 22 700) {
            $args = @(
              "-o", "BatchMode=yes",
              "-o", "ConnectTimeout=3",
              "-o", "ConnectionAttempts=1",
              "-o", "StrictHostKeyChecking=no",
              "-o", "UserKnownHostsFile=/dev/null",
              "-o", "LogLevel=ERROR",
              "-o", "PreferredAuthentications=publickey",
              "-o", "IdentitiesOnly=yes",
              "-i", $idFile,
              "sandbox@$dhcpIp",
              "echo ok"
            )
            & ssh @args 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
              Write-Progress -Id $progressId -Activity "Waiting for SSH" -Completed
              Write-Host ("[INFO] Using DHCP IPv4 discovered by MAC: {0}" -f $dhcpIp)
              #region agent log B
              Write-DebugNdjson $script:repoRoot $runId "B" "SmokeTest-OnecInfra.ps1:Wait-Ssh" "ssh ok via dhcp ip" @{
                dhcp_ip_by_mac = $dhcpIp
              }
              #endregion
              return $dhcpIp
            }
          }
        }
        Start-Sleep -Seconds 2
        continue
      }

      # Deterministic SSH probe: never prompt, short timeouts.
      $idFile = $env:ONEC_SSH_IDENTITY_FILE
      $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=3",
        "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "PreferredAuthentications=publickey",
        "-o", "IdentitiesOnly=yes",
        "-i", $idFile,
        "sandbox@$targetHost",
        "echo ok"
      )

      $probe = Invoke-SshProbe $args 5000
      $sshOk = [bool]$probe.ok
      $state = if ($sshOk) { "ssh:ok" } elseif ($probe.timed_out) { "ssh:hang" } else { "ssh:fail" }
      $elapsed = [int]((Get-Date) - $start).TotalSeconds
      # Avoid Hyper-V/WMI calls here: they can stall and make progress look "frozen".
      $status = ("{0} | elapsed={1}s | target={2} | observed=<none>" -f $state, $elapsed, $targetHost)
      Write-Progress -Id $progressId -Activity "Waiting for SSH" -Status $status
      if ($state -ne $lastState -or ((Get-Date) - $lastReport).TotalSeconds -ge 20) {
        if (((Get-Date) - $lastCheckpoint).TotalSeconds -ge 60) {
          Write-Host ("[WAIT] Waiting for SSH: {0}" -f $status)
          $lastCheckpoint = Get-Date
        }
        #region agent log B
        Write-DebugNdjson $script:repoRoot $runId "B" "SmokeTest-OnecInfra.ps1:Wait-Ssh" "ssh wait probe" @{
          elapsed_s = $elapsed
          target = $targetHost
          observed = $obs
          ssh_ok = $sshOk
        }
        #endregion
        $lastReport = Get-Date
        $lastState = $state
      }
      if ($sshOk) {
        Write-Progress -Id $progressId -Activity "Waiting for SSH" -Completed
        return $targetHost
      }
    } catch {}
    Start-Sleep -Seconds 3
  }
  Write-Progress -Id $progressId -Activity "Waiting for SSH" -Completed
  throw "SSH is not available on $targetHost after $timeoutSec seconds."
}

function Get-ObservedVmIpv4([string]$vmName) {
  try {
    if (-not (Get-Command Get-VMNetworkAdapter -ErrorAction SilentlyContinue)) { return $null }
    $ad = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $ad) { return $null }

    foreach ($ip in @($ad.IPAddresses)) {
      if (-not $ip) { continue }
      if ($ip -match "^\d{1,3}(\.\d{1,3}){3}$") {
        if ($ip -like "169.254.*" -or $ip -like "127.*") { continue }
        return $ip
      }
    }
  } catch {}
  return $null
}

function Get-ObservedVmIpv4s([string]$vmName) {
  $ips = @()
  try {
    if (-not (Get-Command Get-VMNetworkAdapter -ErrorAction SilentlyContinue)) { return @() }
    $ad = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $ad) { return @() }
    foreach ($ip in @($ad.IPAddresses)) {
      if (-not $ip) { continue }
      if ($ip -match "^\d{1,3}(\.\d{1,3}){3}$") {
        if ($ip -like "169.254.*" -or $ip -like "127.*") { continue }
        $ips += $ip
      }
    }
  } catch {}
  return ($ips | Select-Object -Unique)
}

function Read-InfobaseNames([string]$repoRoot, [string]$path) {
  $p = $path
  if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $repoRoot $path }
  if (-not (Test-Path $p)) { return @() }
  $json = Get-Content $p -Raw
  $arr = $json | ConvertFrom-Json
  $names = @()
  foreach ($x in $arr) {
    if ($null -ne $x.name -and "$($x.name)".Trim().Length -gt 0) { $names += "$($x.name)" }
  }
  return $names
}

$repoRoot = Repo-Root
$script:repoRoot = $repoRoot

$envPath = $EnvFile
if (-not [System.IO.Path]::IsPathRooted($envPath)) { $envPath = Join-Path $repoRoot $EnvFile }
$envMap = Load-DotEnv $envPath

function Test-Truthy([string]$v) {
  if (-not $v) { return $false }
  return ($v.Trim().ToLowerInvariant() -in @("1","true","yes","y","on"))
}

function Require-File([string]$path, [string]$label, [switch]$NonEmpty) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw ("Missing required file: {0} ({1})" -f $path, $label)
  }
  if ($NonEmpty) {
    $len = 0
    try { $len = (Get-Item -LiteralPath $path).Length } catch { $len = 0 }
    if ($len -le 0) {
      throw ("Required file is empty: {0} ({1})" -f $path, $label)
    }
  }
}

function Has-LocalInstaller([string]$repoRoot) {
  # Used by onec-server Dockerfile downloader stage:
  # it checks .devcontainer/distr for setup-full-*.run.
  try {
    $d = Join-Path $repoRoot ".devcontainer\\distr"
    if (-not (Test-Path -LiteralPath $d)) { return $false }
    $any = Get-ChildItem -LiteralPath $d -File -Filter "setup-full-*.run" -ErrorAction SilentlyContinue | Select-Object -First 1
    return ($null -ne $any)
  } catch {
    return $false
  }
}

# Generate/refresh secrets from secrets/.env (idempotent), then run preflight checks.
function Prepare-Secrets([string]$repoRoot) {
  $prepare = Join-Path $repoRoot "scripts\\prepare-secrets.ps1"
  if (-not (Test-Path -LiteralPath $prepare)) {
    throw "Missing script: $prepare"
  }
  # This script writes raw UTF-8 bytes (no BOM/newline) to secrets/*.
  & $prepare -EnvFile "secrets/.env" -SecretsDir "secrets" | Out-Host
}

# --- Secrets preflight (fail fast) ---
$secretsDir = Join-Path $repoRoot "secrets"
$pgPasswordPath = Join-Path $secretsDir "pg_password"
$devLoginPath = Join-Path $secretsDir "dev_login"
$devPasswordPath = Join-Path $secretsDir "dev_password"
$onecUserPath = Join-Path $secretsDir "onec_username"
$onecPassPath = Join-Path $secretsDir "onec_password"

# Generate secrets first so smoke test can be started from a single entrypoint.
Prepare-Secrets $repoRoot

# PG_PASSWORD is critical always (used by Postgres + infobase creation).
Require-File $pgPasswordPath "Postgres password secret" -NonEmpty

# These files are referenced by compose; keep them present. Content may be empty depending on scenario.
Require-File $devLoginPath "developer.1c.ru login secret (may be empty if activation is disabled)"
Require-File $devPasswordPath "developer.1c.ru password secret (may be empty if activation is disabled)"
Require-File $onecUserPath "releases.1c.ru login secret (may be empty if local installer exists)"
Require-File $onecPassPath "releases.1c.ru password secret (may be empty if local installer exists)"

$needActivation = $false
if ($EnableCommunityActivation) { $needActivation = $true }
if (-not $needActivation -and (Test-Truthy $envMap["ENABLE_COMMUNITY_ACTIVATION"])) { $needActivation = $true }

$devLen1 = 0
$devLen2 = 0
try { $devLen1 = (Get-Item -LiteralPath $devLoginPath).Length } catch {}
try { $devLen2 = (Get-Item -LiteralPath $devPasswordPath).Length } catch {}
if ($needActivation -or ($devLen1 -gt 0) -or ($devLen2 -gt 0)) {
  if ($devLen1 -le 0 -or $devLen2 -le 0) {
    throw "Community activation requires non-empty secrets/dev_login and secrets/dev_password (or disable activation)."
  }
}

$hasInstaller = Has-LocalInstaller $repoRoot
if (-not $hasInstaller) {
  $len1 = (Get-Item -LiteralPath $onecUserPath).Length
  $len2 = (Get-Item -LiteralPath $onecPassPath).Length
  if ($len1 -le 0 -or $len2 -le 0) {
    throw "Local 1C installer is not found in .devcontainer/distr (setup-full-*.run). Need non-empty secrets/onec_username and secrets/onec_password to download from releases.1c.ru."
  }
}

Require-Admin
Require-Cmd ssh
Require-Cmd scp
Require-Cmd tar

$NetAdapterName = Coalesce $NetAdapterName $envMap["NET_ADAPTER_NAME"]
$VmName = Coalesce $VmName $envMap["VM_NAME"]
$SwitchName = Coalesce $SwitchName $envMap["SWITCH_NAME"]
$NetIface = Coalesce $NetIface (Coalesce $envMap["NET_IFACE"] "eth0")
$MgmtVmIp = Coalesce $envMap["MGMT_VM_IP"] "192.168.250.2"
$RemoteDir = Coalesce $RemoteDir (Coalesce $envMap["REMOTE_DIR"] "/opt/onec-sandbox")
$SshWaitSeconds = CoalesceInt $SshWaitSeconds $envMap["SSH_WAIT_SECONDS"]
  $ubuntuVhdPath = $envMap["UBUNTU_VHD_PATH"]
  $ubuntuIsoUrl = $envMap["UBUNTU_ISO_URL"]
  $ubuntuIsoPath = $envMap["UBUNTU_ISO_PATH"]
  $osDiskGb = 0
  if ($envMap["OS_DISK_GB"]) { $osDiskGb = [int]$envMap["OS_DISK_GB"] }
  $forceRecreate = $false
  if ($envMap["FORCE_RECREATE_VM"] -and $envMap["FORCE_RECREATE_VM"].ToLowerInvariant() -in @("1","true","yes")) {
    $forceRecreate = $true
  }

if (-not $KeepVm -and ($envMap["KEEP_VM"] -and $envMap["KEEP_VM"].ToLowerInvariant() -in @("1","true","yes"))) {
  $KeepVm = $true
}

foreach ($req in @(
  @{Name="NET_ADAPTER_NAME"; Value=$NetAdapterName},
  @{Name="VM_NAME"; Value=$VmName},
  @{Name="SWITCH_NAME"; Value=$SwitchName}
)) {
  if (-not $req.Value -or $req.Value.Trim().Length -eq 0 -or $req.Value -eq "0") {
    throw "Missing required parameter: $($req.Name). Set it in $EnvFile or pass via CLI."
  }
}

$newVmScript = Join-Path $repoRoot "scripts\\hyperv\\New-OnecInfraVm.ps1"
$deployScript = Join-Path $repoRoot "scripts\\hyperv\\Deploy-OnecInfra.ps1"
$diagScript = Join-Path $repoRoot "scripts\\tests\\Diag-OnecInfraVm.ps1"

# Repo-managed SSH key (generated by New-OnecInfraVm.ps1 when user has no keys)
$sshKeyPath = Join-Path (Join-Path $repoRoot ".cache\\hyperv") ("_ssh\\{0}\\id_ed25519" -f $VmName)

if (-not (Test-Path $newVmScript)) { throw "Missing script: $newVmScript" }
if (-not (Test-Path $deployScript)) { throw "Missing script: $deployScript" }

Write-Host "[STEP] Creating VM (Hyper-V) ..."
Write-Host ("      VM_NAME={0} SWITCH={1} ADAPTER={2} FORCE_RECREATE_VM={3}" -f $VmName,$SwitchName,$NetAdapterName,$forceRecreate)

$isAutoinstall = $false
if (-not ($ubuntuVhdPath -and $ubuntuVhdPath.Trim().Length -gt 0)) {
  if (($ubuntuIsoPath -and $ubuntuIsoPath.Trim().Length -gt 0) -or ($ubuntuIsoUrl -and $ubuntuIsoUrl.Trim().Length -gt 0)) {
    $isAutoinstall = $true
  }
}
if ($isAutoinstall) {
  Write-Host "[INFO] Autoinstall mode: first boot is OS installation."
  Write-Host "       Monitor progress via Hyper-V VMConnect console (Subiquity installer)."
}

# If we're going to recreate the VM, remove the existing one BEFORE checking IP-in-use.
# Otherwise this script fails early on the IP check even though the old VM is the reason the IP is "in use".
$existingVm = Get-VmStatus $VmName
if ($existingVm -and $forceRecreate) {
  Write-Host ("[INFO] VM '{0}' already exists and FORCE_RECREATE_VM=true. Removing it before IP pre-flight..." -f $VmName)
  try { Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
  try { Remove-VM -Name $VmName -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
  Start-Sleep -Seconds 2
}

$vmParams = @{
  VmName = $VmName
  SwitchName = $SwitchName
  NetAdapterName = $NetAdapterName
  NetIface = $NetIface
  ForceRecreate = $forceRecreate
}

# Only pass optional params when explicitly set; otherwise keep callee defaults.
if ($ubuntuVhdPath -and $ubuntuVhdPath.Trim().Length -gt 0) { $vmParams["UbuntuVhdPath"] = $ubuntuVhdPath }
if ($ubuntuIsoUrl -and $ubuntuIsoUrl.Trim().Length -gt 0) { $vmParams["UbuntuIsoUrl"] = $ubuntuIsoUrl }
if ($ubuntuIsoPath -and $ubuntuIsoPath.Trim().Length -gt 0) { $vmParams["UbuntuIsoPath"] = $ubuntuIsoPath }
if ($osDiskGb -gt 0) { $vmParams["OsDiskGB"] = $osDiskGb }

& $newVmScript @vmParams | Out-Null

Write-Host "[STEP] Hyper-V adapter snapshot ..."
try {
  if (Get-Command Get-VMNetworkAdapter -ErrorAction SilentlyContinue) {
    Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue |
      Select-Object Name, MacAddress, SwitchName, Status, IPAddresses |
      Format-List
  } else {
    Write-Host "Get-VMNetworkAdapter not available."
  }
} catch {
  Write-Host ("Get-VMNetworkAdapter failed: {0}" -f $_.Exception.Message)
}

 $observedIps = Get-ObservedVmIpv4s $VmName
 if ($observedIps.Count -gt 0) {
   $obs = ($observedIps -join ", ")
   Write-Host ("[INFO] VM reported IPv4(s): {0}" -f $obs)
 }

Write-Host "[STEP] Waiting for SSH (mgmt IP) ..."
try {
  # Prefer mgmt IP; use explicit identity file to avoid relying on user ssh-agent/keys.
  $env:ONEC_SSH_IDENTITY_FILE = $sshKeyPath
  $actualIp = Wait-Ssh $VmName $MgmtVmIp $SshWaitSeconds
  if (-not $actualIp) { throw "Cannot determine VM IP for SSH." }
  Write-Host ("[INFO] Using VM management IP {0}" -f $actualIp)
  $VmIp = $actualIp
} catch {
  Write-Host ""
  Write-Host "[FAIL] SSH wait timed out. Auto-diagnostics:"
  if ($VmIp) {
    Write-Host ("- ping {0}" -f $VmIp)
    ping -n 1 $VmIp | Out-Host
    Write-Host ("- Test-NetConnection {0}:22" -f $VmIp)
    Test-NetConnection -ComputerName $VmIp -Port 22 | Select-Object ComputerName, RemotePort, TcpTestSucceeded | Format-Table -AutoSize
    Write-Host "- ARP:"
    arp -a | Select-String -SimpleMatch $VmIp | ForEach-Object { $_.Line } | Out-Host
  }

  if (Test-Path $diagScript) {
    Write-Host ""
    Write-Host ("- Running {0} ..." -f $diagScript)
    & $diagScript -EnvFile $EnvFile | Out-Host
  }

  Write-Host ""
  Write-Host "Next checks inside VM console:"
  Write-Host "- cloud-init status --long"
  Write-Host "- ip a; ip r"
  Write-Host "- systemctl status ssh --no-pager"
  if ($VmIp -and $observedIps.Count -gt 0 -and ($observedIps -notcontains $VmIp)) {
    Write-Host ""
    Write-Host ("VM currently reports IPv4(s): {0}. Try SSH to inspect:" -f ($observedIps -join ", "))
    foreach ($ip in $observedIps) {
      Write-Host ("- ssh sandbox@{0}" -f $ip)
    }
  }
  throw
}

Write-Host "[STEP] Deploying repo to VM and starting infra ..."
& $deployScript -VmIp $VmIp -RemoteDir $RemoteDir -InfobasesJsonPath $InfobasesJsonPath -SshIdentityFile $sshKeyPath | Out-Null

Write-Host "[STEP] Waiting for onec-server to become healthy ..."
$remote = "sandbox@$VmIp"
Wait-OnecServerHealthy $remote $sshKeyPath 1200

Write-Host "[STEP] Checking ports (TCP) ..."
$ports = @(22,1540,1541,1545,5432)
$failed = @()
foreach ($p in $ports) {
  if (-not (Test-Port $VmIp $p)) { $failed += $p }
}
if ($failed.Count -gt 0) { throw "Ports not reachable on ${VmIp}: $($failed -join ', ')" }

Write-Host "[STEP] Checking services inside VM ..."
$psOut = Ssh-Run $remote $sshKeyPath 'sudo -n docker ps --format "{{.Names}} {{.Status}}"'
if (-not $psOut) { throw "docker ps failed on VM (SSH) or returned empty output." }

Write-Host "[STEP] Checking 1C cluster via rac/ras ..."
$clusterOut = Ssh-Run $remote $sshKeyPath "sudo -n docker exec -i onec-server /opt/1cv8/current/rac cluster list 127.0.0.1:1545 2>&1"
if (-not $clusterOut) { throw "rac cluster list returned empty output" }

$clusterId = ($clusterOut | Select-String -Pattern "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" | Select-Object -First 1).Matches.Value
if (-not $clusterId) { throw "Cannot parse cluster id from rac output" }

$names = Read-InfobaseNames $repoRoot $InfobasesJsonPath
if ($names.Count -gt 0) {
  Write-Host "[STEP] Checking infobases registration ..."
  $ibOut = Ssh-Run $remote $sshKeyPath "sudo -n docker exec -i onec-server /opt/1cv8/current/rac infobase summary list 127.0.0.1:1545 --cluster=$clusterId 2>&1"
  foreach ($n in $names) {
    if ($ibOut -notmatch [Regex]::Escape($n)) {
      throw "Infobase '$n' not found in cluster summary."
    }
  }
}

Write-Host "[PASS] Smoke test completed."
Write-Host "       VM: $VmName ($VmIp)"
Write-Host "       Ports OK: 1540,1541,1545,5432"

if (-not $KeepVm) {
  Write-Host "[STEP] Removing VM (cleanup) ..."
  Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-VM -Name $VmName -Force -ErrorAction SilentlyContinue | Out-Null
}

