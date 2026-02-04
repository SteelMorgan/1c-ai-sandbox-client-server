param(
  [string]$EnvFile = "infra/vm/.env"
)

$ErrorActionPreference = "Stop"

function Repo-Root {
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

$root = Repo-Root
$envPath = $EnvFile
if (-not [System.IO.Path]::IsPathRooted($envPath)) { $envPath = Join-Path $root $EnvFile }
$envMap = Load-DotEnv $envPath

$vmName = $envMap["VM_NAME"]
$vmIp = $envMap["VM_IP"]
$switchName = $envMap["SWITCH_NAME"]
$adapterName = $envMap["NET_ADAPTER_NAME"]
$mgmtSwitchName = $envMap["MGMT_SWITCH_NAME"]
$mgmtHostIp = $envMap["MGMT_HOST_IP"]

Write-Host "VM_NAME=$vmName"
Write-Host "VM_IP=$vmIp"
Write-Host "SWITCH_NAME=$switchName"
Write-Host "NET_ADAPTER_NAME=$adapterName"
Write-Host ""

Write-Host "== Host network =="
Get-NetAdapter -Physical | Select-Object Name, Status, MacAddress, LinkSpeed | Format-Table -AutoSize
Write-Host ""

Write-Host "== Host IPv4 (selected adapter + vSwitch) =="
if ($adapterName) {
  try {
    Write-Host ("Adapter '{0}' IPv4:" -f $adapterName)
    Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Select-Object InterfaceAlias, IPAddress, PrefixLength |
      Format-Table -AutoSize
  } catch {
    Write-Host ("Get-NetIPAddress failed for adapter '{0}': {1}" -f $adapterName, $_.Exception.Message)
  }
}
if ($switchName) {
  $vEth = "vEthernet ($switchName)"
  try {
    Write-Host ("{0} IPv4:" -f $vEth)
    Get-NetIPAddress -InterfaceAlias $vEth -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Select-Object InterfaceAlias, IPAddress, PrefixLength |
      Format-Table -AutoSize
  } catch {
    Write-Host ("Get-NetIPAddress failed for '{0}': {1}" -f $vEth, $_.Exception.Message)
  }
}
if ($mgmtSwitchName) {
  $vEth2 = "vEthernet ($mgmtSwitchName)"
  try {
    Write-Host ("{0} IPv4 (mgmt):" -f $vEth2)
    Get-NetIPAddress -InterfaceAlias $vEth2 -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Select-Object InterfaceAlias, IPAddress, PrefixLength |
      Format-Table -AutoSize
  } catch {
    Write-Host ("Get-NetIPAddress failed for '{0}': {1}" -f $vEth2, $_.Exception.Message)
  }
  if ($mgmtHostIp) {
    Write-Host ("Expected mgmt host IP: {0}" -f $mgmtHostIp)
  }
}
try {
  Write-Host "Default route:"
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric |
    Select-Object -First 5 |
    Select-Object InterfaceAlias, NextHop, RouteMetric |
    Format-Table -AutoSize
} catch {}
Write-Host ""

Write-Host "== Hyper-V objects =="
try {
  if (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue) {
    Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue |
      Select-Object Name, SwitchType, NetAdapterInterfaceDescription |
      Format-Table -AutoSize
  } else {
    Write-Host "Get-VMSwitch not available in this session."
  }
} catch {
  Write-Host ("Get-VMSwitch failed: {0}" -f $_.Exception.Message)
}

$observedIps = @()
try {
  if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
    Get-VM -Name $vmName -ErrorAction SilentlyContinue |
      Select-Object Name, State, Uptime |
      Format-Table -AutoSize
  } else {
    Write-Host "Get-VM not available in this session."
  }
} catch {
  Write-Host ("Get-VM failed: {0}" -f $_.Exception.Message)
}

try {
  if (Get-Command Get-VMNetworkAdapter -ErrorAction SilentlyContinue) {
    $ad = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 1
    $ad |
      Select-Object Name, MacAddress, SwitchName, Status, IPAddresses |
      Format-List

    if ($null -ne $ad) {
      foreach ($ip in @($ad.IPAddresses)) {
        if ($ip -match "^\d{1,3}(\.\d{1,3}){3}$" -and $ip -notlike "169.254.*" -and $ip -notlike "127.*") {
          $observedIps += $ip
        }
      }
    }
  } else {
    Write-Host "Get-VMNetworkAdapter not available in this session."
  }
} catch {
  Write-Host ("Get-VMNetworkAdapter failed: {0}" -f $_.Exception.Message)
}
Write-Host ""

Write-Host "== Connectivity =="
if ($vmIp) {
  Write-Host ("ping {0}" -f $vmIp)
  ping -n 1 $vmIp | Out-Host
  Write-Host ("Test-NetConnection {0}:22" -f $vmIp)
  Test-NetConnection -ComputerName $vmIp -Port 22 | Select-Object ComputerName, RemotePort, TcpTestSucceeded | Format-Table -AutoSize
  Write-Host "ARP:"
  arp -a | Select-String -SimpleMatch $vmIp | ForEach-Object { $_.Line } | Out-Host
} else {
  Write-Host "VM_IP is not set (DHCP mode). Use SmokeTest to discover IP by MAC, or check router/ARP table."
}

if ($observedIps.Count -gt 0) {
  Write-Host ""
  Write-Host "== Observed VM IPv4 from Hyper-V =="
  foreach ($ip in ($observedIps | Select-Object -Unique)) {
    if ($vmIp -and $ip -eq $vmIp) { continue }
    Write-Host ("ping {0}" -f $ip)
    ping -n 1 $ip | Out-Host
    Write-Host ("Test-NetConnection {0}:22" -f $ip)
    Test-NetConnection -ComputerName $ip -Port 22 | Select-Object ComputerName, RemotePort, TcpTestSucceeded | Format-Table -AutoSize
    Write-Host "ARP:"
    arp -a | Select-String -SimpleMatch $ip | ForEach-Object { $_.Line } | Out-Host
    Write-Host ""
  }
}

Write-Host ""
Write-Host "== Notes =="
Write-Host "- If Hyper-V objects section is empty: run this script from Administrator PowerShell to see VM IPAddresses/MAC."
Write-Host "- If ping shows 'Destination host unreachable' from your host IP: VM is not reachable at VM_IP (no ARP/route)."
Write-Host "- If VM reports a different IPv4 (Observed VM IPv4): your static VM_IP isn't applied yet (cloud-init/netplan)."

