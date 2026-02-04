param(
  [string]$VmName = "onec-infra",
  [string]$SwitchName = "onec-external",
  [Parameter(Mandatory=$true)]
  [string]$NetAdapterName,

  # Network:
  # We intentionally default to DHCP and discover the resulting IP by MAC from the host.
  # Static IP is optional and not required for smoke/deploy flow.
  [string]$VmIp = "",
  [int]$PrefixLength = 0,
  [string]$Gateway = "",
  [string]$Dns1 = "",
  [string]$Dns2 = "",
  [string]$NetIface = "eth0",

  # Internal management network (host<->VM), to avoid relying on router/DHCP DNS for provisioning.
  [string]$MgmtSwitchName = "onec-mgmt",
  [string]$MgmtHostIp = "192.168.250.1",
  [string]$MgmtVmIp = "192.168.250.2",
  [int]$MgmtPrefixLength = 24,

  [string]$SshPublicKeyPath = "",

  [int]$CpuCount = 4,
  [int]$MemoryGB = 8,

  [switch]$ForceRecreate,

  # Optional: path to a local base image (.vhd or .vhdx) prepared for Hyper-V Gen2.
  # Recommended for local infra: install Ubuntu Server from ISO once, enable OpenSSH,
  # then reuse that VHDX as a "golden image" (more predictable than cloud/azure images).
  [string]$UbuntuVhdPath = "",

  # Autoinstall (recommended): download Ubuntu Server ISO and install into a fresh VHDX.
  # Requires WSL + xorriso to build a custom ISO with embedded NoCloud data and kernel params.
  [string]$UbuntuIsoUrl = "https://releases.ubuntu.com/24.04/ubuntu-24.04.3-live-server-amd64.iso",
  [string]$UbuntuIsoPath = "",
  # 1C images are large; keep a generous default to avoid docker build failures.
  [int]$OsDiskGB = 200,

  [string]$UbuntuVhdTarUrl = "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz"
)

$ErrorActionPreference = "Stop"

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
    $json = ($obj | ConvertTo-Json -Depth 10 -Compress)
    [System.IO.File]::AppendAllText($logPath, $json + "`n", $utf8bom)
  } catch {}
}

function Write-AgentDebugLog([string]$repoRoot, [string]$runId, [string]$hypothesisId, [string]$location, [string]$message, $data) {
  # Legacy debug logger from previous sessions.
  # It used to write into `.cursor/debug.log` on disk (noisy + breaks deterministic runs).
  # Intentionally disabled; keep a stub to avoid touching dozens of call sites.
  return
}

function Require-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    throw "Run PowerShell as Administrator."
  }
}

function Ensure-HyperV {
  if (-not (Get-Command -Name Get-VM -ErrorAction SilentlyContinue)) {
    throw "Hyper-V PowerShell module not available. Enable Hyper-V feature and reboot."
  }
  if (-not (Get-Command -Name Convert-VHD -ErrorAction SilentlyContinue)) {
    throw "Convert-VHD is not available. Make sure Hyper-V management tools are installed."
  }
}

function Remove-DirFast([string]$path) {
  if (-not $path) { return }
  try {
    if (-not (Test-Path -LiteralPath $path)) { return }
    $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
    # Safety: never allow deleting drive roots.
    if ($resolved -match '^[A-Za-z]:\\?$') { throw "Refusing to delete drive root: $resolved" }
    # Use native rmdir: faster and does not emit PowerShell progress.
    & cmd /c "rmdir /s /q ""$resolved""" | Out-Null
  } catch {
    # Fallback: best-effort PowerShell delete (should be rare).
    try { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue } catch {}
  }
}

function Ensure-ExternalSwitch([string]$name, [string]$adapter) {
  $existing = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
  if ($null -ne $existing) {
    # Validate that the existing switch matches the requested physical adapter.
    # This avoids a silent footgun where SWITCH_NAME already exists but is bound to a different NIC.
    if ($existing.SwitchType -ne "External") {
      throw "VMSwitch '$name' already exists but is not External (type=$($existing.SwitchType)). Delete/rename it or set SWITCH_NAME to a different value."
    }

    $na = Get-NetAdapter -Name $adapter -ErrorAction SilentlyContinue
    if ($null -eq $na) {
      $avail = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
      $hint = ""
      if ($avail) { $hint = "Available physical adapters: " + ($avail -join ", ") }
      throw "Physical network adapter '$adapter' not found. Set -NetAdapterName to an existing adapter name. $hint"
    }

    $wantDesc = $na.InterfaceDescription
    $haveDesc = $existing.NetAdapterInterfaceDescription
    if ($haveDesc -and $wantDesc -and ($haveDesc -ne $wantDesc)) {
      throw "VMSwitch '$name' is bound to a different adapter. Requested='$adapter' ('$wantDesc'), existing switch bound to '$haveDesc'. Fix: delete the switch in Hyper-V Manager or change SWITCH_NAME to a new value."
    }

    if ($na.Status -ne "Up") {
      throw "Physical adapter '$adapter' status is '$($na.Status)'. External switch will not work until the adapter is Up."
    }

    return
  }
  $na = Get-NetAdapter -Name $adapter -ErrorAction SilentlyContinue
  if ($null -eq $na) {
    $avail = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    $hint = ""
    if ($avail) { $hint = "Available physical adapters: " + ($avail -join ", ") }
    throw "Physical network adapter '$adapter' not found. Set -NetAdapterName to an existing adapter name. $hint"
  }

  if ($na.Status -ne "Up") {
    throw "Physical adapter '$adapter' status is '$($na.Status)'. External switch will not work until the adapter is Up."
  }

  New-VMSwitch -Name $name -NetAdapterName $adapter -AllowManagementOS $true | Out-Null
}

function Ensure-InternalSwitch([string]$name, [string]$hostIp, [int]$prefixLength) {
  $existing = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
  if ($null -eq $existing) {
    New-VMSwitch -Name $name -SwitchType Internal | Out-Null
  } elseif ($existing.SwitchType -ne "Internal") {
    throw "VMSwitch '$name' already exists but is not Internal (type=$($existing.SwitchType)). Delete/rename it or change MgmtSwitchName."
  }

  # Ensure host vEthernet has the desired IP.
  $vEth = "vEthernet ($name)"
  $have = @(Get-NetIPAddress -InterfaceAlias $vEth -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
  if ($have -notcontains $hostIp) {
    # Remove other IPv4s on this interface (best-effort).
    foreach ($ip in @(Get-NetIPAddress -InterfaceAlias $vEth -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
      try { Remove-NetIPAddress -InterfaceAlias $vEth -IPAddress $ip.IPAddress -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    New-NetIPAddress -InterfaceAlias $vEth -IPAddress $hostIp -PrefixLength $prefixLength -ErrorAction Stop | Out-Null
  }
}

function Compute-MacPair([string]$vmName, [string]$lanSwitchName, [string]$netIface, [string]$mgmtSwitchName) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $seedLan = [System.Text.Encoding]::UTF8.GetBytes(("{0}|lan|{1}|{2}" -f $vmName,$lanSwitchName,$netIface))
    $hashLan = $sha.ComputeHash($seedLan)
    $macDashLan = ("00-15-5D-{0:X2}-{1:X2}-{2:X2}" -f $hashLan[0], $hashLan[1], $hashLan[2])
    $macColonLan = $macDashLan.ToLowerInvariant().Replace("-", ":")

    $seedMgmt = [System.Text.Encoding]::UTF8.GetBytes(("{0}|mgmt|{1}" -f $vmName,$mgmtSwitchName))
    $hashMgmt = $sha.ComputeHash($seedMgmt)
    $macDashMgmt = ("00-15-5D-{0:X2}-{1:X2}-{2:X2}" -f $hashMgmt[0], $hashMgmt[1], $hashMgmt[2])
    $macColonMgmt = $macDashMgmt.ToLowerInvariant().Replace("-", ":")

    return [ordered]@{
      macDashLan = $macDashLan
      macColonLan = $macColonLan
      macDashMgmt = $macDashMgmt
      macColonMgmt = $macColonMgmt
    }
  } finally {
    $sha.Dispose()
  }
}

function Get-RepoRoot {
  $here = $script:PSScriptRoot
  if (-not $here) { $here = $PSScriptRoot }
  if (-not $here) { throw "Cannot determine script directory (PSScriptRoot is empty)." }
  return (Resolve-Path (Join-Path $here "..\\..")).Path
}

function Resolve-SshKey([string]$path) {
  if ($path -and (Test-Path $path)) { return (Resolve-Path $path).Path }
  $candidates = @(
    (Join-Path $env:USERPROFILE ".ssh\\id_ed25519.pub"),
    (Join-Path $env:USERPROFILE ".ssh\\id_rsa.pub")
  )
  foreach ($p in $candidates) { if (Test-Path $p) { return (Resolve-Path $p).Path } }
  return $null
}

function Ensure-RepoSshKeypair([string]$repoRoot, [string]$vmName) {
  # Create a dedicated keypair for this repo/VM under .cache (never committed).
  $sshDir = Join-Path (Join-Path $repoRoot ".cache\\hyperv") ("_ssh\\{0}" -f $vmName)
  New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
  $priv = Join-Path $sshDir "id_ed25519"
  $pub = Join-Path $sshDir "id_ed25519.pub"

  #region agent log K
  Write-DebugNdjson $repoRoot "run1" "K" "New-OnecInfraVm.ps1:Ensure-RepoSshKeypair" "ensure keypair (pre)" @{
    sshDir = $sshDir
    priv = $priv
    pub = $pub
    priv_exists = (Test-Path $priv)
    pub_exists = (Test-Path $pub)
    ssh_keygen = (Get-Command ssh-keygen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
  }
  #endregion

  if (-not (Test-Path $priv) -or -not (Test-Path $pub)) {
    if (-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
      throw "ssh-keygen not found. Install Windows OpenSSH Client, or provide -SshPublicKeyPath."
    }
    # If only one of the files exists, remove both to avoid ssh-keygen overwrite prompts.
    try { Remove-Item -Force $priv -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -Force $pub -ErrorAction SilentlyContinue } catch {}

    # Generate without passphrase (automation); quiet output.
    $out = & ssh-keygen -t ed25519 -f $priv -N "" -C ("onec-infra:{0}" -f $vmName) -q 2>&1
    $exit = $LASTEXITCODE
    #region agent log K
    Write-DebugNdjson $repoRoot "run1" "K" "New-OnecInfraVm.ps1:Ensure-RepoSshKeypair" "ssh-keygen finished" @{
      exit_code = $exit
      out_tail = ((@($out) -split "`r?`n" | Select-Object -Last 20) -join "`n")
      priv_exists = (Test-Path $priv)
      pub_exists = (Test-Path $pub)
    }
    #endregion
    if (-not (Test-Path $priv) -or -not (Test-Path $pub)) {
      throw "Failed to generate SSH keypair at $priv"
    }
  }

  return [ordered]@{
    PrivateKeyPath = $priv
    PublicKeyPath = $pub
  }
}

function Download-UbuntuVhd([string]$url, [string]$cacheDir) {
  New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
  $tarPath = Join-Path $cacheDir "ubuntu-24.04-azure.vhd.tar.gz"
  if (-not (Test-Path $tarPath)) {
    Invoke-WebRequest -Uri $url -OutFile $tarPath
  }

  $extractDir = Join-Path $cacheDir "extracted"
  if (-not (Test-Path $extractDir)) { New-Item -ItemType Directory -Force -Path $extractDir | Out-Null }

  $vhd = Get-ChildItem $extractDir -Filter "*.vhd" -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $vhd) {
    tar -xf $tarPath -C $extractDir
    $vhd = Get-ChildItem $extractDir -Filter "*.vhd" -File | Select-Object -First 1
  }
  if ($null -eq $vhd) { throw "Cannot find .vhd after extracting $tarPath" }
  return $vhd.FullName
}

function Download-UbuntuIso([string]$url, [string]$cacheDir) {
  New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
  $isoPath = Join-Path $cacheDir "ubuntu-24.04-live-server-amd64.iso"
  if (-not (Test-Path $isoPath)) {
    Invoke-WebRequest -Uri $url -OutFile $isoPath
  }
  return $isoPath
}

function Require-DockerCli {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI not found. Install Docker Desktop (required for autoinstall ISO builder) or provide -UbuntuVhdPath."
  }
  try {
    & docker version | Out-Null
  } catch {
    throw "Docker is not running or not accessible. Start Docker Desktop, then rerun."
  }
}

function Ensure-IsoBuilderImage([string]$repoRoot) {
  # Bump tag when Dockerfile changes (so we rebuild)
  $tag = "onec-autoinstall-iso-builder:24.04-v3"
  $inspectOut = & docker image inspect $tag 2>&1
  $inspectExit = $LASTEXITCODE
  #region agent log H4
  try {
    $lines = @()
    if ($inspectOut) { $lines = @($inspectOut -split "`r?`n") }
    $tail = if ($lines.Count -gt 10) { ($lines[($lines.Count-10)..($lines.Count-1)] -join "`n") } else { ($lines -join "`n") }
    Write-AgentDebugLog $repoRoot "run1" "H4" "New-OnecInfraVm.ps1:Ensure-IsoBuilderImage:inspect" "docker image inspect finished" @{
      Tag = $tag
      ExitCode = $inspectExit
      Tail = $tail
    }
  } catch {}
  #endregion
  if ($inspectExit -eq 0) {
    # Validate required tools exist inside the image; rebuild if not.
    $checkOut = & docker run --rm $tag "command -v mkfs.vfat >/dev/null 2>&1 && echo ok || echo missing" 2>&1
    $checkExit = $LASTEXITCODE
    #region agent log H4
    try {
      Write-AgentDebugLog $repoRoot "run1" "H4" "New-OnecInfraVm.ps1:Ensure-IsoBuilderImage:toolcheck" "image tool check" @{
        Tag = $tag
        ExitCode = $checkExit
        Output = ($checkOut -join "`n")
      }
    } catch {}
    #endregion
    if (($checkOut -join "`n") -match "\bok\b") { return $tag }
  }

  $dockerfile = Join-Path $repoRoot "scripts\\iso\\iso-builder.Dockerfile"
  if (-not (Test-Path $dockerfile)) { throw "Missing ISO builder Dockerfile: $dockerfile" }
  # Build the image and FAIL FAST on errors (otherwise later docker run will try to pull a non-existent image).
  $buildOut = & docker build -f $dockerfile -t $tag $repoRoot 2>&1
  $buildExit = $LASTEXITCODE
  #region agent log H4
  try {
    $lines = @()
    if ($buildOut) { $lines = @($buildOut -split "`r?`n") }
    $tail = if ($lines.Count -gt 30) { ($lines[($lines.Count-30)..($lines.Count-1)] -join "`n") } else { ($lines -join "`n") }
    Write-AgentDebugLog $repoRoot "run1" "H4" "New-OnecInfraVm.ps1:Ensure-IsoBuilderImage:build" "docker build finished" @{
      Tag = $tag
      ExitCode = $buildExit
      Tail = $tail
    }
  } catch {}
  #endregion
  if ($buildExit -ne 0) {
    $lines = @()
    if ($buildOut) { $lines = @($buildOut -split "`r?`n") }
    $tail = if ($lines.Count -gt 60) { ($lines[($lines.Count-60)..($lines.Count-1)] -join "`n") } else { ($lines -join "`n") }
    throw ("Failed to build ISO builder image '{0}' (docker build exit={1}). Last output:`n{2}" -f $tag, $buildExit, $tail)
  }
  return $tag
}

function Write-TextFileUtf8NoBom([string]$path, [string]$text) {
  $t = $text.Replace("`r`n", "`n")
  [System.IO.File]::WriteAllText($path, $t, (New-Object System.Text.UTF8Encoding($false)))
}

function Sha256-String([string]$text) {
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash($bytes)
  } finally {
    $sha.Dispose()
  }
  return ([System.BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

function Get-IsoBuildSignature([string]$repoRoot, [string]$baseIsoPath, [hashtable]$vars) {
  # Bump this when ISO patching logic changes.
  # It is included into the signature so cached ISOs get invalidated automatically.
  $builderVersion = 11

  $tmplDir = Join-Path $repoRoot "scripts\\cloud-init"
  $userDataTmpl = Join-Path $tmplDir "autoinstall-user-data.yaml"
  $metaDataTmpl = Join-Path $tmplDir "autoinstall-meta-data.yaml"

  $baseIsoAbs = (Resolve-Path $baseIsoPath).Path
  $baseIsoInfo = Get-Item $baseIsoAbs
  $ud = Get-Content $userDataTmpl -Raw
  $md = Get-Content $metaDataTmpl -Raw

  $sshKeyText = ""
  if ($vars.ContainsKey("__SSH_PUBLIC_KEY__") -and $vars["__SSH_PUBLIC_KEY__"]) {
    $sshKeyText = [string]$vars["__SSH_PUBLIC_KEY__"]
  }

  $sigObj = [ordered]@{
    builder = [ordered]@{
      version = $builderVersion
    }
    base_iso = [ordered]@{
      path = $baseIsoAbs
      length = [int64]$baseIsoInfo.Length
      last_write_utc = $baseIsoInfo.LastWriteTimeUtc.ToString("o")
    }
    templates = [ordered]@{
      autoinstall_user_data_sha256 = (Sha256-String $ud)
      autoinstall_meta_data_sha256 = (Sha256-String $md)
    }
    vars = [ordered]@{
      hostname = $vars["__HOSTNAME__"]
      instance_id = $vars["__INSTANCE_ID__"]
      mac_lan = $vars["__MAC_LAN__"]
      mac_mgmt = $vars["__MAC_MGMT__"]
      net_iface = $vars["__NET_IFACE__"]
      # Don't store the raw key; store a hash.
      ssh_public_key_sha256 = (Sha256-String $sshKeyText)
    }
  }

  $sigJson = ($sigObj | ConvertTo-Json -Depth 10 -Compress)
  return [ordered]@{
    signature = $sigObj
    signature_json = $sigJson
    signature_sha256 = (Sha256-String $sigJson)
  }
}

function Write-SeedFiles([string]$dir, [hashtable]$vars, [string]$userDataTemplatePath, [string]$metaDataTemplatePath) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $ud = Get-Content $userDataTemplatePath -Raw
  $md = Get-Content $metaDataTemplatePath -Raw
  $ud2 = Render-Template $ud $vars
  $md2 = Render-Template $md $vars
  # Write as UTF-8 without BOM (cloud-init expects plain UTF-8)
  [System.IO.File]::WriteAllText((Join-Path $dir "user-data"), $ud2, (New-Object System.Text.UTF8Encoding($false)))
  [System.IO.File]::WriteAllText((Join-Path $dir "meta-data"), $md2, (New-Object System.Text.UTF8Encoding($false)))
}

function Build-AutoinstallIso([string]$repoRoot, [string]$baseIsoPath, [string]$outIsoPath, [hashtable]$vars) {
  Require-DockerCli
  $image = Ensure-IsoBuilderImage $repoRoot
  $runId = "run1"
  $buildSucceeded = $false

  #region agent log H4
  Write-AgentDebugLog $repoRoot $runId "H4" "New-OnecInfraVm.ps1:Build-AutoinstallIso:entry" "Build-AutoinstallIso entry" @{
    BaseIsoPath = $baseIsoPath
    OutIsoPath = $outIsoPath
    ImageTag = $image
  }
  #endregion

  $tmplDir = Join-Path $repoRoot "scripts\\cloud-init"
  $userDataTmpl = Join-Path $tmplDir "autoinstall-user-data.yaml"
  $metaDataTmpl = Join-Path $tmplDir "autoinstall-meta-data.yaml"
  if (-not (Test-Path $userDataTmpl)) { throw "Missing autoinstall template: $userDataTmpl" }
  if (-not (Test-Path $metaDataTmpl)) { throw "Missing autoinstall template: $metaDataTmpl" }

  $sig = Get-IsoBuildSignature $repoRoot $baseIsoPath $vars
  $sigHash = $sig.signature_sha256
  $cacheRoot = Join-Path (Split-Path -Parent (Resolve-Path $baseIsoPath).Path) "_iso-cache"
  if (-not (Test-Path $cacheRoot)) { New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null }
  $cachedIso = Join-Path $cacheRoot ("ubuntu-autoinstall-{0}.iso" -f $sigHash)
  $cachedMeta = Join-Path $cacheRoot ("ubuntu-autoinstall-{0}.json" -f $sigHash)

  Write-Host ("[ISO] base={0}" -f (Resolve-Path $baseIsoPath).Path)
  Write-Host ("[ISO] signature_sha256={0}" -f $sigHash)
  Write-Host ("[ISO] cache_dir={0}" -f (Resolve-Path $cacheRoot).Path)

  #region agent log A
  Write-DebugNdjson $repoRoot $runId "A" "New-OnecInfraVm.ps1:Build-AutoinstallIso:sig" "iso signature computed" @{
    sig = $sigHash
    vars = @{
      hostname = $vars["__HOSTNAME__"]
      mac_lan = $vars["__MAC_LAN__"]
      mac_mgmt = $vars["__MAC_MGMT__"]
      net_iface = $vars["__NET_IFACE__"]
      ssh_key_sha256 = $sig.signature.vars.ssh_public_key_sha256
    }
  }
  #endregion

  if ((Test-Path $cachedIso) -and (Test-Path $cachedMeta)) {
    try {
      $meta = Get-Content $cachedMeta -Raw | ConvertFrom-Json
      if ($meta.signature_sha256 -eq $sigHash) {
        Write-Host ("[ISO] cache_hit=yes cached_iso={0}" -f $cachedIso)
        Copy-Item -Force $cachedIso $outIsoPath
        Write-Host ("[ISO] output_iso={0}" -f $outIsoPath)

        #region agent log H3
        Write-AgentDebugLog $repoRoot $runId "H3" "New-OnecInfraVm.ps1:Build-AutoinstallIso:cache-hit" "ISO cache hit" @{
          Sig = $sigHash
          CachedIso = $cachedIso
          OutIso = $outIsoPath
        }
        #endregion
        #region agent log A
        Write-DebugNdjson $repoRoot $runId "A" "New-OnecInfraVm.ps1:Build-AutoinstallIso:cache" "iso cache hit" @{
          sig = $sigHash
          cachedIso = $cachedIso
        }
        #endregion

        return
      }
    } catch {}
  }
  Write-Host "[ISO] cache_hit=no (building ISO via Docker/xorriso)"
  #region agent log A
  Write-DebugNdjson $repoRoot $runId "A" "New-OnecInfraVm.ps1:Build-AutoinstallIso:cache" "iso cache miss" @{
    sig = $sigHash
  }
  #endregion

  $outDir = [System.IO.Path]::GetDirectoryName($outIsoPath)
  # Avoid reusing a stale ISO if docker run fails.
  try { Remove-Item -Force $outIsoPath -ErrorAction SilentlyContinue } catch {}

  $workDir = Join-Path $outDir "iso-work"
  if (Test-Path $workDir) { Remove-DirFast $workDir }
  New-Item -ItemType Directory -Force -Path $workDir | Out-Null

  # Render autoinstall yaml. For ISO-root autoinstall.yaml we must NOT include the "#cloud-config" header.
  $udRaw = Get-Content $userDataTmpl -Raw
  $mdRaw = Get-Content $metaDataTmpl -Raw
  $udRendered = Render-Template $udRaw $vars
  $mdRendered = Render-Template $mdRaw $vars
  $udLines = $udRendered -split "`r?`n"
  $start = 0
  for ($i = 0; $i -lt $udLines.Length; $i++) {
    if ($udLines[$i] -match "^\s*autoinstall\s*:") { $start = $i; break }
  }
  $autoinstallYaml = ($udLines[$start..($udLines.Length-1)] -join "`n") + "`n"

  #region agent log A
  $hasAutoinstallNetwork = [bool]($autoinstallYaml -match "(?m)^\s{2}network\s*:")
  $netIdx = -1
  for ($i = 0; $i -lt $udLines.Length; $i++) { if ($udLines[$i] -match "^\s{2}network\s*:") { $netIdx = $i; break } }
  $netSnippet = ""
  if ($netIdx -ge 0) {
    $end = [Math]::Min($udLines.Length - 1, $netIdx + 25)
    $netSnippet = ($udLines[$netIdx..$end] -join "\n")
  }
  Write-DebugNdjson $repoRoot $runId "A" "New-OnecInfraVm.ps1:Build-AutoinstallIso:yaml" "autoinstall yaml rendered" @{
    sig = $sigHash
    has_autoinstall_network = $hasAutoinstallNetwork
    network_snippet = $netSnippet
  }
  #endregion

  # Persist build info as an artifact and also embed into ISO (nocloud/build-info.json)
  $buildInfo = [ordered]@{
    signature_sha256 = $sigHash
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    signature = $sig.signature
  } | ConvertTo-Json -Depth 10
  Write-TextFileUtf8NoBom (Join-Path $workDir "build-info.json") $buildInfo

  $baseIsoAbs = (Resolve-Path $baseIsoPath).Path
  $outDirAbs = (Resolve-Path $outDir).Path
  $workDirAbs = (Resolve-Path $workDir).Path
  $outName = [System.IO.Path]::GetFileName($outIsoPath)

  $runSh = Join-Path $workDir "run.sh"
  $scriptLines = @(
    "set -euo pipefail",
    "mkdir -p /work/iso",
    "",
    "# Full ISO rebuild with updated GRUB for both BIOS and UEFI (Hyper-V Gen2 uses UEFI).",
    "",
    "BASE=/in/base.iso",
    ("OUT=/out/{0}" -f $outName),
    "",
    "# xorriso refuses to write if outdev already exists with data. Ensure clean output file.",
    'rm -f "$OUT" || true',
    "",
    "# Extract ISO",
    'xorriso -osirrox on -indev "$BASE" -extract / /work/iso >/dev/null',
    "# xorriso preserves file permissions from the ISO (often read-only). Make tree writable for patching.",
    'chmod -R u+w /work/iso || true',
    "",
    "# Place autoinstall.yaml at ISO root",
    'cp /work/autoinstall.yaml /work/iso/autoinstall.yaml',
    "",
    "# Write minimal grub.cfg for both BIOS and UEFI",
    'cat > /work/iso/boot/grub/grub.cfg <<''EOF''',
    'search --set=root --file /casper/vmlinuz',
    'set default=0',
    'set timeout=0',
    'menuentry "Autoinstall Ubuntu Server" {',
    '  linux /casper/vmlinuz autoinstall ---',
    '  initrd /casper/initrd',
    '}',
    'EOF',
    "",
    "# Build UEFI bootx64.efi embedding grub.cfg",
    'mkdir -p /work/iso/EFI/boot',
    'grub-mkstandalone --format=x86_64-efi --output=/work/iso/EFI/boot/bootx64.efi --locales="" --fonts="" "boot/grub/grub.cfg=/work/iso/boot/grub/grub.cfg"',
    "",
    "# Create UEFI boot image (FAT) at /boot/grub/efi.img",
    'dd if=/dev/zero of=/work/iso/boot/grub/efi.img bs=1M count=10 >/dev/null 2>&1',
    'mkfs.vfat /work/iso/boot/grub/efi.img >/dev/null',
    'mmd -i /work/iso/boot/grub/efi.img efi efi/boot',
    'mcopy -i /work/iso/boot/grub/efi.img /work/iso/EFI/boot/bootx64.efi ::efi/boot/',
    "",
    "# Update MD5 sums (Ubuntu's md5sum.txt is checked by installer)",
    'cd /work/iso',
    'chmod u+w md5sum.txt || true',
    'rm -f md5sum.txt',
    # Use xargs to avoid shell escaping issues with -exec in this generated script
    'find . -type f ! -name md5sum.txt ! -path "./ubuntu/*" -print0 | xargs -0 md5sum > md5sum.txt',
    "",
    "# Repack ISO with BIOS+UEFI entries",
    'cd /work',
    'xorriso -as mkisofs -iso-level 3 -o "$OUT" -full-iso9660-filenames -volid "UBUNTU_2404_AUTOINSTALL" -eltorito-boot boot/grub/i386-pc/eltorito.img -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat /work/iso'
  )
  Write-TextFileUtf8NoBom $runSh ($scriptLines -join "`n")

  $args = @(
    "run","--rm",
    "--entrypoint","/bin/bash",
    "-v", "$baseIsoAbs`:/in/base.iso:ro",
    "-v", "$outDirAbs`:/out",
    "-v", "$workDirAbs`:/work",
    "-v", "$workDirAbs`:/work",
    $image,
    "-lc","bash /work/run.sh"
  )
  # Provide rendered autoinstall.yaml into container
  $autoinstallPath = Join-Path $workDir "autoinstall.yaml"
  Write-TextFileUtf8NoBom $autoinstallPath $autoinstallYaml
  $args = @(
    "run","--rm",
    "--entrypoint","/bin/bash",
    "-v", "$baseIsoAbs`:/in/base.iso:ro",
    "-v", "$outDirAbs`:/out",
    "-v", "$workDirAbs`:/work",
    $image,
    "-lc","bash /work/run.sh"
  )
  # Do not suppress output: it contains critical diagnostics when ISO patching fails
  # (and shows whether the autoinstall kernel params were actually injected).
  $runOut = & docker @args 2>&1
  $runExit = $LASTEXITCODE
  #region agent log H4
  try {
    $lines = @()
    if ($runOut) { $lines = @($runOut -split "`r?`n") }
    $tail = if ($lines.Count -gt 40) { ($lines[($lines.Count-40)..($lines.Count-1)] -join "`n") } else { ($lines -join "`n") }
    Write-AgentDebugLog $repoRoot $runId "H4" "New-OnecInfraVm.ps1:Build-AutoinstallIso:docker-run" "docker run finished" @{
      ExitCode = $runExit
      Tail = $tail
    }
  } catch {}
  #endregion
  if ($runExit -ne 0) {
    $lines = @()
    if ($runOut) { $lines = @($runOut -split "`r?`n") }
    $tail = if ($lines.Count -gt 80) { ($lines[($lines.Count-80)..($lines.Count-1)] -join "`n") } else { ($lines -join "`n") }
    throw ("Failed to build autoinstall ISO (docker run exit={0}). Last output:`n{1}" -f $runExit, $tail)
  }

  if (-not (Test-Path $outIsoPath)) { throw "Failed to build autoinstall ISO: $outIsoPath" }
  $buildSucceeded = $true
  Write-Host ("[ISO] output_iso={0}" -f $outIsoPath)

  #region agent log H2-H5
  try {
    $verifyCmd = @(
      "run","--rm",
      "-v", "$outIsoPath`:/in/auto.iso:ro",
      $image,
      "bash","-lc",
      "set -e; " +
      "echo 'HAS_AUTOINSTALL_YAML='; xorriso -indev /in/auto.iso -ls /autoinstall.yaml || true; " +
      "echo 'GRUB_CFG='; xorriso -osirrox on -indev /in/auto.iso -extract /boot/grub/grub.cfg /tmp/grub.cfg >/dev/null; head -n 25 /tmp/grub.cfg; " +
      "echo 'EFI_IMG_LIST='; xorriso -osirrox on -indev /in/auto.iso -extract /boot/grub/efi.img /tmp/efi.img >/dev/null; mdir -i /tmp/efi.img ::/; mdir -i /tmp/efi.img ::/efi/; mdir -i /tmp/efi.img ::/efi/boot/;"
    )
    $out = & docker @verifyCmd 2>&1
    $lines = @()
    if ($out) { $lines = @($out -split "`r?`n") }
    $head = if ($lines.Count -gt 40) { ($lines[0..39] -join "`n") } else { ($lines -join "`n") }
    Write-AgentDebugLog $repoRoot $runId "H2" "New-OnecInfraVm.ps1:Build-AutoinstallIso:verify" "ISO verify snapshot (head)" @{
      Sig = $sigHash
      OutIso = $outIsoPath
      VerifyHead = $head
    }
  } catch {}
  #endregion

  # Cache ISO + metadata for future runs (survives VM dir recreation).
  try {
    Copy-Item -Force $outIsoPath $cachedIso
    Write-TextFileUtf8NoBom $cachedMeta $buildInfo
    Write-Host ("[ISO] cached_iso={0}" -f $cachedIso)
  } catch {}

  # Clean up temporary ISO work directory to avoid blowing up VM dir size and slow VM recreation.
  # Safety rails:
  # - delete ONLY "<outDir>\iso-work"
  # - require marker file build-info.json that we created in this run
  if ($buildSucceeded -and (Test-Path $workDir)) {
    try {
      $workDirResolved = (Resolve-Path -LiteralPath $workDir -ErrorAction Stop).Path.TrimEnd('\')
      $outDirResolved = (Resolve-Path -LiteralPath $outDir -ErrorAction Stop).Path.TrimEnd('\')
      $expected = ($outDirResolved + "\iso-work")
      $marker = Join-Path $workDirResolved "build-info.json"

      if (($workDirResolved -ieq $expected) -and (Test-Path -LiteralPath $marker)) {
        $sizeBytes = 0
        try {
          $sum = (Get-ChildItem -LiteralPath $workDirResolved -Force -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
          if ($sum) { $sizeBytes = [int64]$sum }
        } catch {}

        Remove-DirFast $workDirResolved
        Write-Host ("[ISO] cleaned iso-work (GB={0})" -f ([math]::Round(($sizeBytes/1GB),2)))

        #region agent log H6
        Write-AgentDebugLog $repoRoot $runId "H6" "New-OnecInfraVm.ps1:Build-AutoinstallIso:cleanup" "cleaned iso-work" @{
          OutDir = $outDirResolved
          WorkDir = $workDirResolved
          Marker = $marker
          SizeBytes = $sizeBytes
          Deleted = $true
        }
        #endregion
      } else {
        #region agent log H6
        Write-AgentDebugLog $repoRoot $runId "H6" "New-OnecInfraVm.ps1:Build-AutoinstallIso:cleanup" "skip iso-work cleanup (safety check failed)" @{
          OutDir = $outDirResolved
          WorkDir = $workDirResolved
          Expected = $expected
          MarkerExists = (Test-Path -LiteralPath $marker)
          Deleted = $false
        }
        #endregion
      }
    } catch {
      #region agent log H6
      try {
        Write-AgentDebugLog $repoRoot $runId "H6" "New-OnecInfraVm.ps1:Build-AutoinstallIso:cleanup" "iso-work cleanup error" @{
          WorkDir = $workDir
          Error = $_.Exception.Message
          Deleted = $false
        }
      } catch {}
      #endregion
    }
  }
}

function Render-Template([string]$text, [hashtable]$vars) {
  foreach ($k in $vars.Keys) {
    $text = $text.Replace($k, $vars[$k])
  }
  return $text
}

function New-CloudInitConfigDriveVhdx([string]$repoRoot, [string]$outVhdxPath, [hashtable]$vars) {
  $tmplDir = Join-Path $repoRoot "scripts\\cloud-init"
  $ud = Get-Content (Join-Path $tmplDir "user-data.yaml") -Raw
  $md = Get-Content (Join-Path $tmplDir "meta-data.yaml") -Raw
  $nc = Get-Content (Join-Path $tmplDir "network-config.yaml") -Raw

  $seedDir = Join-Path ([System.IO.Path]::GetDirectoryName($outVhdxPath)) "seed"
  if (Test-Path $seedDir) { Remove-DirFast $seedDir }
  New-Item -ItemType Directory -Force -Path $seedDir | Out-Null

  $ud2 = Render-Template $ud $vars
  $md2 = Render-Template $md $vars
  $nc2 = Render-Template $nc $vars

  # Write as UTF-8 without BOM (cloud-init expects plain UTF-8)
  [System.IO.File]::WriteAllText((Join-Path $seedDir "user-data"), $ud2, (New-Object System.Text.UTF8Encoding($false)))
  [System.IO.File]::WriteAllText((Join-Path $seedDir "meta-data"), $md2, (New-Object System.Text.UTF8Encoding($false)))
  [System.IO.File]::WriteAllText((Join-Path $seedDir "network-config"), $nc2, (New-Object System.Text.UTF8Encoding($false)))

  # Build a config-drive as FAT32 VHDX with volume label CIDATA.
  if (Test-Path $outVhdxPath) { Remove-Item -Force $outVhdxPath }
  New-VHD -Path $outVhdxPath -SizeBytes 64MB -Dynamic | Out-Null
  $disk = Mount-VHD -Path $outVhdxPath -PassThru
  try {
    $diskNum = $disk.DiskNumber
    Initialize-Disk -Number $diskNum -PartitionStyle MBR -ErrorAction Stop | Out-Null

    # Do NOT assign drive letters (can trigger popups / conflicts). Use a directory mount point.
    $part = New-Partition -DiskNumber $diskNum -UseMaximumSize
    $mountPath = Join-Path $seedDir "mnt"
    New-Item -ItemType Directory -Force -Path $mountPath | Out-Null
    Add-PartitionAccessPath -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -AccessPath $mountPath | Out-Null

    Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel "CIDATA" -Confirm:$false | Out-Null

    Copy-Item (Join-Path $seedDir "user-data") (Join-Path $mountPath "user-data") -Force
    Copy-Item (Join-Path $seedDir "meta-data") (Join-Path $mountPath "meta-data") -Force
    Copy-Item (Join-Path $seedDir "network-config") (Join-Path $mountPath "network-config") -Force

    Remove-PartitionAccessPath -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -AccessPath $mountPath -ErrorAction SilentlyContinue | Out-Null
  } finally {
    Dismount-VHD -Path $outVhdxPath -ErrorAction SilentlyContinue | Out-Null
  }
}

function New-NoCloudSeedVhdx([string]$outVhdxPath, [string]$userDataText, [string]$metaDataText) {
  $seedDir = Join-Path ([System.IO.Path]::GetDirectoryName($outVhdxPath)) "seed"
  if (Test-Path $seedDir) { Remove-DirFast $seedDir }
  New-Item -ItemType Directory -Force -Path $seedDir | Out-Null

  # Write as UTF-8 without BOM (cloud-init expects plain UTF-8)
  [System.IO.File]::WriteAllText((Join-Path $seedDir "user-data"), $userDataText, (New-Object System.Text.UTF8Encoding($false)))
  [System.IO.File]::WriteAllText((Join-Path $seedDir "meta-data"), $metaDataText, (New-Object System.Text.UTF8Encoding($false)))

  # Build a config-drive as FAT32 VHDX with volume label CIDATA.
  if (Test-Path $outVhdxPath) { Remove-Item -Force $outVhdxPath }
  New-VHD -Path $outVhdxPath -SizeBytes 64MB -Dynamic | Out-Null
  $disk = Mount-VHD -Path $outVhdxPath -PassThru
  try {
    $diskNum = $disk.DiskNumber
    Initialize-Disk -Number $diskNum -PartitionStyle MBR -ErrorAction Stop | Out-Null

    $part = New-Partition -DiskNumber $diskNum -UseMaximumSize
    $mountPath = Join-Path $seedDir "mnt"
    New-Item -ItemType Directory -Force -Path $mountPath | Out-Null
    Add-PartitionAccessPath -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -AccessPath $mountPath | Out-Null

    Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel "CIDATA" -Confirm:$false | Out-Null

    Copy-Item (Join-Path $seedDir "user-data") (Join-Path $mountPath "user-data") -Force
    Copy-Item (Join-Path $seedDir "meta-data") (Join-Path $mountPath "meta-data") -Force

    Remove-PartitionAccessPath -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -AccessPath $mountPath -ErrorAction SilentlyContinue | Out-Null
  } finally {
    Dismount-VHD -Path $outVhdxPath -ErrorAction SilentlyContinue | Out-Null
  }
}

function Test-IpInUse([string]$ip) {
  # Conservative: if we get an ICMP reply -> it's definitely in use.
  # If ping is blocked, this can return false even when the IP is in use.
  try {
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) { return $true }
  } catch {}

  # Best-effort ARP check (works only if the host has seen the IP recently).
  try {
    $line = (arp -a | Select-String -SimpleMatch $ip | Select-Object -First 1).Line
    if ($line) {
      # Typical formats:
      #  192.168.1.50           xx-xx-xx-xx-xx-xx     dynamic
      #  192.168.1.50           ff-ff-ff-ff-ff-ff     static
      #  192.168.1.50           ---                   invalid/incomplete
      if ($line -match "\b([0-9a-f]{2}-){5}[0-9a-f]{2}\b") { return $true }
    }
  } catch {}

  return $false
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

Require-Admin
Ensure-HyperV

$repoRoot = Get-RepoRoot
# Always ensure a repo-managed keypair exists for automation.
# If user explicitly provided a public key path, use it instead (advanced usage).
$kp = Ensure-RepoSshKeypair $repoRoot $VmName
$sshPriv = $kp.PrivateKeyPath
$sshKeyPath = $kp.PublicKeyPath

if ($SshPublicKeyPath -and (Test-Path $SshPublicKeyPath)) {
  $sshKeyPath = (Resolve-Path $SshPublicKeyPath).Path
  # We cannot reliably infer the corresponding private key from a .pub path.
  $sshPriv = $null
} else {
  # Backward-compatible: if user has a pub key but no explicit override, we still use repo key.
  # This avoids a common footgun where ~/.ssh/id_rsa.pub exists but private key is missing.
  $fallbackUserPub = Resolve-SshKey ""
  if ($fallbackUserPub) {
    # no-op; intentionally ignore
  }
}

$sshKey = (Get-Content $sshKeyPath -Raw).Trim()

$cacheDir = Join-Path $repoRoot ".cache\\hyperv"
$vmDir = Join-Path $cacheDir $VmName

$macs = Compute-MacPair $VmName $SwitchName $NetIface $MgmtSwitchName

# If VM already exists, don't try to overwrite seed.iso (it is typically mounted by the VM).
# Reuse existing VM unless -ForceRecreate is provided.
$existingVm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
if ($null -ne $existingVm) {
  if ($ForceRecreate) {
    try { Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Remove-VM -Name $VmName -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    if (Test-Path $vmDir) {
      #region agent log H10
      Write-AgentDebugLog $repoRoot "run1" "H10" "New-OnecInfraVm.ps1:ForceRecreate" "vmDir deletion start" @{
        VmName = $VmName
        VmDir = $vmDir
      }
      #endregion

      Write-Host ("[STEP] Removing VM directory (can be large): {0}" -f $vmDir)
      $t0 = Get-Date
      try {
        # PowerShell's recursive deletion can be painfully slow on tens of thousands of files
        # and sometimes shows nonsensical "GB of GB" progress. Use native rmdir (fast + quiet).
        & cmd /c "rmdir /s /q ""$vmDir""" | Out-Null
      } catch {
        # Fallback: best-effort PowerShell delete.
        try { Remove-Item -Recurse -Force $vmDir -ErrorAction SilentlyContinue } catch {}
      }
      $secs = [int]((Get-Date) - $t0).TotalSeconds
      Write-Host ("[OK] VM directory removed in ~{0}s" -f $secs)

      #region agent log H10
      Write-AgentDebugLog $repoRoot "run1" "H10" "New-OnecInfraVm.ps1:ForceRecreate" "vmDir deletion done" @{
        VmName = $VmName
        VmDir = $vmDir
        ElapsedSeconds = $secs
        ExistsAfter = (Test-Path $vmDir)
      }
      #endregion
    }
  } else {
    # Ensure management switch + mgmt NIC exist even when reusing VM.
    Ensure-InternalSwitch $MgmtSwitchName $MgmtHostIp $MgmtPrefixLength

    try {
      $hasMgmt = $false
      $adapters = @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue)
      foreach ($a in $adapters) {
        if (($a.Name -eq "mgmt") -or ($a.SwitchName -eq $MgmtSwitchName)) { $hasMgmt = $true; break }
      }
      if (-not $hasMgmt) {
        Add-VMNetworkAdapter -VMName $VmName -SwitchName $MgmtSwitchName -Name "mgmt" | Out-Null
      }
      # Ensure deterministic MACs so autoinstall/netplan match works.
      Set-VMNetworkAdapter -VMName $VmName -StaticMacAddress $macs.macDashLan | Out-Null
      Set-VMNetworkAdapter -VMName $VmName -Name "mgmt" -StaticMacAddress $macs.macDashMgmt | Out-Null
    } catch {}

    if ($existingVm.State -ne "Running") {
      Start-VM -Name $VmName | Out-Null
    }
    Write-Host "[OK] VM already exists: $VmName"
    Write-Host ("     SSH (mgmt): ssh sandbox@{0}" -f $MgmtVmIp)
    return
  }
}

# Early sanity check: user-provided static IP should be free.
if ($VmIp -and $VmIp.Trim().Length -gt 0) {
  if (Test-IpInUse $VmIp) {
    throw "VM_IP=$VmIp appears to be in use (ping/ARP). Choose a free IP before creating the VM."
  }

  # Additional strong signal: if any common TCP port responds, the IP is almost certainly in use.
  foreach ($p in @(22, 53, 80, 443, 445, 5432, 1545)) {
    if (Test-TcpPortFast $VmIp $p 700) {
      throw "VM_IP=$VmIp appears to be in use (TCP port $p responded). Choose a free IP before creating the VM."
    }
  }
}

$isoMode = $false
$isoPath = $null
# If caller passed empty ISO URL, restore default (we prefer autoinstall).
if (-not $UbuntuIsoUrl -or $UbuntuIsoUrl.Trim().Length -eq 0) {
  $UbuntuIsoUrl = "https://releases.ubuntu.com/24.04/ubuntu-24.04.3-live-server-amd64.iso"
}

if ($UbuntuIsoPath -and (Test-Path $UbuntuIsoPath)) {
  $isoMode = $true
  $isoPath = (Resolve-Path $UbuntuIsoPath).Path
} elseif ($UbuntuIsoUrl -and $UbuntuIsoUrl.Trim().Length -gt 0) {
  # Prefer autoinstall when VHD path is not explicitly provided.
  if (-not ($UbuntuVhdPath -and (Test-Path $UbuntuVhdPath))) {
    $isoMode = $true
    $isoPath = Download-UbuntuIso $UbuntuIsoUrl $cacheDir
  }
}

New-Item -ItemType Directory -Force -Path $vmDir | Out-Null
$vmVhd = Join-Path $vmDir "$VmName.vhd"
$vmVhdx = Join-Path $vmDir "$VmName.vhdx"

$bootIso = $null
if ($isoMode) {
  # Fresh OS disk for installation.
  if (Test-Path $vmVhdx) { Remove-Item -Force $vmVhdx -ErrorAction SilentlyContinue }
  New-VHD -Path $vmVhdx -SizeBytes ([Int64]$OsDiskGB * 1GB) -Dynamic | Out-Null
  $bootIso = Join-Path $vmDir "ubuntu-autoinstall.iso"
} else {
  $baseVhd = $null
  if ($UbuntuVhdPath -and (Test-Path $UbuntuVhdPath)) {
    $baseVhd = (Resolve-Path $UbuntuVhdPath).Path
  } else {
    $baseVhd = Download-UbuntuVhd $UbuntuVhdTarUrl $cacheDir
  }

  # Hyper-V Gen2 requires VHDX. Ubuntu cloud image ships as .vhd -> convert.
  if ($baseVhd.ToLowerInvariant().EndsWith(".vhdx")) {
    Copy-Item -Force $baseVhd $vmVhdx
  } else {
    Copy-Item -Force $baseVhd $vmVhd
    if (-not (Test-Path $vmVhdx)) {
      Convert-VHD -Path $vmVhd -DestinationPath $vmVhdx -VHDType Dynamic | Out-Null
    }
  }
}

$seedVhdx = Join-Path $vmDir "seed.vhdx"

$vars = @{
  "__SSH_PUBLIC_KEY__" = $sshKey
  "__HOSTNAME__" = $VmName
  # Keep instance-id stable for the same config to enable ISO caching and avoid cache bloat.
  "__INSTANCE_ID__" = ("{0}-{1}-{2}" -f $VmName, $macs.macColonLan, $macs.macColonMgmt)
  "__MAC_LAN__" = $macs.macColonLan
  "__MAC_MGMT__" = $macs.macColonMgmt
  "__MGMT_IP__" = $MgmtVmIp
  "__MGMT_PREFIX__" = $MgmtPrefixLength.ToString()
  "__NET_IFACE__" = $NetIface
}
if (-not $isoMode) {
  # For cloud/azure VHD mode, use full NoCloud seed incl. network-config.
  New-CloudInitConfigDriveVhdx $repoRoot $seedVhdx $vars
}

if ($isoMode) {
  Write-Host ("[ISO] vm_boot_iso={0}" -f $bootIso)
  Build-AutoinstallIso $repoRoot $isoPath $bootIso $vars
}

Ensure-ExternalSwitch $SwitchName $NetAdapterName
Ensure-InternalSwitch $MgmtSwitchName $MgmtHostIp $MgmtPrefixLength

$mem = [Int64]$MemoryGB * 1GB
New-VM -Name $VmName -Generation 2 -MemoryStartupBytes $mem -VHDPath $vmVhdx -SwitchName $SwitchName | Out-Null
Set-VMProcessor -VMName $VmName -Count $CpuCount | Out-Null

# Ensure MAC matches cloud-init netplan match (LAN adapter)
Set-VMNetworkAdapter -VMName $VmName -StaticMacAddress $macs.macDashLan | Out-Null

# Add management NIC on internal switch for reliable SSH from host
Add-VMNetworkAdapter -VMName $VmName -SwitchName $MgmtSwitchName -Name "mgmt" | Out-Null
Set-VMNetworkAdapter -VMName $VmName -Name "mgmt" -StaticMacAddress $macs.macDashMgmt | Out-Null

# Secure Boot:
# - For custom autoinstall ISO we generate a custom bootx64.efi (unsigned) -> disable Secure Boot.
# - For other modes keep Secure Boot enabled.
if ($isoMode) {
  #region agent log H1
  try {
    $fw0 = Get-VMFirmware -VMName $VmName -ErrorAction SilentlyContinue
    Write-AgentDebugLog $repoRoot "run1" "H1" "New-OnecInfraVm.ps1:secureboot:before" "firmware before secureboot change" @{
      VmName = $VmName
      IsoMode = $isoMode
      SecureBoot = $fw0.SecureBoot
      SecureBootTemplate = $fw0.SecureBootTemplate
    }
  } catch {}
  #endregion

  Set-VMFirmware -VMName $VmName -EnableSecureBoot Off -ErrorAction Stop | Out-Null

  #region agent log H1
  try {
    $fw1 = Get-VMFirmware -VMName $VmName -ErrorAction SilentlyContinue
    Write-AgentDebugLog $repoRoot "run1" "H1" "New-OnecInfraVm.ps1:secureboot:after" "firmware after secureboot change" @{
      VmName = $VmName
      IsoMode = $isoMode
      SecureBoot = $fw1.SecureBoot
      SecureBootTemplate = $fw1.SecureBootTemplate
    }
  } catch {}
  #endregion

  # Fail fast: if Secure Boot is still on, our custom UEFI boot loader will be ignored.
  $fwCheck = Get-VMFirmware -VMName $VmName -ErrorAction SilentlyContinue
  if ($fwCheck -and ($fwCheck.SecureBoot -eq [Microsoft.HyperV.PowerShell.OnOffState]::On)) {
    throw "Secure Boot is still enabled for VM '$VmName' in ISO autoinstall mode. Disable Secure Boot to boot custom bootx64.efi."
  }
} else {
  Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate "MicrosoftUEFICertificateAuthority" -ErrorAction Stop | Out-Null
}

# Attach config-drive disk (NoCloud) for cloud-image mode only
if (-not $isoMode) {
  Add-VMHardDiskDrive -VMName $VmName -Path $seedVhdx | Out-Null
}
Set-VM -VMName $VmName -AutomaticCheckpointsEnabled $false | Out-Null

if ($isoMode) {
  Add-VMDvdDrive -VMName $VmName -Path $bootIso | Out-Null
  # Ensure VM boots from DVD for installation
  $dvd = Get-VMDvdDrive -VMName $VmName | Select-Object -First 1
  if ($dvd) {
    Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd | Out-Null
  }
}

Start-VM -Name $VmName | Out-Null

#region agent log H1-H2
try {
  $fw = Get-VMFirmware -VMName $VmName -ErrorAction SilentlyContinue
  $dvd = Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue | Select-Object -First 1
  Write-AgentDebugLog $repoRoot "run1" "H1" "New-OnecInfraVm.ps1:post-start" "firmware after start" @{
    VmName = $VmName
    IsoMode = $isoMode
    SecureBoot = $fw.SecureBoot
    SecureBootTemplate = $fw.SecureBootTemplate
    FirstBootDevice = ($fw.FirstBootDevice | ForEach-Object { $_.Device } | Select-Object -First 1)
    DvdPath = $dvd.Path
  }
} catch {}
#endregion

Write-Host "[OK] VM started: $VmName"
Write-Host ("     SSH (mgmt): ssh sandbox@{0}" -f $MgmtVmIp)
if ($sshPriv) {
  Write-Host ("     SSH key: {0}" -f $sshPriv)
}

