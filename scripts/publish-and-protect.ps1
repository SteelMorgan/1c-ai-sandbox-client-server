param(
  [Parameter(Mandatory = $true)]
  [string] $RepoName,

  # Optional owner/org. If omitted, uses the currently authenticated gh user.
  [Parameter(Mandatory = $false)]
  [string] $Owner,

  # Optional: override branch to protect. If omitted, uses repo default branch.
  [Parameter(Mandatory = $false)]
  [string] $Branch,

  # Protection knobs (simple defaults).
  [Parameter(Mandatory = $false)]
  [int] $RequiredApprovals = 1,

  [Parameter(Mandatory = $false)]
  [switch] $EnforceAdmins
)

$ErrorActionPreference = 'Stop'

function Require-Command([string] $name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $name"
  }
}

# Resolve external executable explicitly (avoid PowerShell command-name shadowing)
$script:ghExe = (Get-Command gh -CommandType Application -ErrorAction Stop).Source

# In PowerShell 7+, native stderr can become ErrorRecords and respect ErrorActionPreference.
# We don't want warnings on stderr to abort the script.
try {
  if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
  }
} catch {}

function Invoke-Gh([string[]] $GhArgs) {
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = & $script:ghExe @GhArgs 2>&1
  $ErrorActionPreference = $old
  if ($LASTEXITCODE -ne 0) {
    throw ("gh failed (exit {0}): {1}`n{2}" -f $LASTEXITCODE, ($GhArgs -join " "), ($out -join "`n"))
  }
  return $out
}

function Invoke-GhTry([string[]] $GhArgs) {
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = & $script:ghExe @GhArgs 2>&1
  $ErrorActionPreference = $old
  if ($LASTEXITCODE -ne 0) { return $null }
  return $out
}

Require-Command "gh"

# Must be logged in on the machine where you run this script.
$null = Invoke-Gh @("auth","status")

$actorLogin = (Invoke-Gh @("api","user","--jq",".login")).Trim()
if (-not $actorLogin) { throw "Couldn't determine current gh user login." }

if (-not $Owner) { $Owner = $actorLogin }
$full = "$Owner/$RepoName"

$exists = Invoke-GhTry @("api","repos/$full","--jq",".full_name")
if (-not ($exists -and $exists.Trim())) {
  throw "Repo not found (or no access): $full"
}

# Make public (required flag for gh visibility changes).
Write-Host "Setting visibility: public ($full)"
$null = Invoke-Gh @(
  "repo","edit",$full,
  "--visibility","public",
  "--accept-visibility-change-consequences"
)

if (-not $Branch) {
  $Branch = (Invoke-Gh @("api","repos/$full","--jq",".default_branch")).Trim()
  if (-not $Branch) { $Branch = "main" }
}

Write-Host "Enabling branch protection on: $Branch"

$payload = @{
  required_status_checks = $null
  enforce_admins = [bool]$EnforceAdmins
  required_pull_request_reviews = @{
    dismiss_stale_reviews = $true
    require_code_owner_reviews = $false
    required_approving_review_count = [Math]::Max(0, $RequiredApprovals)
  }
  restrictions = $null
}

$json = $payload | ConvertTo-Json -Depth 10
$old = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$out = $json | & $script:ghExe api --method PUT "repos/$full/branches/$Branch/protection" --input - 2>&1
$ErrorActionPreference = $old
if ($LASTEXITCODE -ne 0) {
  throw ("Failed to set branch protection for {0}.`n{1}" -f $Branch, ($out -join "`n"))
}

Write-Host "OK"
Write-Host "Repo:        https://github.com/$full"
Write-Host "Visibility:  public"
Write-Host "Protected:   $Branch (PR-only, approvals=$RequiredApprovals)"

