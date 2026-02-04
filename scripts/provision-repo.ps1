param(
  [Parameter(Mandatory = $true)]
  [string] $RepoName,

  # Optional owner/org. If omitted, uses the currently authenticated gh user.
  [Parameter(Mandatory = $false)]
  [string] $Owner,

  [Parameter(Mandatory = $false)]
  [string] $Description = "",

  # Hardcoded by default as requested.
  [Parameter(Mandatory = $false)]
  [string] $AgentUsername = "steel-code-agent",

  # Default: private repo
  [Parameter(Mandatory = $false)]
  [ValidateSet("private","public","internal")]
  [string] $Visibility = "private",

  # Optional: path to a folder with a pre-made repo skeleton to push to the new repo
  # (e.g. .cursor/skills, docs, configs). This will be committed to the default branch.
  [Parameter(Mandatory = $false)]
  [string] $SeedPath,

  # Create an initial commit so branches/protection can be set immediately.
  [Parameter(Mandatory = $false)]
  [switch] $AddReadme,

  # Branch to create for agent work (simple, as requested).
  [Parameter(Mandatory = $false)]
  [string] $AgentBranch = "agent",
)

$ErrorActionPreference = 'Stop'

function Require-Command([string] $name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $name"
  }
}

# Resolve external executables explicitly (avoid PowerShell command-name shadowing)
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

function Exec([string] $exe, [string[]] $CmdArgs, [string] $cwd) {
  Push-Location $cwd
  try {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & $exe @CmdArgs 2>&1
    $ErrorActionPreference = $old
    if ($LASTEXITCODE -ne 0) {
      throw ("{0} failed (exit {1}): {2}`n{3}" -f $exe, $LASTEXITCODE, ($CmdArgs -join " "), ($out -join "`n"))
    }
    return $out
  } finally {
    Pop-Location
  }
}

Require-Command "gh"
if ($SeedPath) { Require-Command "git" }

# Must be logged in on the machine where you run this script.
$null = Invoke-Gh @("auth","status")

$actorLogin = (Invoke-Gh @("api","user","--jq",".login")).Trim()
if (-not $actorLogin) { throw "Couldn't determine current gh user login." }

if (-not $Owner) {
  $Owner = $actorLogin
}

$full = "$Owner/$RepoName"

$exists = Invoke-GhTry @("api","repos/$full","--jq",".full_name")
if ($exists -and $exists.Trim()) {
  Write-Host "Repo already exists: $full (skipping create)"
} else {
  Write-Host "Creating repo: $full ($Visibility)"

  $createArgs = @("repo","create",$full)
  switch ($Visibility) {
    "private" { $createArgs += "--private" }
    "public"  { $createArgs += "--public" }
    "internal"{ $createArgs += "--internal" }
  }
  if ($Description) { $createArgs += @("--description",$Description) }
  if ($AddReadme) { $createArgs += "--add-readme" }

  # gh v2.0+ creates non-interactively when name + visibility flag are provided.
  $null = Invoke-Gh $createArgs
}

# Determine default branch (usually main) and its SHA.
$defaultBranch = (Invoke-Gh @("api","repos/$full","--jq",".default_branch")).Trim()
if (-not $defaultBranch) { $defaultBranch = "main" }

if ($SeedPath) {
  $seed = Resolve-Path -Path $SeedPath -ErrorAction Stop
  if (-not (Test-Path -Path $seed -PathType Container)) {
    throw "SeedPath is not a directory: $seed"
  }

  # If repo is empty (no ref yet), we bootstrap by initializing a local repo and pushing first.
  $existingSha = (Invoke-GhTry @("api","repos/$full/git/ref/heads/$defaultBranch","--jq",".object.sha"))
  if ($existingSha) { $existingSha = $existingSha.Trim() }

  $tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("provision-repo-" + [Guid]::NewGuid().ToString("N"))
  $repoDir = Join-Path $tmpRoot "repo"
  New-Item -ItemType Directory -Force -Path $repoDir | Out-Null

  if ($existingSha) {
    Write-Host "Seeding repo content into existing default branch: $defaultBranch"
    $null = Exec "git" @("clone","--branch",$defaultBranch,"--depth","1","https://github.com/$full.git",$repoDir) $tmpRoot
  } else {
    Write-Host "Repo looks empty. Bootstrapping initial commit on: $defaultBranch"
    try {
      $null = Exec "git" @("init","-b",$defaultBranch) $repoDir
    } catch {
      $null = Exec "git" @("init") $repoDir
      $null = Exec "git" @("checkout","-b",$defaultBranch) $repoDir
    }
    $null = Exec "git" @("remote","add","origin","https://github.com/$full.git") $repoDir
  }

  # Copy seed contents into repo
  Copy-Item -Path (Join-Path $seed "*") -Destination $repoDir -Recurse -Force

  # Commit only if there are changes
  $null = Exec "git" @("config","user.name",$actorLogin) $repoDir
  $null = Exec "git" @("config","user.email","$actorLogin@users.noreply.github.com") $repoDir
  $null = Exec "git" @("add","-A") $repoDir
  $status = (Exec "git" @("status","--porcelain") $repoDir)
  if ($status -and $status.Trim()) {
    $null = Exec "git" @("commit","-m","chore: bootstrap repo skeleton") $repoDir
    $null = Exec "git" @("push","-u","origin",$defaultBranch) $repoDir
  } else {
    Write-Host "SeedPath copy produced no changes; skipping commit."
  }

  try { Remove-Item -Recurse -Force $tmpRoot -ErrorAction SilentlyContinue } catch {}
}

$sha = (Invoke-Gh @("api","repos/$full/git/ref/heads/$defaultBranch","--jq",".object.sha")).Trim()
if (-not $sha) {
  throw "Couldn't resolve SHA for default branch: $defaultBranch. Create an initial commit (use -AddReadme or -SeedPath) and retry."
}

Write-Host "Default branch: $defaultBranch"

# Create agent branch from default branch.
$agentSha = Invoke-GhTry @("api","repos/$full/git/ref/heads/$AgentBranch","--jq",".object.sha")
if ($agentSha -and $agentSha.Trim()) {
  Write-Host "Branch already exists: $AgentBranch (skipping create)"
} else {
  Write-Host "Creating branch: $AgentBranch"
  $null = Invoke-Gh @(
    "api",
    "--method","POST",
    "repos/$full/git/refs",
    "-f","ref=refs/heads/$AgentBranch",
    "-f","sha=$sha"
  )
}

# Invite agent as collaborator with write permission (push).
Write-Host "Inviting collaborator: $AgentUsername (permission=push)"
$null = Invoke-Gh @(
  "api",
  "--method","PUT",
  "repos/$full/collaborators/$AgentUsername",
  "-f","permission=push"
)

Write-Host "OK"
Write-Host "Repo:        https://github.com/$full"
Write-Host "Branch:      $AgentBranch"
Write-Host "Next:        collaborator must accept the invite on GitHub."

