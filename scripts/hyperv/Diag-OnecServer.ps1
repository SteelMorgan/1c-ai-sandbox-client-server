<#
  .SYNOPSIS
  Диагностика healthcheck контейнера onec-server на удалённой Hyper-V ВМ.
  Запускать из корня репозитория.

  .EXAMPLE
  pwsh -File .\scripts\hyperv\Diag-OnecServer.ps1
#>

$ErrorActionPreference = "Continue"
try { chcp 65001 | Out-Null } catch {}

# --- Определяем корень репозитория ---
$repoRoot = $null
# 1) по расположению скрипта (scripts/hyperv/ → ../..)
if ($PSScriptRoot) {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..") -ErrorAction SilentlyContinue).Path
}
# 2) поднимаемся от текущей директории
if (-not $repoRoot -or -not (Test-Path (Join-Path $repoRoot "infra\vm\.env"))) {
  $candidate = (Get-Location).Path
  for ($i = 0; $i -lt 5; $i++) {
    if (Test-Path (Join-Path $candidate "infra\vm\.env")) { $repoRoot = $candidate; break }
    $parent = Split-Path $candidate -Parent
    if (-not $parent -or $parent -eq $candidate) { break }
    $candidate = $parent
  }
}

if (-not $repoRoot -or -not (Test-Path (Join-Path $repoRoot "infra\vm\.env"))) {
  throw "Не удалось найти корень репозитория (ищу infra/vm/.env). Запустите скрипт из корня репо или из scripts/hyperv/."
}
Write-Host "[INFO] Repo root: $repoRoot"

# --- IP из infra/vm/.env (MGMT_VM_IP) ---
$VmIp = $null
foreach ($line in (Get-Content (Join-Path $repoRoot "infra\vm\.env"))) {
  if ($line -match '^\s*MGMT_VM_IP\s*=\s*(.+)$') {
    $VmIp = $Matches[1].Trim()
    break
  }
}
if (-not $VmIp) {
  throw "MGMT_VM_IP не найден в infra/vm/.env"
}
Write-Host "[INFO] VM IP: $VmIp (из infra/vm/.env)"

# --- SSH-ключ из .cache/hyperv/_ssh/onec-infra/id_ed25519 ---
$SshUser = "sandbox"
$SshIdentityFile = Join-Path $repoRoot ".cache\hyperv\_ssh\onec-infra\id_ed25519"
if (-not (Test-Path $SshIdentityFile)) {
  throw "SSH-ключ не найден: $SshIdentityFile`nУбедитесь что ВМ была создана через New-OnecInfraVm.ps1 (он генерирует ключ)."
}
Write-Host "[INFO] SSH-ключ: $SshIdentityFile"

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
  $sshOpts += @("-o", "IdentitiesOnly=yes", "-i", $SshIdentityFile)
}

function Run-Ssh([string]$cmd) {
  $out = & ssh @sshOpts $remote "sudo bash -lc '$cmd'" 2>&1
  return ($out | Out-String)
}

$sep = "=" * 70

Write-Host $sep
Write-Host " Диагностика контейнера onec-server на $VmIp"
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host $sep
Write-Host ""

# --- 1 ---
Write-Host ">>> 1. Статус контейнера"
Write-Host (Run-Ssh 'docker inspect -f "{{.State.Status}}" onec-server 2>&1; echo "---"; docker inspect -f "{{.State.Health.Status}}" onec-server 2>&1')

# --- 2 ---
Write-Host ">>> 2. Последние 5 результатов healthcheck"
# docker inspect --format с range/if — передаём через heredoc чтобы избежать проблем с экранированием
$hcCmd = @'
docker inspect --format='{{range $i, $h := .State.Health.Log}}{{if lt $i 5}}--- check #{{$i}} (exit={{$h.ExitCode}}) ---
{{$h.Output}}
{{end}}{{end}}' onec-server 2>&1 || echo "(не удалось получить)"
'@
Write-Host (Run-Ssh $hcCmd)

# --- 3 ---
Write-Host ">>> 3. Процессы (ragent, rmngr, ras)"
Write-Host (Run-Ssh 'docker exec onec-server bash -c "ps -eo pid,comm,args 2>/dev/null | grep -E \"ragent|rmngr|ras|PID\" | grep -v grep" 2>&1 || echo "(не удалось)"')

# --- 4 ---
Write-Host ">>> 4. Слушающие порты (1540, 1541, 1545)"
Write-Host (Run-Ssh 'docker exec onec-server bash -c "ss -tlnp 2>/dev/null | grep -E \"1540|1541|1545|State\" || netstat -tlnp 2>/dev/null | grep -E \"1540|1541|1545|Proto\" || echo \"ss/netstat не найдены\"" 2>&1')

# --- 5 ---
Write-Host ">>> 5. rac cluster list"
Write-Host (Run-Ssh 'docker exec onec-server bash -lc "/opt/1cv8/current/rac cluster list 127.0.0.1:\${RAS_PORT:-1545}" 2>&1; echo "exit=$?"')

# --- 6 ---
Write-Host ">>> 6. Лицензионные файлы (/var/1C/licenses)"
Write-Host (Run-Ssh 'docker exec onec-server bash -c "echo \"Файлов: \$(find /var/1C/licenses -maxdepth 1 -type f -size +0 2>/dev/null | wc -l)\"; ls -la /var/1C/licenses/ 2>/dev/null || echo \"(каталог пуст)\"" 2>&1')

# --- 7 ---
Write-Host ">>> 7. Настройки активации"
$actCmd = @'
docker exec onec-server bash -c '
  echo "ENABLE_COMMUNITY_ACTIVATION=${ENABLE_COMMUNITY_ACTIVATION:-<не задан>}"
  if [ -s /run/secrets/dev_login ]; then
    echo "/run/secrets/dev_login: есть ($(wc -c < /run/secrets/dev_login) bytes)"
  else
    echo "/run/secrets/dev_login: ПУСТ или НЕТ"
  fi
  if [ -s /run/secrets/dev_password ]; then
    echo "/run/secrets/dev_password: есть ($(wc -c < /run/secrets/dev_password) bytes)"
  else
    echo "/run/secrets/dev_password: ПУСТ или НЕТ"
  fi
' 2>&1
'@
Write-Host (Run-Ssh $actCmd)

# --- 8 ---
Write-Host ">>> 8. Статус активации"
$actLogCmd = @'
docker exec onec-server bash -c '
  if [ -f /var/log/onec/activation.status ]; then
    echo "activation.status: $(cat /var/log/onec/activation.status)"
  else
    echo "activation.status: файл не найден"
  fi
  if [ -f /var/log/onec/activation.done ]; then
    echo "activation.done:   $(cat /var/log/onec/activation.done)"
  else
    echo "activation.done:   файл не найден"
  fi
  echo "--- Последние 30 строк activation.log ---"
  tail -n 30 /var/log/onec/activation.log 2>/dev/null || echo "(файл не найден)"
' 2>&1
'@
Write-Host (Run-Ssh $actLogCmd)

# --- 9 ---
Write-Host ">>> 9. Логи контейнера (последние 50 строк)"
Write-Host (Run-Ssh 'docker logs onec-server --tail 50 2>&1')

# --- 10 ---
Write-Host ">>> 10. Логи процессов"
foreach ($log in @("ragent.log", "rmngr.log", "ras.log")) {
  Write-Host "  --- $log ---"
  Write-Host (Run-Ssh "docker exec onec-server bash -c ""tail -n 20 /var/log/onec/$log 2>/dev/null || echo '(не найден)'"" 2>&1")
}

# --- 11 ---
Write-Host ">>> 11. Эмуляция healthcheck (пошагово)"
$emulateCmd = @'
docker exec onec-server bash -lc '
  ep="127.0.0.1:${RAS_PORT:-1545}"

  echo "[step1] rac cluster list $ep ..."
  out="$(/opt/1cv8/current/rac cluster list "$ep" 2>/dev/null || true)"
  echo "output: $out"

  id="$(printf "%s" "$out" | grep -Eo "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" | head -n1 || true)"
  echo "[step2] cluster id = \"$id\""

  if [ -z "$id" ]; then
    echo "[FAIL] cluster id пустой"
    exit 1
  fi
  if [ "$id" = "00000000-0000-0000-0000-000000000000" ]; then
    echo "[FAIL] cluster id = нулевой UUID"
    exit 1
  fi
  echo "[OK] cluster id валидный"

  # License check (informational only — does NOT affect healthcheck result).
  lic_count=$(find /var/1C/licenses -maxdepth 1 -type f -size +0 2>/dev/null | wc -l)
  echo "[step3] файлов лицензий: $lic_count"
  if [ "$lic_count" -eq 0 ]; then
    echo "[INFO] лицензий нет (пользователь может подключить USB-ключ или программную лицензию)"
    if [ -f /var/log/onec/activation.status ]; then
      echo "[INFO] activation.status: $(cat /var/log/onec/activation.status | head -n3)"
    fi
  else
    echo "[OK] лицензии найдены"
  fi

  echo ""
  echo "====> HEALTHCHECK PASSED <===="
' 2>&1
'@
Write-Host (Run-Ssh $emulateCmd)

Write-Host ""
Write-Host $sep
Write-Host " Диагностика завершена"
Write-Host $sep
