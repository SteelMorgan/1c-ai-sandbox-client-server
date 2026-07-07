## infra/vm (1С сервер + Postgres в Linux VM)

Цель: поднять инфраструктуру 1С **внутри Linux VM (Hyper‑V, bridge)**, чтобы избежать проблем идентичности/лицензирования при Docker на Windows.

### Ограничения

- Деплой/управление VM в этом репозитории ориентированы на **Windows-хост** (Hyper‑V + PowerShell скрипты).
- На Linux-хостах (KVM/QEMU, VirtualBox, и т.п.) этот сценарий **не тестировался**.

### Что тут лежит

- `docker-compose.yml` — `onec-server` + `postgres` + `onec-web` (и ручной `onec-init`, если понадобится).
- `onec-server/` — Dockerfile и entrypoint для 1С сервера (берёт локальный `.run` из `.devcontainer/distr`, иначе скачивает).
- `infobases.example.json` — пример конфига ИБ (JSON-массив) для `onec-init` (регистрация через `rac` внутри контейнера).
- `infobases.txt.example` — пример списка ИБ (по одной в строке), для **host-side** автосоздания после деплоя (см. `Deploy-OnecInfra.ps1` → `New-OnecInfobase.ps1`).

### Быстрый запуск (внутри VM)

1) Подготовь `.env` для VM/infra (не секреты):

- `cp .env.example .env`

2) Убедись, что secrets файлы созданы в `../../secrets/` (внутри VM):

- `onec_username/onec_password` — только если требуется скачивание
- `dev_login/dev_password` — для community activation
- `pg_password` — пароль для Postgres (чтобы не писать в `docker-compose.yml`)

Важно: `pg_password` должен быть **стабильным**. Если его поменять при живом `pgdata`, Postgres не начнёт принимать новый пароль.
Для ротации пароля — сбрасывай `pgdata` (в Hyper-V деплое: `Deploy-OnecInfra.ps1 -ResetPgData`).

3) Подними инфраструктуру:

```bash
cd <repo-root>
./infra/vm/up.sh
```

`up.sh` также ставит/обновляет systemd unit `onec-infra.service` и включает автозапуск, чтобы после перезагрузки VM Docker Compose стек поднимался автоматически:

```bash
sudo systemctl status onec-infra.service
sudo systemctl status docker
```

### Вариант A: зарегистрировать ИБ внутри VM (onec-init + `infobases.json`)

Если хочешь, чтобы регистрация/создание ИБ шло **внутри VM** (контейнер `onec-init`), подготовь файл:

- `infra/vm/infobases.json` (скопируй из `infra/vm/infobases.example.json`)

Файл **локальный** (под публичный репо его не коммитим; см. корневой `.gitignore`).

Запуск one-shot инициализации:

```bash
cd <repo-root>
sudo -n docker compose \
  --env-file infra/vm/.env \
  -f infra/vm/docker-compose.yml \
  --profile manual \
  up --build --abort-on-container-exit onec-init
```

### Вариант B: создать пустую ИБ после развёртки VM (host-side)

На хосте Windows (PowerShell), когда VM уже поднята и `onec-server`/`postgres` запущены:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\hyperv\New-OnecInfobase.ps1
```

Скрипт спросит:
- `Ref` (имя ИБ в кластере, используется в строке подключения `Srvr=...;Ref=...;`)
- имя БД Postgres (по умолчанию = `Ref`)

### Веб‑публикация (web‑клиент + HTTP‑сервисы)

В составе стека по умолчанию поднимается контейнер `onec-web` (Apache 2.4) и слушает порт:

- `ONEC_WEB_PORT_HOST` из `infra/vm/.env` (по умолчанию `8080`, см. `.env.example`)

Публикация управляется host‑side скриптом (PowerShell на Windows-хосте):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\hyperv\Publish-OnecInfobase.ps1 -Action Publish -InfobaseName demo
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\hyperv\Publish-OnecInfobase.ps1 -Action Update  -InfobaseName demo
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\hyperv\Publish-OnecInfobase.ps1 -Action Unpublish -InfobaseName demo
```

URL после публикации:

- `http://<VM_IP>:<ONEC_WEB_PORT_HOST>/<Ref>/`
- HTTP‑сервисы: `http://<VM_IP>:<ONEC_WEB_PORT_HOST>/<Ref>/hs/<service>`

### Автосоздание ИБ по списку (host-side)

Для автоматического создания ИБ в конце `Deploy-OnecInfra.ps1` подготовь файл:

- `infra/vm/infobases.txt` (см. `infra/vm/infobases.txt.example`)

Скрипт создаст ИБ **после** успешного старта инфраструктуры и healthcheck `onec-server`.

Остановить:

```bash
./infra/vm/down.sh
```

`down.sh` также отключает автозапуск systemd unit `onec-infra.service`, чтобы стек не поднимался снова после перезагрузки VM.

## Обновление платформы 1С в существующей VM

Штатный апгрейд платформы в этой схеме делается через пересборку контейнеров внутри уже существующей VM. Пересоздавать VM для этого не нужно.

### Важно

- В `infra/vm/.env` параметр `FORCE_RECREATE_VM` должен быть `false`.
- Если включить `FORCE_RECREATE_VM=true`, можно получить пересоздание VM вместо обновления платформы.
- Для обычного апгрейда не использовать режимы очистки данных (`ResetOnecData`, `ResetPgData`).

### Подготовка

1. Положить новый дистрибутив платформы в `.devcontainer/distr/`:
   `setup-full-<ONEC_VERSION>-x86_64.run`
2. Обновить `ONEC_VERSION` в `infra/vm/.env`.
3. Проверить, что `FORCE_RECREATE_VM=false`.
4. Сделать backup/checkpoint VM и backup данных Postgres/1С.

### Обновление

С Windows-хоста:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\hyperv\Deploy-OnecInfra.ps1 -VmIp <MGMT_VM_IP> -SshIdentityFile .\.cache\hyperv\_ssh\onec-infra\id_ed25519
```

Если VM была создана штатным сценарием `New-OnecInfraVm.ps1`, для воспроизводимого запуска рекомендуется использовать repo-managed SSH-ключ:

- `.\.cache\hyperv\_ssh\onec-infra\id_ed25519`

Иначе `ssh` может пойти с другим ключом пользователя Windows и деплой завершится ещё на preflight-проверке доступа к VM.

Или прямо внутри VM:

```bash
cd <repo-root>
./infra/vm/up.sh
```

`up.sh` выполняет `docker compose up -d --build`, поэтому `onec-server` и `onec-web` будут пересобраны на новой версии платформы, а volumes с данными останутся на месте.

### После обновления

- проверить health контейнера `onec-server`;
- проверить доступность кластера через `rac`;
- проверить открытие ИБ;
- проверить web-публикации, если используются;
- затем отдельно пересобрать клиентский devcontainer на хосте.

## Лицензирование

Healthcheck контейнера `onec-server` проверяет **только** работоспособность кластера (rac cluster list). Наличие лицензии **не является** условием healthy-статуса: пользователь может подключить USB-ключ, программную лицензию, или использовать community-активацию.

### Community-активация

При наличии секретов `dev_login`/`dev_password` контейнер автоматически пытается активировать community-лицензию при старте. Логи активации: `/var/log/onec/activation.log`, статус: `/var/log/onec/activation.status`.

### Типичные ошибки активации

**"Ответ Центра лицензирования не соответствует введенным данным лицензии или владельца"**

Две возможные причины:

1. **Неверные учётные данные** — проверьте `secrets/dev_login` и `secrets/dev_password`, они должны совпадать с аккаунтом portal.1c.ru.

2. **Лицензия привязана к другому билду** — community-лицензия привязана к **конкретному билду** платформы (например `8.3.27.2074`), а не к мажорной версии `8.3.27`. Если платформа обновлена даже на патч-релиз — старая лицензия перестанет работать.

   Решение:
   - Вернуться на версию платформы, на которую была получена лицензия, **или**
   - Удалить старую лицензию в ЛК https://users.v8.1c.ru и запросить новую под текущий билд (`ONEC_VERSION` из `infra/vm/.env`)

После исправления причины — перезапустите контейнер, активация запустится заново:

```bash
sudo docker compose -f infra/vm/docker-compose.yml restart onec-server
```

## (Опционально) Webhook для рестарта 1С из dev-контейнера

Маленький HTTP-сервис на ВМ, позволяющий перезапускать контейнеры `onec-server` / `onec-web` **без SSH-доступа** — только по Bearer-токену. Полезно, когда рестарт нужно дёргать из dev-контейнера, CI, мониторинга или прямо из 1С-кода (HTTP-запрос), а раздавать SSH-ключ от ВМ туда нежелательно.

Если рестарт нужен только лично тебе с этой машины — проще без webhook'а:

```bash
ssh -i .cache/hyperv/_ssh/onec-infra/id_ed25519 sandbox@<MGMT_VM_IP> 'sudo docker restart onec-server'
```

### Что устанавливается

- `/opt/onec-restart/restart_svc.py` — HTTP-сервис (stdlib, без зависимостей), слушает `:8765`.
- `/etc/systemd/system/onec-restart.service` — systemd unit под пользователем `sandbox`, автозапуск.
- `/etc/onec-restart/token` — Bearer-токен (`root:sandbox 640`).
- ufw-правило: `8765/tcp` открыт **только из mgmt-сети `192.168.250.0/24`**.
- Whitelist контейнеров (в unit): `onec-server`, `onec-web` — других рестартовать нельзя.
- `usermod -aG docker sandbox` (если cloud-init этого не сделал).

Исходники сервиса лежат в `infra/vm/restart-svc/`.

### Установка / обновление

Из dev-контейнера или git-bash на хосте (требуется SSH-ключ из `.cache/hyperv/_ssh/onec-infra/`):

```bash
./scripts/install-restart-svc.sh
```

Скрипт идемпотентен — повторный запуск обновит файлы и перезапустит сервис, используя **тот же** токен, если `secrets/onec_restart_token` уже существует.

При первом запуске будет сгенерирован 32-байтный токен (`secrets.token_hex(32)`) и записан в:
- `/etc/onec-restart/token` на ВМ;
- `secrets/onec_restart_token` в репозитории (под общим `.gitignore` для `secrets/*`).

### Использование

Из dev-контейнера (ВМ резолвится по имени `onec-infra` через `.devcontainer/sync-onec-infra-hosts.sh`):

```bash
.devcontainer/bin/restart-1c            # рестарт onec-server (по умолчанию)
.devcontainer/bin/restart-1c onec-web   # рестарт onec-web
```

Или curl'ом напрямую:

```bash
curl -X POST \
  -H "Authorization: Bearer $(cat secrets/onec_restart_token)" \
  http://onec-infra:8765/restart/onec-server
```

Health-эндпоинт (без авторизации):

```bash
curl http://onec-infra:8765/health
# {"status": "ok", "allowed": ["onec-server", "onec-web"]}
```

Логи сервиса:

```bash
ssh sandbox@onec-infra 'sudo journalctl -u onec-restart.service -f'
```

### Ротация токена

```bash
rm secrets/onec_restart_token
./scripts/install-restart-svc.sh
```

### Удаление

```bash
./scripts/install-restart-svc.sh --uninstall
```

Локальный файл `secrets/onec_restart_token` после `--uninstall` не удаляется — снеси вручную, если он больше не нужен.

## Обратный канал: onec-infra → песочница (v8-session-manager)

Иногда нужно, чтобы **1С-сервер в VM** достучался **в обратную сторону** — до `v8-session-manager`
песочницы (`ws://.../sessions`, порт `:4000` внутри контейнера `1c-ai-sandbox`).

### Почему «в лоб» не работает

Песочница и `onec-infra` живут в **разных гипервизорах**:

- `1c-ai-sandbox` — контейнер в **Docker Desktop (WSL2)**. Его сети (`infra` `192.168.0.0/24`,
  IP `192.168.0.10`, шлюз `192.168.65.254`) — приватные внутри Docker Desktop, заNATлены и
  **снаружи не маршрутизируются**. Пробросить с VM маршрут на `192.168.0.x` / `192.168.65.x`
  нельзя — за `192.168.250.1` этих подсетей нет.
- `onec-infra` — отдельная **Hyper-V VM**.

Контейнер Docker Desktop **нельзя подключить к Hyper-V-свитчу** (`onec-external` / `onec-mgmt`).
Поэтому единственный мост — **через Windows-хост**: published-порт Docker Desktop +
проброс на mgmt-интерфейс, который VM видит.

### Постоянная схема

```
onec-infra (192.168.250.2)
  → 192.168.250.1:14000        Windows-хост, vEthernet (onec-mgmt)
  → netsh portproxy → 127.0.0.1:14000
  → Docker Desktop published 14000→4000
  → 1c-ai-sandbox: v8-session-manager :4000
manager_url = ws://192.168.250.1:14000/sessions
```

Выбран mgmt-свитч `192.168.250.0/24` (а не LAN `onec-external`): IP хоста статический,
канал приватный host↔VM, и проект уже стандартизировал на нём host↔VM трафик
(SSH, restart-webhook с `ufw allow 192.168.250.0/24`).

### Что устанавливается

- Публикация портов `14000→4000` / `14001→4001` уже зашита в `.devcontainer/docker-compose.yml`
  (переживает пересоздание контейнера).
- На Windows-хосте — `netsh portproxy` + inbound-правило брандмауэра, **сужённое до
  `192.168.250.0/24`**. Отдельного приложения/демона нет: сам проброс держит штатная
  служба Windows **IP Helper (`iphlpsvc`)**, конфиг персистентен и переживает перезагрузку.

### Установка (Windows-хост, от администратора)

```powershell
# 1. Пересоздать контейнер с публикацией портов
docker compose -f .devcontainer\docker-compose.yml up -d

# 2. Поднять портпрокси + firewall-правило (идемпотентно)
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\hyperv\Set-SandboxV8smPortProxy.ps1
```

Скрипт читает `MGMT_HOST_IP` из `infra/vm/.env` (по умолчанию `192.168.250.1`), при
необходимости включает `iphlpsvc` и печатает итоговую таблицу `portproxy`.

### Проверка (с onec-infra)

```bash
timeout 3 bash -lc '</dev/tcp/192.168.250.1/14000' && echo open
```

→ `manager_url = ws://192.168.250.1:14000/sessions`

### Удаление

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\hyperv\Set-SandboxV8smPortProxy.ps1 -Remove
```
