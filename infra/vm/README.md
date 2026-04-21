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
