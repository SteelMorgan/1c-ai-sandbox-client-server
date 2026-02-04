## Secrets (локально, не коммитим)

Эта папка нужна для файлов-секретов, которые монтируются в контейнеры как `/run/secrets/*`.

### Какие файлы нужны

- `onec_username`, `onec_password` — учётка `releases.1c.ru` (нужна **только если** локального установщика нет и образ должен скачать дистрибутив во время сборки).
- `dev_login`, `dev_password` — учётка `developer.1c.ru` (community activation).
- `github_token` — GitHub PAT для `gh` внутри devcontainer (монтируется как `/run/secrets/github_token` и используется для автоматического `gh auth login`).
- `pg_password` — пароль Postgres (монтируется как `/run/secrets/pg_password` и используется и Postgres-контейнером, и скриптами создания ИБ).

### Как подготовить

1) Скопируй шаблон:

- `.env.example` → `.env` (файл не коммитится, см. `.gitignore`)

2) Запусти генератор:

```bash
./scripts/prepare-secrets.sh
```

На Windows (PowerShell 7/5.1) без bash/WSL:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\prepare-secrets.ps1
```

Скрипт создаст/перезапишет файлы `onec_username`, `onec_password`, `dev_login`, `dev_password` с правами `0600`.

### Важно про `pg_password` (чтобы деплой был воспроизводимым)

- Если `PG_PASSWORD` **задан** в `secrets/.env`, он будет записан в `secrets/pg_password`.
- Если `PG_PASSWORD` **не задан**, `secrets/pg_password` будет **сгенерирован один раз** и дальше сохраняется (не ротируется на каждом деплое).
- Если `secrets/pg_password` уже существует и **отличается** от `PG_PASSWORD`, скрипт **упадёт** (иначе ты получишь неработающий Postgres с существующим `pgdata` и ошибки “password authentication failed”).
  - Чтобы сознательно перезаписать — выставь `FORCE_OVERWRITE_PG_PASSWORD=1` и **сбрось** Postgres data volume (в Hyper-V деплое: `Deploy-OnecInfra.ps1 -ResetPgData`).

