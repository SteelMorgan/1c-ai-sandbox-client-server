# Инструкция: перенос конфигурации CLI-агентов в соседний проект

## Контекст

В проекте `SteelMorgan/ai-sandbox` настроена работа трёх AI CLI-агентов
(**Claude Code**, **Codex**, **Gemini CLI**) внутри devcontainer-песочницы.
Все они подключены к единому кастомному OpenAI-совместимому бэкенду (9Router)
через общий API key. Задача — скопировать этот подход в соседний проект.

---

## Исходные файлы (брать отсюда)

Репозиторий: `https://github.com/SteelMorgan/ai-sandbox`
Ветка: `main`

```
.devcontainer/
├── Dockerfile                          # установка CLI + копирование файлов в образ
├── postCreateCommand.sh                # оркестратор: запускает все bootstrap-скрипты
├── .env                                # не-секретные настройки (модели, URLs, флаги)
├── cli-agents/
│   ├── claude/
│   │   ├── helper.mjs                  # настройка Claude Code под кастомный бэкенд
│   │   └── tools/
│   │       ├── claude-safe.sh          # wrapper для запуска claude
│   │       └── statusline.js           # statusline для Claude Code UI
│   ├── codex/
│   │   ├── bootstrap.sh                # настройка Codex CLI
│   │   ├── model-map.json              # маппинг cx/* алиасов → upstream slugs
│   │   └── model-overrides.json        # ручные overrides для ag/* моделей
│   └── gemini/
│       ├── bootstrap.sh                # настройка Gemini CLI
│       └── prompt.md                   # fallback системный промт (не используется — берётся из репо Codex)
```

---

## Архитектура — как это работает

### Уровень 1: Dockerfile
- Устанавливает Node.js 22 LTS (нужен для всех трёх CLI)
- Устанавливает CLI глобально через npm:
  ```dockerfile
  RUN npm install -g @anthropic-ai/claude-code
  RUN npm install -g @openai/codex
  RUN npm install -g @google/gemini-cli
  ```
- Копирует все файлы из `cli-agents/` в образ по пути
  `/usr/local/share/agent-sandbox/cli-agents/` — это fallback на случай,
  если workspace volume пустой при первом старте
- Обязательно делает `sed -i 's/\r$//'` на все `.sh` файлы
  (Windows CRLF → Linux LF)

### Уровень 2: postCreateCommand.sh (оркестратор)
Запускается при каждом открытии devcontainer. Логика для каждого CLI:
```bash
# Сначала пробует workspace-локальную копию (актуальная версия из репо)
# Если нет — fallback на копию в образе (бэкап на момент сборки)
if [[ -f "/workspaces/work/.devcontainer/cli-agents/codex/bootstrap.sh" ]]; then
  bash /workspaces/work/.devcontainer/cli-agents/codex/bootstrap.sh \
    || bash /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh
else
  bash /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh
fi
```
Это позволяет обновлять bootstrap-скрипты без пересборки образа.

### Уровень 3: cli-agents/*/bootstrap.sh (конфигурация CLI)
Каждый bootstrap-скрипт:
- Читает настройки из env vars (инжектируются из `.env`)
- Читает секреты из Docker secrets (`/run/secrets/cc_api_key`)
- Пишет конфиги в домашнюю директорию пользователя (`~/.claude/`, `~/.gemini/`, `~/.codex/`)
- Идемпотентен (можно запускать повторно)

### Уровень 4: .env (параметры)
Содержит только **не-секретные** значения. Секреты (API key) — через Docker secrets.

---

## Пошаговая инструкция

### Шаг 1: Скопировать файлы

Скопировать целиком папку `.devcontainer/cli-agents/` из исходного репо в целевой проект.

Дополнительно нужны файлы-оркестраторы (если их нет в целевом проекте):
- `.devcontainer/postCreateCommand.sh`
- `.devcontainer/entrypoint.sh`
- `.devcontainer/gh-auth-bootstrap.sh`

### Шаг 2: Обновить Dockerfile

Добавить в Dockerfile целевого проекта:

```dockerfile
# Node.js 22 LTS (если нет — нужен для всех трёх CLI)
RUN set -eux; \
  mkdir -p /etc/apt/keyrings; \
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list; \
  apt-get update -o Acquire::ForceIPv4=true -o Acquire::Retries=3; \
  apt-get install -y --no-install-recommends nodejs; \
  rm -rf /var/lib/apt/lists/*

# Создать директории в образе
RUN mkdir -p /usr/local/share/agent-sandbox/cli-agents/claude/tools \
             /usr/local/share/agent-sandbox/cli-agents/codex \
             /usr/local/share/agent-sandbox/cli-agents/gemini

# Скопировать файлы CLI-агентов
COPY cli-agents/claude/helper.mjs            /usr/local/share/agent-sandbox/cli-agents/claude/helper.mjs
COPY cli-agents/claude/tools/claude-safe.sh  /usr/local/share/agent-sandbox/cli-agents/claude/tools/claude-safe.sh
COPY cli-agents/claude/tools/statusline.js   /usr/local/share/agent-sandbox/cli-agents/claude/tools/statusline.js
COPY cli-agents/codex/bootstrap.sh           /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh
COPY cli-agents/codex/model-map.json         /usr/local/share/agent-sandbox/cli-agents/codex/model-map.json
COPY cli-agents/codex/model-overrides.json   /usr/local/share/agent-sandbox/cli-agents/codex/model-overrides.json
COPY cli-agents/gemini/bootstrap.sh          /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh
COPY cli-agents/gemini/prompt.md             /usr/local/share/agent-sandbox/cli-agents/gemini/prompt.md

# Убрать Windows CRLF
RUN sed -i 's/\r$//' \
      /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/tools/claude-safe.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/tools/statusline.js \
  && chmod +x \
      /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/tools/claude-safe.sh

# Установить CLI
RUN npm install -g @anthropic-ai/claude-code
RUN npm install -g @openai/codex
RUN npm install -g @google/gemini-cli
```

### Шаг 3: Обновить postCreateCommand.sh

Добавить вызовы bootstrap-скриптов (перед секцией Claude):

```bash
# Codex bootstrap
if [[ "${CUSTOM_OPENAI_ENABLED:-0}" == "1" ]]; then
  if [[ -f "/workspaces/work/.devcontainer/cli-agents/codex/bootstrap.sh" ]]; then
    bash /workspaces/work/.devcontainer/cli-agents/codex/bootstrap.sh \
      || bash /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh || true
  else
    bash /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh || true
  fi
fi

# Gemini bootstrap
if [[ "${CUSTOM_OPENAI_ENABLED:-0}" == "1" ]]; then
  if [[ -f "/workspaces/work/.devcontainer/cli-agents/gemini/bootstrap.sh" ]]; then
    bash /workspaces/work/.devcontainer/cli-agents/gemini/bootstrap.sh \
      || bash /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh || true
  else
    bash /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh || true
  fi
fi
```

Для Claude — в postCreateCommand.sh обновить пути к helper и statusline:
```bash
helper="/workspaces/work/.devcontainer/cli-agents/claude/helper.mjs"
helper_fallback="/usr/local/share/agent-sandbox/cli-agents/claude/helper.mjs"
# ...
local statusline_js="/usr/local/share/agent-sandbox/cli-agents/claude/tools/statusline.js"
```

### Шаг 4: Настроить .env

Добавить в `.devcontainer/.env` целевого проекта:

```ini
## --- Общие настройки кастомного бэкенда ---
CUSTOM_OPENAI_ENABLED=1
OPENAI_BASE_URL=https://ai.gbig.holdings/v1   # ← URL своего бэкенда

## --- Claude Code ---
CC_HELPER_VALIDATE_MODE=anthropic
CC_HELPER_MODEL=sonnet
CC_HELPER_ALIAS_OPUS=opus
CC_HELPER_ALIAS_SONNET=sonnet
CC_HELPER_ALIAS_HAIKU=haiku
CC_HELPER_API_TIMEOUT_MS=30000
CC_HELPER_DISABLE_NONESSENTIAL_TRAFFIC=1
CC_HELPER_SKIP_VALIDATE=0
CC_HELPER_SKIP_UPDATE=1

## --- Codex ---
CODEX_MODEL=cx/gpt-5.3-codex
CODEX_MODELS=cx/gpt-5.3-codex, cx/gpt-5.3-codex-high, ...   # список моделей
CODEX_MODEL_PROVIDER_ID=9R
CODEX_MODEL_PROVIDER_NAME=9Router
CODEX_WIRE_API=responses
CODEX_SOURCE_MODELS_URL=https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/models.json
CODEX_MODEL_MAP_FILE=/workspaces/work/.devcontainer/cli-agents/codex/model-map.json
CODEX_MODEL_OVERRIDES_FILE=/workspaces/work/.devcontainer/cli-agents/codex/model-overrides.json
# CODEX_GEMINI_PROMPT_FILE=   ← не задавать, будет браться свежий из репо Codex

## --- Gemini CLI ---
GEMINI_MODEL=gemini-pro-high        # имя модели на бэкенде
GEMINI_MODEL_PRO_LOW=gemini-pro-low
GEMINI_MODEL_FLASH=gemini-3-flash
```

**Важно:** `OPENAI_BASE_URL` должен заканчиваться на `/v1`.
Gemini bootstrap сам строит правильный URL: `${BASE_URL%/v1}/api`.

### Шаг 5: Настроить Docker secrets

API key передаётся через Docker secret, **не** через `.env`.
В `docker-compose.yml` целевого проекта:

```yaml
secrets:
  cc_api_key:
    file: ../secrets/cc_api_key.txt   # путь к файлу с ключом

services:
  app:
    secrets:
      - cc_api_key
```

Bootstrap-скрипты читают ключ из `/run/secrets/cc_api_key`.

---

## Ключевые нюансы

### Gemini CLI — URL бэкенда
Gemini CLI использует `GOOGLE_GEMINI_BASE_URL`. Если бэкенд — 9Router,
нужно добавить `/api` суффикс, потому что Gemini API роут живёт на `/api/v1beta/`,
а не на `/v1beta/` напрямую:
```bash
GEMINI_BASE_URL="${OPENAI_BASE_URL%/v1}/api"
# https://ai.gbig.holdings/v1 → https://ai.gbig.holdings/api
```
Это уже сделано в `cli-agents/gemini/bootstrap.sh`.

### Gemini CLI — маппинг моделей
Gemini CLI внутри использует имена вида `gemini-2.5-pro`, `gemini-2.5-flash` и т.д.
В `settings.json` через `modelConfigs.customOverrides` они перенаправляются
на реальные модели бэкенда. Логика в `cli-agents/gemini/bootstrap.sh`.

### Codex — model-map.json и model-overrides.json
- `model-map.json` — маппинг коротких алиасов (`cx/*`) на реальные upstream slugs
- `model-overrides.json` — ручные overrides для моделей без upstream маппинга (`ag/*`)
Эти файлы специфичны для конкретного набора моделей на бэкенде.
При переносе — проверить актуальность содержимого.

### 9Router — SSE формат
Если бэкенд — 9Router, и используется Gemini CLI, нужно убедиться что
в 9Router применён патч конвертации SSE формата:
`src/app/api/v1beta/models/[...path]/route.js` — функция `transformOpenAISSEToGeminiSSE()`.
Без него Gemini CLI падает с ошибкой `"[DONE]" is not valid JSON`.
PR с патчем: `https://github.com/decolua/9router/pull/225`

---

## Проверка после установки

```bash
# Claude Code
claude --version
claude "скажи привет"

# Codex
codex --version
codex "скажи привет"

# Gemini CLI (gg — алиас из bootstrap)
gg --version
gg "скажи привет"
```

Если что-то не работает — смотреть логи postCreateCommand.sh
(они видны в терминале при открытии devcontainer).
