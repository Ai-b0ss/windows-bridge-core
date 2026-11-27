# Настройка Cloudflare Worker (MCP-шлюз для Windows Bridge)

Этот гайд описывает независимое развёртывание облачного MCP-шлюза из папки [`cloudflare-worker/`](../cloudflare-worker/) на Cloudflare Workers (Durable Object `DeviceHub` + KV для OAuth) и подключение локального Windows Bridge v3 через воспроизводимый клиент [`cloudflare-worker/agent/cf-bridge-agent.mjs`](../cloudflare-worker/agent/cf-bridge-agent.mjs).

---

## 1. Требования

- Аккаунт Cloudflare (Workers + Durable Objects с SQLite-бэкендом + KV).
- `Node.js 20+` и `npm`.
- Запущенный локальный Windows Bridge v3 на целевом Windows-ПК (loopback RPC, по умолчанию `http://127.0.0.1:39073/rpc`).

---

## 2. Подготовка и деплой Worker

1. Установите зафиксированные зависимости (`package-lock.json`):
   ```powershell
   cd cloudflare-worker
   npm ci
   npx wrangler login
   ```
2. Создайте KV namespace для OAuth-сессий:
   ```powershell
   npx wrangler kv namespace create OAUTH_KV
   ```
3. Создайте рабочий `wrangler.jsonc` из шаблона:
   ```powershell
   Copy-Item wrangler.jsonc.example wrangler.jsonc
   ```
   Замените `<YOUR_OAUTH_KV_NAMESPACE_ID>` на реальный ID и при желании задайте своё имя воркера в `"name"`.
4. В `src/index.ts` замените в начале файла две константы:
   - `ORIGIN` → ваш URL воркера (`https://<your-worker>.<your-subdomain>.workers.dev`);
   - `HOME_DEVICE` → имя вашего Windows-ПК (`hostname`).
5. Задайте два случайных длинных секрета (минимум 32+ байта):
   ```powershell
   npx wrangler secret put DEVICE_TOKEN
   npx wrangler secret put MCP_TOKEN
   ```
   - `DEVICE_TOKEN` — Bearer-токен, которым WebSocket-агент авторизуется на `/ws`.
   - `MCP_TOKEN` — owner-секрет для получения cookie `__Host-FF_OWNER` на `/bootstrap` и подписи OAuth-подтверждений на `/approve`. Сам маршрут `/mcp` защищён строго через `OAuthProvider` (OAuth 2.1 access/refresh tokens).
6. Выполните деплой и проверку `/health`:
   ```powershell
   npx wrangler deploy
   curl.exe -s https://<your-worker>.<your-subdomain>.workers.dev/health
   ```
   Ожидаемый ответ: `{"ok":true,"service":"windows-bridge-mcp"}`.

---

## 3. Подключение локального Windows-ПК (`cf-bridge-agent.mjs`)

1. Скопируйте шаблон конфигурации клиента:
   ```powershell
   Copy-Item cloudflare-worker/agent/cf-agent-settings.example.json cloudflare-worker/agent/cf-agent-settings.json
   ```
2. Заполните поля (или передайте через переменные окружения `FF_MCP_BASE`, `FF_DEVICE_NAME`, `FF_RPC_URL`, `FF_DEVICE_TOKEN_FILE`, `FF_RPC_SECRET_FILE`):
   - `workerBaseUrl`: `https://<your-worker>.<your-subdomain>.workers.dev`
   - `wsPath`: `/ws` (совпадает с маршрутом в `src/index.ts`)
   - `deviceName`: имя вашего ПК (совпадает с `HOME_DEVICE`)
   - `rpcUrl`: адрес локального loopback RPC (например, `http://127.0.0.1:39073/rpc`)
   - `deviceTokenFile` и `rpcSecretFile`: пути к локальным файлам с секретами вне репозитория (доступ только для текущего пользователя).
3. Запустите клиент:
   ```powershell
   node cloudflare-worker/agent/cf-bridge-agent.mjs
   ```
   В логе должна появиться строка `ONLINE <ваш_ПК>`. Клиент использует `tools/cf-flight-controller/flight-controller.mjs` — длинные операции передаются через soft handover, а мутации после неизвестного исхода автоматически не повторяются.

---

## 4. Owner-only OAuth bootstrap для ChatGPT и Gemini Web

1. В браузере, где открыт ChatGPT или Gemini Web, перейдите на:
   ```text
   https://<your-worker>.<your-subdomain>.workers.dev/bootstrap
   ```
2. Введите ваш `MCP_TOKEN` и нажмите **Authorize owner browser** — воркер выдаст `HttpOnly; Secure; SameSite=Lax` cookie `__Host-FF_OWNER`. (Если вы перейдёте на `/authorize` без cookie, воркер автоматически перенаправит вас на `/bootstrap?return_to=...` и вернёт обратно после ввода токена.)
3. В настройках MCP-коннекторов ChatGPT или Gemini Web добавьте сервер:
   ```text
   https://<your-worker>.<your-subdomain>.workers.dev/mcp
   ```
4. Пройдите OAuth flow (DCR `/register` → `/authorize` → `/approve` → `/token`).

---

## 5. Инструменты и политика подтверждений

После подключения доступны 5 инструментов с корректными MCP-аннотациями (из `src/bridge-tool-policy.ts`):
- **Read-only (`readOnlyHint: true`, `destructiveHint: false`):** `device_status`, `device_ping`, `device_exec_test`, `bridge_capabilities`.
- **Универсальный / мутирующий (`readOnlyHint: false`, `destructiveHint: true`, `idempotentHint: false`):** `bridge_call`.

> **Безопасность:** не включайте *Always allow* для мутирующих операций `bridge_call` по умолчанию. Оставляйте ручное подтверждение для `bridge_call` (или ограничивайте расширенные права только собственным доверенным устройством).

---

## 6. Проверка работы

1. `device_status` → `"online": true` и имя вашего ПК.
2. `device_ping` → успешный round-trip через Cloudflare.
3. `bridge_call(op="ping", args={})` → подтверждает полную цепочку `MCP Client → Worker → DeviceHub (/ws) → cf-bridge-agent → Windows Bridge v3`.
4. Негативная проверка: запрос на `/ws` с неверным `Authorization: Bearer` должен возвращать `401 Unauthorized`.
