# Настройка Cloudflare Worker (MCP-шлюз для Windows Bridge)

Этот гайд описывает развёртывание облачного MCP-шлюза из папки [`cloudflare-worker/`](../cloudflare-worker/) на Cloudflare Workers (с Durable Object `DeviceHub` и KV-хранилищем для OAuth).

---

## 1. Требования

- Аккаунт Cloudflare (Workers + Durable Objects с SQLite-бэкендом + KV).
- Установленные `Node.js 20+` и `npm`.
- Установленный локально Windows Bridge v3 на целевом Windows-ПК (порт `127.0.0.1:39073`).

---

## 2. Подготовка конфигурации

1. Перейдите в папку воркера и установите зависимости:
   ```powershell
   cd cloudflare-worker
   npm install
   npx wrangler login
   ```
2. Создайте KV namespace для OAuth-сессий:
   ```powershell
   npx wrangler kv namespace create OAUTH_KV
   ```
   Скопируйте полученный `id`.
3. Скопируйте шаблон конфига:
   ```powershell
   Copy-Item wrangler.jsonc.example wrangler.jsonc
   ```
   Откройте `wrangler.jsonc` и замените `<YOUR_OAUTH_KV_NAMESPACE_ID>` на ваш реальный `id` (и при желании задайте своё имя в `"name"`).
4. Откройте `src/index.ts` и замените в начале файла две константы:
   - `ORIGIN` — на ваш реальный URL воркера (`https://<your-worker>.<your-subdomain>.workers.dev`);
   - `HOME_DEVICE` — на имя вашего Windows-ПК (вывод команды `hostname`).

---

## 3. Секреты и деплой

Задайте два случайных длинных токена (минимум 32+ символа, например через `openssl rand -hex 32`):

```powershell
npx wrangler secret put DEVICE_TOKEN
npx wrangler secret put MCP_TOKEN
```

- `DEVICE_TOKEN` — секрет, которым локальный агент на Windows-ПК авторизуется при открытии WebSocket к `DeviceHub`.
- `MCP_TOKEN` — секрет для прямого Bearer-доступа к `/mcp` (дополнительно к OAuth flow).

Разверните воркер:

```powershell
npx wrangler deploy
```

После деплоя проверьте, что воркер отвечает:
```powershell
curl.exe -s https://<your-worker>.<your-subdomain>.workers.dev/health
```

---

## 4. Подключение локального Windows-ПК

На Windows-ПК агент `prelogin-cf-agent.mjs` (в связке с `tools/cf-flight-controller/flight-controller.mjs`) держит постоянный WebSocket к Durable Object `DeviceHub` и проксирует `bridge_call` на локальный `127.0.0.1:39073/rpc`.

Укажите в локальных настройках агента (`prelogin-cf-settings.json` или переменных окружения):
- URL воркера (`wss://<your-worker>.<your-subdomain>.workers.dev/ws` / базовый `https://...`);
- имя устройства (должно совпадать с `HOME_DEVICE`);
- тот же `DEVICE_TOKEN`, что задан в Cloudflare Secrets.

Убедитесь, что в логе агента появилась запись `ONLINE`.

---

## 5. Подключение в Gemini Web / ChatGPT

1. Откройте настройки коннекторов (MCP) в Gemini Web или ChatGPT.
2. Добавьте новый MCP-сервер с URL:
   ```text
   https://<your-worker>.<your-subdomain>.workers.dev/mcp
   ```
3. Пройдите OAuth-авторизацию. После синхронизации появятся 5 инструментов:
   - `device_status`
   - `device_ping`
   - `device_exec_test`
   - `bridge_capabilities`
   - `bridge_call`
4. В настройках коннектора переключите нужные инструменты (включая `bridge_call`, если требуется автономная работа в Task Mode) на **«Разрешать всегда»** (*Always allow*).

---

## 6. Проверка работы

1. Вызовите `device_status` — должно вернуться `"online": true` и имя вашего ПК в `devices`.
2. Вызовите `device_ping` — убедитесь в успешном round-trip через Cloudflare.
3. Вызовите `bridge_call(op="ping", args={})` — подтверждает полную цепочку `MCP Client → Cloudflare Worker → DeviceHub → prelogin-cf-agent → Windows Bridge v3`.
