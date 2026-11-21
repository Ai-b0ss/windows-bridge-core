# Руководство владельца: безопасное переключение (P0 Production Cutover), откат и гигиена Playwright

> **ВАЖНО:** Данный регламент выполняется **только после явного подтверждения владельца**. Никакие команды из этого документа не должны запускаться автоматически во время аудита, разработки или локальных тестов.
>
> Все пути в документе параметризованы (`<BRIDGE_ROOT>`, `<CHECKOUT>`, `<RECOVERY_ROOT>`, `<USER_HOME>`) в соответствии с политикой публичного репозитория.

---

## 0. Цели P0-переключения

Переключение устраняет следующие подтверждённые дефекты эксплуатации:

1. **Split-brain контуров runtime:** консолидация всех сервисов (`39073` Primary Bridge, `39076` Prelogin Bridge, `39090` Shared Agent Hub, Browser Hub `ff_browser_hub.mjs` и всех MCP-клиентов AGY / Claude Desktop / Codex / Cursor / OpenCode) на **единый проверенный 40-символьный Git SHA** и **единый чистый корень `playwright-core 1.65.1`**.
2. **Основной скрытый owner-auth маршрут браузера (`owner_chrome_profile1_hidden_secondary`):** скрытый windowless-контекст внутри **уже запущенного Google Chrome (`Profile 1`)** с наследованием авторизованных сессий, без копирования профиля/cookies, без видимых окон/вкладок и с жёстким fail-closed при нарушении предусловий — с чётким отделением от дополнительного изолированного режима (`managed_browser` / `private_browser`) и видимой группы вкладок расширения (`browser` / `owner_chrome_extension`).
3. **Защита от тихого отката после перезагрузки:** переход от ручной правки `$agent` в `ff_win_v3_keeper.ps1` к атомарному проверенному указателю `<BRIDGE_ROOT>\state\active-release.json` (`schema: ff-bridge-active-release/v1`), который хранитель проверяет по SHA-256 манифеста и каждого файла перед запуском.
4. **Достоверное происхождение релизов (`release-manifest.json` / `installed-runtime-manifest.json`):** исключение устаревших предковых коммитов (`c034e527...`, `abd6666...`, `8f510489...`) и принудительная проверка реального 40-символьного Git SHA.
5. **Гигиена безопасности Playwright (`coreBundle.js`):** замена локально пропатченного `bridge-v3\node_modules\playwright-core\lib\coreBundle.js` (отладочный `writeFileSync` URL/токена в `pw_connect_url.txt`) на чистый закреплённый `playwright-core 1.65.1` и ротация токена расширения Chrome **только с явного подтверждения владельца**.

---

## 1. Предварительные проверки (строго read-only)

1. **Проверить свободное место на дисках (`C:` и том `<BRIDGE_ROOT>`):**
   - Перед созданием холодного снимка и нового релиза убедитесь, что на обоих томах достаточно свободного места (рекомендуется не менее `5–10 GB` на системном диске и на томе `<BRIDGE_ROOT>`). При критически малом остатке сначала освободите место согласованными инструментами (без удаления `backups/`, `.cua-deploy/`, `state/chat-permission.json`, `stop.flag` и `secret`).
2. **Зафиксировать целевой коммит `<TARGET_SHA>` (40-символьный hex из `origin/main` после merge PR и зелёного CI):**
   ```powershell
   git -C <CHECKOUT> fetch origin
   git -C <CHECKOUT> rev-parse --verify origin/main^{commit}
   ```
3. **Проверить, что в целевом checkout настроен `core.autocrlf=false`, дерево чистое, и все тесты пройдены:**
   ```powershell
   git -C <CHECKOUT> config --get core.autocrlf
   git -C <CHECKOUT> status --short
   python -m unittest discover -s tests -p "test_*.py"
   python tests/integration/isolated_rpc_smoke.py
   ```
4. **Если `%LOCALAPPDATA%\FF-Windows-Bridge` является NTFS Junction на `<BRIDGE_ROOT>`:**
   - Все команды развёртывания, снимков и проверки паритета передавайте с **физическим** путём `<BRIDGE_ROOT>` (защита `DEPLOY_REPARSE_OR_TYPE_FORBIDDEN` намеренно блокирует запись сквозь reparse-точку).

---

## 2. Шаг 1 — Холодный снимок отката и автономный комплект восстановления

До остановки любых боевых процессов создайте неизменяемый SHA-проверенный снимок и внешний комплект восстановления за пределами `<BRIDGE_ROOT>\bridge-v3`:

```powershell
# 1.1 Read-only проверка происхождения текущего bridge-v3 (подставьте подтверждённый <TRUSTED_HEAD>)
python <CHECKOUT>\tools\cua_cold_rollback_bundle.py preflight `
  --repo <CHECKOUT> `
  --runtime <BRIDGE_ROOT>\bridge-v3 `
  --trusted-head <TRUSTED_HEAD> `
  --candidate-ref <TARGET_SHA>

# 1.2 Захват неизменяемого снимка (сохраняет файлы, previous-manifest.json и при наличии previous-active-release.json)
python <CHECKOUT>\tools\cua_cold_rollback_bundle.py capture `
  --repo <CHECKOUT> `
  --runtime <BRIDGE_ROOT>\bridge-v3 `
  --snapshot <RECOVERY_ROOT>\pre-p0-cutover `
  --trusted-head <TRUSTED_HEAD> `
  --candidate-ref <TARGET_SHA>

python <CHECKOUT>\tools\cua_cold_rollback_bundle.py verify `
  --snapshot <RECOVERY_ROOT>\pre-p0-cutover

# 1.3 Автономный комплект восстановления (7 независимых модулей вне bridge-v3)
python <CHECKOUT>\tools\cua_cold_rollback_bundle.py kit `
  --repo <CHECKOUT> `
  --kit-root <RECOVERY_ROOT>\pre-p0-cutover\kit `
  --candidate-ref <TARGET_SHA>

python <CHECKOUT>\tools\cua_cold_rollback_bundle.py verify-kit `
  --kit-root <RECOVERY_ROOT>\pre-p0-cutover\kit
```

> Также сделайте резервную копию текущих MCP-конфигов клиентов (`Claude`, `Codex`, `Cursor`, `Antigravity`, `OpenCode`) и `hub-start-config.json` в `<RECOVERY_ROOT>\pre-p0-cutover\client-configs\`. Не копируйте секреты в публичный репозиторий.

---

## 3. Шаг 2 — Сборка и верификация единого кандидатного релиза

1. **Разверните единый каталог релиза `<RELEASE_DIR> = <BRIDGE_ROOT>\runtime-releases\p0-<SHORT_SHA>\bridge-v3` из зафиксированного Git-коммита:**
   ```powershell
   python <CHECKOUT>\runtime\bridge-v3\cua_runtime_deploy.py apply `
     --repo <CHECKOUT> `
     --runtime-root <BRIDGE_ROOT>\runtime-releases\p0-<SHORT_SHA>\bridge-v3 `
     --ref <TARGET_SHA> `
     --strict-external-validation
   ```
2. **Подключите чистый закреплённый `playwright-core 1.65.1`** (скопируйте/установите чистый `node_modules` в `<RELEASE_DIR>` либо укажите единый проверенный неизменяемый `<PLAYWRIGHT_ROOT>`, не зависящий от временных canary-каталогов `state\universal-agent-canary-*`).
3. **Запустите fail-closed проверку целостности Playwright `coreBundle.js` и паритета релиза ДО переключения:**
   ```powershell
   python <RELEASE_DIR>\cua_playwright_integrity.py --playwright-root <PLAYWRIGHT_ROOT> --json
   python <CHECKOUT>\tools\runtime_parity.py `
     --installed <RELEASE_DIR> `
     --ref <TARGET_SHA> `
     --repo <CHECKOUT> `
     --require-manifest `
     --playwright-root <PLAYWRIGHT_ROOT> `
     --disk
   ```
   - Ожидается: `status: "clean"`, `finding_count: 0`, `parity: true`, `manifest_provenance.ok: true`, `playwright_integrity.ok: true`, код возврата `0`.
   - При любом несоответствии или признаке локального патча в `coreBundle.js` **остановите процедуру**.
4. **Проверьте preflight Browser Hub на новом релизе:**
   ```powershell
   node <RELEASE_DIR>\ff_browser_hub.mjs --preflight --playwright-root <PLAYWRIGHT_ROOT>
   ```
   - Ожидается `available: true` без ошибок ABI и без зависимости от временных каталогов.

---

## 4. Шаг 3 — Включение основного маршрута `owner_chrome_profile1_hidden_secondary` (только с явного opt-in владельца)

Основной P0-маршрут для авторизованной работы в уже открытом Chrome владельца реализован модулем `runtime/bridge-v3/cua_owner_chrome_secondary.py` и подключён через Hub (`op: "owner_chrome_hidden"`, класс риска `owner_chrome_hidden_secondary`, явный opt-in `/agent/v1` scope `owner_chrome_hidden` и MCP-инструменты).

### 4.1 Обязательные предусловия и механизм работы
1. **Google Chrome `158+` (`>= 158.0.8127.2`)** с уже открытым окном нужного профиля **`Profile 1`**.
2. **Явный локальный opt-in владельца в Chrome:** открыть `chrome://inspect/#remote-debugging` в рабочем Chrome и включить loopback browser-level remote debugging (только `127.0.0.1`, без запуска второго процесса `chrome.exe` на том же `User Data` и без копирования каких-либо файлов профиля или cookies).
3. **Требование единого активного `defaultBrowserContextId` (`Profile 1`):**
   - Механизм `Target.createTarget({url: "about:blank", hidden: true})` + `Emulation.setDeviceMetricsOverride(1280x800)` привязывается к `defaultBrowserContextId` запущенного Chrome.
   - Если в Chrome одновременно активен другой профиль (например, `Default`) или более одного профильного контекста, модуль гарантированно завершается **fail-closed** с ошибкой `OWNER_CHROME_PROFILE_CONTEXT_MISMATCH`.
4. **Гарантии незаметности и fail-closed:**
   - **0** новых Win32 HWND, **0** записей на панели задач, **0** новых вкладок в полосе вкладок основного окна владельца, **0** перехватов фокуса и курсора.
   - Полное наследование авторизации `Profile 1` (`HttpOnly` cookies + `localStorage`) без повторного логина и без копирования профиля (`OWNER_PROFILE_COPY_FORBIDDEN`, `SECOND_CHROME_PROCESS_SAME_PROFILE_FORBIDDEN`).
   - Скриншоты на windowless hidden target не имеют композиторной поверхности ОС и честно отклоняются fail-closed с кодом `HIDDEN_TARGET_SCREENSHOT_UNSUPPORTED`.
   - Закрытие целей выполняется через `Target.closeTarget` с подтверждением исчезновения `target_id` в `Target.getTargets`; при неподтверждённом закрытии цель удерживается в SQLite (`forget_unconfirmed: false`, `TARGET_CLEANUP_UNCONFIRMED`, `resources_retained > 0`).
   - Если Chrome не запущен, версия ниже `158.0.8127.2` или `chrome://inspect/#remote-debugging` выключен, маршрут завершается **fail-closed** (`OWNER_CHROME_NOT_RUNNING`, `OWNER_CHROME_VERSION_UNSUPPORTED`, `OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE`) **без молчаливой подмены** другим маршрутом.

### 4.2 Два независимых рубежа согласия и site-scoped разрешения (`owner_chrome_hidden_secondary`)

Для маршрута `owner_chrome_hidden` действуют **два независимых рубежа согласия** (оба сохраняются fail-closed и никогда не обходятся программно):

1. **Рубеж 1 — локальная политика Hub (`consent_gate: "hub_policy"`, класс `owner_chrome_hidden_secondary`):**
   - Проверяется в Hub **до** установления WebSocket-соединения с Chrome (`execution_started: false`). Без разрешения возвращается `PERMISSION_REQUIRED` (`NO_MATCHING_GRANT` или `HOST_NOT_GRANTED`).
   - Поддерживает **ограничение по сайту (`--hosts`)**, срок действия (`--ttl`) и **мгновенный отзыв** (`ff_hub.py grant revoke <grant_id>`; файл `policy.json` перечитывается на каждом решении без кэша).
   - Выдача и управление выполняются только локально владельцем (никогда через RPC/MCP):
     ```powershell
     # Просмотреть ожидающие запросы (с указанием consent_gate и подсказками команд)
     python <RELEASE_DIR>\ff_hub.py --state-dir <BRIDGE_ROOT>\state\hub requests

     # Выдать постоянный site-scoped grant для конкретного HTTPS-сайта (или одобрить pending-запрос для HTTPS-сайта)
     python <RELEASE_DIR>\ff_hub.py --state-dir <BRIDGE_ROOT>\state\hub grant add --classes owner_chrome_hidden_secondary --agents <agent> --hosts <site-host> --ttl 1h
     python <RELEASE_DIR>\ff_hub.py --state-dir <BRIDGE_ROOT>\state\hub approve <request_id> --ttl 1h

     # Отклонить/закрыть ненужный pending-запрос (например, smoke about:blank с пустым target.host)
     python <RELEASE_DIR>\ff_hub.py --state-dir <BRIDGE_ROOT>\state\hub reject <request_id>

     # Мгновенно отозвать выданный grant
     python <RELEASE_DIR>\ff_hub.py --state-dir <BRIDGE_ROOT>\state\hub grant list
     python <RELEASE_DIR>\ff_hub.py --state-dir <BRIDGE_ROOT>\state\hub grant revoke <grant_id>
     ```
   - **Важно про `about:blank` и пустой `target.host`:** у URL `about:blank` нет доменного имени (`target.host == ""`), поэтому он не соответствует site-scoped grant по `--hosts <site-host>`. Команда `ff_hub.py approve <request_id>` без `--hosts` **отказывает fail-closed (`APPROVE_HOST_SCOPE_REQUIRED`)** для запросов `owner_chrome_hidden_secondary` / `browser_script` с пустым `target.host`, чтобы случайно не выдать доступ ко всем сайтам в Chrome владельца (для явного unscoped-режима требуется отдельный флаг `--all-hosts`). Параметр `--hosts` принимает только голые имена хостов (`example.com`, `*.example.com`), а не полные URL с протоколом/путём/портом.
   - Для активного `preflight` с `connect_ws: true` при наличии site-scoped grant передавайте `url: "https://<site-host>/"` или `host: "<site-host>"`.
2. **Рубеж 2 — нативный диалог Chrome (`consent_gate: "chrome_remote_debugging_dialog"`):**
   - В режиме `chrome://inspect/#remote-debugging` (HTTP `/json/version` возвращает `404`, обнаружение идёт через `DevToolsActivePort`) Chrome 158+ требует явного подтверждения владельцем в **нативном диалоге браузера** при подключении WebSocket.
   - Одобрение политики Hub (Рубеж 1) **не** подтверждает и не отключает диалог Chrome (Рубеж 2). Пассивные `route_plan` и `preflight` (без `connect_ws: true`) не открывают WebSocket и сообщают `OWNER_CHROME_CDP_APPROVAL_REQUIRED` (`remedy: "OWNER_CHROME_APPROVE_REMOTE_DEBUGGING_DIALOG"`, `automatic: false`). При таймауте или отказе на этапе рукопожатия (`retry_safe: true, execution_started: false`) повтор с тем же `request_key` безопасен после подтверждения диалога в Chrome.

**Поддержание ранее подтверждённой CDP-сессии:** после проверки Chrome и точного профиля Manager раз в 45 секунд выполняет безопасный Browser.getVersion по уже открытому WebSocket. Это уменьшает вероятность потери соединения из-за простоя и не создаёт новые WebSocket/вкладки или запросы прав. После разрыва соединения, остановки Hub или перезапуска Chrome повторное нативное подтверждение Chrome может понадобиться; автоматического нажатия «Разрешить» и самовыдачи grant нет. Любое действие по-прежнему проходит через текущую политику Hub, включая срок действия и отзыв разрешений.

### 4.3 Строгое разделение трёх браузерных режимов (запрет молчаливого fallback)

| Режим / маршрут | Назначение | Наследование auth `Profile 1` | Видимые окна / вкладки | Молчаливый fallback из `owner_chrome_profile1_hidden_secondary` |
|---|---|---|---|---|
| **Основной:** `owner_chrome_profile1_hidden_secondary` (`owner_chrome_hidden`) | Авторизованные сайты в уже открытом Chrome `Profile 1` через windowless CDP `hidden: true` | **Да** (без копирования профиля/cookies) | **Нет** (`windowless=true`, 0 HWND, 0 вкладок) | — (fail-closed при недоступности) |
| **Дополнительный изолированный:** `managed_browser` / `private_browser` (`persistent_playwright` / `private_cdp`) | Отдельный изолированный/персистентный профиль агента для задач без сессии владельца | **Нет** (`satisfies_owner_profile_auth: false`) | **Нет** (headless / Win32 Private Desktop) | **Запрещён** (`isolated_substitution_forbidden: true`) |
| **Явный видимый extension:** `browser` (`owner_chrome_extension` / `ff_browser_hub.mjs`) | Работа через Playwright Chrome Extension в видимой группе вкладок Chrome | **Да** (через расширение Chrome) | **Да** (`visible_tab_strip: true`, `hidden_secondary_window_supported: false`) | **Запрещён** (`OWNER_CHROME_HIDDEN_SECONDARY_UNSUPPORTED_ON_TRANSPORT`) |

### 4.4 Пользовательский режим чтения сайта без прерывания (`site_read`) и ограничения доступности

Для чтения конкретного запрошенного URL (`http`/`https`) **только для чтения и без прерывания владельца** предусмотрен единый пользовательский маршрут `site_read` (Hub RPC/MCP `op: "site_read"`, планирование `route_plan(capability="background_tab_read", url=...)`, локальный CLI `ff_hub.py site-read --url <url>` и `/agent/v1` для scope `owner_chrome_hidden`):

1. **Только уже авторизованные и подключённые поддерживаемые провайдеры:**
   - Проверка выполняется до любого UI, запуска браузера, нового WebSocket-рукопожатия (`allow_new_ws=false`) и создания pending-запросов Hub (`pending_request_created: false`).
   - Все существующие разрешения и настройки сохраняются неизменными: маршрут никогда не выполняет авто-одобрение, обход проверок, изменение настроек Chrome, добавление stealth-режимов или извлечение cookies/учётных данных/токенов сессии.
   - Мутирующие и запрещённые аргументы (`act`, `evaluate`, `foreground`, `auto_approve`, `stealth`, `extract_cookies`, `copy_profile` и др.) отклоняются fail-closed (`SITE_READ_ARG_FORBIDDEN`).
2. **Строгое разделение видимости запроса:**
   - **Обычная фоновая вкладка без запросов пользователю (`visibility: "background_tab"`, `strict_invisibility: false`):** сначала проверяет уже подключённый `owner_chrome_profile1_hidden_secondary`, а при его недоступности может выбрать `owner_chrome_extension` **только если подтверждены все 5 условий**: локальная политика Hub (`browser_own_tabs` + `read_diagnose`), активное подключение (`connected=true`, `stopping=false`, `circuit_open=false`), открытие в фоне без активации (`background=true`, `activates_tab=false`, `isolated_profile=false`), подтверждённое чтение и совместимый манифест расширения (исключая downloads-only), а также доказуемое владение вкладками (`tab_ledger.enabled=true` без ошибок и корректные лимиты).
   - **Строгая невидимость (`visibility: "strict_invisible"` или `strict_invisibility: true`):** допускает исключительно windowless-цель `owner_chrome_profile1_hidden_secondary`; видимая фоновая вкладка `owner_chrome_extension` **никогда не подставляется** (`VISIBLE_TAB_SUBSTITUTION_FORBIDDEN`).
3. **Единый понятный результат при отсутствии подходящего провайдера:**
   - Если ни один поддерживаемый провайдер не готов, `site_read` немедленно возвращает **один** структурированный результат возможностей (`schema: "ff-no-interruption-site-read-v1"`, `error_code: "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER"`, `providers`, `excluded_providers`, `actionable_next_steps`, `ui_triggered: false`, `prompts_triggered: false`, `pending_request_created: false`) до любого UI или pending-запроса.
4. **Оставшиеся ограничения доступности (честные границы):**
   - **Отсутствие подключения без диалога при закрытом соединении:** в Chrome 158+ с `chrome://inspect/#remote-debugging` (HTTP 404 `/json/version`) маршрут `owner_chrome_profile1_hidden_secondary` требует как локальный site-scoped grant Hub (Рубеж 1), так и уже одобренное активное loopback CDP WebSocket-соединение (Рубеж 2); если WebSocket ещё не открыт, `site_read` не инициирует подключение и не вызывает нативный диалог Chrome.
   - **Предварительно подключённый relay для `owner_chrome_extension`:** выбор `owner_chrome_extension` возможен только при уже запущенном и подключённом в фоне `ff_browser_hub.mjs` (Chrome `>= 158.0.8127.2`, Playwright Extension `>= 0.5.0`, Playwright `1.65.1`, исправный `tab-ledger.json`, разрешённые классы Hub). Такой провайдер добавляет неактивную вкладку в видимую полосу вкладок Chrome (`visible_tab_strip: true`), поэтому непригоден для `strict_invisible`.
   - **FF Browser Companion `0.1.1`:** фактический манифест содержит только `downloads` и `nativeMessaging`; расширение не умеет открывать вкладки или читать страницы (`COMPANION_DOWNLOADS_AND_NATIVE_MESSAGING_ONLY`).
   - **Неуправляемые сторонние расширения (например, сторонние браузерные расширения ИИ-ассистентов):** не управляются брокером Hub, не дают доказуемого владения, неактивации и очистки (`PROVIDER_UNMANAGED_NO_BROKER_OWNERSHIP`) и никогда не перехватываются.
   - **Изолированные профили (`managed_browser` / `private_browser`):** не наследуют авторизацию профиля Chrome владельца (`ISOLATED_PROFILE_SUBSTITUTION_FORBIDDEN`) и не подставляются молча.
   - **Контекст профиля и редиректы:** смена `defaultBrowserContextId` в многопрофильном Chrome приводит к отказу `OWNER_CHROME_PROFILE_CONTEXT_MISMATCH`; перенаправление страницы на хост вне действующего разрешения приводит к отказу `REDIRECT_HOST_NOT_GRANTED` с сокрытием содержимого (`content_withheld: true`) и гарантированным закрытием вкладки/цели.
   - **Потеря подтверждения закрытия:** при разрыве связи во время закрытия запись владения удерживается fail-closed (`cleanup_verified: false`, `resources_retained: 1`) и никогда не списывается как закрытая.

### 4.5 Фоновые операции с формами в уже авторизованных собственных вкладках (`background_tab_form`)

Для заполнения, редактирования, сохранения и перезагрузки веб-форм **без foreground-взаимодействия и без изменения политики доступа** используются штатные stateful API Hub (`owner_chrome_hidden` для строго невидимых целей `owner_chrome_profile1_hidden_secondary` или `browser` для фоновых вкладок `owner_chrome_extension`) после планирования `route_plan(surface="browser", capability="background_tab_form", url=..., visibility="background_tab"|"strict_invisible")`:

1. **Поддерживаемые фоновые операции DOM (`trusted_input: false`, `physical_input_used: false`):**
   - `act`: `fill` (ввод/замена текста в редактируемых `<input>`, `<textarea>`, `[contenteditable=true]`, отказ `TARGET_NOT_EDITABLE` для `readOnly` и нередактируемых типов), `select` (чисто DOM-выбор опций `<select>` с проверкой существования опции `OPTION_NOT_FOUND` без нативного Playwright `selectOption`), `check` / `uncheck` (флажки, переключатели, radio с запретом `uncheck` для radio), `click` (DOM pointer/mouse/click без активации окна/вкладки), `press` (DOM `KeyboardEvent` `keydown`/`keyup`, `Enter` отправляет форму через `form.requestSubmit()` ровно один раз и не отправляет форму из `<textarea>`).
   - `reload` (журналируемая мутация с обязательным `request_key`, проверкой текущего хоста `TAB_HOST_CHANGED` до перезагрузки, ожиданием реального коммита перезагрузки и `bringToFront = 0`).
   - `wait_for`, `observe` / `snapshot`, `read` (чтение `.value` и `checked` у полей формы после перезагрузки для независимой верификации сохранённых данных).
2. **Защита от дублирования отправки и сохранность фокуса:**
   - Каждая мутация (`open`, `navigate`, `reload`, `act`, `close`) требует стабильного `request_key` (`REQUEST_KEY_REQUIRED`); повтор того же ключа с тем же payload возвращает кэшированный ответ (`deduplicated: true`) без повторного нажатия/отправки; повтор ключа с другим payload отклоняется fail-closed (`REQUEST_KEY_REUSED`); после потери ответа используется `request_status` (`automatic_replay: false`).
   - Все операции выполняются строго в собственной вкладке/цели сессии (`RESOURCE_NOT_OWNED` для чужих агентов), отклоняют `foreground: true` (`FOREGROUND_ROUTE_REQUIRED`) и проверяют текущий живой хост перед действием и перезагрузкой (`TAB_HOST_CHANGED`).
   - Никакие политики Hub (`policy.json`) и разрешения браузера/расширений не изменяются; `site_read` остаётся строго read-only (`SITE_READ_ARG_FORBIDDEN`).
3. **Ограничения доступности фоновых форм:**
   - Требуется уже авторизованный и подключённый провайдер (`owner_chrome_profile1_hidden_secondary` или `owner_chrome_extension` при `visibility="background_tab"`).
   - События являются DOM-уровня (`isTrusted: false`); сайты, требующие аппаратных событий ввода (`isTrusted: true`), нативных файловых диалогов, перетаскивания (drag-and-drop), canvas-взаимодействия, CAPTCHA, MFA или UAC, не обходятся и требуют остановки либо отдельного согласованного маршрута.
   - `owner_chrome_extension` добавляет неактивную вкладку в видимую полосу вкладок (`visible_tab_strip: true`) и не подставляется при `strict_invisibility: true`; `owner_chrome_profile1_hidden_secondary` не поддерживает `screenshot` (`HIDDEN_TARGET_SCREENSHOT_UNSUPPORTED`).
   - Chrome ограничивает таймеры и `requestAnimationFrame` в фоновых вкладках (`background_tab_timers`); формы, завязанные на видимый кадр анимации, могут не завершать перерисовку в фоне.

---

## 5. Шаг 4 — Согласованная очистка устаревшего debug-патча Playwright и ротация токена (ТОЛЬКО с подтверждения владельца)

Аудит зафиксировал, что в legacy-каталоге `<BRIDGE_ROOT>\bridge-v3\node_modules\playwright-core\lib\coreBundle.js` присутствовал локальный отладочный патч `writeFileSync`, записывавший URL подключения расширения (с query-параметром `token`) во внешний файл `pw_connect_url.txt`.

**Выполнять ТОЛЬКО после отдельного явного подтверждения владельца:**

1. **Никогда не выводить содержимое `pw_connect_url.txt` в консоль, чат или логи.**
2. **Заменить `bridge-v3\node_modules\playwright-core`** (или перевести все клиенты, включая локальные обёртки, на чистый `<PLAYWRIGHT_ROOT>` с `playwright-core 1.65.1`), затем подтвердить чистоту сканером:
   ```powershell
   python <RELEASE_DIR>\cua_playwright_integrity.py --playwright-root <BRIDGE_ROOT>\bridge-v3 --allow-missing --json
   ```
3. **Удалить отладочный артефакт `pw_connect_url.txt`** на рабочей станции владельца (если он существует), используя явную команду владельца.
4. **Ротировать токен расширения Playwright в Chrome:**
   - Открыть настройки расширения Playwright MCP Bridge в Chrome владельца и сгенерировать новый токен (или пересоздать привязку расширения).
   - Обновить локальный секрет/конфигурацию, потребляющую токен, и убедиться, что старый токен больше не принимается.

---

## 6. Шаг 5 — Контролируемое переключение (`39073`, `39076`, `39090` и MCP-клиенты)

> Всегда сохраняйте нетронутыми пользовательские файлы состояния: `<BRIDGE_ROOT>\state\chat-permission.json`, `<BRIDGE_ROOT>\state\chat-permission\stop.flag` (никогда не удалять!), `<BRIDGE_ROOT>\bridge-v3\secret`, а также посторонние пользовательские приложения и VPN-клиенты.

1. **Установите замок обслуживания `.cua-cold-maintenance.lock` (TTL <= 300 с) и при структурном обновлении взведите независимый сторож `cua_cold_recovery_watchdog.py` из `<RECOVERY_ROOT>\pre-p0-cutover\kit`** согласно [`OPERATOR_COLD_UPGRADE_RU.md`](OPERATOR_COLD_UPGRADE_RU.md).
2. **Обновите `<BRIDGE_ROOT>\bridge-v3\ff_win_v3_keeper.ps1`** (и сопутствующие скрипты `bridge-v3` через транзакционный `cua_runtime_deploy.py apply` или из проверенного `<RELEASE_DIR>`), чтобы удалить ручной хардкод `$agent` на строке 34 и включить разрешение через `state\active-release.json`.
3. **Атомарно активируйте новый релиз в `<BRIDGE_ROOT>\state\active-release.json`:**
   ```powershell
   python <RELEASE_DIR>\cua_runtime_deploy.py activate `
     --bridge-root <BRIDGE_ROOT> `
     --release-dir <RELEASE_DIR> `
     --repo <CHECKOUT> `
     --release-name p0-<SHORT_SHA> `
     --playwright-root <PLAYWRIGHT_ROOT>
   ```
   Команда сама перепроверяет `installed-runtime-manifest.json`, SHA-256 всех файлов релиза, 40-символьный `source_head`, отсутствие symlink/junction и чистоту `coreBundle.js`, сохраняет предыдущий релиз в поле `previous` и атомарно записывает `state\active-release.json`.
4. **Выровняйте все контуры на единый `<RELEASE_DIR>` и `<PLAYWRIGHT_ROOT>`:**
   - **Primary Bridge (`127.0.0.1:39073`):** перезапустите штатную задачу `FF-Bridge-V3-Keeper` (после снятия `.cua-cold-maintenance.lock`). Хранитель автоматически поднимет `<RELEASE_DIR>\ff_win_v3_main.py` через `state\active-release.json`.
   - **Prelogin Bridge (`127.0.0.1:39076`):** обновите скрипт запуска prelogin-службы, чтобы он запускал `<RELEASE_DIR>\ff_win_v3_main.py` (или читал `<BRIDGE_ROOT>\state\active-release.json`), сохраняя отдельный prelogin-root и резервный порт `39076`.
   - **Shared Universal Agent Hub (`127.0.0.1:39090`) и Browser Hub (`ff_browser_hub.mjs`):** обновите `hub-start-config.json` / задачу `FF-Universal-Agent-Hub-*` и `state\hub\config.json` на `<RELEASE_DIR>\ff_hub.py` и единый чистый `<PLAYWRIGHT_ROOT>`.
   - **MCP-конфиги всех агентов (Antigravity / AGY, Claude Desktop, Codex, Cursor, OpenCode):** укажите единый путь `<RELEASE_DIR>\ff_hub_mcp.py` с общим `--state-dir <BRIDGE_ROOT>\state\hub` (устраняет рассинхрон версий между AGY и Claude Desktop).
   - **Вывод из эксплуатации дублирующих/устаревших контуров (по согласованию с владельцем):**
     - Остановите и отключите дублирующий второй Private Hub (порт `52136`), если его задачи переведены на единый Hub (`39090`).
     - Отключите устаревшие задачи `FF-Universal-RC2-Cutover-39073` / `39076`, ссылавшиеся на временный canary-каталог.
     - Переместите архивные исторические манифесты `canonical-rc-manifest.json` (`abd6666`) и `G0_RELEASE_MANIFEST.json` из корня `bridge-v3` в `<BRIDGE_ROOT>\bridge-v3\backups\legacy-manifests\` (без удаления).

---

## 7. Шаг 6 — Верификация после переключения (обязательно)

Выполните и сохраните результаты следующих проверок:

1. **Проверка указателя и паритета с `origin/main`:**
   ```powershell
   python <RELEASE_DIR>\cua_runtime_deploy.py pointer-status `
     --bridge-root <BRIDGE_ROOT> `
     --repo <CHECKOUT>

   python <CHECKOUT>\tools\runtime_parity.py `
     --installed <RELEASE_DIR> `
     --ref <TARGET_SHA> `
     --repo <CHECKOUT> `
     --require-manifest `
     --bridge-root <BRIDGE_ROOT> `
     --playwright-root <PLAYWRIGHT_ROOT> `
     --disk
   ```
2. **Проверка RPC-методов Bridge (`127.0.0.1:39073`) и Hub (`127.0.0.1:39090`):**
   - `ping` — подтвердить `ok: true`, новый `pid` и ожидаемый `agent_sha256`.
   - `capabilities` — подтвердить `features.atomic_release_pointer == true` и `features.universal_agent_runtime`.
   - `release_provenance` — подтвердить `ok: true`, `pointer_present: true`, `source_head == <TARGET_SHA>`.
   - `agent_workflows` — подтвердить наличие `browser_workflow` с приоритетным `owner_chrome_profile1_hidden_secondary` (и разделением с дополнительным изолированным режимом и видимой группой вкладок расширения) в `route_preference`.
   - Hub `owner_chrome_hidden` (`op: "preflight"`, `profile_dir_name: "Profile 1"`) — подтвердить `available: true` при включённом `chrome://inspect/#remote-debugging` на Chrome 158+ с единственным активным контекстом `Profile 1` (или честный fail-closed код без подмены, если опция не включена).
   - `chat_permission_status` и `scope_report` — подтвердить сохранность всех защитных ограничений (`stop.flag`, `OWNER_ACTIVE`, `chat-permission.json`).
3. **Проверка отсутствия split-brain в живых процессах (`Win32_Process`):**
   - Убедитесь, что `39073`, `39076`, `39090`, Browser Hub и запущенные MCP-адаптеры `ff_hub_mcp.py` исполняются из **одного и того же `<RELEASE_DIR>`**.
4. **Проверка устойчивости к перезапуску хранителя:**
   - Перезапустите задачу `FF-Bridge-V3-Keeper` (и/или проверьте после плановой перезагрузки ПК) и убедитесь, что `ping` и `release_provenance` по-прежнему возвращают `<TARGET_SHA>`, а не предыдущую версию.

---

## 8. Шаг 7 — Безопасный откат (Rollback)

### Вариант A: быстрый атомарный откат через `state\active-release.json` (если предыдущий релиз находится в `runtime-releases`)

```powershell
# 1. Проверить и вернуть указатель на предыдущий подтверждённый релиз
python <RELEASE_DIR>\cua_runtime_deploy.py rollback `
  --bridge-root <BRIDGE_ROOT> `
  --repo <CHECKOUT>

# 2. Убедиться, что указатель переключился и прошёл SHA-проверку
python <RELEASE_DIR>\cua_runtime_deploy.py pointer-status `
  --bridge-root <BRIDGE_ROOT> `
  --repo <CHECKOUT>
```

После этого выполните контролируемый перезапуск только процессов Bridge (`39073` / `FF-Bridge-V3-Keeper`) и Hub (`39090`), не затрагивая посторонние пользовательские процессы, VPN-клиенты и файлы состояния (`chat-permission.json`, `stop.flag`, `secret`).

### Вариант B: полный холодный откат из неизменяемого снимка (`<RECOVERY_ROOT>\pre-p0-cutover`)

Используйте при структурных сбоях или повреждении самого `bridge-v3`:

```powershell
python <RECOVERY_ROOT>\pre-p0-cutover\kit\tools\cua_cold_rollback_bundle.py restore `
  --runtime <BRIDGE_ROOT>\bridge-v3 `
  --snapshot <RECOVERY_ROOT>\pre-p0-cutover `
  --target-port 39073 --peer-port 39076 `
  --offline-confirmed
```

При восстановлении снимка автоматически возвращаются и файлы `bridge-v3`, и `installed-runtime-manifest.json`, и сохранённый `state\active-release.json` (если он присутствовал на момент `capture`), с полной SHA-256 проверкой после записи и сохранением пользовательских файлов и журналов `.cua-deploy`.
