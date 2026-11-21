# Руководство владельца: безопасное переключение (P0 Production Cutover), откат и гигиена Playwright

> **ВАЖНО:** Данный регламент выполняется **только после явного подтверждения владельца**. Никакие команды из этого документа не должны запускаться автоматически во время аудита, разработки или локальных тестов.
>
> Все пути в документе параметризованы (`<BRIDGE_ROOT>`, `<CHECKOUT>`, `<RECOVERY_ROOT>`, `<USER_HOME>`) в соответствии с политикой публичного репозитория.

---

## 0. Цели P0-переключения

Переключение устраняет следующие подтверждённые дефекты эксплуатации:

1. **Split-brain контуров runtime:** консолидация всех сервисов (`39073` Primary Bridge, `39076` Prelogin Bridge, `39090` Shared Agent Hub, Browser Hub `ff_browser_hub.mjs` и всех MCP-клиентов AGY / Claude Desktop / Codex / Cursor / OpenCode) на **единый проверенный 40-символьный Git SHA** и **единый чистый корень `playwright-core 1.65.1`**.
2. **Защита от тихого отката после перезагрузки:** переход от ручной правки `$agent` в `ff_win_v3_keeper.ps1` к атомарному проверенному указателю `<BRIDGE_ROOT>\state\active-release.json` (`schema: ff-bridge-active-release/v1`), который хранитель проверяет по SHA-256 манифеста и каждого файла перед запуском.
3. **Достоверное происхождение релизов (`release-manifest.json` / `installed-runtime-manifest.json`):** исключение устаревших предковых коммитов (`c034e527...`, `abd6666...`, `8f510489...`) и принудительная проверка реального 40-символьного Git SHA.
4. **Гигиена безопасности Playwright (`coreBundle.js`):** замена локально пропатченного `bridge-v3\node_modules\playwright-core\lib\coreBundle.js` (отладочный `writeFileSync` URL/токена в `pw_connect_url.txt`) на чистый закреплённый `playwright-core 1.65.1` и ротация токена расширения Chrome **только с явного подтверждения владельца**.

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

## 4. Шаг 3 — Согласованная очистка устаревшего debug-патча Playwright и ротация токена (ТОЛЬКО с подтверждения владельца)

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

## 5. Шаг 4 — Контролируемое переключение (`39073`, `39076`, `39090` и MCP-клиенты)

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

## 6. Шаг 5 — Верификация после переключения (обязательно)

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
2. **Проверка RPC-методов Bridge (`127.0.0.1:39073`):**
   - `ping` — подтвердить `ok: true`, новый `pid` и ожидаемый `agent_sha256`.
   - `capabilities` — подтвердить `features.atomic_release_pointer == true` и `features.universal_agent_runtime`.
   - `release_provenance` — подтвердить `ok: true`, `pointer_present: true`, `source_head == <TARGET_SHA>`.
   - `agent_workflows` — подтвердить наличие `browser_workflow` и `shared_hub_browser_background` в `route_preference`.
   - `chat_permission_status` и `scope_report` — подтвердить сохранность всех защитных ограничений (`stop.flag`, `OWNER_ACTIVE`, `chat-permission.json`).
3. **Проверка отсутствия split-brain в живых процессах (`Win32_Process`):**
   - Убедитесь, что `39073`, `39076`, `39090`, Browser Hub и запущенные MCP-адаптеры `ff_hub_mcp.py` исполняются из **одного и того же `<RELEASE_DIR>`**.
4. **Проверка устойчивости к перезапуску хранителя:**
   - Перезапустите задачу `FF-Bridge-V3-Keeper` (и/или проверьте после плановой перезагрузки ПК) и убедитесь, что `ping` и `release_provenance` по-прежнему возвращают `<TARGET_SHA>`, а не предыдущую версию.

---

## 7. Шаг 6 — Безопасный откат (Rollback)

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
