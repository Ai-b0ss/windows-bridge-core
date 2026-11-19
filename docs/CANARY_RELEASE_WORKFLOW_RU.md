# Безопасный канареечный workflow релиза и отката (C1 + C2)

Руководство оператора по продуктовому канареечному конвейеру для **FF Windows Bridge (C1)** и **GeminiTaskGateway / Unified API (C2)**.

Инструменты:
- `tools/canary_release_workflow.py` — fail-closed движок канареечного staging, проверок здоровья, 4-факторной верификации процессов, резервного копирования SQLite и неизменяемых квитанций;
- `tools/canary_cutover_c1_c2.ps1` — PowerShell-обёртка для `DryRun`, `ShadowStage`, `ShadowVerify`, `ShadowFull`, `PrepareReadiness` и проверки owner-gate;
- `tools/canary_rollback_c1_c2.ps1` — PowerShell-обёртка для `DryRun`, `ShadowRollback`, `StopIdleShadow` и `VerifyReceipts`;
- [`CANARY_MANUAL_CUTOVER_PLAYBOOK_RU.md`](CANARY_MANUAL_CUTOVER_PLAYBOOK_RU.md) — пошаговый плейбук ручного переключения production и аварийного отката;
- [`OPERATOR_COLD_UPGRADE_RU.md`](OPERATOR_COLD_UPGRADE_RU.md) — холодный откат ядра Bridge через `cua_cold_rollback_bundle.py` и внешний watchdog.

> **Ключевое правило:** ни `canary_cutover_c1_c2.ps1`, ни `canary_rollback_c1_c2.ps1`, ни `canary_release_workflow.py` **никогда автоматически не перезапускают и не изменяют живой production**. Все реальные операции выполняются строго в изолированном shadow-каталоге `<SHADOW_ROOT>` на непроизводственных портах.

## 1. Гарантии безопасности (fail-closed)

1. **Обязательный pinned SHA-256 и pinned Git commit:**
   - Пустой, укороченный или некорректный `-FullCoreSha256` вызывает немедленный отказ (`PINNED_SHA256_REQUIRED` / `PINNED_SHA256_INVALID`) до любых файловых операций.
   - Проверяется не только внешний SHA-256 архива C1, но и CRC всего ZIP, безопасность путей (запрет `..`, абсолютных путей, симлинков и зарезервированных имён Windows), а также SHA-256 **каждого** файла внутри `release-manifest.json` и компиляция Python-модулей.
   - Для отдельной кодовой базы C2 требуется точный 40-символьный Git commit SHA (`-C2ExpectedCommit`) при чистом дереве либо ZIP с обязательным 64-hex `-C2ZipSha256`. Экспорт выполняется через read-only `git archive`; сам репозиторий C2 и production-каталог никогда не модифицируются и не переводятся командой `git checkout`.
   - Для восстановления БД C2 из резервной копии и проверки базового ZIP отката SHA-256 также обязателен.

2. **Изолированное shadow-состояние и защита границ production:**
   - Производственные порты **`20128`, `21476`, `21477`, `39073`, `39076`, `39090`** жёстко запрещены в shadow-режиме (`SHADOW_PORT_FORBIDDEN_PRODUCTION_PORT`).
   - Производственные каталоги (`%LOCALAPPDATA%\FF-Windows-Bridge`, `%USERPROFILE%\Documents\GeminiTaskGateway`, а также их физические цели за NTFS junction) жёстко запрещены (`SHADOW_ROOT_FORBIDDEN_PRODUCTION_PATH`).
   - Любые симлинки и NTFS junction в цепочке `<SHADOW_ROOT>` отклоняются (`REPARSE_POINT_FORBIDDEN`).
   - Непустой сторонний каталог без маркера `canary-shadow-owner.json` (`schema: ff-canary-shadow-owner-v1`) никогда не перехватывается (`SHADOW_ROOT_NOT_OWNED`).

3. **Резервное копирование SQLite только через SQLite Online Backup API:**
   - Снимки `hub.db`, `entry-grants.sqlite3` и `gateway.db` создаются строго через `sqlite3.Connection.backup()` с открытием источника в режиме read-only (`?mode=ro`), проверкой `PRAGMA integrity_check == ok`, подсчётом строк таблиц и фиксацией SHA-256.
   - При подготовке C2 shadow staging источник `--c2-source-db` никогда не изменяется; в shadow-профиле создаётся отдельный `gateway.db` и собственный изолированный `gateway.key`.

4. **4-факторная проверка идентичности процесса и запрет force-kill активных сессий:**
   - Каждый запущенный shadow-процесс (`c1_rpc`, `c1_hub`, `c2_gateway`, `c2_unified`) получает owner-scoped lease в `<SHADOW_ROOT>/leases/<role>.lease.json` (`schema: ff-canary-process-lease-v1`), связывающий 4 независимых фактора:
     1. `pid`;
     2. 64-битный kernel `FILETIME` времени старта процесса (`GetProcessTimes`);
     3. физический путь исполняемого файла (`QueryFullProcessImageNameW` на том же kernel handle) + проверку пути скрипта внутри `<SHADOW_ROOT>` и командной строки;
     4. `owner_scope_id`, совпадающий с `canary-shadow-owner.json`.
   - Поиск процессов по подстроке и слепой `Stop-Process -Force` полностью исключены.
   - При несовпадении `create_time_filetime` (повторно использованный PID ОС) процесс не трогается (`PID_REUSED_OR_EXITED_NO_KILL`).
   - **Запрет принудительного завершения активных сессий:** перед любой остановкой или откатом проверяются:
     - C1 Hub (`hub_status` + read-only `hub.db`: активные `sessions`, удерживаемые `resources`, ожидающие `permission_requests`);
     - C1 Bridge RPC (активные гранты desktop-режима и сессии Hub);
     - C2 Gateway (read-only `gateway.db`: задания в состояниях `queued`, `running`, `submitted`, `needs_attention` и активные `agent_turns`).
   - Если обнаружена хотя бы одна активная сессия/задача или состояние невозможно достоверно прочитать — остановка и откат отклоняются (`ACTIVE_SESSIONS_PRESENT`, `ACTIVE_C2_JOBS_PRESENT`, `SESSION_STATE_UNKNOWN_REFUSE_KILL`), а процессы остаются работать. Флага обхода «убить активные сессии» не существует.

5. **Постоянные квитанции SQLite (`canary_receipts.sqlite3`):**
   - Хранятся в `<SHADOW_ROOT>/state/canary_receipts.sqlite3` (`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`).
   - Таблицы: `canary_runs`, `canary_steps`, `canary_backups`, `canary_leases` и `canary_receipt_chain` (append-only цепочка SHA-256 хэшей).
   - Поддерживают идемпотентность через `-RequestKey` (повтор с теми же параметрами возвращает сохранённую квитанцию без повторной мутации; конфликт параметров на том же ключе отклоняется с `REQUEST_KEY_CONFLICT`).
   - Квитанции и база `entry-grants.sqlite3` / `hub.db` никогда не удаляются при откате; любое повреждение или подмена строк цепочки выявляется проверкой `VerifyReceipts` (`RECEIPT_CHAIN_CORRUPTED`).

## 2. Структура shadow-каталога

```text
<SHADOW_ROOT>/
  canary-shadow-owner.json           # маркер владения (owner_scope_id)
  releases/
    c1/<commit12>-<zipsha12>/        # неизменяемый релиз C1 + install-manifest.json
    c2/<commit12>-<mfsha12>/         # неизменяемый релиз C2 + c2-stage-manifest.json
  state/
    canary_receipts.sqlite3          # постоянные квитанции SQLite + hash-цепочка
    c1/
      active.json                    # атомарный указатель релиза C1
      runtime/                       # изолированный FF_BRIDGE_ROOT
      hub/                           # hub.db, entry-grants.sqlite3, endpoint.json, config.json
    c2/
      active.json                    # атомарный указатель релиза C2
      runtime/                       # управляемый staging-слот C2 (код + gateway.db + gateway.key)
    logs/                            # журналы shadow-процессов
  backups/<run_id>/                  # снимки SQLite Online Backup API
  leases/<role>.lease.json           # 4-факторные process leases
```

## 3. Основные команды оператора

### 3.1. Безопасный dry-run (без изменений на диске)

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_cutover_c1_c2.ps1 `
  -Mode DryRun `
  -FullCoreZipPath <C1_ZIP> `
  -FullCoreSha256 <64_HEX_SHA256> `
  -C1ExpectedCommit <40_HEX_C1_COMMIT> `
  -ShadowRoot <SHADOW_ROOT> `
  -C1RpcPort 39173 -C1HubPort 39190 `
  -C2RepoPath <C2_REPO> `
  -C2ExpectedCommit <40_HEX_C2_COMMIT> `
  -C2GatewayPort 21587 -C2UnifiedPort 21588
```

### 3.2. Полный shadow-цикл (staging C1 + C2, запуск, health-контракты)

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_cutover_c1_c2.ps1 `
  -Mode ShadowFull `
  -FullCoreZipPath <C1_ZIP> `
  -FullCoreSha256 <64_HEX_SHA256> `
  -C1ExpectedCommit <40_HEX_C1_COMMIT> `
  -ShadowRoot <SHADOW_ROOT> `
  -C1RpcPort 39173 -C1HubPort 39190 `
  -C2RepoPath <C2_REPO> `
  -C2ExpectedCommit <40_HEX_C2_COMMIT> `
  -C2SourceDbPath <READONLY_BASELINE_GATEWAY_DB> `
  -C2GatewayPort 21587 -C2UnifiedPort 21588 `
  -StartC1Rpc -HealthConsecutivePasses 2 -RequestKey "canary-shadow-001"
```

Проверка здоровья (`ShadowVerify`) честно разделяет:
- `shadow_health_ok` — дисковая целостность, `ping`/`capabilities`/`agent_sha256` C1 RPC, `hub_status` + аутентифицированный запрос `/agent/v1` (`capabilities` и `route_plan` с чистым отзывом временного гранта), `/health` C2 Gateway, `/health` C2 Unified API с проверкой `gateway_port == C2GatewayPort` и `/ready`;
- `upstream_omniroute_ok` — реальная доступность upstream OmniRoute (если в изолированном стенде OmniRoute не подключён, поле честно остаётся `false` и фиксируется в `remaining_release_gates`);
- `live_production_cutover_executed` — всегда `false` для shadow-режима.

### 3.3. Остановка простаивающих shadow-процессов и проверка квитанций

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_rollback_c1_c2.ps1 `
  -Mode StopIdleShadow -ShadowRoot <SHADOW_ROOT>

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_rollback_c1_c2.ps1 `
  -Mode VerifyReceipts -ShadowRoot <SHADOW_ROOT>
```

### 3.4. Безопасный shadow-откат (с сохранением квитанций и опциональным восстановлением БД C2)

```powershell
# Сначала DryRun:
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_rollback_c1_c2.ps1 `
  -Mode DryRun -ShadowRoot <SHADOW_ROOT>

# Выполнение shadow-отката (блокируется при любых активных сессиях/задачах):
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_rollback_c1_c2.ps1 `
  -Mode ShadowRollback -ConfirmShadowRollback `
  -ShadowRoot <SHADOW_ROOT> `
  -C2RestoreDbBackupPath <SHADOW_BACKUP_DB> `
  -C2RestoreDbBackupSha256 <64_HEX_BACKUP_SHA256> `
  -RequestKey "canary-rollback-001"
```

## 4. Регрессионные тесты

Все тесты работают исключительно во временных каталогах (`TemporaryDirectory`) на свободных локальных портах и никогда не касаются production или видимого рабочего стола:

```powershell
python -m unittest tests/test_canary_release_workflow.py tests/test_canary_powershell_regression.py -v
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests/test_canary_powershell.ps1
```
