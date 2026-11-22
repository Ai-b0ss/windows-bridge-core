# Плейбук ручного переключения (cutover) и аварийного отката C1 + C2

Пошаговая процедура для владельца ПК при переводе живого production-контура **FF Windows Bridge (C1)** и **GeminiTaskGateway / Unified API (C2)** на проверенный релиз-кандидат.

> **Важно:** агентам и автоматическим скриптам запрещено выполнять `ConfirmOwnerCutover` / `ConfirmOwnerRollback` и перезапускать production без новой явно проверенной готовности (`readiness`) и свежего одобрения владельца. Переключение выполняется осознанно, с живой инвентаризацией сессий и окном обслуживания.

## 0. Неизменяемые release gates перед началом

Переключение production **запрещено**, пока не закрыт каждый пункт:

| # | Release Gate | Чем подтверждается |
| --- | --- | --- |
| 1 | Чистые, воспроизводимые артефакты C1 и C2 | Пиннинг 64-hex SHA-256 ZIP C1 + 40-hex commit C1 + 40-hex commit C2 + зелёные unit/PowerShell/integration/Node тесты |
| 2 | Успешный shadow-прогон (`ShadowFull`) | `shadow_health_ok == true`, `receipt_chain_verified == true`, проверенный shadow rollback в `<SHADOW_ROOT>` |
| 3 | Живая приёмка A1–A7 и upstream OmniRoute | Подтверждён `upstream_omniroute_ok == true` и реальные клиентские маршруты (без замаскированных деградаций) |
| 4 | Независимая интеграция C2 и Cloudflare P6 | Проверены ветка C2 (M4 + adapter + E2E) и соответствие живого Cloudflare Worker (отдельные release gates) |
| 5 | Свежая инвентаризация живых процессов и сессий | Не опираться на устаревший `g0_live_inventory.json`; проверить активные сессии прямо перед окном обслуживания |
| 6 | Зафиксированный план отката и снимки | Снят SHA-проверенный холодный снимок C1 (`cua_cold_rollback_bundle.py`) и SQLite Online Backup живых БД |
| 7 | Явное одобрение владельца с ограниченным TTL | Файл `owner-approval.json` (`schema: ff-canary-owner-approval-v1`) с точными SHA-256 / commit и подтверждением drain |

## 1. Подготовка и верификация shadow-кандидата

1. Выполните полный shadow-прогон в изолированном каталоге `<SHADOW_ROOT>` (не пересекающемся с `<BRIDGE_ROOT>` и `<C2_PROD_ROOT>`) на shadow-портах (`39173 / 39190 / 21587 / 21588`):
   ```powershell
   powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_cutover_c1_c2.ps1 `
     -Mode ShadowFull -StartC1Rpc `
     -FullCoreZipPath <C1_ZIP> -FullCoreSha256 <C1_ZIP_SHA256> -C1ExpectedCommit <C1_COMMIT> `
     -ShadowRoot <SHADOW_ROOT> `
     -C2RepoPath <C2_REPO> -C2ExpectedCommit <C2_COMMIT> `
     -C2SourceDbPath <C2_PROD_ROOT>\gateway.db `
     -HealthConsecutivePasses 3 -RequestKey "prod-prep-shadow-001"
   ```
2. Убедитесь, что `shadow_health_ok == true`, проверьте `VerifyReceipts` и сформируйте манифест готовности:
   ```powershell
   powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_cutover_c1_c2.ps1 `
     -Mode PrepareReadiness -ShadowRoot <SHADOW_ROOT> `
     -ReadinessOutputPath <SHADOW_ROOT>\state\cutover-readiness.json
   ```
3. Проверьте отработку shadow-отката (`ShadowRollback`) и затем остановите shadow-процессы (`StopIdleShadow`).

## 2. Свежая инвентаризация и drain активных сессий (перед любым изменением production)

**Никогда не завершайте активные сессии силой.** Проверьте живые сервисы непосредственно перед переключением:

1. **C1 Hub (`39090` / живой `<BRIDGE_ROOT>\state\hub`):**
   ```powershell
   python <BRIDGE_ROOT>\bridge-v3\ff_hub.py --state-dir <BRIDGE_ROOT>\state\hub status
   ```
   Требуется: `sessions == []`, `resources == []`, `pending_owner_requests == 0`.
2. **C1 Bridge RPC (`39073` / `39076`):**
   - Проверьте `scope_report` и `desktop_mode_status` (отсутствие активных desktop-грантов и выполняющихся задач).
3. **C2 Gateway (`21476` / `<C2_PROD_ROOT>\gateway.db`):**
   - Проверить read-only состояние `jobs` (`queued`, `running`, `submitted`, `needs_attention` == `0`) и отсутствие активных `agent_turns`:
   ```powershell
   python -c "import sys; sys.path.insert(0, 'tools'); import canary_release_workflow as c, pathlib, json; print(json.dumps(c.inspect_c2_gateway_active_jobs(pathlib.Path(sys.argv[1]))))" <C2_PROD_ROOT>\gateway.db
   ```
4. Если есть активные задачи — дождитесь их естественного завершения (drain) или отмените штатным `task_cancel`.

## 3. Проверка owner-gate (readiness + одобрение владельца)

Владелец создаёт локальный файл `<APPROVAL_FILE>` с коротким TTL (например, 30 минут):

```json
{
  "schema": "ff-canary-owner-approval-v1",
  "approved": true,
  "c1_zip_sha256": "<64_HEX_C1_ZIP_SHA256>",
  "c2_commit": "<40_HEX_C2_COMMIT>",
  "expires_epoch": 1795100000,
  "owner_statement": "Одобряю ручное окно переключения C1+C2 после drain активных сессий",
  "active_sessions_drain_acknowledged": true
}
```

Проверьте gate (скрипт проверит совпадение хэшей, срока действия и цепочки квитанций, не перезапуская production):

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tools/canary_cutover_c1_c2.ps1 `
  -ConfirmOwnerCutover `
  -FullCoreZipPath <C1_ZIP> -FullCoreSha256 <C1_ZIP_SHA256> -C2ExpectedCommit <C2_COMMIT> `
  -ShadowRoot <SHADOW_ROOT> `
  -ReadinessManifestPath <SHADOW_ROOT>\state\cutover-readiness.json `
  -OwnerApprovalFile <APPROVAL_FILE>
```

## 4. Неизменяемые снимки production перед переключением

1. **C1 Bridge:** снимите SHA-проверенный холодный снимок и автономный комплект восстановления по [`OPERATOR_COLD_UPGRADE_RU.md`](OPERATOR_COLD_UPGRADE_RU.md):
   ```powershell
   python tools/cua_cold_rollback_bundle.py preflight --repo <C1_CHECKOUT> --runtime <BRIDGE_ROOT>\bridge-v3 --trusted-head <LIVE_TRUSTED_HEAD>
   python tools/cua_cold_rollback_bundle.py capture --repo <C1_CHECKOUT> --runtime <BRIDGE_ROOT>\bridge-v3 --snapshot <RECOVERY_ROOT>\<SNAPSHOT_NAME> --trusted-head <LIVE_TRUSTED_HEAD>
   python tools/cua_cold_rollback_bundle.py verify --snapshot <RECOVERY_ROOT>\<SNAPSHOT_NAME>
   python tools/cua_cold_rollback_bundle.py kit --repo <C1_CHECKOUT> --kit-root <RECOVERY_ROOT>\<SNAPSHOT_NAME>\kit
   ```
2. **Живые SQLite БД (C1 Hub + C2 Gateway):** снимите консистентные снимки строго через SQLite Online Backup API (не простым `Copy-Item` по живому WAL!):
   ```powershell
   python -c "import sys, pathlib, json; sys.path.insert(0, 'tools'); import canary_release_workflow as c; print(json.dumps(c.sqlite_online_backup(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))" <BRIDGE_ROOT>\state\hub\hub.db <RECOVERY_ROOT>\hub_pre_cutover.db
   python -c "import sys, pathlib, json; sys.path.insert(0, 'tools'); import canary_release_workflow as c; print(json.dumps(c.sqlite_online_backup(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))" <BRIDGE_ROOT>\state\hub\entry-grants.sqlite3 <RECOVERY_ROOT>\entry_grants_pre_cutover.sqlite3
   python -c "import sys, pathlib, json; sys.path.insert(0, 'tools'); import canary_release_workflow as c; print(json.dumps(c.sqlite_online_backup(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))" <C2_PROD_ROOT>\gateway.db <RECOVERY_ROOT>\gateway_pre_cutover.db
   ```
3. Зафиксируйте SHA-256 всех трёх резервных БД и неизменяемой копии текущего кода C2 (архив без `gateway.db`/`gateway.key`).

## 5. Пошаговое ручное переключение (по одному компоненту)

### Шаг 5A. Переключение C1 Windows Bridge

- Если текущий runtime поддерживает `socket_handover_v1` — используйте транзакционный `cua_runtime_deploy.py` + `cua_socket_transfer.py` (см. [`OPERATOR_GUIDE_RU.md`](OPERATOR_GUIDE_RU.md)).
- Если требуется холодный перезапуск — выставьте замок `.cua-cold-maintenance.lock`, вооружите внешний `cua_cold_recovery_watchdog.py` из `<RECOVERY_ROOT>\kit` через Планировщик задач, дождитесь idle-остановки `39073` (сохраняя `39076` по правилам [`OPERATOR_COLD_UPGRADE_RU.md`](OPERATOR_COLD_UPGRADE_RU.md)), обновите `bridge-v3` и перезапустите штатную задачу `FF-Bridge-V3-Keeper`.
- Проверьте после старта C1:
  - `ping`, `capabilities` (совпадение `agent_sha256`), `chat_permission_status`, `scope_report`;
  - `python tools/runtime_parity.py --installed <BRIDGE_ROOT>\bridge-v3 --ref <C1_COMMIT> --disk`;
  - `ff_hub.py status` (непрерывность квитанций `entry-grants.sqlite3` и `hub.db`).

### Шаг 5B. Переключение C2 (только после подтверждённой стабильности C1)

- **Никогда не запускайте `git checkout` прямо поверх живого production-каталога C2.**
- Подготовьте неизменяемый каталог нового релиза C2 (`c2-stage-manifest.json`), убедитесь в `active_jobs == 0`, приостановите задачи-супервизоры C2, выполните атомарную замену проверенных файлов кода с сохранением `gateway.db` и `gateway.key` (после снятия свежего SQLite Online Backup API снимка), затем запустите штатные супервизоры C2.
- Проверьте 3 последовательных ответа:
  - `GET http://127.0.0.1:21476/health` == `200`;
  - `GET http://127.0.0.1:21477/health` == `200` (`gateway_port == 21476`);
  - `GET http://127.0.0.1:21477/ready` == `200` (`gateway.ok == true` и `omniroute.ok == true`).

## 6. Процедура аварийного ручного отката

1. **Условие остановки:** немедленный откат при провале health-контракта (3 последовательные пробы), несовпадении `agent_sha256`, ошибках схемы SQLite или росте аномальных отказов.
2. **Сначала убедитесь в idle-состоянии или штатно завершите активные сессии** (не применяйте слепой `Stop-Process -Force` по имени `python.exe`).
3. **Откат C2:** остановите только проверенные процессы C2 по `PID + creation time + path`, восстановите файлы кода из неизменяемого baseline-снимка (без `git checkout` на prod); при необходимости отката схемы БД восстановите `gateway.db` из SHA-проверенного `<RECOVERY_ROOT>\gateway_pre_cutover.db` строго через `sqlite_restore_from_backup` (SQLite Online Backup API), предварительно сняв forensic-снимок текущего состояния.
4. **Откат C1:** выполните offline-восстановление из `<RECOVERY_ROOT>\<SNAPSHOT_NAME>` через автономный комплект `cua_cold_rollback_bundle.py restore --offline-confirmed` (см. [`OPERATOR_COLD_UPGRADE_RU.md`](OPERATOR_COLD_UPGRADE_RU.md)), сохраняя `hub.db`, `entry-grants.sqlite3` и исторические журналы `.cua-deploy`.
5. **Пост-откатная проверка:** проверьте `PRAGMA integrity_check` всех SQLite БД, непрерывность квитанций `grant_receipts` / `canary_receipts.sqlite3`, и health-эндпоинты `39073`, `39076`, `39090`, `21476`, `21477`, `20128`.
