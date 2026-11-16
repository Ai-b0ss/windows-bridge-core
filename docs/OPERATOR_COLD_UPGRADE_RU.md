# Безопасное холодное обновление и сторожевой откат Windows Bridge

Инструменты: `tools/cua_cold_rollback_bundle.py` (проверка происхождения, создание и верификация снимка и автономного комплекта), `tools/cua_cold_recovery_watchdog.py` (независимый внешний сторож автоматического отката) и эталонные обёртки хоста `tools/host-wrappers/bridge-v3-keeper-launch.ps1` / `runtime/bridge-v3/ff_win_v3_keeper.ps1`.

**Сам по себе инструмент подготовки не останавливает Bridge, не перезапускает службы и не запускает обновление без явной команды владельца.**

## Когда применяется процедура

Процедура предназначена для обновлений, в которых требуется контролируемая остановка процессов (переход со старой версии без поддержки `socket_handover_v1`, обновление системных обёрток запуска или аварийное восстановление):

- Если `%LOCALAPPDATA%\FF-Windows-Bridge` настроен как NTFS-соединение (`junction`) на физический том `<BRIDGE_ROOT>`, все файловые операции выполняются строго по физическому пути `<BRIDGE_ROOT>\bridge-v3` (прямой проход через reparse-точку блокируется защитой `DEPLOY_REPARSE_OR_TYPE_FORBIDDEN`).
- Если установленный `manifest.json` отстаёт от фактических файлов на диске, перед захватом снимка обязательно доказать происхождение каждого файла по объектам Git через `trusted_head` (см. [`MIGRATION_PROVENANCE_RU.md`](MIGRATION_PROVENANCE_RU.md)).
- Исторические журналы транзакций в `<BRIDGE_ROOT>\bridge-v3\.cua-deploy` сохраняются неизменными и никогда не удаляются вслепую по возрасту.

## Шаг 1. Read-only проверка и создание комплекта отката

1. Зафиксировать целевой коммит кандидата (40-символьный SHA), убедиться в чистоте дерева (`git status`), зелёном статусе GitHub CI и локальных тестов.
2. Выполнить проверку без записи на диск:
   ```powershell
   python tools/cua_cold_rollback_bundle.py preflight --repo <CHECKOUT> --runtime <BRIDGE_ROOT>\bridge-v3 --trusted-head <40-HEX-SHA>
   ```
3. Сохранить неизменяемый снимок ядра в отдельный каталог `<RECOVERY_ROOT>\<BUNDLE_NAME>` вне `bridge-v3`:
   ```powershell
   python tools/cua_cold_rollback_bundle.py capture --repo <CHECKOUT> --runtime <BRIDGE_ROOT>\bridge-v3 --snapshot <RECOVERY_ROOT>\<BUNDLE_NAME> --trusted-head <40-HEX-SHA>
   python tools/cua_cold_rollback_bundle.py verify --snapshot <RECOVERY_ROOT>\<BUNDLE_NAME>
   ```
4. Собрать и проверить автономный комплект модулей восстановления (7 самодостаточных файлов, независимых от заменяемого `bridge-v3`):
   ```powershell
   python tools/cua_cold_rollback_bundle.py kit --repo <CHECKOUT> --kit-root <RECOVERY_ROOT>\<BUNDLE_NAME>\kit
   python tools/cua_cold_rollback_bundle.py verify-kit --kit-root <RECOVERY_ROOT>\<BUNDLE_NAME>\kit
   ```

## Шаг 2. Согласованный замок `.cua-cold-maintenance.lock` с жёстким TTL 300 с в обоих слоях хранителя

На рабочей станции могут одновременно работать:
- основной интерактивный экземпляр `127.0.0.1:39073` под управлением задачи Планировщика `FF-Bridge-V3-Keeper` (`tools/host-wrappers/bridge-v3-keeper-launch.ps1` + внутренний цикл `runtime/bridge-v3/ff_win_v3_keeper.ps1`);
- резервный prelogin-экземпляр `127.0.0.1:39076` (запускаемый службой/задачей `SYSTEM`, в том числе через `C:\Users\<USER>\AppData\Local\FF-Windows-Bridge` junction).

Правила безопасности при восстановлении и переключении:
- **Единая функция `Test-FF3ColdMaintenanceLockActive` (TTL 300 с) во внутреннем и внешнем хранителях:** во время `recover_failed_rollout` сторож атомарно записывает JSON-файл `<BRIDGE_ROOT>\bridge-v3\.cua-cold-maintenance.lock` (`schema: ff-cold-maintenance-lock/v1`, `expires_epoch = now + 300`). И внутренний цикл `ff_win_v3_keeper.ps1` (`Test-FF3AgentStartAllowed`), и внешняя обёртка `bridge-v3-keeper-launch.ps1` (`Test-KeeperLauncherStartAllowed`) проверяют активность замка и запрещают старт агента, пока замок действителен; при истечении `expires_epoch` (или возраста файла свыше 300 с) осиротевший замок автоматически игнорируется и не способен навечно заблокировать самовосстановление.
- **Распознавание кросс-профильных junction:** проверка активных процессов корректно сопоставляет пути вида `C:\Users\*\AppData\Local\FF-Windows-Bridge\bridge-v3` с физическим `<BRIDGE_ROOT>\bridge-v3`, даже когда сторож выполняется под учётной записью `SYSTEM`.
- **Режим сохранения резервного порта `39076`:** при восстановлении основного порта `39073` допускается не останавливать живой экземпляр `--port 39076`, если в плане сторожа явно заданы `port=39073` и `peer_port=39076` (или флаги `--target-port 39073 --peer-port 39076`), командная строка и PID `39076` однозначно подтверждены через `Win32_Process`, а изменения затрагивают только `.py`-файлы и `manifest.json`. Если меняются не-Python файлы или жив процесс `39073` / `keeper`, запись строго блокируется.

## Шаг 3. Независимый сторожевой процесс (`cua_cold_recovery_watchdog.py`)

Перед остановкой старого процесса на `39073` сторож запускается **из автономного каталога `<RECOVERY_ROOT>` отдельной задачей Windows Task Scheduler** (никогда не внутри дочернего дерева самого Bridge):

- Сторож принимает локальный план `schema=ff-bridge-rollback-watchdog/v1` с `authorized_cold_rollout=true`, точными `source_head`, `candidate_head`, `old_agent_sha256`, `candidate_agent_sha256`, `port`, `deadline_epoch` и параметрами задачи `keeper_task=FF-Bridge-V3-Keeper` (для изолированных стендовых учений вне боевых портов поддерживается флаг `isolated_drill=true`, запрещающий порты `39073`/`39076` и боевой путь `%LOCALAPPDATA%\FF-Windows-Bridge\bridge-v3`).
- Обновление признаётся успешным только после **трёх последовательных ответов** нового экземпляра с ожидаемым `agent_sha256` и подтверждённым PID/временем старта (`status: candidate_ready`).
- Если к `deadline_epoch` новый код не прошёл проверку, сторож выставляет `.cua-cold-maintenance.lock`, останавливает только проверенный процесс кандидата/хранителя, выполняет `restore` из SHA-проверенного снимка, снимает замок в блоке `finally`, перезапускает штатную задачу `FF-Bridge-V3-Keeper` и сохраняет квитанцию `status: rollback_performed`, `rollback: restored`, `rollback_executed: true`.

## Ручное offline-восстановление

После подтверждённой остановки процессов целевого порта:
```powershell
python <RECOVERY_ROOT>\<BUNDLE_NAME>\kit\tools\cua_cold_rollback_bundle.py restore `
  --runtime <BRIDGE_ROOT>\bridge-v3 `
  --snapshot <RECOVERY_ROOT>\<BUNDLE_NAME> `
  --target-port 39073 --peer-port 39076 `
  --offline-confirmed
```
При обнаружении любых сторонних правок вне Git-объектов кандидата команда завершается отказом до изменения первого байта, сохраняя пользовательские файлы и журналы нетронутыми.
