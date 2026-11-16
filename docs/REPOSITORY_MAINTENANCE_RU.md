# Сопровождение репозитория Windows Bridge Core

## Единственный источник правды

Канонический публичный репозиторий исходного кода — [`Ai-b0ss/windows-bridge-core`](https://github.com/Ai-b0ss/windows-bridge-core), единственная постоянная ветка — `main`. Исторический приватный транспорт и локальные эксплуатационные состояния хранятся отдельно; запрещено копировать закрытую историю `.git`, имена машин, локальные пути пользователя, токены и рабочие журналы в публичный репозиторий.

Исходный код в `main`, опубликованный портативный архив GitHub Release (`*.zip`) и установленный экземпляр на ПК — **три независимых артефакта**, пока их побайтовое совпадение не подтверждено проверкой (`tools/build_portable_release.py` и `tools/runtime_parity.py`).

## Карта репозитория

| Раздел / файл | Назначение |
| :--- | :--- |
| `runtime/bridge-v3/` | Ядро локального сервера (`127.0.0.1`), RPC-маршрутизация, модель разрешений из чата, защёлка `Stop`, бесшовная передача сокета WinSock (`cua_socket_transfer.py`), транзакционный деплоер (`cua_runtime_deploy.py`), адаптеры Chrome и Windows-MCP |
| `runtime/github-transport/` | Автономный транспорт через приватный GitHub-репозиторий с защитой аренды и досылкой исходящей очереди |
| `tools/cf-flight-controller/` | Локальный диспетчер `FlightController + ContextShield v0.5.1` для Cloudflare-туннеля (`12,5 с` async handover, дедупликация, переключение `39073 -> 39076`, выгрузка больших логов) |
| `tools/prelogin-recovery/` | Опциональный супервизор восстановления сетевого подключения до входа в Windows |
| `tools/cua_cold_rollback_bundle.py`, `tools/cua_cold_recovery_watchdog.py` | Автономный захват SHA-проверенного снимка и внешний сторож автоматического отката при холодном обновлении |
| `tools/build_portable_release.py`, `tools/build_skill_plugin.py` | Воспроизводимая сборка портативного архива `Full Core ZIP` и пакетов `ChatGPT Skill / Plugin` |
| `tools/runtime_parity.py` | Безопасная read-only сверка SHA-256 установленного `bridge-v3` с `origin/main` без чтения содержимого в вывод |
| `skills/windows-bridge/` | Канонический исходник навыка (`SKILL.md` и справочники) |
| `docs/` | Руководства владельца (`OPERATOR_GUIDE_RU.md`, `OPERATOR_COLD_UPGRADE_RU.md`, `MIGRATION_PROVENANCE_RU.md`, `GITHUB_RETRY_RECOVERY_RU.md`), архитектурные спецификации (`docs/design/`), модели угроз (`docs/security/`) и исторический архив (`docs/archive/`) |
| `tests/` | Модульные, контрактные и изолированные интеграционные испытания (`isolated_rpc_smoke.py`, `installed_package_smoke.py`) |
| `release-manifest.json` | Контрольные суммы SHA-256 всех упаковываемых исходных файлов (в формате LF) и привязанных вендорных архивов |

## Политика веток, PR и релизов

1. **Одна задача — одна короткоживущая ветка и один PR.** Слияние в `main` выполняется через `squash merge` только после прохождения всех обязательных проверок GitHub Actions (`ci.yml`, `candidate-install.yml`, `prelogin-recovery.yml`, `windows-bridge-local-safety.yml`).
2. **Удаление веток после squash merge.** Не полагайтесь на `git branch --merged`: при squash-слиянии проверяйте точное совпадение `head.sha` ветки с `head.sha` слитого PR и отсутствие новых открытых PR, после чего удаляйте временную ветку (`gh pr merge --squash --delete-branch`).
3. **Итоги генеральной ревизии (16 ноября 2026 г.):**
   - Все исторические слитые сервисные ветки (62 ветки из реестра [`docs/archive/merged-branches-2026-11-14.json`](archive/merged-branches-2026-11-14.json) и последующие рабочие ветки после интеграции PR [#106](https://github.com/Ai-b0ss/windows-bridge-core/pull/106) и [#107](https://github.com/Ai-b0ss/windows-bridge-core/pull/107)) очищены; поглощённые черновые PR (`#97`–`#104`) закрыты с указанием точных коммитов-преемников; одноразовые миграционные скрипты и workflow удалены из рабочего контура.
   - При необходимости восстановить любую историческую ветку для справки используйте её `name` и 40-символьный `sha` из `docs/archive/merged-branches-2026-11-14.json` или истории закрытых PR в GitHub (`gh api repos/Ai-b0ss/windows-bridge-core/git/refs -f ref=refs/heads/<name> -f sha=<sha>`).
4. **Базовый релиз вендорных бинарников:** тег [`v2026.10.24-remote-beta2`](https://github.com/Ai-b0ss/windows-bridge-core/releases/tag/v2026.10.24-remote-beta2) хранит неизменяемый базовый архив вендорных рантаймов (`Python`, `Node.js`, `gh`), проверяемый по `PREVIOUS_RELEASE_SHA` в `tools/build_portable_release.py` и `candidate-install.yml` — **удалять этот релиз нельзя**.

## Гигиена рабочей среды Windows

- Изолированные git-клоны для разработки и сборки релизов создавайте во временном каталоге вне рабочего `bridge-v3` с параметром `git config core.autocrlf false` и удаляйте после публикации изменений.
- Никогда не останавливайте боевой Bridge, туннель Cloudflare, VPN-клиент или пользовательский Chrome ради обслуживания Git-репозитория.
